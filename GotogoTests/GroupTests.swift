//
//  GroupTests.swift
//  GotogoTests
//
//  In-simulator end-to-end proof of GROUP MESSAGING with Signal Sender Keys,
//  driving the app's OWN services (AuthService + MessagingService + GroupService)
//  against the live local backend. Three accounts (A, B, C) become pairwise mutual
//  contacts, A creates a group, the N² `group_setup` exchange converges via a
//  `pump()` of each user's `GroupService.sync()`, and group messages flow + decrypt
//  for every member. Finally, removing a member ROTATES the sender key so the
//  removed member can no longer read future group messages.
//
import XCTest
import ImageIO
import CoreGraphics
import UniformTypeIdentifiers
@testable import Gotogo

@MainActor
final class GroupTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    /// A per-user stack: the app's own services over a distinct in-memory secret
    /// store + a distinct on-disk cache (so each user keeps distinct session/group
    /// files), plus the resolved public id once registered.
    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let groups: GroupService
        let store: InMemorySecretStore
        var publicId: String = ""
    }

    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        // Distinct temp cache (=> distinct session + group files) per user.
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-grp-\(tag)-\(UUID().uuidString).json")
        let media = MediaService(baseURL: apiURL)
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache,
                                         media: media)
        let groupStore = GroupStore(cacheURL: cache)
        let keyPackages = MLSKeyPackageStore(cacheURL: cache)
        let groups = GroupService(messaging: messaging, store: groupStore,
                                  keyPackages: keyPackages,
                                  myPublicId: { store.loadSession()?.publicId },
                                  myDeviceId: { store.loadSession()?.deviceId })
        return Stack(auth: auth, messaging: messaging, groups: groups, store: store)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run the local server")
    }

    /// Registers an account, retrying on a 429 (the register rate-limiter) after a
    /// short pause so back-to-back test runs don't flake.
    @discardableResult
    private func register(_ stack: Stack) async throws -> RegistrationResult {
        for attempt in 0..<5 {
            do {
                return try await stack.auth.register()
            } catch let error as APIError {
                if case .server(let status, _, _) = error, status == 429, attempt < 4 {
                    try await Task.sleep(nanoseconds: 2_300_000_000)
                    continue
                }
                throw error
            }
        }
        return try await stack.auth.register()
    }

    /// Makes two registered stacks mutual contacts (A requests, B accepts).
    private func makeMutual(_ a: Stack, _ b: Stack) async throws {
        try await a.messaging.requestContact(publicId: b.publicId)
        try await b.messaging.acceptContact(fromPublicId: a.publicId)
    }

    /// Runs `GroupService.sync()` on every user a few rounds so the pairwise
    /// control-message exchange (the N² `group_setup`s, rekeys, redistributions)
    /// converges and inbound group messages are decrypted into each conversation.
    private func pump(_ users: [Stack], rounds: Int = 4) async throws {
        for _ in 0..<rounds {
            for u in users { _ = try await u.groups.sync() }
        }
    }

    /// The decrypted text bodies of a user's group conversation that came from
    /// `senderId` (i.e. inbound, decrypted group messages from that sender).
    private func receivedTexts(_ user: Stack, group: String, from senderId: String) -> [String] {
        user.groups.conversation(group).messages
            .filter { $0.decrypted && !$0.isMine && $0.senderPublicId == senderId }
            .map(\.body)
    }

    // MARK: - The full group-messaging proof

    /// Registers A, B, C; each publishes MLS KeyPackages; makes all three pairwise
    /// mutual; A creates an MLS group (members join via Welcome); group text flows
    /// both ways and decrypts under the shared epoch for every member; then removing
    /// C COMMITS a new epoch (re-keying the tree) so C — whose stale keys can't open
    /// the UpdatePath — can no longer read future messages while B still can.
    func testGroupMessagingOverMLSWithEpochRekeyAndRemovalLockout() async throws {
        try await requireBackend()

        // 1. Register A, B, C (each uploads prekeys during register).
        var a = makeStack("A"); var b = makeStack("B"); var c = makeStack("C")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        c.publicId = try await register(c).session.publicId

        // MLS KeyPackage publication (RFC 9420 §10 Delivery-Service role): every
        // device publishes a pool of KeyPackages to the key directory so a committer
        // can Add it to a group without a round trip. Must precede group creation.
        for s in [a, b, c] { _ = try await s.groups.publishKeyPackages() }

        // Make all three pairwise mutual contacts (A-B, A-C, B-C) so they can
        // exchange the pairwise control messages.
        try await makeMutual(a, b)
        try await makeMutual(a, c)
        try await makeMutual(b, c)

        // 2. A creates an MLS group "Team" with B and C, then pump so B and C each
        //    process the Welcome and join the group at A's epoch.
        let groupId = try await a.groups.createGroup(name: "Team", memberPublicIds: [b.publicId, c.publicId])
        XCTAssertFalse(groupId.isEmpty, "createGroup returns a group id")
        try await pump([a, b, c])

        // Every member should know the group with its DECRYPTED name.
        let bGroups = try await b.groups.groups()
        XCTAssertTrue(bGroups.contains { $0.groupId == groupId && $0.name == "Team" },
                      "B sees the group with its decrypted name")
        let cGroups = try await c.groups.groups()
        XCTAssertTrue(cGroups.contains { $0.groupId == groupId && $0.name == "Team" },
                      "C sees the group with its decrypted name")

        // 3. A sends a group text; B and C each decrypt "hello team" from A.
        _ = try await a.groups.sendGroupText("hello team", to: groupId)
        try await pump([a, b, c])
        XCTAssertTrue(receivedTexts(b, group: groupId, from: a.publicId).contains("hello team"),
                      "B decrypts A's group message")
        XCTAssertTrue(receivedTexts(c, group: groupId, from: a.publicId).contains("hello team"),
                      "C decrypts A's group message")

        // 4. B sends a group text; A and C each decrypt "hi from B".
        _ = try await b.groups.sendGroupText("hi from B", to: groupId)
        try await pump([a, b, c])
        XCTAssertTrue(receivedTexts(a, group: groupId, from: b.publicId).contains("hi from B"),
                      "A decrypts B's group message")
        XCTAssertTrue(receivedTexts(c, group: groupId, from: b.publicId).contains("hi from B"),
                      "C decrypts B's group message")

        // 5. Rotation on removal: A removes C, then sends a message only the
        //    remaining members can read. B must decrypt it; C must NOT.
        try await a.groups.removeMember(groupId: groupId, publicId: c.publicId)
        try await pump([a, b, c])

        _ = try await a.groups.sendGroupText("after C left", to: groupId)
        try await pump([a, b, c])

        XCTAssertTrue(receivedTexts(b, group: groupId, from: a.publicId).contains("after C left"),
                      "B decrypts A's post-removal message")
        XCTAssertFalse(receivedTexts(c, group: groupId, from: a.publicId).contains("after C left"),
                       "removed member C must NOT be able to read post-removal messages")
    }

    // MARK: - Group media (photo + video)

    /// A sends a PHOTO and a VIDEO to an MLS group; B and C each decrypt the media
    /// message (the per-file key rode INSIDE the MLS application message) and then
    /// download + decrypt the opaque blob from storage. Also proves the 25 MB video
    /// gate is enforced on the group path. This is exactly what the group composer's
    /// photo/video picker now drives, proven for every member.
    func testGroupImageAndVideoDeliverEncrypted() async throws {
        try await requireBackend()

        var a = makeStack("GMA"); var b = makeStack("GMB"); var c = makeStack("GMC")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        c.publicId = try await register(c).session.publicId
        for s in [a, b, c] { _ = try await s.groups.publishKeyPackages() }
        try await makeMutual(a, b); try await makeMutual(a, c); try await makeMutual(b, c)

        let groupId = try await a.groups.createGroup(name: "Media", memberPublicIds: [b.publicId, c.publicId])
        try await pump([a, b, c])

        // --- PHOTO: a real JPEG so uploadImage (decode + strip + thumbnail) accepts it.
        let jpeg = Self.makeJPEG()
        let imgCaption = "group selfie 📸"
        let sentImg = try await a.groups.sendGroupImage(jpeg, caption: imgCaption, to: groupId)
        XCTAssertEqual(sentImg.mediaKind, "image")
        XCTAssertNotNil(sentImg.media)
        try await pump([a, b, c])

        for member in [b, c] {
            guard let got = member.groups.conversation(groupId).messages
                .first(where: { $0.senderPublicId == a.publicId && $0.mediaKind == "image" }) else {
                return XCTFail("a member received no group image from A")
            }
            XCTAssertTrue(got.decrypted, "the group media envelope decrypts")
            XCTAssertEqual(got.body, imgCaption, "caption rides inside the MLS app message")
            let ref = try XCTUnwrap(got.media, "group image carries a MediaReference")
            let blob = await member.groups.loadFull(ref)
            let data = try XCTUnwrap(blob, "member downloads + decrypts the group image blob")
            XCTAssertNotNil(CGImageSourceCreateWithData(data as CFData, nil),
                            "decrypted group media is a valid image")
        }

        // --- VIDEO: opaque bytes (uploadData does no decoding); must round-trip exactly.
        let video = Data((0..<24_000).map { UInt8(($0 * 7) & 0xFF) })
        let vidCaption = "the winning goal ⚽️"
        let sentVid = try await a.groups.sendGroupVideo(video, caption: vidCaption, to: groupId)
        XCTAssertEqual(sentVid.mediaKind, "video")
        try await pump([a, b, c])

        for member in [b, c] {
            guard let got = member.groups.conversation(groupId).messages
                .first(where: { $0.senderPublicId == a.publicId && $0.mediaKind == "video" }) else {
                return XCTFail("a member received no group video from A")
            }
            XCTAssertTrue(got.decrypted)
            XCTAssertEqual(got.body, vidCaption)
            let ref = try XCTUnwrap(got.media)
            XCTAssertEqual(ref.contentType, "video/mp4")
            let blob = await member.groups.loadFull(ref)
            XCTAssertEqual(blob, video, "member recovers the EXACT group video bytes")
        }

        // The 25 MB gate (shared with 1:1) rejects an oversize group video before any
        // upload or fan-out.
        do {
            _ = try await a.groups.sendGroupVideo(Data(count: MediaLimits.maxVideoBytes + 1), caption: nil, to: groupId)
            XCTFail("oversize group video should be rejected")
        } catch let error as MessagingError {
            guard case .mediaTooLarge = error else { return XCTFail("wrong error: \(error)") }
        }
    }

    /// A tiny real JPEG so `MediaService.uploadImage` (which decodes, strips metadata,
    /// and thumbnails) accepts it.
    private static func makeJPEG(width: Int = 48, height: Int = 48) -> Data {
        let cs = CGColorSpaceCreateDeviceRGB()
        let ctx = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8,
                            bytesPerRow: 0, space: cs,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.setFillColor(red: 0.3, green: 0.7, blue: 0.4, alpha: 1)
        ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let image = ctx.makeImage()!
        let out = NSMutableData()
        let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, image, nil)
        precondition(CGImageDestinationFinalize(dest), "failed to encode test JPEG")
        return out as Data
    }

    // MARK: - Group metadata (admin rename + photo) + realtime refresh

    /// The owner (admin) renames the group and sets a photo; the change distributes
    /// E2EE (a `group_meta` control on the group channel) and every member converges
    /// on the new name + downloads the photo. A non-admin is refused. Bug fix #3.
    func testGroupRenameAndPhotoPropagateFromOwnerOnly() async throws {
        try await requireBackend()
        var a = makeStack("GRA"); var b = makeStack("GRB")    // A = admin/owner, B = member
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        for s in [a, b] { _ = try await s.groups.publishKeyPackages() }
        try await makeMutual(a, b)

        let groupId = try await a.groups.createGroup(name: "Original", memberPublicIds: [b.publicId])
        try await pump([a, b])
        XCTAssertEqual(b.groups.state(groupId)?.name, "Original", "B joined with the original name")
        // B lists its groups (exactly what the Groups tab does on appear) so its
        // roster learns A's admin role — the apply-side gate for `group_meta`.
        _ = try await b.groups.groups()

        // Owner renames + sets a photo; it applies locally immediately.
        try await a.groups.updateGroupMeta(groupId: groupId, name: "Renamed Team", photo: Self.makeJPEG())
        XCTAssertEqual(a.groups.state(groupId)?.name, "Renamed Team")
        XCTAssertNotNil(a.groups.state(groupId)?.photoRef)
        try await pump([a, b])

        // B converges on the new name + receives the photo (key rode inside the control).
        XCTAssertEqual(b.groups.state(groupId)?.name, "Renamed Team", "B sees the owner's new name")
        let ref = try XCTUnwrap(b.groups.state(groupId)?.photoRef, "B receives the group photo ref")
        let blob = await b.groups.loadFull(ref)
        let data = try XCTUnwrap(blob, "B downloads + decrypts the group photo")
        XCTAssertNotNil(CGImageSourceCreateWithData(data as CFData, nil), "the group photo decodes")

        // A NON-admin cannot rename: the service refuses before sending anything.
        do {
            try await b.groups.updateGroupMeta(groupId: groupId, name: "Hacked", photo: nil)
            XCTFail("a non-admin must not rename the group")
        } catch let error as MessagingError {
            guard case .notGroupAdmin = error else { return XCTFail("wrong error: \(error)") }
        }
        try await pump([a, b])
        XCTAssertEqual(b.groups.state(groupId)?.name, "Renamed Team", "the non-admin attempt changed nothing")
    }

    /// Processing an inbound group message fires `onGroupsChanged` — the signal
    /// `AppState` wires to refresh the open group view in REAL TIME. Bug fix #1.
    func testInboundGroupMessageFiresOnGroupsChanged() async throws {
        try await requireBackend()
        var a = makeStack("OGCA"); var b = makeStack("OGCB")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        for s in [a, b] { _ = try await s.groups.publishKeyPackages() }
        try await makeMutual(a, b)
        let groupId = try await a.groups.createGroup(name: "RT", memberPublicIds: [b.publicId])
        try await pump([a, b])

        var changes = 0
        b.groups.onGroupsChanged = { changes += 1 }
        _ = try await a.groups.sendGroupText("are you seeing this live?", to: groupId)
        try await pump([a, b])

        XCTAssertGreaterThan(changes, 0,
                             "an inbound group message fires onGroupsChanged → drives the live UI refresh")
        XCTAssertTrue(receivedTexts(b, group: groupId, from: a.publicId).contains("are you seeing this live?"))
    }

    // MARK: - Removal ejects the member; creator leaving dissolves the group

    /// Admin A removes C. C is told directly (pairwise `group_removed`), so C's group
    /// state is dropped locally (its app would eject it from the conversation), while
    /// B stays in and keeps receiving — and C can no longer read group messages.
    func testRemovedMemberIsEjectedAndCannotRead() async throws {
        try await requireBackend()
        var a = makeStack("REJA"); var b = makeStack("REJB"); var c = makeStack("REJC")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        c.publicId = try await register(c).session.publicId
        for s in [a, b, c] { _ = try await s.groups.publishKeyPackages() }
        try await makeMutual(a, b); try await makeMutual(a, c); try await makeMutual(b, c)

        let groupId = try await a.groups.createGroup(name: "Kick", memberPublicIds: [b.publicId, c.publicId])
        try await pump([a, b, c])
        XCTAssertNotNil(c.groups.state(groupId), "C joined the group")

        // Admin removes C.
        try await a.groups.removeMember(groupId: groupId, publicId: c.publicId)
        try await pump([a, b, c])

        // C is ejected locally (the open conversation would dismiss); B stays.
        XCTAssertNil(c.groups.state(groupId), "removed member C is dropped from the group on its device")
        XCTAssertNotNil(b.groups.state(groupId), "remaining member B keeps the group")

        // B still receives; C cannot read post-removal messages.
        _ = try await a.groups.sendGroupText("after kick", to: groupId)
        try await pump([a, b, c])
        XCTAssertTrue(receivedTexts(b, group: groupId, from: a.publicId).contains("after kick"), "B still receives")
        XCTAssertFalse(receivedTexts(c, group: groupId, from: a.publicId).contains("after kick"),
                       "removed member C cannot read post-removal messages")
    }

    /// When the CREATOR (admin) leaves, the group is dissolved for everyone: each
    /// member is told (`group_dissolved`) and drops the group locally.
    func testCreatorLeavingDissolvesGroupForEveryone() async throws {
        try await requireBackend()
        var a = makeStack("DISA"); var b = makeStack("DISB"); var c = makeStack("DISC")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        c.publicId = try await register(c).session.publicId
        for s in [a, b, c] { _ = try await s.groups.publishKeyPackages() }
        try await makeMutual(a, b); try await makeMutual(a, c); try await makeMutual(b, c)

        let groupId = try await a.groups.createGroup(name: "Doomed", memberPublicIds: [b.publicId, c.publicId])
        try await pump([a, b, c])
        XCTAssertNotNil(b.groups.state(groupId)); XCTAssertNotNil(c.groups.state(groupId))

        // The creator leaves → dissolve for all.
        try await a.groups.leaveGroup(groupId: groupId)
        try await pump([a, b, c])

        XCTAssertNil(a.groups.state(groupId), "the creator dropped the group")
        XCTAssertNil(b.groups.state(groupId), "B's group was dissolved")
        XCTAssertNil(c.groups.state(groupId), "C's group was dissolved")
    }

    // MARK: - Group deletion (per-message "for everyone" + clear conversation)

    /// A, B, C in an MLS group. A deletes one of its messages "for everyone" (gone on
    /// B and C), then deletes the whole group conversation (all of A's messages gone
    /// on B and C while their own remain; A's local thread is cleared). Deletion
    /// controls ride MLS application messages over the group.
    func testGroupDeletionForEveryoneAndConversation() async throws {
        try await requireBackend()

        var a = makeStack("DA"); var b = makeStack("DB"); var c = makeStack("DC")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        c.publicId = try await register(c).session.publicId
        for s in [a, b, c] { _ = try await s.groups.publishKeyPackages() }
        try await makeMutual(a, b); try await makeMutual(a, c); try await makeMutual(b, c)

        let groupId = try await a.groups.createGroup(name: "Del", memberPublicIds: [b.publicId, c.publicId])
        try await pump([a, b, c])

        let g1 = try await a.groups.sendGroupText("g1", to: groupId)
        _ = try await a.groups.sendGroupText("g2", to: groupId)
        _ = try await b.groups.sendGroupText("gb", to: groupId)
        try await pump([a, b, c])

        XCTAssertTrue(receivedTexts(b, group: groupId, from: a.publicId).contains("g1"), "B sees A's g1")
        XCTAssertTrue(receivedTexts(c, group: groupId, from: a.publicId).contains("g1"), "C sees A's g1")

        // 1) A deletes g1 for EVERYONE → removed on B and C; g2 stays.
        let ok = await a.groups.deleteGroupMessageForEveryone(g1)
        XCTAssertTrue(ok, "deleting my own group message for everyone succeeds")
        try await pump([a, b, c])
        XCTAssertFalse(receivedTexts(b, group: groupId, from: a.publicId).contains("g1"), "g1 removed on B")
        XCTAssertFalse(receivedTexts(c, group: groupId, from: a.publicId).contains("g1"), "g1 removed on C")
        XCTAssertTrue(receivedTexts(b, group: groupId, from: a.publicId).contains("g2"), "g2 still on B")

        // 2) A clears the whole group conversation → all of A's messages drop on B & C
        //    (their own remain); A's local thread is emptied.
        await a.groups.deleteGroupConversation(groupId)
        try await pump([a, b, c])
        XCTAssertTrue(receivedTexts(b, group: groupId, from: a.publicId).isEmpty, "all of A's messages gone on B")
        XCTAssertTrue(receivedTexts(c, group: groupId, from: a.publicId).isEmpty, "all of A's messages gone on C")
        XCTAssertTrue(b.groups.conversation(groupId).messages.contains { $0.isMine && $0.body == "gb" },
                      "B keeps its OWN group message")
        XCTAssertTrue(a.groups.conversation(groupId).messages.isEmpty, "A's local group thread is cleared")
    }

    // MARK: - Group multi-device convergence

    /// Builds a SECOND device for an existing account (its own identity/prekeys/MLS
    /// material), sharing the account's public id but a distinct device id/token —
    /// so it is its own MLS leaf.
    private func makeSecondDevice(_ aReg: RegistrationResult, _ added: AddDeviceResponse,
                                  tag: String) async throws -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        api.setToken(added.token)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-grp-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache)

        let identity = engine.generateIdentity()
        let generated = try engine.generatePreKeys(identity: identity, signedPreKeyId: 1,
                                                   oneTimeCount: 20, firstOneTimeId: 1)
        try store.saveIdentity(identity)
        try store.savePreKeyStore(generated.store)
        try store.saveSession(Session(publicId: aReg.session.publicId, accountId: aReg.session.accountId,
                                      deviceId: added.deviceId, token: added.token, deviceName: tag))
        try await api.uploadPreKeys(AuthService.uploadRequest(identity: identity, store: generated.store))

        let groupStore = GroupStore(cacheURL: cache)
        let keyPackages = MLSKeyPackageStore(cacheURL: cache)
        let groups = GroupService(messaging: messaging, store: groupStore, keyPackages: keyPackages,
                                  myPublicId: { store.loadSession()?.publicId },
                                  myDeviceId: { store.loadSession()?.deviceId })
        var stack = Stack(auth: auth, messaging: messaging, groups: groups, store: store)
        stack.publicId = aReg.session.publicId
        return stack
    }

    /// Account A has TWO devices (A1, A2). A1 creates an MLS group with B; A2 is
    /// added as its own leaf so A's devices converge. A message from any of the
    /// three lands on the other two — and A1 ⇄ A2 see each other's sends as `isMine`.
    func testGroupMultiDeviceConvergence() async throws {
        try await requireBackend()

        var a1 = makeStack("MA1")
        let aReg = try await register(a1)
        a1.publicId = aReg.session.publicId
        _ = try await a1.groups.publishKeyPackages()

        // Provision A's second device and publish its KeyPackages so A1 can add it.
        let added = try await a1.messaging.api.addDevice(deviceName: "A2")
        let a2 = try await makeSecondDevice(aReg, added, tag: "MA2")
        _ = try await a2.groups.publishKeyPackages()

        var b = makeStack("MB")
        b.publicId = try await register(b).session.publicId
        _ = try await b.groups.publishKeyPackages()
        try await makeMutual(a1, b)

        let groupId = try await a1.groups.createGroup(name: "MD", memberPublicIds: [b.publicId])
        try await pump([a1, a2, b])

        let m1 = try await a1.groups.sendGroupText("from-a1", to: groupId)
        try await pump([a1, a2, b])
        _ = try await a2.groups.sendGroupText("from-a2", to: groupId)
        try await pump([a1, a2, b])
        _ = try await b.groups.sendGroupText("from-b", to: groupId)
        try await pump([a1, a2, b])

        let expected: Set = ["from-a1", "from-a2", "from-b"]
        func decrypted(_ s: Stack) -> Set<String> {
            Set(s.groups.conversation(groupId).messages.filter { $0.decrypted }.map(\.body))
        }
        XCTAssertEqual(decrypted(a1), expected, "A device 1 has all three messages")
        XCTAssertEqual(decrypted(a2), expected, "A device 2 CONVERGES with device 1")
        XCTAssertEqual(decrypted(b), expected, "B sees all three messages")

        // Each of A's devices shows the OTHER's message as its own.
        XCTAssertTrue(a2.groups.conversation(groupId).messages.contains { $0.body == "from-a1" && $0.isMine },
                      "device 2 shows device 1's message as mine")
        XCTAssertTrue(a1.groups.conversation(groupId).messages.contains { $0.body == "from-a2" && $0.isMine },
                      "device 1 shows device 2's message as mine")

        // Delete-for-everyone now reaches MY OWN other device too (the group control
        // fans out to my devices), not just the other members.
        _ = await a1.groups.deleteGroupMessageForEveryone(m1)
        try await pump([a1, a2, b])
        XCTAssertFalse(decrypted(a1).contains("from-a1"), "deleter A1 dropped from-a1")
        XCTAssertFalse(decrypted(a2).contains("from-a1"), "from-a1 removed on my OTHER device A2")
        XCTAssertFalse(decrypted(b).contains("from-a1"), "from-a1 removed on member B")
    }

    /// LATE JOIN: a group is created while account A has a single device; A's second
    /// device is provisioned AFTERWARDS. A1 (the admin) retro-adds it on sync, and
    /// subsequent group traffic converges across A1, the late A2, and B.
    func testGroupLateJoinNewDevice() async throws {
        try await requireBackend()

        var a1 = makeStack("LJ1")
        let aReg = try await register(a1)
        a1.publicId = aReg.session.publicId
        _ = try await a1.groups.publishKeyPackages()

        var b = makeStack("LJB")
        b.publicId = try await register(b).session.publicId
        _ = try await b.groups.publishKeyPackages()
        try await makeMutual(a1, b)

        // Group created while A has ONE device.
        let groupId = try await a1.groups.createGroup(name: "LJ", memberPublicIds: [b.publicId])
        try await pump([a1, b])
        _ = try await a1.groups.sendGroupText("before", to: groupId)
        try await pump([a1, b])

        // Provision A's SECOND device AFTER the group already exists.
        let added = try await a1.messaging.api.addDevice(deviceName: "A2")
        let a2 = try await makeSecondDevice(aReg, added, tag: "LJ2")
        _ = try await a2.groups.publishKeyPackages()

        // A1's sync retro-adds A2 into the group; pump so A2 joins via the Welcome.
        try await pump([a1, a2, b])

        _ = try await a1.groups.sendGroupText("after-a1", to: groupId)
        try await pump([a1, a2, b])
        _ = try await a2.groups.sendGroupText("after-a2", to: groupId)
        try await pump([a1, a2, b])

        func decrypted(_ s: Stack) -> Set<String> {
            Set(s.groups.conversation(groupId).messages.filter { $0.decrypted }.map(\.body))
        }
        // The late-joined device converges on POST-join traffic (history isn't backfilled).
        XCTAssertTrue(decrypted(a2).isSuperset(of: ["after-a1", "after-a2"]),
                      "late-joined A2 must receive post-join messages: \(decrypted(a2))")
        // A1 and B have the full history including the late device's own message.
        XCTAssertTrue(decrypted(a1).isSuperset(of: ["before", "after-a1", "after-a2"]),
                      "A1 has everything: \(decrypted(a1))")
        XCTAssertTrue(decrypted(b).isSuperset(of: ["before", "after-a1", "after-a2"]),
                      "B has everything incl. the late device's message: \(decrypted(b))")
        // The late device's message reached A1 as its own.
        XCTAssertTrue(a1.groups.conversation(groupId).messages.contains { $0.body == "after-a2" && $0.isMine },
                      "A1 sees the late device's message as its own")
    }

    // MARK: - Non-admin late join (unblocked by the server commit register)

    /// A NON-admin member's device, provisioned AFTER the group exists, now joins on
    /// its own — previously only the admin could reconcile devices, because concurrent
    /// commits would fork without a server ordering point. With the CAS register any
    /// member orders its own device-Add, so B (a plain member) retro-adds its late
    /// second device and post-join traffic converges across A, B1 and the late B2.
    func testNonAdminLateJoinNewDevice() async throws {
        try await requireBackend()

        var a = makeStack("NAJA")                 // the admin
        a.publicId = try await register(a).session.publicId
        _ = try await a.groups.publishKeyPackages()

        var b1 = makeStack("NAJB1")               // a plain (non-admin) member
        let bReg = try await register(b1)
        b1.publicId = bReg.session.publicId
        _ = try await b1.groups.publishKeyPackages()
        try await makeMutual(a, b1)

        // Admin A creates the group with B as a member; each has a single device.
        let groupId = try await a.groups.createGroup(name: "NAJ", memberPublicIds: [b1.publicId])
        try await pump([a, b1])
        _ = try await a.groups.sendGroupText("hello", to: groupId)
        try await pump([a, b1])
        XCTAssertTrue(receivedTexts(b1, group: groupId, from: a.publicId).contains("hello"),
                      "B1 joined and reads A")

        // The NON-admin B provisions a SECOND device AFTER the group already exists.
        let added = try await b1.messaging.api.addDevice(deviceName: "B2")
        let b2 = try await makeSecondDevice(bReg, added, tag: "NAJB2")
        _ = try await b2.groups.publishKeyPackages()

        // B1 — a non-admin — reconciles its own device set on sync and retro-adds B2
        // through the CAS register. Pump so B2 joins via the Welcome.
        try await pump([a, b1, b2], rounds: 6)

        _ = try await a.groups.sendGroupText("after-a", to: groupId)
        try await pump([a, b1, b2])
        _ = try await b2.groups.sendGroupText("after-b2", to: groupId)
        try await pump([a, b1, b2])

        func decrypted(_ s: Stack) -> Set<String> {
            Set(s.groups.conversation(groupId).messages.filter { $0.decrypted }.map(\.body))
        }
        XCTAssertTrue(decrypted(b2).isSuperset(of: ["after-a", "after-b2"]),
                      "non-admin's late device B2 receives post-join messages: \(decrypted(b2))")
        XCTAssertTrue(decrypted(a).isSuperset(of: ["after-a", "after-b2"]),
                      "A sees the non-admin late device's message: \(decrypted(a))")
        XCTAssertTrue(decrypted(b1).isSuperset(of: ["after-a", "after-b2"]),
                      "B1 converges with its own late device: \(decrypted(b1))")
        // B2's message is attributed to B's account on A, and shown as mine on B1.
        XCTAssertTrue(a.groups.conversation(groupId).messages.contains {
                          $0.body == "after-b2" && $0.senderPublicId == b1.publicId },
                      "A attributes the late device's message to B's account")
        XCTAssertTrue(b1.groups.conversation(groupId).messages.contains { $0.body == "after-b2" && $0.isMine },
                      "B1 sees its own other device's message as mine")
    }

    // MARK: - Concurrent membership commits (serialized, no fork)

    /// A1 and B1 each reconcile a freshly provisioned second device from the SAME
    /// epoch — a genuine concurrent membership change. The server CAS register lets
    /// exactly one win the slot; the other is rejected, rebases onto the winner and
    /// retries. The group does NOT fork: all four devices converge on one epoch chain
    /// (identical commit seq) and every message decrypts everywhere.
    func testConcurrentMembershipCommitsConverge() async throws {
        try await requireBackend()

        var a1 = makeStack("CCA1")
        let aReg = try await register(a1)
        a1.publicId = aReg.session.publicId
        _ = try await a1.groups.publishKeyPackages()

        var b1 = makeStack("CCB1")
        let bReg = try await register(b1)
        b1.publicId = bReg.session.publicId
        _ = try await b1.groups.publishKeyPackages()
        try await makeMutual(a1, b1)

        let groupId = try await a1.groups.createGroup(name: "CC", memberPublicIds: [b1.publicId])
        try await pump([a1, b1])

        // Provision a SECOND device for BOTH accounts; publish their KeyPackages.
        let aAdded = try await a1.messaging.api.addDevice(deviceName: "A2")
        let a2 = try await makeSecondDevice(aReg, aAdded, tag: "CCA2")
        _ = try await a2.groups.publishKeyPackages()
        let bAdded = try await b1.messaging.api.addDevice(deviceName: "B2")
        let b2 = try await makeSecondDevice(bReg, bAdded, tag: "CCB2")
        _ = try await b2.groups.publishKeyPackages()

        // Concurrent reconciliations: A1 adds A2 while B1 adds B2 from the same epoch.
        // One wins the CAS slot; the loser rebases onto it and retries — pump drives
        // both reconciliations + the rebase + the late devices joining via Welcome.
        try await pump([a1, b1, a2, b2], rounds: 8)

        _ = try await a1.groups.sendGroupText("x-from-a1", to: groupId)
        try await pump([a1, b1, a2, b2], rounds: 6)
        _ = try await b2.groups.sendGroupText("x-from-b2", to: groupId)
        try await pump([a1, b1, a2, b2], rounds: 6)

        func decrypted(_ s: Stack) -> Set<String> {
            Set(s.groups.conversation(groupId).messages.filter { $0.decrypted }.map(\.body))
        }
        let expect: Set = ["x-from-a1", "x-from-b2"]
        XCTAssertTrue(decrypted(a1).isSuperset(of: expect), "A1 converged: \(decrypted(a1))")
        XCTAssertTrue(decrypted(a2).isSuperset(of: expect), "A2 (concurrently added) converged: \(decrypted(a2))")
        XCTAssertTrue(decrypted(b1).isSuperset(of: expect), "B1 converged: \(decrypted(b1))")
        XCTAssertTrue(decrypted(b2).isSuperset(of: expect), "B2 (concurrently added) converged: \(decrypted(b2))")

        // No fork: every device is on the SAME commit seq, and it advanced by exactly
        // the two device-adds (genesis 0 → 2), proving the two concurrent commits were
        // serialized rather than diverging.
        let seqs = [a1, a2, b1, b2].map { $0.groups.state(groupId)?.commitSeq ?? -1 }
        XCTAssertEqual(Set(seqs).count, 1, "all devices share ONE commit seq (no fork): \(seqs)")
        XCTAssertEqual(seqs.first, 2, "exactly two ordered commits (A2 add + B2 add): \(seqs)")
    }

    // MARK: - Device linking (the real link → adopt provisioning flow)

    /// Builds a fresh stack and links it to an existing account via the REAL
    /// device-linking flow used by the UI (payload → shareable code → adopt), then
    /// returns the provisioned second-device stack.
    private func adoptLinkedStack(code: String, tag: String) async throws -> Stack {
        var stack = makeStack(tag)
        let payload = try XCTUnwrap(DeviceLinkPayload(code: code))
        let session = try await stack.auth.adoptDeviceLink(payload)
        stack.publicId = session.publicId
        return stack
    }

    /// Proves the end-user device-linking flow yields a fully working second device:
    /// the primary mints a link payload, it round-trips through its shareable code
    /// (the QR/paste transport), the new device adopts it (generating its OWN keys),
    /// and — via the commit-ordering reconciliation — it converges into the primary's
    /// existing group and exchanges messages as the same account.
    func testDeviceLinkingProvisionsAWorkingSecondDevice() async throws {
        try await requireBackend()

        var primary = makeStack("DLP")
        let reg = try await register(primary)
        primary.publicId = reg.session.publicId
        _ = try await primary.groups.publishKeyPackages()

        var b = makeStack("DLB")
        b.publicId = try await register(b).session.publicId
        _ = try await b.groups.publishKeyPackages()
        try await makeMutual(primary, b)

        // Primary creates a group with B while it has a single device.
        let groupId = try await primary.groups.createGroup(name: "DL", memberPublicIds: [b.publicId])
        try await pump([primary, b])
        _ = try await primary.groups.sendGroupText("before-link", to: groupId)
        try await pump([primary, b])

        // REAL linking: mint a payload, encode it to a shareable code, adopt it.
        let payload = try await primary.auth.createDeviceLink(deviceName: "iPad")
        XCTAssertEqual(payload.publicId, primary.publicId, "link payload carries the account")
        let code = payload.encoded()
        XCTAssertTrue(code.hasPrefix(DeviceLinkPayload.scheme), "code is a recognizable gotogo link")
        XCTAssertNotNil(DeviceLinkPayload(code: code), "code decodes back to a payload")

        let secondary = try await adoptLinkedStack(code: code, tag: "DL2")
        XCTAssertEqual(secondary.publicId, primary.publicId, "linked device shares the account")
        _ = try await secondary.groups.publishKeyPackages()

        // Primary reconciles its device set on sync → retro-adds the linked device to
        // the existing group; pump so it joins via the Welcome.
        try await pump([primary, secondary, b], rounds: 6)

        _ = try await primary.groups.sendGroupText("after-link", to: groupId)
        try await pump([primary, secondary, b])
        _ = try await secondary.groups.sendGroupText("from-linked", to: groupId)
        try await pump([primary, secondary, b])

        func decrypted(_ s: Stack) -> Set<String> {
            Set(s.groups.conversation(groupId).messages.filter { $0.decrypted }.map(\.body))
        }
        XCTAssertTrue(decrypted(secondary).isSuperset(of: ["after-link", "from-linked"]),
                      "linked device converges on post-join traffic: \(decrypted(secondary))")
        XCTAssertTrue(decrypted(primary).contains("from-linked"),
                      "primary receives the linked device's message")
        XCTAssertTrue(decrypted(b).isSuperset(of: ["after-link", "from-linked"]),
                      "member B sees both: \(decrypted(b))")
        // The linked device's message is attributed to the shared account (shown as
        // mine on the primary, since it's the same account on another device).
        XCTAssertTrue(primary.groups.conversation(groupId).messages.contains { $0.body == "from-linked" && $0.isMine },
                      "primary shows the linked device's message as its own account's")
    }
}
