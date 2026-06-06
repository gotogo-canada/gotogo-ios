//
//  GroupService.swift
//  Gotogo
//
//  Group messaging on **MLS (RFC 9420 / TreeKEM)** — the live group transport —
//  built ON TOP of the pairwise Triple-Ratchet `MessagingService`. UI-free.
//
//  Model: per group I keep (in a `GroupStore`) my own `MLSGroup` state (ratchet
//  tree + epoch + epoch secrets + my leaf/init private keys), a `groupKey` that
//  AES-GCM-seals the group name for the backend listing, the member roster, and a
//  committer-side leaf→owner map (so an admin can turn "remove this member" into
//  the right `Remove(leaf)`).
//
//  All MLS handshake + application messages travel as ORDINARY 1:1 messages over
//  the pairwise channel (so they are themselves pairwise-E2EE and fan out to every
//  member's devices). Three `MessageContent` control/transport types ride it:
//    • `group_mls_welcome` — admits a member: an MLS Welcome (sealed to the
//      member's published KeyPackage) plus the group key + name + roster. On
//      ingest, the member finds its matching private KeyPackage, JOINS the MLS
//      group (deriving the current epoch secret), and can immediately read/write.
//    • `group_mls_commit` — an MLS Commit (membership change / re-key) that every
//      existing member PROCESSES to advance one epoch. A removed member's stale
//      keys can't open the UpdatePath, so it's locked out of the new epoch.
//    • `group_mls_app` — a group chat payload encrypted under the CURRENT epoch
//      (per-sender/per-generation key derived from the shared encryption secret).
//      Its inner plaintext is itself a JSON `MessageContent` (text/sticker/image).
//
//  KeyPackages: each device publishes a pool of one-time MLS KeyPackages to the
//  server's key directory (namespace "mls-kp"); a committer claims one per device
//  to Add a member (RFC 9420 §10 Delivery-Service role). The private halves live
//  in an `MLSKeyPackageStore` and are consumed on join.
//
//  Inbound control messages are delivered SYNCHRONOUSLY by `MessagingService`'s
//  group handler; a test can deterministically converge by `pump()`-ing each
//  user's `GroupService.sync()` a few rounds (each pulls inbound + tops up the
//  KeyPackage pool). Foundation + CryptoKit only.
//

import Foundation
import CryptoKit

@MainActor
public final class GroupService {

    private let messaging: MessagingService
    private let store: GroupStore
    /// Persisted MLS KeyPackage material (signing identity + unconsumed privates).
    private let keyPackages: MLSKeyPackageStore
    /// Resolves my own public id (the group-message sender id and fan-out exclusion).
    private let myPublicId: () -> String?

    /// The key-directory namespace for MLS KeyPackages.
    private static let mlsNamespace = "mls-kp"

    /// Application (group chat) messages that arrived before I could decrypt them —
    /// before I joined the group, or addressed to a FUTURE epoch I haven't reached
    /// yet — buffered per group id and replayed after I join / process the relevant
    /// Commit. Each entry keeps the pairwise sender so replay can stamp it.
    private var pendingApps: [String: [(from: String, msg: MLSApplicationMessage)]] = [:]

    /// MLS Commits that arrived out of order (ahead of my current `commitSeq`), or
    /// before I joined the group, buffered per group id and applied strictly in
    /// sequence as their turn comes. The server-assigned `commitSeq` gives a total
    /// order, so even though Commits travel pairwise (and may interleave), every
    /// member converges on the same epoch chain.
    private var pendingCommits: [String: [MessageContent]] = [:]

    /// How many times a committer re-tries the server compare-and-swap (catching up
    /// to the winner between tries) before giving up for this call.
    private static let maxCommitRetries = 8

    /// The genesis ordering head: the opaque `commitToken` of a group before any
    /// Commit has been ordered (matches the server's empty head).
    private static var genesisToken: Data { Data() }

    /// Resolves my own device id (used to exclude THIS device when adding my other
    /// devices to a group as their own MLS leaves).
    private let myDeviceId: () -> String?

    /// Invoked after an inbound group message/control is processed, so `AppState`
    /// can refresh its published conversations + groups and the open group view
    /// updates in REAL TIME (not just on the next manual sync). Set by `AppState`.
    var onGroupsChanged: (() -> Void)?

    init(messaging: MessagingService,
         store: GroupStore,
         keyPackages: MLSKeyPackageStore,
         myPublicId: @escaping () -> String?,
         myDeviceId: @escaping () -> String? = { nil }) {
        self.messaging = messaging
        self.store = store
        self.keyPackages = keyPackages
        self.myPublicId = myPublicId
        self.myDeviceId = myDeviceId
        messaging.setGroupHandler { [weak self] content, from in
            guard let self else { return }
            self.handle(content, from: from)
            self.onGroupsChanged?()
        }
    }

    // MARK: - KeyPackage publication

    /// Tops up the server's MLS KeyPackage pool when it runs low, so other members
    /// can Add this device to a group without a round trip. Mints fresh KeyPackages
    /// (privates kept locally), publishes the PUBLIC halves to the key directory.
    /// Best-effort; returns the number newly published (0 if no top-up was needed).
    @discardableResult
    func publishKeyPackages(minimum: Int = 4, topUpTo: Int = 10) async throws -> Int {
        let available = (try? await messaging.api.keyCount(namespace: Self.mlsNamespace)) ?? 0
        guard available < minimum else { return 0 }
        let needed = max(0, topUpTo - available)
        guard needed > 0 else { return 0 }

        let minted = keyPackages.mint(count: needed)
        let entries: [PublishKeysRequest.Entry] = minted.compactMap { kp in
            guard let blob = try? JSONEncoder().encode(kp.keyPackage) else { return nil }
            return PublishKeysRequest.Entry(keyId: UUID().uuidString, blob: blob, lastResort: false)
        }
        guard !entries.isEmpty else { return 0 }
        _ = try await messaging.api.publishKeys(namespace: Self.mlsNamespace, entries: entries)
        return entries.count
    }

    // MARK: - Listing

    /// Lists my groups from the backend, decrypting each sealed name with the
    /// locally cached `groupKey` (falling back to "Group" when not yet known). Also
    /// refreshes each group's cached roster in the `GroupStore`.
    func groups() async throws -> [GroupInfo] {
        let response = try await messaging.api.listGroups()
        return response.groups.map { entry in
            let members = entry.members.map { GroupMember(publicId: $0.publicId, role: GroupRole(from: $0.role)) }
            let cached = store.state(entry.groupId)
            // Prefer the locally cached name when set: it reflects admin renames
            // distributed via the E2EE `group_meta` control (the server only holds the
            // original creation-time encrypted name and is never updated). Fall back to
            // decrypting the server's name when there's no cached name yet.
            let name: String
            if let cachedName = cached?.name, !cachedName.isEmpty {
                name = cachedName
            } else {
                name = decryptName(entry.encryptedName, groupKey: cached?.groupKey) ?? "Group"
            }
            if let cached {
                store.update(entry.groupId) { st in
                    st.members = members
                    st.name = name
                    st.myRole = myRole(in: members, fallback: cached.myRole)
                }
            }
            return GroupInfo(groupId: entry.groupId, name: name, members: members,
                             createdAt: entry.createdAt, photoRef: store.state(entry.groupId)?.photoRef)
        }
    }

    /// The locally cached group state (crypto + roster) for a group, if known.
    func state(_ groupId: String) -> GroupState? { store.state(groupId) }

    /// Drops all persisted group crypto + KeyPackage state (used on logout).
    func clear() { store.clear(); keyPackages.clear() }

    /// The group conversation (reuses the messaging cache, keyed by group id).
    func conversation(_ groupId: String) -> Conversation { messaging.conversation(with: groupId) }

    // MARK: - Create

    /// Creates a group: mint a `groupKey`, seal the name, POST to the backend,
    /// CLAIM an MLS KeyPackage for every device of every initial member, found the
    /// MLS group, and send each member a `group_mls_welcome` over the pairwise
    /// channel. Returns the new group id.
    @discardableResult
    func createGroup(name: String, memberPublicIds: [String]) async throws -> String {
        guard let me = myPublicId() else { throw MessagingError.notSignedIn }
        let groupKey = Self.randomKey()
        let sealedName = try Self.seal(name, groupKey: groupKey)

        let response = try await messaging.api.createGroup(encryptedName: sealedName,
                                                           memberPublicIds: memberPublicIds)
        let groupId = response.groupId
        let members = response.members.map { GroupMember(publicId: $0.publicId, role: GroupRole(from: $0.role)) }

        // Claim a published KeyPackage for every device of every initial member,
        // remembering which owner each KeyPackage (by init key) belongs to so the
        // leaf→owner map can be read back EXACTLY from the Welcome — correct even
        // when one member contributes several device leaves.
        var memberKPs: [MLSKeyPackage] = []
        var ownerByInitKey: [Data: String] = [:]
        for memberId in memberPublicIds {
            let claimed = try await messaging.api.claimKeys(namespace: Self.mlsNamespace, publicId: memberId)
            for dev in claimed {
                guard let kp = try? JSONDecoder().decode(MLSKeyPackage.self, from: dev.blob) else { continue }
                memberKPs.append(kp)
                ownerByInitKey[kp.initKey] = memberId
            }
        }
        // Also add MY OWN other devices — each its own MLS leaf — so all my devices
        // converge on this group. Claim my account's KeyPackages and skip THIS device.
        let currentDeviceId = myDeviceId()
        var ownDeviceIds: Set<String> = []
        if let currentDeviceId { ownDeviceIds.insert(currentDeviceId) }
        let myClaimed = (try? await messaging.api.claimKeys(namespace: Self.mlsNamespace, publicId: me)) ?? []
        for dev in myClaimed where dev.deviceId != currentDeviceId {
            guard let kp = try? JSONDecoder().decode(MLSKeyPackage.self, from: dev.blob) else { continue }
            memberKPs.append(kp)
            ownerByInitKey[kp.initKey] = me
            ownDeviceIds.insert(dev.deviceId)
        }
        guard !memberKPs.isEmpty else { throw MessagingError.missingKeyMaterial }

        let founderKP = keyPackages.freshLocalKeyPackage()
        let (group, welcome) = MLSGroup.create(groupId: Data(groupId.utf8),
                                               founder: founderKP, members: memberKPs)

        // Authoritative leaf→owner map: the Welcome carries each admitted device's
        // exact leaf (matched back to its owner by init key).
        var leafOwners: [UInt32: String] = [group.myLeaf.value: me]
        for secret in welcome.secrets {
            if let owner = ownerByInitKey[secret.initKeyHint] { leafOwners[secret.leaf.value] = owner }
        }

        store.save(GroupState(groupId: groupId, groupKey: groupKey, name: name,
                              mls: group, outgoingGeneration: 0, members: members,
                              leafOwners: leafOwners, myDeviceIds: ownDeviceIds,
                              myRole: myRole(in: members, fallback: .admin)))

        let roster = members.map(\.publicId)
        let welcomeMsg = MessageContent.groupMLSWelcome(groupId: groupId, welcome: welcome,
                                                        groupKey: groupKey, name: name, members: roster)
        for memberId in memberPublicIds {
            try await messaging.sendControl(welcomeMsg, to: memberId)
        }
        // Welcome my own other devices into the group too, carrying the own-device
        // set so each one seeds `myDeviceIds` and never re-adds a present sibling.
        var ownWelcome = welcomeMsg
        ownWelcome.ownDeviceIds = Array(ownDeviceIds)
        try await messaging.sendGroupControlToOwnDevices(ownWelcome)
        return groupId
    }

    // MARK: - Sending

    /// Encrypts `text` under the current MLS epoch and fans the `group_mls_app` out
    /// to every other member. Appends a local outgoing `ChatMessage`.
    @discardableResult
    func sendGroupText(_ text: String, to groupId: String) async throws -> ChatMessage {
        try await sendGroupContent(.text(text), to: groupId,
                                    local: { id, date in
                                        ChatMessage(id: id, peerPublicId: groupId, isMine: true,
                                                    body: text, createdAt: date)
                                    })
    }

    /// Encrypts an internal sticker (catalog id) into a `group_mls_app` and fans it out.
    @discardableResult
    func sendGroupSticker(_ stickerId: String, to groupId: String) async throws -> ChatMessage {
        try await sendGroupContent(.sticker(stickerId), to: groupId,
                                    local: { id, date in
                                        ChatMessage(id: id, peerPublicId: groupId, isMine: true,
                                                    body: "", createdAt: date,
                                                    mediaKind: "sticker", stickerId: stickerId)
                                    })
    }

    /// Metadata-strips + thumbnails + chunk-encrypts an image, then MLS-encrypts its
    /// `MediaReference` (carrying the per-file key) into a `group_mls_app` fanned out
    /// to every member. The blob itself is opaque in object storage. Appends a local
    /// image message.
    @discardableResult
    func sendGroupImage(_ imageData: Data, caption: String?, to groupId: String) async throws -> ChatMessage {
        let ref = try await messaging.uploadImageMedia(imageData)
        return try await sendGroupContent(.image(ref, caption: caption), to: groupId,
                                          local: { id, date in
                                              ChatMessage(id: id, peerPublicId: groupId, isMine: true,
                                                          body: caption ?? "", createdAt: date,
                                                          media: ref, mediaKind: "image")
                                          })
    }

    /// Size-gates a video (≤ `MediaLimits.maxVideoBytes`, else throws before any
    /// upload), chunk-encrypts + uploads it, then MLS-encrypts its `MediaReference`
    /// into a `group_mls_app` fanned out to every member. Appends a local video
    /// message.
    @discardableResult
    func sendGroupVideo(_ videoData: Data, caption: String?, to groupId: String) async throws -> ChatMessage {
        let ref = try await messaging.uploadVideoMedia(videoData)
        return try await sendGroupContent(.video(ref, caption: caption), to: groupId,
                                          local: { id, date in
                                              ChatMessage(id: id, peerPublicId: groupId, isMine: true,
                                                          body: caption ?? "", createdAt: date,
                                                          media: ref, mediaKind: "video")
                                          })
    }

    /// Admin-only: changes the group's name and/or avatar. Uploads the (encrypted)
    /// photo if one is given, distributes the change E2EE to every member as a
    /// `group_meta` MLS app message, and applies it locally. Members apply it only if
    /// it came from the admin. Throws `MessagingError.notGroupAdmin` for non-admins.
    func updateGroupMeta(groupId: String, name: String?, photo: Data?) async throws {
        guard let st = store.state(groupId) else { throw MessagingError.userNotFound }
        guard st.myRole == .admin else { throw MessagingError.notGroupAdmin }

        var photoRef = st.photoRef
        if let photo { photoRef = try await messaging.uploadImageMedia(photo) }
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        let newName = (trimmed?.isEmpty == false) ? trimmed : nil

        try await sendGroupApp(.groupMeta(name: newName, photoRef: photoRef), to: groupId)
        store.update(groupId) { state in
            if let newName { state.name = newName }
            if let photoRef { state.photoRef = photoRef }
        }
    }

    /// Shared group-send path: stamp the inner content with a stable cross-member
    /// `clientId`, MLS-encrypt + fan it out, and append the caller-built local
    /// message carrying the SAME id (so "delete for everyone" can target it on
    /// every member, whose own copy stores the same clientId).
    private func sendGroupContent(_ inner: MessageContent,
                                  to groupId: String,
                                  local: (String, Date) -> ChatMessage) async throws -> ChatMessage {
        let clientId = UUID().uuidString
        var content = inner
        content.clientId = clientId
        try await sendGroupApp(content, to: groupId)

        var message = local(clientId, Date())
        message.clientId = clientId
        // Stamp the author on my own copy too, so a later sender-scoped "delete for
        // everyone" matches every copy (mine, the members', my other devices').
        message.senderPublicId = myPublicId()
        messaging.append(message, to: groupId)
        return message
    }

    /// MLS-encrypts `inner` under the current epoch (advancing my per-epoch
    /// generation) and ships one `group_mls_app` to every OTHER member. Does NOT
    /// append anything locally — used both by `sendGroupContent` and by the group
    /// deletion controls.
    private func sendGroupApp(_ inner: MessageContent, to groupId: String) async throws {
        guard let me = myPublicId() else { throw MessagingError.notSignedIn }
        guard let st = store.state(groupId), let group = st.mls else { throw MessagingError.userNotFound }

        let plaintext = try JSONEncoder().encode(inner)
        let generation = st.outgoingGeneration
        let msg = try group.encryptApplication(plaintext, generation: generation)
        store.update(groupId) { $0.outgoingGeneration = generation &+ 1 }

        let envelope = MessageContent.groupMLSApp(groupId: groupId, app: msg)
        for memberId in st.others(excluding: me) {
            try await messaging.sendControl(envelope, to: memberId)
        }
        // Fan out to my own other devices (each its own leaf) so they converge.
        try await messaging.sendGroupControlToOwnDevices(envelope)
    }

    // MARK: - Media download (backs the group conversation view model)

    /// Downloads + decrypts a group attachment's thumbnail (falling back to the full
    /// blob). The blob is opaque in object storage; its per-file key rode inside the
    /// MLS app message. Returns nil on failure.
    func loadThumbnail(_ ref: MediaReference) async -> Data? {
        messaging.syncMediaToken()
        if let thumb = try? await messaging.media.downloadThumbnail(ref) { return thumb }
        return try? await messaging.media.download(ref)
    }

    /// Downloads + decrypts a group attachment's full media bytes. Returns nil on failure.
    func loadFull(_ ref: MediaReference) async -> Data? {
        messaging.syncMediaToken()
        return try? await messaging.media.download(ref)
    }

    // MARK: - Deletion (per-message "for everyone" / clear thread)

    /// "Delete for me": removes a group message from THIS device only.
    func deleteGroupMessageForMe(_ message: ChatMessage) {
        messaging.removeMessageLocally(id: message.id, in: message.peerPublicId)
    }

    /// "Delete for everyone": removes one of MY OWN group messages on every member
    /// (and locally), keyed by its stable `clientId`, via an MLS app message.
    @discardableResult
    func deleteGroupMessageForEveryone(_ message: ChatMessage) async -> Bool {
        guard message.isMine, let clientId = message.clientId else { return false }
        let groupId = message.peerPublicId
        do { try await sendGroupApp(.deleteMessages([clientId]), to: groupId) }
        catch { return false }
        messaging.removeMessage(clientId: clientId, in: groupId)
        return true
    }

    /// Clears a group conversation: removes the whole thread on THIS device and asks
    /// every member to drop MY messages from their copy (I remain a group member —
    /// use `leaveGroup` to actually leave). Best-effort transport.
    func deleteGroupConversation(_ groupId: String) async {
        try? await sendGroupApp(.deleteConversation(), to: groupId)
        messaging.removeConversation(groupId)
    }

    // MARK: - Membership (ordered through the server commit register)

    /// Everything a won Commit needs to persist + fan out, built from the CURRENT
    /// epoch INSIDE the CAS retry loop, so it's recomputed against the latest state
    /// after catching up to a race winner.
    private struct BuiltCommit {
        var group: MLSGroup
        var commit: MLSCommit
        var welcome: MLSWelcome?
        var leafOwners: [UInt32: String]
        var members: [GroupMember]
        var myDeviceIds: Set<String>
        /// External member public ids to send the Welcome to.
        var welcomeRecipients: [String]
        /// Also Welcome my own other devices (a NEW own-device leaf joins via it).
        var welcomeToOwnDevices: Bool
        /// Existing member public ids to send the Commit to (my own devices always
        /// get it too).
        var commitRecipients: [String]
    }

    /// Orders a membership-changing Commit through the server's per-group CAS
    /// register so ANY member (not just an admin) can commit and concurrent commits
    /// never fork the group. Each attempt builds a candidate Commit from the current
    /// epoch, then reserves the next slot with `submitCommit(prev: myToken, new:
    /// fresh)`. On a win it persists the new MLS state + ordering head and fans out
    /// the Commit (and Welcome) carrying that head. On a lost race it pulls the
    /// winner's Commit (a pairwise sync advances my epoch + token) and retries from
    /// the new head. `build` returns nil when there's nothing to commit. Returns
    /// true once a commit lands (or there was nothing to do); throws
    /// `commitOrderingUnavailable` if the slot can't be won within the retry budget.
    @discardableResult
    private func commitThroughCAS(groupId: String,
                                  build: () throws -> BuiltCommit?) async throws -> Bool {
        for _ in 0..<Self.maxCommitRetries {
            guard let st = store.state(groupId), st.mls != nil else { throw MessagingError.userNotFound }
            guard let built = try build() else { return true } // nothing to commit

            let newToken = Self.randomKey()
            let resp = try await messaging.api.submitCommit(groupId: groupId,
                                                            prevToken: st.commitToken, newToken: newToken)
            guard resp.accepted else {
                // Lost the race: catch up (process the winner's Commit over the
                // pairwise channel), then retry rebuilding from the advanced epoch.
                _ = try? await messaging.sync()
                continue
            }

            let seq = resp.seq
            store.update(groupId) { s in
                s.mls = built.group
                s.outgoingGeneration = 0
                s.leafOwners = built.leafOwners
                s.members = built.members
                s.myDeviceIds = built.myDeviceIds
                s.commitToken = newToken
                s.commitSeq = seq
            }
            let stNow = store.state(groupId) ?? st
            let roster = built.members.map(\.publicId)
            // My current own-device set, attached ONLY to copies sent to my own
            // devices so they converge it (never to other members).
            let ownIds = Array(built.myDeviceIds)

            if let welcome = built.welcome {
                // External members: a plain Welcome (no own-device topology).
                let welcomeMsg = MessageContent.groupMLSWelcome(groupId: groupId, welcome: welcome,
                    groupKey: stNow.groupKey, name: stNow.name, members: roster,
                    commitToken: newToken, commitSeq: seq)
                for r in built.welcomeRecipients {
                    try? await messaging.sendControl(welcomeMsg, to: r)
                }
                if built.welcomeToOwnDevices {
                    var ownWelcome = welcomeMsg
                    ownWelcome.ownDeviceIds = ownIds
                    try? await messaging.sendGroupControlToOwnDevices(ownWelcome)
                }
            }
            let commitMsg = MessageContent.groupMLSCommit(groupId: groupId, commit: built.commit,
                committerLeaf: built.group.myLeaf.value, commitToken: newToken, commitSeq: seq)
            for r in built.commitRecipients {
                try? await messaging.sendControl(commitMsg, to: r)
            }
            // My own other devices are existing leaves — they process the Commit too,
            // and learn the converged own-device set so none of them re-adds a sibling.
            var ownCommit = commitMsg
            ownCommit.ownDeviceIds = ownIds
            try? await messaging.sendGroupControlToOwnDevices(ownCommit)
            return true
        }
        throw MessagingError.commitOrderingUnavailable
    }

    /// Adds a member: add them to the backend roster + claim their KeyPackage(s),
    /// then order an Add Commit through the CAS register (rebasing automatically if
    /// another member commits first). The new member gets a Welcome; existing
    /// members + my own devices get the Commit.
    func addMember(groupId: String, publicId: String) async throws {
        guard let me = myPublicId() else { throw MessagingError.notSignedIn }
        guard store.state(groupId)?.mls != nil else { throw MessagingError.userNotFound }
        try await messaging.api.addGroupMember(groupId: groupId, publicId: publicId)

        // Claim once (claim-once semantics) and reuse the KeyPackages across retries.
        let claimed = try await messaging.api.claimKeys(namespace: Self.mlsNamespace, publicId: publicId)
        let kps: [MLSKeyPackage] = claimed.compactMap { try? JSONDecoder().decode(MLSKeyPackage.self, from: $0.blob) }
        guard !kps.isEmpty else { throw MessagingError.missingKeyMaterial }

        try await commitThroughCAS(groupId: groupId) {
            guard let st = self.store.state(groupId), let base = st.mls else { return nil }
            var group = base
            var ownerByInitKey: [Data: String] = [:]
            var proposals: [MLSProposal] = []
            for kp in kps {
                proposals.append(group.proposeAdd(kp))
                ownerByInitKey[kp.initKey] = publicId
            }
            let (commit, welcome) = try group.commit(proposals)
            // Authoritative leaf→owner from the Welcome's exact leaf assignment.
            var leafOwners = st.leafOwners
            for secret in (welcome?.secrets ?? []) {
                if let owner = ownerByInitKey[secret.initKeyHint] { leafOwners[secret.leaf.value] = owner }
            }
            var members = st.members
            if !members.contains(where: { $0.publicId == publicId }) {
                members.append(GroupMember(publicId: publicId, role: .member))
            }
            let commitRecipients = members.map(\.publicId).filter { $0 != me && $0 != publicId }
            return BuiltCommit(group: group, commit: commit, welcome: welcome,
                               leafOwners: leafOwners, members: members, myDeviceIds: st.myDeviceIds,
                               welcomeRecipients: [publicId], welcomeToOwnDevices: false,
                               commitRecipients: commitRecipients)
        }
    }

    /// Removes a member: drop them from the backend roster, then order a Remove
    /// Commit of every leaf they own through the CAS register (re-keying the tree so
    /// their stale keys can't open the new UpdatePath — forward secrecy + lockout).
    /// The Commit reaches every REMAINING member + my own devices.
    func removeMember(groupId: String, publicId: String) async throws {
        guard let me = myPublicId() else { throw MessagingError.notSignedIn }
        guard store.state(groupId)?.mls != nil else { throw MessagingError.userNotFound }
        try await messaging.api.removeGroupMember(groupId: groupId, publicId: publicId)

        try await commitThroughCAS(groupId: groupId) {
            guard let st = self.store.state(groupId), let base = st.mls else { return nil }
            let leaves = st.leafOwners.filter { $0.value == publicId }.map(\.key)
            guard !leaves.isEmpty else {
                // We never committed their Add, so we don't know their leaf — the
                // backend already removed them; just drop them from the local roster.
                self.store.update(groupId) { $0.members.removeAll { $0.publicId == publicId } }
                return nil
            }
            var group = base
            let proposals = leaves.map { group.proposeRemove(MLSLeafIndex($0)) }
            let (commit, _) = try group.commit(proposals)
            var leafOwners = st.leafOwners
            for l in leaves { leafOwners[l] = nil }
            var members = st.members
            members.removeAll { $0.publicId == publicId }
            let commitRecipients = members.map(\.publicId).filter { $0 != me }
            return BuiltCommit(group: group, commit: commit, welcome: nil,
                               leafOwners: leafOwners, members: members, myDeviceIds: st.myDeviceIds,
                               welcomeRecipients: [], welcomeToOwnDevices: false,
                               commitRecipients: commitRecipients)
        }

        // Tell the removed member directly (pairwise — they're off the group channel
        // now) so their app ejects them from the conversation immediately. Best-effort;
        // they're already cryptographically locked out of future messages either way.
        try? await messaging.sendControl(.groupRemoved(groupId: groupId), to: publicId)
    }

    /// Leaves a group. If I'm the group's ADMIN (creator), leaving DISSOLVES the group
    /// for everyone: each member is told (pairwise `group_dissolved`) and the group is
    /// deleted on the backend. A regular member just removes itself. Either way this
    /// device drops all local state.
    func leaveGroup(groupId: String) async throws {
        guard let me = myPublicId() else { throw MessagingError.notSignedIn }
        let st = store.state(groupId)
        if st?.myRole == .admin {
            let others = (st?.members ?? []).map(\.publicId).filter { $0 != me }
            for member in others {
                try? await messaging.sendControl(.groupDissolved(groupId: groupId), to: member)
            }
            try? await messaging.api.deleteGroup(groupId: groupId)
        } else {
            try? await messaging.api.removeGroupMember(groupId: groupId, publicId: me)
        }
        dropGroupLocally(groupId)
    }

    /// Deletes a group (admin): DELETE on the backend and drop local state.
    func deleteGroup(groupId: String) async throws {
        try await messaging.api.deleteGroup(groupId: groupId)
        store.remove(groupId)
    }

    // MARK: - Own-device late join

    /// Retro-adds any of MY account's devices that aren't yet a leaf into EVERY group
    /// I'm in — so a device provisioned AFTER a group already exists converges into
    /// it. This now works for non-admin members too: each own-device Add is ordered
    /// through the server CAS register, so concurrent reconciliations by different
    /// members serialize instead of forking. Runs (best-effort) only when I actually
    /// have >1 device, opportunistically from `sync()`.
    func ensureOwnDevicesInGroups() async {
        guard let me = myPublicId(), let current = myDeviceId() else { return }
        let groups = store.all().filter { $0.mls != nil }
        guard !groups.isEmpty else { return }

        let myDevices = ((try? await messaging.api.fetchAllPreKeyBundles(publicId: me)) ?? []).map(\.deviceId)
        guard myDevices.count > 1 else { return } // single device: nothing to add

        for st in groups {
            let known = st.myDeviceIds.union([current])
            let missing = myDevices.filter { !known.contains($0) }
            guard !missing.isEmpty else { continue }

            let claimed = (try? await messaging.api.claimKeys(namespace: Self.mlsNamespace, publicId: me)) ?? []
            var kpByDevice: [String: MLSKeyPackage] = [:]
            for dev in claimed where missing.contains(dev.deviceId) {
                if let kp = try? JSONDecoder().decode(MLSKeyPackage.self, from: dev.blob) {
                    kpByDevice[dev.deviceId] = kp
                }
            }
            for deviceId in missing {
                guard let kp = kpByDevice[deviceId] else { continue } // not published a KeyPackage yet
                await addOwnDeviceLeaf(kp, deviceId: deviceId, in: st.groupId)
            }
        }
    }

    /// Orders an Add of one of MY OWN devices into a group through the CAS register,
    /// Welcoming that device and Committing the new epoch to the other members + my
    /// other devices. Adding a device of an EXISTING member account is purely an MLS
    /// tree change — no backend roster call. Best-effort: a lost race just leaves the
    /// device to be added on the next `sync()`.
    private func addOwnDeviceLeaf(_ kp: MLSKeyPackage, deviceId: String, in groupId: String) async {
        guard let me = myPublicId() else { return }
        try? await commitThroughCAS(groupId: groupId) {
            guard let st = self.store.state(groupId), let base = st.mls else { return nil }
            if st.myDeviceIds.contains(deviceId) { return nil } // already added (caught up meanwhile)
            var group = base
            let (commit, welcome) = try group.commit([group.proposeAdd(kp)])
            guard let welcome else { return nil }
            var leafOwners = st.leafOwners
            for secret in welcome.secrets where secret.initKeyHint == kp.initKey {
                leafOwners[secret.leaf.value] = me
            }
            var myDeviceIds = st.myDeviceIds
            myDeviceIds.insert(deviceId)
            let commitRecipients = st.members.map(\.publicId).filter { $0 != me }
            return BuiltCommit(group: group, commit: commit, welcome: welcome,
                               leafOwners: leafOwners, members: st.members, myDeviceIds: myDeviceIds,
                               welcomeRecipients: [], welcomeToOwnDevices: true,
                               commitRecipients: commitRecipients)
        }
    }

    // MARK: - Sync / pump

    /// Tops up the KeyPackage pool, retro-adds any new device of mine into my groups,
    /// pulls pairwise messages (feeding the synchronous group handler — joins via
    /// Welcome, epoch advances via Commit, decrypts `group_mls_app`s into each
    /// conversation). Returns the inbound 1:1 chat messages.
    @discardableResult
    func sync() async throws -> [ChatMessage] {
        _ = try? await publishKeyPackages()
        await ensureOwnDevicesInGroups()
        return try await messaging.sync()
    }

    // MARK: - Inbound handler (synchronous)

    /// Dispatches one decrypted inbound group control/transport message. `from` is
    /// the PAIRWISE sender — i.e. the human author of a group message.
    private func handle(_ content: MessageContent, from fromPublicId: String) {
        switch content.type {
        case "group_mls_welcome": ingestWelcome(content, from: fromPublicId)
        case "group_mls_commit":  ingestCommit(content, from: fromPublicId)
        case "group_mls_app":     ingestApp(content, from: fromPublicId)
        case "group_removed", "group_dissolved":
            if let gid = content.groupId { dropGroupLocally(gid) }
        default: break
        }
    }

    /// Drops a group entirely from THIS device: removes its crypto/roster state and
    /// clears its cached conversation. Used when an admin removed me (`group_removed`)
    /// or the group's creator dissolved it (`group_dissolved`). The open conversation
    /// dismisses via `onGroupsChanged` → the group vanishing from `AppState.groups`.
    private func dropGroupLocally(_ groupId: String) {
        store.remove(groupId)
        messaging.removeConversation(groupId)
    }

    /// Ingests a `group_mls_welcome`: find my matching private KeyPackage (by the
    /// init key the Welcome sealed to), JOIN the MLS group (deriving the current
    /// epoch secret), cache the group key + name + roster, and replay any buffered
    /// application messages.
    private func ingestWelcome(_ content: MessageContent, from fromPublicId: String) {
        guard let groupId = content.groupId, let welcome = content.mlsWelcome else { return }
        if store.state(groupId)?.mls != nil { return } // already a member

        let initHints = Set(welcome.secrets.map(\.initKeyHint))
        guard let kp = keyPackages.take(matchingInitKeys: initHints) else { return } // not for me
        guard let group = try? MLSGroup.join(welcome: welcome, keyPackage: kp) else { return }

        let roster = (content.members ?? []).map { GroupMember(publicId: $0, role: .member) }
        let myDevice = myDeviceId()
        store.update(groupId) { st in
            st.mls = group
            st.outgoingGeneration = 0
            // Seed my commit-ordering head to the epoch this Welcome admits me at, so
            // subsequent Commits apply in lockstep with the server's order.
            st.commitToken = content.commitToken ?? Self.genesisToken
            st.commitSeq = content.commitSeq ?? 0
            if let gk = content.groupKey { st.groupKey = gk }
            if let nm = content.name { st.name = nm }
            if let myDevice { st.myDeviceIds.insert(myDevice) }
            // Seed the own-device set from the Welcome (only my own devices receive a
            // Welcome carrying it), so I won't mistake an already-present sibling for
            // a missing device and re-add it.
            if let own = content.ownDeviceIds { for d in own { st.myDeviceIds.insert(d) } }
            var ids = Set(st.members.map(\.publicId))
            for m in roster where !ids.contains(m.publicId) {
                st.members.append(m); ids.insert(m.publicId)
            }
        }
        // A Commit may have arrived before this Welcome — drain any now-applicable.
        drainCommits(groupId)
        replayBuffered(groupId)
    }

    /// Ingests a `group_mls_commit`. Commits carry the server-assigned `commitSeq`,
    /// which is a TOTAL ORDER, so we buffer the commit and apply commits strictly in
    /// sequence (`commitSeq == my commitSeq + 1`). Even though commits travel
    /// pairwise and can interleave, every member converges on the same epoch chain.
    /// A commit that arrives before I've joined (no MLS state yet) waits in the
    /// buffer until the Welcome; one at a seq I've already passed is dropped.
    private func ingestCommit(_ content: MessageContent, from fromPublicId: String) {
        guard let groupId = content.groupId, content.mlsCommit != nil,
              content.committerLeaf != nil, content.commitSeq != nil else { return }
        pendingCommits[groupId, default: []].append(content)
        drainCommits(groupId)
    }

    /// Applies buffered Commits for a group in strict `commitSeq` order, advancing
    /// one epoch at a time (and replaying epoch-matched application messages after
    /// each step). Stops when the next sequence number isn't buffered yet. A commit
    /// that won't process (e.g. it removed me) is dropped and draining stops — I stay
    /// at my old epoch, locked out of further epochs.
    private func drainCommits(_ groupId: String) {
        while true {
            guard let st = store.state(groupId), st.mls != nil else { return } // not joined yet
            // Discard commits already reflected in my current epoch.
            pendingCommits[groupId] = (pendingCommits[groupId] ?? []).filter { ($0.commitSeq ?? -1) > st.commitSeq }
            guard let pending = pendingCommits[groupId], !pending.isEmpty else { return }
            guard let idx = pending.firstIndex(where: { ($0.commitSeq ?? -1) == st.commitSeq + 1 }) else { return }
            let next = pending[idx]
            pendingCommits[groupId]?.remove(at: idx)
            guard let commit = next.mlsCommit, let leaf = next.committerLeaf,
                  let seq = next.commitSeq, let token = next.commitToken,
                  var group = store.state(groupId)?.mls else { continue }
            do {
                try group.process(commit, from: MLSLeafIndex(leaf))
            } catch {
                continue // can't process (e.g. removed): stay put; this commit is dropped
            }
            store.update(groupId) { s in
                s.mls = group
                s.outgoingGeneration = 0
                s.commitToken = token
                s.commitSeq = seq
                // Converge the own-device set from the (own-fan-out only) Commit, so
                // every device of my account agrees on which siblings are already in
                // and none of them re-adds one.
                if let own = next.ownDeviceIds { for d in own { s.myDeviceIds.insert(d) } }
            }
            replayBuffered(groupId)
        }
    }

    /// Ingests a `group_mls_app`. If I'm not yet in the group, or the message is for
    /// a FUTURE epoch I haven't reached, BUFFER it (replayed on join / next Commit);
    /// a PAST-epoch message is dropped. Otherwise decrypt under the current epoch
    /// and append.
    private func ingestApp(_ content: MessageContent, from fromPublicId: String) {
        guard let groupId = content.groupId, let msg = content.mlsApp else { return }
        guard let st = store.state(groupId), let group = st.mls else {
            pendingApps[groupId, default: []].append((fromPublicId, msg)); return
        }
        if msg.epoch != group.epoch {
            if msg.epoch > group.epoch { pendingApps[groupId, default: []].append((fromPublicId, msg)) }
            return
        }
        decodeAppAndAppend(group: group, from: fromPublicId, groupId: groupId, msg: msg)
    }

    /// Decrypts one application message under the (matching-epoch) MLS group and
    /// appends the resulting `ChatMessage`. The pairwise sender is the human author.
    private func decodeAppAndAppend(group: MLSGroup, from fromPublicId: String,
                                    groupId: String, msg: MLSApplicationMessage) {
        do {
            let plaintext = try group.decryptApplication(msg)
            let inner = (try? JSONDecoder().decode(MessageContent.self, from: plaintext))
                ?? .text(String(decoding: plaintext, as: UTF8.self))

            // Deletion controls carried as MLS app messages: apply them to the group
            // conversation instead of appending. A member can only delete its OWN
            // messages (matched by sender), so we scope removal to `fromPublicId`.
            switch inner.type {
            case "delete_message":
                for clientId in (inner.deleteIds ?? []) {
                    messaging.removeGroupMessage(clientId: clientId, from: fromPublicId, in: groupId)
                }
                return
            case "delete_conversation":
                if fromPublicId == myPublicId() {
                    messaging.removeConversation(groupId)              // my own device cleared → clear the whole thread
                } else {
                    messaging.removeGroupMessages(from: fromPublicId, in: groupId)
                }
                return
            case "group_meta":
                applyGroupMeta(inner, from: fromPublicId, groupId: groupId)
                return
            default:
                break
            }

            messaging.append(groupChatMessage(inner, from: fromPublicId, groupId: groupId, msg: msg), to: groupId)
        } catch {
            let id = "\(groupId)|\(fromPublicId)|\(msg.sender.value)|\(msg.epoch)|\(msg.generation)"
            messaging.append(ChatMessage(id: id, peerPublicId: groupId, isMine: false,
                                         body: "[Unable to decrypt group message]",
                                         createdAt: Date(), decrypted: false), to: groupId)
        }
    }

    /// Applies an inbound group metadata change (name and/or avatar), but ONLY if the
    /// sender is the group's admin (owner) — so a non-owner can't rename the group or
    /// swap its photo. The change is persisted locally; the UI refreshes via
    /// `onGroupsChanged`.
    private func applyGroupMeta(_ inner: MessageContent, from fromPublicId: String, groupId: String) {
        guard let st = store.state(groupId) else { return }
        let senderIsAdmin = st.members.first(where: { $0.publicId == fromPublicId })?.role == .admin
        guard senderIsAdmin else { return }
        store.update(groupId) { state in
            if let name = inner.text, !name.isEmpty { state.name = name }
            if let photo = inner.media { state.photoRef = photo }
        }
    }

    /// Replays application messages buffered for a group after I join or advance an
    /// epoch: decrypt the ones matching my new epoch, re-buffer still-future ones,
    /// drop now-past ones.
    private func replayBuffered(_ groupId: String) {
        guard let buffered = pendingApps[groupId], !buffered.isEmpty else { return }
        pendingApps[groupId] = nil
        guard let st = store.state(groupId), let group = st.mls else {
            pendingApps[groupId] = buffered; return
        }
        for (from, msg) in buffered {
            if msg.epoch == group.epoch {
                decodeAppAndAppend(group: group, from: from, groupId: groupId, msg: msg)
            } else if msg.epoch > group.epoch {
                pendingApps[groupId, default: []].append((from, msg))
            }
        }
    }

    // MARK: - Helpers

    /// Builds an inbound group `ChatMessage` from a decrypted inner content. The id
    /// is deterministic per (group, sender, epoch, generation) so dedup is stable;
    /// `peerPublicId` is the group id and the human author is `senderPublicId`.
    private func groupChatMessage(_ inner: MessageContent,
                                  from senderPublicId: String,
                                  groupId: String,
                                  msg: MLSApplicationMessage) -> ChatMessage {
        // Include the MLS sender LEAF, not just the account public id: two devices of
        // the SAME account are distinct leaves, so leaf disambiguates their otherwise
        // identical (account, epoch, generation) — without it, device A's and device
        // A2's first messages would collide on id and one would be deduped away.
        let id = "\(groupId)|\(senderPublicId)|\(msg.sender.value)|\(msg.epoch)|\(msg.generation)"
        // A group message authored by MY OWN account (delivered from one of my other
        // devices) is shown as mine.
        let isMine = (senderPublicId == myPublicId())
        var message: ChatMessage
        switch inner.type {
        case "sticker":
            message = ChatMessage(id: id, peerPublicId: groupId, isMine: isMine, body: "",
                                  createdAt: Date(), mediaKind: "sticker", stickerId: inner.stickerId,
                                  senderPublicId: senderPublicId)
        case "image":
            message = ChatMessage(id: id, peerPublicId: groupId, isMine: isMine, body: inner.text ?? "",
                                  createdAt: Date(), media: inner.media, mediaKind: "image",
                                  senderPublicId: senderPublicId)
        case "video":
            message = ChatMessage(id: id, peerPublicId: groupId, isMine: isMine, body: inner.text ?? "",
                                  createdAt: Date(), media: inner.media, mediaKind: "video",
                                  senderPublicId: senderPublicId)
        case "voice":
            message = ChatMessage(id: id, peerPublicId: groupId, isMine: isMine, body: "",
                                  createdAt: Date(), media: inner.media, mediaKind: "voice",
                                  durationMs: inner.durationMs, senderPublicId: senderPublicId)
        default:
            message = ChatMessage(id: id, peerPublicId: groupId, isMine: isMine, body: inner.text ?? "",
                                  createdAt: Date(), senderPublicId: senderPublicId)
        }
        // The sender's stable cross-member id, so "delete for everyone" targets it here.
        message.clientId = inner.clientId
        return message
    }

    private func myRole(in members: [GroupMember], fallback: GroupRole) -> GroupRole {
        guard let me = myPublicId() else { return fallback }
        return members.first(where: { $0.publicId == me })?.role ?? fallback
    }

    /// Decrypts a sealed group name with `groupKey` (nil key / open failure → nil).
    private func decryptName(_ sealed: Data?, groupKey: Data?) -> String? {
        guard let sealed, let groupKey, !groupKey.isEmpty else { return nil }
        return Self.open(sealed, groupKey: groupKey)
    }

    // MARK: - Name sealing (AES-GCM with the group key)

    private static func randomKey() -> Data {
        var k = Data(count: 32)
        k.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        return k
    }

    private static func seal(_ name: String, groupKey: Data) throws -> Data {
        let box = try AES.GCM.seal(Data(name.utf8), using: SymmetricKey(data: groupKey))
        guard let combined = box.combined else { throw MessagingError.missingKeyMaterial }
        return combined
    }

    private static func open(_ sealed: Data, groupKey: Data) -> String? {
        guard let box = try? AES.GCM.SealedBox(combined: sealed),
              let pt = try? AES.GCM.open(box, using: SymmetricKey(data: groupKey)) else { return nil }
        return String(decoding: pt, as: UTF8.self)
    }
}
