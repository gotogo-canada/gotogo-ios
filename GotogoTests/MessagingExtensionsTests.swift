//
//  MessagingExtensionsTests.swift
//  GotogoTests
//
//  In-simulator end-to-end tests for the three messaging extensions, driving the
//  app's OWN services against the live local backend:
//    (A) multi-device fan-out  — a message reaches every recipient device,
//    (B) one-time prekey auto-replenishment — the server pool tops back up,
//    (C) internal stickers — a sticker round-trips through the ratchet.
//
import XCTest
@testable import Gotogo

@MainActor
final class MessagingExtensionsTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    /// A per-user stack: the app's own services plus the raw API client + store so
    /// the test can provision extra devices and inspect counts directly.
    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let api: APIClient
        let store: InMemorySecretStore
        let engine: CryptoKitEngine
    }

    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        // Distinct temp cache (and therefore distinct session file) per user/device.
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-ext-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache)
        return Stack(auth: auth, messaging: messaging, api: api, store: store, engine: engine)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run `docker compose up` in gotogo-service")
    }

    /// Registers an account, retrying once on a 429 (the register rate-limiter)
    /// after a short pause so back-to-back test runs don't flake.
    @discardableResult
    private func register(_ stack: Stack) async throws -> RegistrationResult {
        do {
            return try await stack.auth.register()
        } catch let error as APIError {
            if case .server(let status, _, _) = error, status == 429 {
                try await Task.sleep(nanoseconds: 2_200_000_000)
                return try await stack.auth.register()
            }
            throw error
        }
    }

    /// Makes two registered stacks mutual contacts.
    private func makeMutual(_ a: Stack, _ aId: String, _ b: Stack, _ bId: String) async throws {
        try await a.messaging.requestContact(publicId: bId)
        try await b.messaging.acceptContact(fromPublicId: aId)
    }

    // MARK: - (A) Multi-device fan-out

    /// A sends one text to B; B has TWO devices, each with its own identity +
    /// uploaded prekeys. Both devices must independently sync + decrypt it — proof
    /// that one envelope was fanned out to each device's own ratchet session.
    func testMultiDeviceFanOut() async throws {
        try await requireBackend()

        let alice = makeStack("md-alice")
        let bob1 = makeStack("md-bob1")
        let aliceReg = try await register(alice)
        let bobReg = try await register(bob1)
        try await makeMutual(alice, aliceReg.session.publicId, bob1, bobReg.session.publicId)

        // Provision a SECOND device for Bob (token2), with its OWN identity+prekeys
        // uploaded via a separate MessagingService/SecretStore sharing Bob's account.
        let added = try await bob1.api.addDevice(deviceName: "Bob-2")
        let bob2 = makeStack("md-bob2")
        let bob2Api = APIClient(baseURL: apiURL)
        bob2Api.setToken(added.token)
        // The second device needs the same persisted session/keys to ingest.
        let bob2Identity = bob2.engine.generateIdentity()
        let bob2Generated = try bob2.engine.generatePreKeys(identity: bob2Identity,
                                                            signedPreKeyId: 1,
                                                            oneTimeCount: 20,
                                                            firstOneTimeId: 1)
        try bob2.store.saveIdentity(bob2Identity)
        try bob2.store.savePreKeyStore(bob2Generated.store)
        try bob2.store.saveSession(Session(publicId: bobReg.session.publicId,
                                           accountId: bobReg.session.accountId,
                                           deviceId: added.deviceId,
                                           token: added.token,
                                           deviceName: "Bob-2"))
        try await bob2Api.uploadPreKeys(AuthService.uploadRequest(identity: bob2Identity,
                                                                  store: bob2Generated.store))
        // Rebuild bob2's messaging on the token2-authenticated API client.
        let bob2Realtime = RealtimeClient(baseURL: wsURL)
        let bob2Cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-ext-md-bob2-\(UUID().uuidString).json")
        let bob2Messaging = MessagingService(api: bob2Api, engine: bob2.engine,
                                             store: bob2.store, realtime: bob2Realtime,
                                             cacheURL: bob2Cache)
        // Sanity: the server now reports two devices for Bob.
        let devices = try await alice.api.fetchAllPreKeyBundles(publicId: bobReg.session.publicId)
        XCTAssertEqual(devices.count, 2, "Bob should publish two devices")

        // Alice sends ONE message; it fans out to both of Bob's devices.
        let text = "hi all your devices"
        _ = try await alice.messaging.sendText(text, to: bobReg.session.publicId)

        // Device 1 receives + decrypts.
        let inbox1 = try await bob1.messaging.sync()
        XCTAssertTrue(inbox1.contains { $0.body == text && !$0.isMine && $0.decrypted },
                      "Bob device 1 should decrypt the fanned-out message")

        // Device 2 receives + decrypts (its own envelope on its own session).
        let inbox2 = try await bob2Messaging.sync()
        XCTAssertTrue(inbox2.contains { $0.body == text && !$0.isMine && $0.decrypted },
                      "Bob device 2 should decrypt its own copy of the message")
    }

    // MARK: - (B) One-time prekey auto-replenishment

    /// Forces a top-up (minimum far above the current count) and asserts the
    /// server's available one-time-prekey count strictly increased.
    func testPreKeyReplenishment() async throws {
        try await requireBackend()

        let user = makeStack("rep-user")
        _ = try await register(user)

        let before = try await user.api.prekeyCount()
        let uploaded = try await user.messaging.replenishPreKeysIfNeeded(minimum: 100, topUpTo: 120)
        XCTAssertGreaterThan(uploaded, 0, "a top-up should have uploaded new prekeys")

        let after = try await user.api.prekeyCount()
        XCTAssertGreaterThan(after, before,
                             "available one-time prekeys should increase after replenishment")
    }

    // MARK: - (C) Internal stickers

    /// A sends a sticker to B; B syncs and gets a sticker `ChatMessage` carrying the
    /// catalog id, which resolves via `StickerCatalog`.
    func testStickerRoundTrip() async throws {
        try await requireBackend()

        let alice = makeStack("st-alice")
        let bob = makeStack("st-bob")
        let aliceReg = try await register(alice)
        let bobReg = try await register(bob)
        try await makeMutual(alice, aliceReg.session.publicId, bob, bobReg.session.publicId)

        let stickerId = "reactions/heart"
        let sent = try await alice.messaging.sendSticker(stickerId, to: bobReg.session.publicId)
        XCTAssertEqual(sent.mediaKind, "sticker")
        XCTAssertEqual(sent.stickerId, stickerId)

        let inbox = try await bob.messaging.sync()
        guard let got = inbox.first(where: { $0.peerPublicId == aliceReg.session.publicId }) else {
            return XCTFail("Bob received no sticker from Alice")
        }
        XCTAssertEqual(got.mediaKind, "sticker", "received message should be a sticker")
        XCTAssertEqual(got.stickerId, stickerId, "sticker id should round-trip")
        XCTAssertTrue(got.decrypted)
        XCTAssertFalse(got.isMine)
        XCTAssertNotNil(StickerCatalog.sticker(id: got.stickerId ?? ""),
                        "sticker id should resolve in the bundled catalog")
    }
}
