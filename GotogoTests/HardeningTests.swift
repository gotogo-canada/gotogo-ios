//
//  HardeningTests.swift
//  GotogoTests
//
//  In-simulator tests for the persistence + multi-device hardening work, driving
//  the app's OWN services against the live local backend:
//    1. Keychain round-trip — KeychainSecretStore save/load/clear.
//    2. Encrypted cache at rest — the on-disk cache is ciphertext, yet round-trips.
//    3. Self-device sync — a sent message mirrors to my OWN other device as `isMine`.
//    4. account_deleted — a peer's deletion drops them from my contacts + history.
//
import XCTest
import CryptoKit
import Security
@testable import Gotogo

@MainActor
final class HardeningTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    /// A per-user stack: the app's own services plus the raw API client + store so a
    /// test can provision extra devices and inspect state directly.
    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let api: APIClient
        let store: InMemorySecretStore
        let engine: CryptoKitEngine
        let cacheURL: URL
    }

    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-hard-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache)
        return Stack(auth: auth, messaging: messaging, api: api, store: store,
                     engine: engine, cacheURL: cache)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run `docker compose up` in gotogo-service")
    }

    /// Registers an account, retrying once on a 429 (the register rate-limiter).
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

    private func skipIfKeychainUnavailable(_ error: Error) throws {
        if case KeychainError.unexpectedStatus(let status) = error,
           status == errSecMissingEntitlement {
            throw XCTSkip("Keychain is unavailable in this simulator context")
        }
        throw error
    }

    // MARK: - 1. Keychain round-trip

    /// `KeychainSecretStore` saves and loads a `Session` + identity, and `clear()`
    /// removes them (load returns nil afterwards). Uses a unique service so it never
    /// collides with the app's real keychain items; cleans up on exit.
    func testKeychainRoundTrip() throws {
        let service = "ca.gotogo.test.\(UUID().uuidString)"
        let store = KeychainSecretStore(keychain: Keychain(service: service))
        defer { try? store.clear() }

        XCTAssertNil(store.loadSession(), "fresh keychain has no session")
        XCTAssertNil(store.loadIdentity(), "fresh keychain has no identity")

        let session = Session(publicId: "ABCD1234", accountId: UUID().uuidString,
                              deviceId: UUID().uuidString, token: "tok-\(UUID().uuidString)",
                              deviceName: "Test Device")
        let identity = CryptoKitEngine().generateIdentity()
        do {
            try store.saveSession(session)
            try store.saveIdentity(identity)
        } catch {
            try skipIfKeychainUnavailable(error)
        }

        let loadedSession = store.loadSession()
        let loadedIdentity = store.loadIdentity()
        XCTAssertEqual(loadedSession, session, "session round-trips through the keychain")
        XCTAssertEqual(loadedIdentity?.publicKey, identity.publicKey, "identity round-trips")
        XCTAssertEqual(loadedIdentity?.privateKey, identity.privateKey)

        try store.clear()
        XCTAssertNil(store.loadSession(), "session is gone after clear()")
        XCTAssertNil(store.loadIdentity(), "identity is gone after clear()")
    }

    // MARK: - 2. Encrypted cache at rest

    /// A `MessagingService` with a REAL Keychain-backed cache key records a
    /// conversation containing a marker string. The on-disk bytes must NOT contain
    /// that marker (the file is AES-GCM ciphertext), yet a fresh `MessagingService`
    /// pointed at the same file + key reads the message back intact.
    func testEncryptedCacheAtRest() throws {
        let marker = "TOPSECRET-MARKER-12345"

        // A unique keychain service so the real cache key doesn't collide / persist.
        let service = "ca.gotogo.test.\(UUID().uuidString)"
        let keychainStore = KeychainSecretStore(keychain: Keychain(service: service))
        defer { try? keychainStore.clear(); try? Keychain(service: service).delete("gotogo.cachekey") }

        // A real identity so `ingest`/cache plumbing is fully exercised if needed.
        do {
            try keychainStore.saveIdentity(CryptoKitEngine().generateIdentity())
        } catch {
            try skipIfKeychainUnavailable(error)
        }
        try XCTSkipUnless(keychainStore.cacheKey() != nil,
                          "Keychain cache key is unavailable in this simulator context")

        let cacheURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-enc-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: cacheURL) }

        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let realtime = RealtimeClient(baseURL: wsURL)
        let peer = "PEER0001"

        // Record a conversation carrying the marker through the encrypted cache.
        do {
            let messaging = MessagingService(api: api, engine: engine, store: keychainStore,
                                             realtime: realtime, cacheURL: cacheURL)
            messaging.append(ChatMessage(id: "m1", peerPublicId: peer, isMine: true,
                                         body: marker, createdAt: Date()),
                             to: peer)
        }

        // The raw on-disk bytes must be ciphertext: no ASCII marker substring.
        let rawBytes = try Data(contentsOf: cacheURL)
        XCTAssertFalse(rawBytes.isEmpty, "the cache file should have been written")
        let markerBytes = Data(marker.utf8)
        XCTAssertNil(rawBytes.range(of: markerBytes),
                     "plaintext marker must NOT appear in the on-disk cache (it is encrypted)")
        // Also confirm it doesn't even look like JSON (no leading '[' / '{').
        XCTAssertFalse(rawBytes.first == UInt8(ascii: "[") || rawBytes.first == UInt8(ascii: "{"),
                       "the cache file should not be plaintext JSON")

        // A fresh service on the SAME file + key (same keychain service) reads it back.
        let reopened = MessagingService(api: api, engine: engine, store: keychainStore,
                                        realtime: realtime, cacheURL: cacheURL)
        let convo = reopened.conversation(with: peer)
        XCTAssertEqual(convo.messages.count, 1, "the encrypted cache round-trips")
        XCTAssertEqual(convo.messages.first?.body, marker, "the decrypted message matches")
        XCTAssertEqual(convo.messages.first?.isMine, true)
    }

    // MARK: - 3. Self-device sync

    /// A registers and provisions a SECOND device (A2) with its own identity/prekeys.
    /// B registers; A and B become mutual. A (device 1) sends a text to B. A2 must
    /// then `sync()` and find that message in `conversation(B)` as `isMine` — proof
    /// that the send was mirrored to the sender's own other device.
    func testSelfDeviceSync() async throws {
        try await requireBackend()

        let a1 = makeStack("ss-a1")
        let aReg = try await register(a1)

        // Provision A's SECOND device (A2): its own SecretStore/identity/prekeys,
        // authenticated with the device-2 token, sharing A's account/publicId.
        let added = try await a1.api.addDevice(deviceName: "A-2")
        let a2 = makeStack("ss-a2")
        let a2Api = APIClient(baseURL: apiURL)
        a2Api.setToken(added.token)
        let a2Identity = a2.engine.generateIdentity()
        let a2Generated = try a2.engine.generatePreKeys(identity: a2Identity,
                                                        signedPreKeyId: 1,
                                                        oneTimeCount: 20,
                                                        firstOneTimeId: 1)
        try a2.store.saveIdentity(a2Identity)
        try a2.store.savePreKeyStore(a2Generated.store)
        try a2.store.saveSession(Session(publicId: aReg.session.publicId,
                                         accountId: aReg.session.accountId,
                                         deviceId: added.deviceId,
                                         token: added.token,
                                         deviceName: "A-2"))
        try await a2Api.uploadPreKeys(AuthService.uploadRequest(identity: a2Identity,
                                                               store: a2Generated.store))
        let a2Realtime = RealtimeClient(baseURL: wsURL)
        let a2Cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-hard-ss-a2-\(UUID().uuidString).json")
        let a2Messaging = MessagingService(api: a2Api, engine: a2.engine,
                                           store: a2.store, realtime: a2Realtime,
                                           cacheURL: a2Cache)
        // B registers and A/B become mutual.
        let b = makeStack("ss-b")
        let bReg = try await register(b)
        try await makeMutual(a1, aReg.session.publicId, b, bReg.session.publicId)

        // Sanity: A now publishes two devices (so a self-sync target exists).
        let aDevices = try await b.api.fetchAllPreKeyBundles(publicId: aReg.session.publicId)
        XCTAssertEqual(aDevices.count, 2, "A should publish two devices")

        // A (device 1) sends a text to B. It also fans out to A2.
        let body = "hello from my phone"
        _ = try await a1.messaging.sendText(body, to: bReg.session.publicId)

        // A2 syncs: it should receive the self-sync copy, filed under B as isMine.
        let produced = try await a2Messaging.sync()
        XCTAssertTrue(produced.contains { $0.peerPublicId == bReg.session.publicId
                                          && $0.isMine && $0.body == body && $0.decrypted },
                      "A2's sync() should surface the self-synced message")
        let a2ConvoWithB = a2Messaging.conversation(with: bReg.session.publicId)
        XCTAssertTrue(a2ConvoWithB.messages.contains { $0.isMine && $0.body == body },
                      "A2's conversation(B) should contain the self-synced message as isMine")
        // It must NOT have created a self-conversation.
        XCTAssertTrue(a2Messaging.conversation(with: aReg.session.publicId).messages.isEmpty,
                      "self-sync must not create a conversation with myself")

        // And B still receives the message normally (unchanged peer delivery).
        let bInbox = try await b.messaging.sync()
        XCTAssertTrue(bInbox.contains { $0.peerPublicId == aReg.session.publicId
                                        && !$0.isMine && $0.body == body && $0.decrypted },
                      "B should still receive the normal peer message")
    }

    // MARK: - 4. account_deleted

    /// A and B register and become mutual. B deletes its account; A syncs and the
    /// server-delivered `account_deleted` system event must drop B from A's local
    /// contacts and conversations.
    func testAccountDeletedEvent() async throws {
        try await requireBackend()

        let a = makeStack("ad-a")
        let b = makeStack("ad-b")
        let aReg = try await register(a)
        let bReg = try await register(b)
        try await makeMutual(a, aReg.session.publicId, b, bReg.session.publicId)

        // Exchange a message so A has a conversation + ratchet session with B.
        _ = try await a.messaging.sendText("hi B", to: bReg.session.publicId)
        _ = try await b.messaging.sync()
        _ = try await b.messaging.sendText("hi A", to: aReg.session.publicId)
        _ = try await a.messaging.sync()
        XCTAssertFalse(a.messaging.conversation(with: bReg.session.publicId).messages.isEmpty,
                       "A should have a conversation with B before deletion")
        let contactsBefore = try await a.messaging.contacts()
        XCTAssertTrue(contactsBefore.contains { $0.publicId == bReg.session.publicId },
                      "B should be in A's contacts before deletion")

        // Install a handler to capture the deletion signal exposed to AppState.
        var notified: String?
        a.messaging.setAccountDeletedHandler { notified = $0 }

        // B deletes its account (DELETE /v1/accounts/me).
        try await b.auth.deleteAccount()

        // A syncs: the account_deleted system event is ingested.
        _ = try await a.messaging.sync()

        XCTAssertEqual(notified, bReg.session.publicId,
                       "A's accountDeletedHandler should fire for B")
        XCTAssertTrue(a.messaging.deletedAccountIds.contains(bReg.session.publicId),
                      "A should record B's account as deleted")
        XCTAssertTrue(a.messaging.conversation(with: bReg.session.publicId).messages.isEmpty,
                      "A's conversation with B should be purged")
        let contactsAfter = try await a.messaging.contacts()
        XCTAssertFalse(contactsAfter.contains { $0.publicId == bReg.session.publicId },
                       "B should no longer appear in A's server contact list")
    }
}
