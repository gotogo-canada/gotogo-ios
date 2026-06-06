//
//  TrustTests.swift
//  GotogoTests
//
//  In-simulator end-to-end tests for the trust & safety features, driving the
//  app's OWN services against the live local backend:
//    (1) Blocking + reporting — block makes sends fail with `.blocked`, unblock
//        restores them, listBlocks reflects the set, report succeeds.
//    (2) Key-transparency verification — a peer's published identity key verifies
//        (RFC 6962 inclusion proof) and identity-key rotation is detected.
//
import XCTest
@testable import Gotogo

@MainActor
final class TrustTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    /// A per-user stack: the app's own services plus the raw API client + store so
    /// tests can drive transparency verification and rotate identities directly.
    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let transparency: TransparencyService
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
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-trust-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache)
        let transparency = TransparencyService(api: api, engine: engine, store: store)
        return Stack(auth: auth, messaging: messaging, transparency: transparency,
                     api: api, store: store, engine: engine)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run `docker compose up` in gotogo-service")
    }

    /// Registers an account, retrying on a 429 (the register rate-limiter) after a
    /// short pause so back-to-back test runs don't flake.
    @discardableResult
    private func register(_ stack: Stack) async throws -> RegistrationResult {
        for attempt in 0..<4 {
            do {
                return try await stack.auth.register()
            } catch let error as APIError {
                if case .server(let status, _, _) = error, status == 429, attempt < 3 {
                    try await Task.sleep(nanoseconds: 2_200_000_000)
                    continue
                }
                throw error
            }
        }
        return try await stack.auth.register()
    }

    /// Makes two registered stacks mutual contacts.
    private func makeMutual(_ a: Stack, _ aId: String, _ b: Stack, _ bId: String) async throws {
        try await a.messaging.requestContact(publicId: bId)
        try await b.messaging.acceptContact(fromPublicId: aId)
    }

    /// B's own identity public key as published (the prekey-store identity).
    private func identityPublicKey(_ stack: Stack) throws -> Data {
        let identity = try XCTUnwrap(stack.store.loadIdentity(), "stack should have a stored identity")
        return identity.publicKey
    }

    // MARK: - (1) Blocking + reporting

    /// A and B are mutual. A blocks B: `listBlocks()` contains B, and A→B sends now
    /// throw `.blocked`. A unblocks B and sends succeed again. A reports C cleanly.
    func testBlockingAndReporting() async throws {
        try await requireBackend()

        let alice = makeStack("blk-alice")
        let bob = makeStack("blk-bob")
        let carol = makeStack("blk-carol")
        let aliceReg = try await register(alice)
        let bobReg = try await register(bob)
        let carolReg = try await register(carol)
        try await makeMutual(alice, aliceReg.session.publicId, bob, bobReg.session.publicId)

        // Baseline: A→B works while they're mutual + unblocked.
        _ = try await alice.messaging.sendText("hi before block", to: bobReg.session.publicId)

        // A blocks B.
        let blocked = try await alice.messaging.block(publicId: bobReg.session.publicId)
        XCTAssertTrue(blocked, "block should report blocked=true")

        // listBlocks() contains B.
        let blocks = try await alice.messaging.blocks()
        XCTAssertTrue(blocks.contains(bobReg.session.publicId),
                      "A's block list should contain B")

        // A→B now fails with `.blocked`.
        do {
            _ = try await alice.messaging.sendText("should be blocked", to: bobReg.session.publicId)
            XCTFail("sending to a blocked contact should throw")
        } catch let error as MessagingError {
            XCTAssertEqual(error, .blocked, "send to blocked contact should map to .blocked")
        }

        // A unblocks B.
        let stillBlocked = try await alice.messaging.unblock(publicId: bobReg.session.publicId)
        XCTAssertFalse(stillBlocked, "unblock should report blocked=false")
        let afterUnblock = try await alice.messaging.blocks()
        XCTAssertFalse(afterUnblock.contains(bobReg.session.publicId),
                       "A's block list should no longer contain B")

        // A→B succeeds again.
        let resent = try await alice.messaging.sendText("hi after unblock", to: bobReg.session.publicId)
        XCTAssertTrue(resent.isMine, "send should succeed after unblocking")

        // A reports C (need not be a contact) — returns without error.
        let reported = try await alice.messaging.report(publicId: carolReg.session.publicId,
                                                        reason: "spam")
        XCTAssertTrue(reported, "report should report reported=true")
    }

    // MARK: - (2) Key-transparency verification

    /// A verifies B's published identity key: the RFC 6962 inclusion proof holds
    /// (`included == true`), it's a first sighting (`keyChanged == false`), the
    /// identity key equals B's published bundle key, and a safety number is
    /// produced. Then B rotates its identity and A's re-verification flags the
    /// change (`included == true`, `keyChanged == true`).
    func testTransparencyVerifyAndKeyChange() async throws {
        try await requireBackend()

        let alice = makeStack("tx-alice")
        let bob = makeStack("tx-bob")
        let aliceReg = try await register(alice)
        let bobReg = try await register(bob)
        try await makeMutual(alice, aliceReg.session.publicId, bob, bobReg.session.publicId)

        let aliceIdentity = try identityPublicKey(alice)
        let bobInitialKey = try identityPublicKey(bob)

        // First verification: B's key is published, verifies, and is new to A.
        let first = try await alice.transparency.verify(publicId: bobReg.session.publicId,
                                                        localIdentityKey: aliceIdentity)
        XCTAssertTrue(first.included, "B's identity key should verify in the transparency log")
        XCTAssertFalse(first.keyChanged, "first sighting should not be a key change")
        XCTAssertEqual(first.identityKey, bobInitialKey,
                       "verified key should equal B's published bundle identity key")
        XCTAssertFalse(first.safetyNumber.isEmpty, "a safety number should be produced")

        // Sanity: the verified key matches the bundle Alice would actually fetch.
        let bundle = try await alice.api.fetchPreKeyBundle(publicId: bobReg.session.publicId)
        XCTAssertEqual(first.identityKey, bundle.identityKey,
                       "transparency key should match the fetched prekey bundle key")

        // B rotates its identity: a fresh identity + prekeys re-uploaded on B's own
        // account token appends a new transparency leaf with a new identity key.
        try await rotateIdentity(bob)
        let bobRotatedKey = try identityPublicKey(bob)
        XCTAssertNotEqual(bobRotatedKey, bobInitialKey, "rotation should change B's identity key")

        // Second verification: still included, now flagged as a key change.
        let second = try await alice.transparency.verify(publicId: bobReg.session.publicId,
                                                         localIdentityKey: aliceIdentity)
        XCTAssertTrue(second.included, "rotated key should still verify in the transparency log")
        XCTAssertTrue(second.keyChanged, "a different key than last-seen should be a key change")
        XCTAssertEqual(second.identityKey, bobRotatedKey,
                       "verified key should now equal B's rotated identity key")
    }

    /// Rotates `stack`'s identity: mints a fresh identity + prekeys (a second
    /// engine), persists them locally, and re-uploads the bundle on the SAME
    /// account/device token — which appends a new leaf to the transparency log
    /// with the new identity key.
    private func rotateIdentity(_ stack: Stack) async throws {
        let newEngine = CryptoKitEngine()
        let newIdentity = newEngine.generateIdentity()
        let generated = try newEngine.generatePreKeys(identity: newIdentity,
                                                      signedPreKeyId: 1,
                                                      oneTimeCount: 20,
                                                      firstOneTimeId: 1)
        try stack.store.saveIdentity(newIdentity)
        try stack.store.savePreKeyStore(generated.store)
        try await stack.api.uploadPreKeys(AuthService.uploadRequest(identity: newIdentity,
                                                                    store: generated.store))
    }
}
