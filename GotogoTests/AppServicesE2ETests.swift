//
//  AppServicesE2ETests.swift
//  GotogoTests
//
//  In-simulator end-to-end test that drives the app's OWN AuthService and
//  MessagingService (the exact code the UI calls) against the live local
//  backend: register two accounts, become mutual contacts, exchange a real
//  post-quantum-encrypted message, and recover an account from its phrase.
//
import XCTest
@testable import Gotogo

@MainActor
final class AppServicesE2ETests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    private struct Stack { let auth: AuthService; let messaging: MessagingService }

    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-test-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store, realtime: realtime, cacheURL: cache)
        return Stack(auth: auth, messaging: messaging)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run `docker compose up` in gotogo-service")
    }

    func testTwoAccountsExchangeE2EEMessage() async throws {
        try await requireBackend()

        let alice = makeStack("alice")
        let bob = makeStack("bob")

        let aliceReg = try await alice.auth.register()
        let bobReg = try await bob.auth.register()
        XCTAssertEqual(aliceReg.recoveryPhrase.count, 24, "registration yields a 24-word phrase")
        XCTAssertGreaterThanOrEqual(aliceReg.session.publicId.count, 8)

        // Become mutual contacts.
        try await alice.messaging.requestContact(publicId: bobReg.session.publicId)
        try await bob.messaging.acceptContact(fromPublicId: aliceReg.session.publicId)

        // Alice seals + sends; Bob syncs + decrypts — all via the app's services.
        let text = "Hello from the app's own services — post-quantum E2EE 🛰️🔐"
        let sent = try await alice.messaging.sendText(text, to: bobReg.session.publicId)
        XCTAssertTrue(sent.isMine)

        let received = try await bob.messaging.sync()
        guard let got = received.first(where: { $0.peerPublicId == aliceReg.session.publicId }) else {
            return XCTFail("Bob received no message from Alice")
        }
        XCTAssertEqual(got.body, text, "Bob decrypts Alice's message")
        XCTAssertFalse(got.isMine)
        XCTAssertTrue(got.decrypted)

        // Reply the other way.
        let reply = "Got it, Alice — secured end to end ✅"
        _ = try await bob.messaging.sendText(reply, to: aliceReg.session.publicId)
        let aliceInbox = try await alice.messaging.sync()
        XCTAssertTrue(aliceInbox.contains { $0.body == reply && !$0.isMine && $0.decrypted },
                      "Alice decrypts Bob's reply")
    }

    func testGatingBlocksNonContacts() async throws {
        try await requireBackend()
        let alice = makeStack("g-alice")
        let bob = makeStack("g-bob")
        let aliceReg = try await alice.auth.register()
        let bobReg = try await bob.auth.register()
        _ = aliceReg
        // Bob already uploaded standard prekeys at registration; the send reaches
        // the server, which applies the mutual-contact gate (the point of this test).
        do {
            _ = try await alice.messaging.sendText("should be blocked", to: bobReg.session.publicId)
            XCTFail("sending to a non-contact should throw")
        } catch let e as MessagingError {
            XCTAssertEqual(e, .notMutualContact)
        }
    }

    func testRecoveryFromPhrase() async throws {
        try await requireBackend()
        let original = makeStack("rec-1")
        let reg = try await original.auth.register()

        // A fresh "device" recovers the same account from the 24-word phrase.
        let newDevice = makeStack("rec-2")
        let restored = try await newDevice.auth.recoverAccount(publicId: reg.session.publicId,
                                                               phrase: reg.recoveryPhrase)
        XCTAssertEqual(restored.publicId, reg.session.publicId, "recovery restores the same account")
        XCTAssertNotNil(newDevice.auth.currentSession())
    }
}
