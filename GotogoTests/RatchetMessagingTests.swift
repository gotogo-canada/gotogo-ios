//
//  RatchetMessagingTests.swift
//  GotogoTests
//
//  In-simulator end-to-end test that drives the app's OWN AuthService and
//  MessagingService through the native PQXDH + Double Ratchet 1:1 transport
//  against the live local backend: register two accounts, become mutual
//  contacts, exchange a long alternating conversation, and assert forward secrecy
//  on the wire (re-sending the same plaintext yields different ciphertext because
//  the Double Ratchet advanced). The wire frame is a `RatchetWireEnvelope`.
//
import XCTest
@testable import Gotogo

@MainActor
final class RatchetMessagingTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    /// Keeps the per-user `APIClient` so the test can read raw inbound ciphertext
    /// (to inspect the on-the-wire ratchet envelopes), not just decoded text.
    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let api: APIClient
    }

    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        // Distinct temp cache (and therefore distinct session file) per user.
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-rtest-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache)
        return Stack(auth: auth, messaging: messaging, api: api)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run `docker compose up` in gotogo-service")
    }

    /// Registers two accounts and makes them mutual contacts.
    private func makeMutualPair() async throws -> (alice: Stack, bob: Stack,
                                                    aliceId: String, bobId: String) {
        let alice = makeStack("alice")
        let bob = makeStack("bob")
        let aliceReg = try await alice.auth.register()
        let bobReg = try await bob.auth.register()
        try await alice.messaging.requestContact(publicId: bobReg.session.publicId)
        try await bob.messaging.acceptContact(fromPublicId: aliceReg.session.publicId)
        return (alice, bob, aliceReg.session.publicId, bobReg.session.publicId)
    }

    /// Sends `text` from `sender` to `peerId`, syncs `receiver`, and asserts the
    /// freshly received message decrypts to exactly `text`.
    private func exchange(_ text: String,
                          from sender: Stack, to peerId: String,
                          receiver: Stack, expectedFrom senderId: String,
                          line: UInt = #line) async throws {
        _ = try await sender.messaging.sendText(text, to: peerId)
        let inbox = try await receiver.messaging.sync()
        guard let got = inbox.first(where: { $0.peerPublicId == senderId && $0.body == text }) else {
            return XCTFail("receiver did not decrypt \"\(text)\" from \(senderId)", line: line)
        }
        XCTAssertTrue(got.decrypted, "message should decrypt", line: line)
        XCTAssertFalse(got.isMine, "received message is not mine", line: line)
    }

    /// A long, strictly-alternating A↔B conversation that flows through the ratchet.
    func testLongAlternatingConversationThroughRatchet() async throws {
        try await requireBackend()
        let (alice, bob, aliceId, bobId) = try await makeMutualPair()

        // 12 messages, alternating sender each turn (>= 10 as required). The first
        // A->B message bootstraps the session ("init"); the rest are "msg" and each
        // drives a DH ratchet step on the receiving side.
        let lines = [
            "A1: opening the channel 🛰️",
            "B1: got it — replying ✅",
            "A2: forward secrecy check",
            "B2: post-compromise security check 🔐",
            "A3: third from Alice",
            "B3: third from Bob",
            "A4: 漢字とemojiも 😺",
            "B4: ratchet still turning",
            "A5: almost there",
            "B5: keep going",
            "A6: final from Alice",
            "B6: final from Bob 🎉",
        ]
        XCTAssertGreaterThanOrEqual(lines.count, 10, "need at least 10 messages")

        for (index, text) in lines.enumerated() {
            let aliceTurn = index % 2 == 0
            if aliceTurn {
                try await exchange(text, from: alice, to: bobId, receiver: bob, expectedFrom: aliceId)
            } else {
                try await exchange(text, from: bob, to: aliceId, receiver: alice, expectedFrom: bobId)
            }
        }
    }

    /// Forward secrecy on the wire: sending the same plaintext twice must produce
    /// different ciphertext, because the ratchet advanced between the two sends.
    func testRepeatedPlaintextYieldsDifferentWireCiphertext() async throws {
        try await requireBackend()
        let (alice, bob, aliceId, bobId) = try await makeMutualPair()

        let repeated = "the exact same plaintext, sent twice"

        // First send bootstraps Alice's session ("init"); drain it off the wire as
        // Bob (`sync` is destructive server-side, so this consumes exactly msg 1).
        _ = try await alice.messaging.sendText(repeated, to: bobId)
        let first = try await drainNextEnvelope(from: bob.api, fromPublicId: aliceId)

        // Second send of the identical plaintext. Alice's session is already
        // established (independent of whether Bob processed the init), so this is a
        // plain "msg" that rides the advanced ratchet.
        _ = try await alice.messaging.sendText(repeated, to: bobId)
        let second = try await drainNextEnvelope(from: bob.api, fromPublicId: aliceId)

        XCTAssertTrue(first.isInitial, "first message bootstraps the session")
        XCTAssertFalse(second.isInitial, "second message rides the established session")
        XCTAssertNotEqual(first.message.ciphertext, second.message.ciphertext,
                          "identical plaintext must encrypt to different ciphertext")
    }

    /// Drains the next queued inbound message for `api`'s device and decodes its raw
    /// ciphertext blob as a `RatchetWireEnvelope`. `sync` is destructive on the
    /// server (marks delivered), so successive calls return successive messages.
    private func drainNextEnvelope(from api: APIClient,
                                   fromPublicId: String) async throws -> RatchetWireEnvelope {
        let response = try await api.sync(limit: 100)
        guard let inbound = response.messages.first(where: { $0.fromPublicId == fromPublicId }) else {
            XCTFail("no inbound message from \(fromPublicId)")
            throw NSError(domain: "RatchetMessagingTests", code: 1)
        }
        return try JSONDecoder().decode(RatchetWireEnvelope.self, from: inbound.ciphertext)
    }
}
