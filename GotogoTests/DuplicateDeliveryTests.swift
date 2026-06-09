//
//  DuplicateDeliveryTests.swift
//  GotogoTests
//
//  Proves the fix for the "random [Unable to decrypt message]" bug: a message is
//  delivered via BOTH the realtime socket (push-only) AND the durable `/sync`, so
//  `ingest` must decode each envelope id only ONCE. Feeding the ratchet the same
//  ciphertext twice burns message keys and desyncs the session, cascading into
//  spurious decrypt
//  failures. No backend needed.
//

import XCTest
@testable import Gotogo

@MainActor
final class DuplicateDeliveryTests: XCTestCase {

    private func messagingWithKeys() throws -> MessagingService {
        let engine = CryptoKitEngine()
        let store = InMemorySecretStore()
        let identity = engine.generateIdentity()
        try store.saveIdentity(identity)
        let gen = try engine.generatePreKeys(identity: identity, signedPreKeyId: 1,
                                             oneTimeCount: 5, firstOneTimeId: 1)
        try store.savePreKeyStore(gen.store)
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("dup-\(UUID().uuidString).json")
        return MessagingService(
            api: APIClient(baseURL: URL(string: "http://localhost:8080")!),
            engine: engine, store: store,
            realtime: RealtimeClient(baseURL: URL(string: "ws://localhost:8080")!),
            cacheURL: cache)
    }

    func testRedeliveredEnvelopeIsDecodedOnlyOnce() throws {
        let messaging = try messagingWithKeys()
        let raw = InboundMessage(id: "ENV-DUP-1", fromPublicId: "AAAA0001", fromAddress: nil, fromDeviceId: "d1",
                                 ciphertext: Data("opaque-ratchet-ciphertext".utf8),
                                 contentType: "text",
                                 createdAt: Date(timeIntervalSince1970: 1))

        let first = messaging.ingest([raw])
        let second = messaging.ingest([raw])   // realtime push + durable sync: SAME envelope id

        XCTAssertEqual(first.count, 1, "the first delivery is decoded")
        XCTAssertEqual(second.count, 0, "the re-delivered envelope id is skipped")

        // Exactly one entry for that envelope in the conversation (no duplicate bubble).
        let convo = messaging.conversation(with: "AAAA0001")
        XCTAssertEqual(convo.messages.filter { $0.id == "ENV-DUP-1" }.count, 1,
                       "a re-delivered message never produces a second bubble")
    }

    func testDistinctEnvelopesAreNotDeduped() throws {
        let messaging = try messagingWithKeys()
        let a = InboundMessage(id: "E-A", fromPublicId: "AAAA0001", fromAddress: nil, fromDeviceId: "d1",
                               ciphertext: Data("c1".utf8), contentType: "text",
                               createdAt: Date(timeIntervalSince1970: 1))
        let b = InboundMessage(id: "E-B", fromPublicId: "AAAA0001", fromAddress: nil, fromDeviceId: "d1",
                               ciphertext: Data("c2".utf8), contentType: "text",
                               createdAt: Date(timeIntervalSince1970: 2))
        // Two genuinely different envelopes (distinct ids) must both be processed.
        XCTAssertEqual(messaging.ingest([a, b]).count, 2, "distinct envelope ids are each decoded")
    }
}
