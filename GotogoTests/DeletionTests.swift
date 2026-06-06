//
//  DeletionTests.swift
//  GotogoTests
//
//  In-simulator proof of message + conversation deletion over the live backend,
//  driving the app's own MessagingService. Covers "delete for everyone" (a sent
//  message is removed on the peer too), "delete conversation" (my messages are
//  removed from the peer's copy while theirs remain), and "delete for me" (local
//  only). The deletion controls travel as pairwise-E2EE messages over /v1/messages.
//
import XCTest
@testable import Gotogo

@MainActor
final class DeletionTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let store: InMemorySecretStore
        var publicId: String = ""
    }

    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-del-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache)
        return Stack(auth: auth, messaging: messaging, store: store)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run the local server")
    }

    @discardableResult
    private func register(_ stack: Stack) async throws -> RegistrationResult {
        for attempt in 0..<5 {
            do { return try await stack.auth.register() }
            catch let error as APIError {
                if case .server(let status, _, _) = error, status == 429, attempt < 4 {
                    try await Task.sleep(nanoseconds: 2_300_000_000); continue
                }
                throw error
            }
        }
        return try await stack.auth.register()
    }

    private func makeMutual(_ a: Stack, _ b: Stack) async throws {
        try await a.messaging.requestContact(publicId: b.publicId)
        try await b.messaging.acceptContact(fromPublicId: a.publicId)
    }

    /// The (chronological) message bodies in a stack's conversation with `peer`.
    private func bodies(_ s: Stack, with peer: String) -> [String] {
        s.messaging.conversation(with: peer).messages
            .sorted { $0.createdAt < $1.createdAt }
            .map(\.body)
    }

    // MARK: - Delete for everyone + delete conversation

    func testDeleteForEveryoneAndDeleteConversationPropagateToPeer() async throws {
        try await requireBackend()

        var a = makeStack("A"); var b = makeStack("B")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        try await makeMutual(a, b)

        // A sends two messages; B syncs to receive them, then replies on the SAME
        // ratchet session (syncing between turns avoids a crossed/simultaneous
        // initiation — both sides bootstrapping independent sessions at once).
        let alpha = try await a.messaging.sendText("alpha", to: b.publicId)
        _ = try await a.messaging.sendText("beta", to: b.publicId)
        _ = try await b.messaging.sync()
        _ = try await b.messaging.sendText("hi-from-b", to: a.publicId)
        _ = try await a.messaging.sync()
        XCTAssertEqual(Set(bodies(b, with: a.publicId)), ["alpha", "beta", "hi-from-b"],
                       "B has both of A's messages plus its own")

        // 1) A deletes "alpha" for EVERYONE — gone on A immediately, gone on B after sync.
        let deleted = await a.messaging.deleteMessageForEveryone(alpha)
        XCTAssertTrue(deleted, "deleting my own id'd message for everyone succeeds")
        XCTAssertFalse(bodies(a, with: b.publicId).contains("alpha"), "A's local copy of alpha is gone")

        _ = try await b.messaging.sync()
        XCTAssertFalse(bodies(b, with: a.publicId).contains("alpha"), "alpha removed on B (delete for everyone)")
        XCTAssertTrue(bodies(b, with: a.publicId).contains("beta"), "beta still on B")
        XCTAssertTrue(bodies(b, with: a.publicId).contains("hi-from-b"), "B's own message untouched")

        // 2) A deletes the whole CONVERSATION — A's thread is gone locally; on B, A's
        //    remaining messages are removed while B keeps its own.
        await a.messaging.deleteConversation(b.publicId)
        XCTAssertTrue(bodies(a, with: b.publicId).isEmpty, "A's local thread is removed entirely")

        _ = try await b.messaging.sync()
        XCTAssertEqual(bodies(b, with: a.publicId), ["hi-from-b"],
                       "after A deletes the conversation, B keeps only its OWN message")
    }

    // MARK: - Delete for me (local only)

    func testDeleteForMeIsLocalOnly() async throws {
        try await requireBackend()

        var a = makeStack("A2"); var b = makeStack("B2")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        try await makeMutual(a, b)

        _ = try await a.messaging.sendText("keep", to: b.publicId)
        _ = try await b.messaging.sync()

        // B deletes A's message "for me" only → gone on B, still present for A (sender).
        let onB = try XCTUnwrap(b.messaging.conversation(with: a.publicId).messages.first { $0.body == "keep" })
        b.messaging.deleteMessageForMe(onB)
        XCTAssertFalse(bodies(b, with: a.publicId).contains("keep"), "deleted locally on B")

        // A never receives a control, so A still has its sent message.
        _ = try await a.messaging.sync()
        XCTAssertTrue(bodies(a, with: b.publicId).contains("keep"),
                      "delete-for-me must not touch the other party's copy")
    }
}
