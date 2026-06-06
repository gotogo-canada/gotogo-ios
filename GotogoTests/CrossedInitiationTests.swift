//
//  CrossedInitiationTests.swift
//  GotogoTests
//
//  Regression for SIMULTANEOUS / CROSSED session initiation: when two peers each
//  send their first message before either syncs, both bootstrap an initiator
//  session at once. The session layer keeps multiple CANDIDATE sessions per device
//  and tries each on decrypt, so neither side's session is clobbered and every
//  message still decrypts. Drives the app's real MessagingService over the live
//  backend.
//
import XCTest
@testable import Gotogo

@MainActor
final class CrossedInitiationTests: XCTestCase {

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
            .appendingPathComponent("gotogo-xinit-\(tag)-\(UUID().uuidString).json")
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

    private func bodies(_ s: Stack, with peer: String) -> [String] {
        s.messaging.conversation(with: peer).messages
            .sorted { $0.createdAt < $1.createdAt }
            .map(\.body)
    }

    func testSimultaneousInitiationConverges() async throws {
        try await requireBackend()

        var a = makeStack("A"); var b = makeStack("B")
        a.publicId = try await register(a).session.publicId
        b.publicId = try await register(b).session.publicId
        try await makeMutual(a, b)

        // Round 1 — CROSSED INIT: both send before either syncs, so each bootstraps
        // its own initiator session at the same time.
        _ = try await a.messaging.sendText("a1", to: b.publicId)
        _ = try await b.messaging.sendText("b1", to: a.publicId)
        _ = try await a.messaging.sync()
        _ = try await b.messaging.sync()

        // Rounds 2 & 3 — keep exchanging both ways across the multi-candidate state.
        for round in [2, 3] {
            _ = try await a.messaging.sendText("a\(round)", to: b.publicId)
            _ = try await b.messaging.sendText("b\(round)", to: a.publicId)
            _ = try await a.messaging.sync()
            _ = try await b.messaging.sync()
        }

        let bHasFromA = bodies(b, with: a.publicId)
        let aHasFromB = bodies(a, with: b.publicId)

        // No undecryptable placeholders despite the crossed initiation.
        XCTAssertFalse(bHasFromA.contains { $0.hasPrefix("[Unable") }, "B must have no undecryptable messages: \(bHasFromA)")
        XCTAssertFalse(aHasFromB.contains { $0.hasPrefix("[Unable") }, "A must have no undecryptable messages: \(aHasFromB)")

        // Every message landed and decrypted on the other side.
        for m in ["a1", "a2", "a3"] { XCTAssertTrue(bHasFromA.contains(m), "B should have decrypted \(m); got \(bHasFromA)") }
        for m in ["b1", "b2", "b3"] { XCTAssertTrue(aHasFromB.contains(m), "A should have decrypted \(m); got \(aHasFromB)") }
    }
}
