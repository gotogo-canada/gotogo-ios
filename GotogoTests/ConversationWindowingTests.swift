//
//  ConversationWindowingTests.swift
//  GotogoTests
//
//  Unit-proves the conversation paging logic (no backend): a long thread loaded
//  from the on-device cache renders only the most-recent window, and "Load earlier
//  messages" reveals older pages. This is the in-memory half of bug fix #3 — the
//  full history lives ONLY on the device (the server deletes envelopes once
//  delivered), so paging is purely a local windowing concern.
//

import XCTest
@testable import Gotogo

@MainActor
final class ConversationWindowingTests: XCTestCase {

    private func bareMessaging() -> MessagingService {
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("win-\(UUID().uuidString).json")
        return MessagingService(
            api: APIClient(baseURL: URL(string: "http://localhost:8080")!),
            engine: CryptoKitEngine(),
            store: InMemorySecretStore(),
            realtime: RealtimeClient(baseURL: URL(string: "ws://localhost:8080")!),
            cacheURL: cache)
    }

    func testConversationWindowsToRecentAndPagesOlder() {
        let messaging = bareMessaging()
        // Seed 60 cached messages directly (no network) — as if synced earlier.
        for i in 0..<60 {
            messaging.append(ChatMessage(id: "m\(i)", peerPublicId: "PEER", isMine: false,
                                         body: "msg \(i)",
                                         createdAt: Date(timeIntervalSince1970: Double(i))),
                             to: "PEER")
        }

        let vm = ConversationViewModel(peerPublicId: "PEER", messaging: messaging)
        XCTAssertEqual(vm.messages.count, 60, "all history is present in memory from the cache")

        // Initial window: only the most-recent 50 render (not all 60 at once).
        XCTAssertEqual(vm.windowed.count, 50, "only the most-recent 50 render initially")
        XCTAssertTrue(vm.hasOlder, "older messages exist beyond the window")
        XCTAssertEqual(vm.windowed.last?.id, "m59", "newest message is at the bottom of the window")
        XCTAssertEqual(vm.windowed.first?.id, "m10", "the window is the SUFFIX (last 50)")

        // "Load earlier messages" reveals the rest.
        vm.loadOlder()
        XCTAssertEqual(vm.windowed.count, 60, "loadOlder reveals the older page")
        XCTAssertFalse(vm.hasOlder, "nothing older remains")
        XCTAssertEqual(vm.windowed.first?.id, "m0", "the oldest message is now visible")
    }

    func testShortConversationShowsAllWithNoPaging() {
        let messaging = bareMessaging()
        for i in 0..<5 {
            messaging.append(ChatMessage(id: "s\(i)", peerPublicId: "P2", isMine: false,
                                         body: "m\(i)", createdAt: Date(timeIntervalSince1970: Double(i))),
                             to: "P2")
        }
        let vm = ConversationViewModel(peerPublicId: "P2", messaging: messaging)
        XCTAssertEqual(vm.windowed.count, 5, "a short thread shows everything")
        XCTAssertFalse(vm.hasOlder, "no 'load earlier' affordance for short threads")
    }
}
