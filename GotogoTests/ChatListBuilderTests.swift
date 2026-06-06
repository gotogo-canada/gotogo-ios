//
//  ChatListBuilderTests.swift
//  GotogoTests
//
//  Unit-proves bug fix #4: GROUP conversations (keyed by a group UUID, stored in the
//  same conversation cache as 1:1 threads) must NOT leak into the 1:1 "Chats" list —
//  they belong in the Groups tab. Pure transform; no backend.
//

import XCTest
@testable import Gotogo

final class ChatListBuilderTests: XCTestCase {

    private func convo(_ peer: String, _ body: String, at t: TimeInterval, kind: String? = nil) -> Conversation {
        Conversation(peerPublicId: peer, messages: [
            ChatMessage(id: "\(peer)-\(t)", peerPublicId: peer, isMine: true, body: body,
                        createdAt: Date(timeIntervalSince1970: t), mediaKind: kind)
        ])
    }

    func testGroupConversationsAreExcludedFromChats() {
        let groupId = "cb8ced18-fbc9-4cda-be1e-14b9728e62ce"   // a group UUID, like the bug screenshot
        let convos = [convo("ALICE001", "hey", at: 10),
                      convo(groupId, "Ça va?", at: 20)]

        let rows = ChatListBuilder.rows(conversations: convos, mutualContacts: [], groupIds: [groupId])
        XCTAssertEqual(rows.map(\.peerPublicId), ["ALICE001"],
                       "only the 1:1 thread shows; the group UUID does NOT leak into Chats")
        XCTAssertFalse(rows.contains { $0.peerPublicId == groupId })
    }

    func testFilterIsWhatRemovesTheGroup() {
        let groupId = "GROUP-1"
        let convos = [convo(groupId, "group msg", at: 5)]
        // Without the filter it WOULD leak (the bug)...
        XCTAssertTrue(ChatListBuilder.rows(conversations: convos, mutualContacts: [], groupIds: [])
                        .contains { $0.peerPublicId == groupId }, "no filter → it leaks (the bug)")
        // ...with the filter it's gone (the fix).
        XCTAssertTrue(ChatListBuilder.rows(conversations: convos, mutualContacts: [], groupIds: [groupId]).isEmpty,
                      "with the filter → no group row (the fix)")
    }

    func testVideoPreviewLabel() {
        let rows = ChatListBuilder.rows(conversations: [convo("BOB0001", "", at: 1, kind: "video")],
                                        mutualContacts: [])
        XCTAssertEqual(rows.first?.preview, "You: Video", "a video shows a 'Video' preview")
    }
}
