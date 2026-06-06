//
//  ChatListViewModel.swift
//  Gotogo
//
//  Derives the chat list: a row per peer the user can talk to (mutual contacts)
//  or has exchanged messages with, ordered by recency. Pulls from `AppState`.
//

import Foundation

/// One row in the chat list.
struct ChatListRow: Identifiable, Equatable {
    let peerPublicId: String
    let preview: String
    let timestamp: Date?
    let unreadHint: Bool

    var id: String { peerPublicId }
}

/// Pure transform helper (kept testable and UI-free).
enum ChatListBuilder {
    /// Builds chat rows from conversations and the mutual-contact list. Every
    /// mutual contact gets a row (so you can start a chat), plus any peer with
    /// message history. GROUP conversations (keyed by group id) are excluded — they
    /// live in their own Groups tab, not the 1:1 Chats list. Sorted most-recent
    /// first, then by id.
    static func rows(conversations: [Conversation],
                     mutualContacts: [Contact],
                     groupIds: Set<String> = []) -> [ChatListRow] {
        var byPeer: [String: ChatListRow] = [:]

        for convo in conversations where !groupIds.contains(convo.peerPublicId) {
            let last = convo.lastMessage
            byPeer[convo.peerPublicId] = ChatListRow(
                peerPublicId: convo.peerPublicId,
                preview: previewText(last),
                timestamp: last?.createdAt,
                unreadHint: false)
        }

        for contact in mutualContacts where byPeer[contact.publicId] == nil && !groupIds.contains(contact.publicId) {
            byPeer[contact.publicId] = ChatListRow(
                peerPublicId: contact.publicId,
                preview: "Tap to start chatting",
                timestamp: nil,
                unreadHint: false)
        }

        return byPeer.values.sorted { lhs, rhs in
            switch (lhs.timestamp, rhs.timestamp) {
            case let (l?, r?): return l > r
            case (_?, nil): return true
            case (nil, _?): return false
            case (nil, nil): return lhs.peerPublicId < rhs.peerPublicId
            }
        }
    }

    private static func previewText(_ message: ChatMessage?) -> String {
        guard let message else { return "No messages yet" }
        let prefix = message.isMine ? "You: " : ""
        switch message.mediaKind {
        case "image":
            let caption = message.body.isEmpty ? "Photo" : "Photo · \(message.body)"
            return prefix + caption
        case "video":
            let caption = message.body.isEmpty ? "Video" : "Video · \(message.body)"
            return prefix + caption
        case "voice":
            return prefix + "Voice message"
        case "sticker":
            return prefix + "Sticker"
        default:
            return prefix + message.body
        }
    }
}
