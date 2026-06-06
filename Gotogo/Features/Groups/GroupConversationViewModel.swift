//
//  GroupConversationViewModel.swift
//  Gotogo
//
//  Backs a single GROUP conversation: loads cached history (keyed by group id),
//  sends group text / media (photo, video) / stickers via `GroupService`
//  (MLS-encrypt + pairwise fan-out), and exposes messages for display. Conforms to
//  `MediaLoading` so the shared media bubbles can download+decrypt attachments.
//  Reflects live updates from `AppState.conversations`.
//

import Foundation
import Observation

@MainActor
@Observable
final class GroupConversationViewModel: MediaLoading {

    let groupId: String
    private(set) var messages: [ChatMessage] = []
    private(set) var sending = false
    var draft: String = ""
    var errorMessage: String?

    /// How many of the most-recent messages the conversation renders. Older ones
    /// stay in the on-device encrypted cache and are revealed on demand ("Load
    /// earlier messages"), so opening a long thread doesn't build thousands of rows
    /// at once. (History is local-only; the server keeps nothing once delivered.)
    private(set) var windowLimit = 50
    private let pageSize = 50

    /// The most-recent `windowLimit` messages — what the list actually renders.
    var windowed: [ChatMessage] {
        messages.count <= windowLimit ? messages : Array(messages.suffix(windowLimit))
    }

    /// Whether older messages exist beyond the current window.
    var hasOlder: Bool { messages.count > windowLimit }

    /// Reveals one older page (called by "Load earlier messages").
    func loadOlder() { windowLimit = min(windowLimit + pageSize, messages.count) }

    private let groups: GroupService

    init(groupId: String, groups: GroupService) {
        self.groupId = groupId
        self.groups = groups
        reload()
    }

    /// Reloads messages for this group from the cache.
    func reload() {
        messages = groups.conversation(groupId).messages
    }

    /// Removes a group message from THIS device only ("delete for me").
    func deleteForMe(_ message: ChatMessage) {
        groups.deleteGroupMessageForMe(message)
        reload()
    }

    /// Removes one of MY OWN group messages on every member ("delete for everyone").
    func deleteForEveryone(_ message: ChatMessage) async {
        _ = await groups.deleteGroupMessageForEveryone(message)
        reload()
    }

    /// Pulls latest (group control + messages) and reloads this conversation.
    func sync() async {
        _ = try? await groups.sync()
        reload()
    }

    /// Sends the current draft as a group message, then clears it.
    func send() async {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !sending else { return }
        sending = true
        let original = draft
        draft = ""
        do {
            _ = try await groups.sendGroupText(text, to: groupId)
            reload()
        } catch {
            draft = original
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Sends an internal sticker by its catalog id (e.g. "reactions/heart").
    func sendSticker(_ stickerId: String) async {
        guard !sending else { return }
        sending = true
        do {
            _ = try await groups.sendGroupSticker(stickerId, to: groupId)
            reload()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Encrypts + sends a picked image to the group (uses the current draft as a
    /// caption). Clears the draft up front since an image send rarely fails on size.
    func sendImage(_ imageData: Data) async {
        guard !sending else { return }
        sending = true
        let caption = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        draft = ""
        do {
            _ = try await groups.sendGroupImage(imageData, caption: caption.isEmpty ? nil : caption, to: groupId)
            reload()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Encrypts + sends a picked video to the group (uses the current draft as a
    /// caption). The 25 MB size gate lives in `GroupService.sendGroupVideo`; on an
    /// oversize error we surface it WITHOUT clearing the draft.
    func sendVideo(_ videoData: Data) async {
        guard !sending else { return }
        sending = true
        let caption = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            _ = try await groups.sendGroupVideo(videoData, caption: caption.isEmpty ? nil : caption, to: groupId)
            draft = ""
            reload()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    // MARK: - MediaLoading (download + decrypt for the media bubbles)

    func loadThumbnail(_ ref: MediaReference) async -> Data? { await groups.loadThumbnail(ref) }
    func loadFull(_ ref: MediaReference) async -> Data? { await groups.loadFull(ref) }
}
