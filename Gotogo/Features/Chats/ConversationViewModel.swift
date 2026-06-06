//
//  ConversationViewModel.swift
//  Gotogo
//
//  Backs a single conversation: loads cached history, sends text (encrypt + post),
//  and exposes messages for display. Reads live updates from `AppState`.
//

import Foundation
import Observation

@MainActor
@Observable
final class ConversationViewModel: MediaLoading {

    let peerPublicId: String
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

    private let messaging: MessagingService

    init(peerPublicId: String, messaging: MessagingService) {
        self.peerPublicId = peerPublicId
        self.messaging = messaging
        reload()
    }

    /// Reloads messages for this peer from the cache (after sync/realtime ticks).
    func reload() {
        messages = messaging.conversation(with: peerPublicId).messages
    }

    /// Removes a message from THIS device only ("delete for me"), then reloads.
    func deleteForMe(_ message: ChatMessage) {
        messaging.deleteMessageForMe(message)
        reload()
    }

    /// Removes one of MY OWN messages everywhere ("delete for everyone") — here, on
    /// the peer, and on my other devices — then reloads.
    func deleteForEveryone(_ message: ChatMessage) async {
        _ = await messaging.deleteMessageForEveryone(message)
        reload()
    }

    /// Pulls latest from the server, then reloads this conversation.
    func sync() async {
        do {
            _ = try await messaging.sync()
        } catch {
            // Non-fatal.
        }
        reload()
    }

    /// Sends the current draft (encrypt + post), appends locally, clears the draft.
    func send() async {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !sending else { return }
        sending = true
        let original = draft
        draft = ""
        do {
            _ = try await messaging.sendText(text, to: peerPublicId)
            reload()
        } catch {
            // Restore the draft so the user doesn't lose their text.
            draft = original
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Encrypts + sends a picked image (uses the current draft as a caption).
    func sendImage(_ imageData: Data) async {
        guard !sending else { return }
        sending = true
        let caption = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        draft = ""
        do {
            _ = try await messaging.sendImage(imageData, caption: caption.isEmpty ? nil : caption, to: peerPublicId)
            reload()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Encrypts + sends a picked video (uses the current draft as a caption). The
    /// size gate lives in `MessagingService.sendVideo`; if the video is too large it
    /// throws and we surface the error WITHOUT sending or clearing the draft.
    func sendVideo(_ videoData: Data) async {
        guard !sending else { return }
        sending = true
        let caption = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            _ = try await messaging.sendVideo(videoData, caption: caption.isEmpty ? nil : caption, to: peerPublicId)
            draft = ""
            reload()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Encrypts + sends a recorded voice note (m4a) of the given duration.
    func sendVoice(_ audioData: Data, durationMs: Int) async {
        guard !sending else { return }
        sending = true
        do {
            _ = try await messaging.sendVoice(audioData, durationMs: durationMs, to: peerPublicId)
            reload()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Sends an internal sticker by its catalog id (e.g. "reactions/heart").
    func sendSticker(_ stickerId: String) async {
        guard !sending else { return }
        sending = true
        do {
            _ = try await messaging.sendSticker(stickerId, to: peerPublicId)
            reload()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        sending = false
    }

    /// Downloads + decrypts a media attachment's thumbnail (falls back to the full
    /// blob if there is no thumbnail). Returns nil on failure.
    func loadThumbnail(_ ref: MediaReference) async -> Data? {
        messaging.syncMediaToken()
        if let thumb = try? await messaging.media.downloadThumbnail(ref) { return thumb }
        return try? await messaging.media.download(ref)
    }

    /// Downloads + decrypts the full media blob (image or audio). Returns nil on failure.
    func loadFull(_ ref: MediaReference) async -> Data? {
        messaging.syncMediaToken()
        return try? await messaging.media.download(ref)
    }
}
