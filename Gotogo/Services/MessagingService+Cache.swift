//
//  MessagingService+Cache.swift
//  Gotogo
//
//  Decryption of inbound messages and the on-disk conversation cache, split out
//  of `MessagingService` to keep each file focused. Foundation + CryptoKit.
//

import Foundation

extension MessagingService {

    // MARK: - Decryption

    /// The outcome of decoding one inbound message.
    private enum DecodeResult {
        /// A normal 1:1 message to append under the SENDER's public id and surface.
        case message(ChatMessage)
        /// A message already filed into the right conversation (self-device sync),
        /// surfaced to `sync()`'s caller but NOT re-appended by the outer loop.
        case filed(ChatMessage)
        /// Consumed internally (group control, or an `account_deleted` system event);
        /// nothing to surface.
        case consumed
    }

    /// Decrypts a batch of inbound messages, appends them to the cache, and
    /// returns the resulting `ChatMessage`s (in input order). Inbound 1:1
    /// plaintexts that turn out to be group control/transport messages
    /// (`"group_*"`) or server `account_deleted` system events are consumed (routed
    /// to their handlers) and DO NOT materialize a 1:1 `ChatMessage`. Messages from
    /// MY OWN other devices (self-device sync) are filed into the recipient's
    /// conversation as `isMine` and surfaced.
    func ingest(_ inbound: [InboundMessage]) -> [ChatMessage] {
        guard let identity = store.loadIdentity(),
              let preKeyStore = store.loadPreKeyStore() else { return [] }

        var produced: [ChatMessage] = []
        for raw in inbound {
            // Decode each envelope id only ONCE. The same message is delivered via the
            // realtime socket AND the durable sync; feeding the ratchet a ciphertext
            // twice burns message keys and can desync the session — the cause of
            // spurious "[Unable to decrypt message]" bubbles.
            guard processedEnvelopeIds.insert(raw.id).inserted else { continue }
            switch decode(raw, identity: identity, preKeyStore: preKeyStore) {
            case .message(let message):
                append(message, to: raw.senderAddress)
                produced.append(message)
            case .filed(let message):
                // Self-sync: already appended to `conversation(syncPeer)` in decode.
                produced.append(message)
            case .consumed:
                continue
            }
        }
        return produced
    }

    /// Decrypts one inbound message into a `DecodeResult`. Branches on a `"system"`
    /// control message (plaintext JSON, e.g. `account_deleted`) BEFORE attempting a
    /// ratchet decode; otherwise opens the ratchet envelope and classifies the
    /// plaintext as a group control message, a self-device-sync copy, or a normal
    /// 1:1 message.
    private func decode(_ raw: InboundMessage,
                        identity: IdentityKeyMaterial,
                        preKeyStore: PreKeyStore) -> DecodeResult {
        // Server control messages are NOT ratchet envelopes: their `ciphertext` is
        // plaintext JSON. Handle them first so we never try to ratchet-decode them.
        if raw.contentType == "system" {
            handleSystem(raw)
            return .consumed
        }
        do {
            let envelope = try decoder.decode(RatchetWireEnvelope.self, from: raw.ciphertext)
            let plaintext = try openRatchetEnvelope(envelope,
                                                    raw: raw,
                                                    identity: identity,
                                                    preKeyStore: preKeyStore)
            let content = try? decoder.decode(MessageContent.self, from: plaintext)

            // Deletion controls ("delete for everyone" / "delete conversation") ride
            // the pairwise channel: apply them to the cache and never surface a chat
            // message. Checked before group/self-sync so a mirrored self-copy is also
            // applied (and not filed as a message).
            if let content, content.type == "delete_message" || content.type == "delete_conversation" {
                handleDeleteControl(content, raw: raw)
                return .consumed
            }

            // A contact re-published its private profile: trigger a re-fetch (the new
            // grant + encrypted profile are already on the server). Never surfaced as
            // a chat message.
            if let content, content.type == "profile_updated" {
                profileUpdatedHandler?(raw.senderAddress)
                return .consumed
            }

            // Group control/transport messages ride the pairwise channel: hand them
            // to the group handler and don't surface them as a 1:1 chat message.
            if let handler = groupHandler,
               let content, content.type.hasPrefix("group_") {
                handler(content, raw.senderAddress)
                return .consumed
            }

            // Self-device sync: a message from one of MY OWN devices. File its inner
            // content under the recipient (`syncPeer`) as `isMine`, not as a chat
            // from myself. Requires a syncPeer; without it we have nowhere to file it.
            if let mySession = store.loadSession(),
               raw.senderAddress == mySession.publicId,
               let content, let target = content.syncPeer {
                let mine = selfSyncMessage(from: content, target: target, raw: raw)
                append(mine, to: target)
                return .filed(mine)
            }

            // Sealed (sender-anonymous) message: the server stored NO sender, so
            // the real sender is carried inside the content. Route the conversation
            // by it, and apply client-side blocking — the server couldn't, because
            // it can't see a sealed sender (V2-C).
            if raw.senderAddress.isEmpty, let content, let sealedFrom = content.sealedSender {
                if SealedSender.shouldDrop(senderAddress: sealedFrom, blocked: blockedSealedSenders) {
                    return .consumed
                }
                return .message(ChatMessage(id: raw.id,
                                            peerPublicId: sealedFrom,
                                            isMine: false,
                                            body: content.text ?? "",
                                            createdAt: raw.createdAt))
            }

            return .message(chatMessage(from: plaintext, raw: raw))
        } catch {
            return .message(ChatMessage(id: raw.id,
                                        peerPublicId: raw.senderAddress,
                                        isMine: false,
                                        body: "[Unable to decrypt message]",
                                        createdAt: raw.createdAt,
                                        decrypted: false))
        }
    }

    /// Builds the `isMine` `ChatMessage` for a self-device-sync copy: the SAME inner
    /// content (text/image/voice/sticker) as the original send, filed under the
    /// recipient `target` so this device's history matches the sending device's.
    private func selfSyncMessage(from content: MessageContent,
                                 target: String,
                                 raw: InboundMessage) -> ChatMessage {
        var message: ChatMessage
        switch content.type {
        case "image":
            message = ChatMessage(id: raw.id, peerPublicId: target, isMine: true,
                                  body: content.text ?? "", createdAt: raw.createdAt,
                                  media: content.media, mediaKind: "image")
        case "video":
            message = ChatMessage(id: raw.id, peerPublicId: target, isMine: true,
                                  body: content.text ?? "", createdAt: raw.createdAt,
                                  media: content.media, mediaKind: "video")
        case "voice":
            message = ChatMessage(id: raw.id, peerPublicId: target, isMine: true,
                                  body: "", createdAt: raw.createdAt,
                                  media: content.media, mediaKind: "voice",
                                  durationMs: content.durationMs)
        case "sticker":
            message = ChatMessage(id: raw.id, peerPublicId: target, isMine: true,
                                  body: "", createdAt: raw.createdAt,
                                  mediaKind: "sticker", stickerId: content.stickerId)
        default: // "text"
            message = ChatMessage(id: raw.id, peerPublicId: target, isMine: true,
                                  body: content.text ?? "", createdAt: raw.createdAt)
        }
        // Same stable id the sending device used, so a later delete matches here too.
        message.clientId = content.clientId
        return message
    }

    /// Handles a `"system"` control message whose `ciphertext` is plaintext JSON.
    /// Currently recognizes `{"type":"account_deleted","publicId":"X"}`: removes X's
    /// local conversation + ratchet sessions and notifies the `accountDeletedHandler`
    /// so `AppState` can drop X from its contacts/conversations/profile cache.
    /// Unknown system types are ignored (no crash).
    private func handleSystem(_ raw: InboundMessage) {
        guard let event = try? decoder.decode(SystemEvent.self, from: raw.ciphertext) else { return }
        switch event.type {
        case "account_deleted":
            guard let gone = event.publicId else { return }
            removeConversation(gone)
            deletedAccountIds.insert(gone)
            accountDeletedHandler?(gone)
        default:
            break // unknown system event: ignore.
        }
    }

    /// Applies an inbound deletion control. The target conversation is resolved
    /// RELATIVE to this receiver: a control from the peer acts on the peer's thread
    /// (`raw.senderAddress`); a control mirrored from MY OWN other device carries the
    /// real peer in `syncPeer`. `delete_conversation` removes the deleter's messages
    /// on a peer's device, or the whole local thread on my own devices.
    /// `delete_message` removes the listed sender `clientId`s wherever they landed.
    private func handleDeleteControl(_ content: MessageContent, raw: InboundMessage) {
        let mine = store.loadSession()?.publicId
        let fromSelf = (mine != nil && raw.senderAddress == mine)
        let conversationId = fromSelf ? (content.syncPeer ?? "") : raw.senderAddress
        guard !conversationId.isEmpty else { return }

        switch content.type {
        case "delete_conversation":
            if fromSelf {
                removeConversation(conversationId)         // my device: drop the whole thread
            } else {
                removeIncomingMessages(in: conversationId) // peer: drop the deleter's messages, keep mine
            }
        case "delete_message":
            for clientId in (content.deleteIds ?? []) {
                removeMessage(clientId: clientId, in: conversationId)
            }
        default:
            break
        }
    }

    /// Builds an inbound `ChatMessage` from decrypted plaintext. The plaintext is
    /// a JSON-encoded `MessageContent`; for an image/voice content the resulting
    /// message carries the `MediaReference` + `mediaKind`. Falls back to treating
    /// the bytes as raw UTF-8 text if they are not a `MessageContent` (legacy).
    private func chatMessage(from plaintext: Data, raw: InboundMessage) -> ChatMessage {
        guard let content = try? decoder.decode(MessageContent.self, from: plaintext) else {
            // Legacy / non-JSON plaintext: treat as raw UTF-8 text.
            return ChatMessage(id: raw.id,
                               peerPublicId: raw.senderAddress,
                               isMine: false,
                               body: String(decoding: plaintext, as: UTF8.self),
                               createdAt: raw.createdAt)
        }
        var message: ChatMessage
        switch content.type {
        case "image":
            message = ChatMessage(id: raw.id, peerPublicId: raw.senderAddress, isMine: false,
                                  body: content.text ?? "", createdAt: raw.createdAt,
                                  media: content.media, mediaKind: "image")
        case "video":
            message = ChatMessage(id: raw.id, peerPublicId: raw.senderAddress, isMine: false,
                                  body: content.text ?? "", createdAt: raw.createdAt,
                                  media: content.media, mediaKind: "video")
        case "voice":
            message = ChatMessage(id: raw.id, peerPublicId: raw.senderAddress, isMine: false,
                                  body: "", createdAt: raw.createdAt,
                                  media: content.media, mediaKind: "voice", durationMs: content.durationMs)
        case "sticker":
            message = ChatMessage(id: raw.id, peerPublicId: raw.senderAddress, isMine: false,
                                  body: "", createdAt: raw.createdAt,
                                  mediaKind: "sticker", stickerId: content.stickerId)
        default: // "text"
            message = ChatMessage(id: raw.id, peerPublicId: raw.senderAddress, isMine: false,
                                  body: content.text ?? "", createdAt: raw.createdAt)
        }
        // Carry the sender's stable cross-device id so "delete for everyone" can
        // target this exact message here later.
        message.clientId = content.clientId
        return message
    }

    /// Decrypts one ratchet envelope, bootstrapping or advancing the session for
    /// the sending `(peerPublicId, fromDeviceId)` as needed. Throws if the message
    /// is undecryptable (no session for a `"msg"`, tampering, or a malformed
    /// envelope), which `decode` maps to a `decrypted == false` placeholder rather
    /// than crashing.
    // MARK: - Cache plumbing

    /// Removes a peer's conversation and every ratchet session keyed to
    /// that peer (all of its devices). Used when the peer's `account_deleted` system
    /// event arrives so no local trace of them remains.
    func removeConversation(_ peerPublicId: String) {
        cacheLock.lock()
        conversations[peerPublicId] = nil
        let convoSnapshot = conversations
        cacheLock.unlock()
        persist(convoSnapshot)
        _ratchets?.removeSessions(forPublicId: peerPublicId)
    }

    /// Appends a message to a peer's conversation (dedup by id) and persists.
    func append(_ message: ChatMessage, to peerPublicId: String) {
        cacheLock.lock()
        var convo = conversations[peerPublicId] ?? Conversation(peerPublicId: peerPublicId)
        if !convo.messages.contains(where: { $0.id == message.id }) {
            convo.messages.append(message)
            convo.messages.sort { $0.createdAt < $1.createdAt }
        }
        conversations[peerPublicId] = convo
        let snapshot = conversations
        cacheLock.unlock()
        persist(snapshot)
    }

    /// Removes every message carrying this sender `clientId` from a conversation —
    /// the "delete for everyone" primitive (applied on the recipient and the
    /// sender's own devices). Persists.
    func removeMessage(clientId: String, in peerPublicId: String) {
        removeMessages(in: peerPublicId) { $0.clientId == clientId }
    }

    /// Removes a single message by its LOCAL id — the "delete for me" primitive
    /// (this device only). Persists.
    func removeMessageLocally(id: String, in peerPublicId: String) {
        removeMessages(in: peerPublicId) { $0.id == id }
    }

    /// Removes the messages I RECEIVED in a conversation (the other party's),
    /// keeping my own — the peer-side effect of the other party "deleting the
    /// conversation". Persists.
    func removeIncomingMessages(in peerPublicId: String) {
        removeMessages(in: peerPublicId) { !$0.isMine }
    }

    /// Removes a GROUP message by sender `clientId`, but only if it was authored by
    /// `senderPublicId` — so a member's "delete for everyone" can only drop its own
    /// messages. Persists.
    func removeGroupMessage(clientId: String, from senderPublicId: String, in groupId: String) {
        removeMessages(in: groupId) { $0.clientId == clientId && $0.senderPublicId == senderPublicId }
    }

    /// Removes every GROUP message authored by `senderPublicId` — the effect of that
    /// member "deleting the conversation" (their footprint is cleared for everyone).
    /// Persists.
    func removeGroupMessages(from senderPublicId: String, in groupId: String) {
        removeMessages(in: groupId) { $0.senderPublicId == senderPublicId }
    }

    /// Removes messages matching `predicate` from a conversation, dropping the
    /// conversation entirely if it becomes empty. Persists.
    private func removeMessages(in peerPublicId: String, where predicate: (ChatMessage) -> Bool) {
        cacheLock.lock()
        guard var convo = conversations[peerPublicId] else { cacheLock.unlock(); return }
        convo.messages.removeAll(where: predicate)
        if convo.messages.isEmpty { conversations[peerPublicId] = nil }
        else { conversations[peerPublicId] = convo }
        let snapshot = conversations
        cacheLock.unlock()
        persist(snapshot)
    }

    /// Loads the persisted conversation cache into memory (called once at init).
    /// The on-disk file is AES-GCM ciphertext; an undecodable/legacy-plaintext file
    /// is tolerated by leaving the in-memory map empty.
    func loadCache() {
        guard let data = cipher.read(cacheURL),
              let list = try? decoder.decode([Conversation].self, from: data) else { return }
        cacheLock.lock()
        conversations = Dictionary(uniqueKeysWithValues: list.map { ($0.peerPublicId, $0) })
        cacheLock.unlock()
    }

    private func persist(_ snapshot: [String: Conversation]) {
        guard let data = try? encoder.encode(Array(snapshot.values)) else { return }
        try? cipher.write(data, to: cacheURL)
    }

    static func defaultCacheURL() -> URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory,
                                           in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("gotogo-conversations.json")
    }
}
