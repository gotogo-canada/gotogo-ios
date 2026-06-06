//
//  MessagingService.swift
//  Gotogo
//
//  UI-free messaging core: contact management, sending (seal -> post), receiving
//  (sync + realtime -> open), and an on-disk conversation cache. Foundation +
//  CryptoKit only. Decryption uses the locally persisted identity + prekey store.
//

import Foundation

/// Errors specific to messaging.
public enum MessagingError: Error, Sendable, LocalizedError, Equatable {
    case notSignedIn
    case missingKeyMaterial
    case userNotFound
    case notMutualContact
    case blocked
    /// A media attachment exceeded its allowed size (carries the limit, in bytes).
    case mediaTooLarge(maxBytes: Int)
    /// A group membership change couldn't be ordered: the server-side commit
    /// register kept rejecting our compare-and-swap (we lost every race within the
    /// retry budget). The caller may retry after syncing.
    case commitOrderingUnavailable
    /// Only a group's admin (owner) may perform this action (e.g. rename / set photo).
    case notGroupAdmin

    public var errorDescription: String? {
        switch self {
        case .notSignedIn: return "You are not signed in."
        case .missingKeyMaterial: return "Local key material is missing."
        case .userNotFound: return "No user with that ID."
        case .notMutualContact: return "You are not connected with this contact yet."
        case .blocked: return "You can't message this contact because one of you has blocked the other."
        case .mediaTooLarge(let maxBytes):
            let mb = maxBytes / (1024 * 1024)
            return "Video too large (max \(mb) MB)"
        case .commitOrderingUnavailable:
            return "Couldn't order the group change right now. Please try again."
        case .notGroupAdmin:
            return "Only the group owner can change the group's name or photo."
        }
    }
}

/// Core messaging service. `@MainActor` (the module default); its `async` methods
/// suspend on `await`, so network/crypto work does not block the UI thread.
/// Construct with an `APIClient`, a `CryptoEngine`, a `SecretStoring` (for
/// identity/prekeys), and an optional `RealtimeClient` + cache URL. An XCTest
/// drives it from a `@MainActor` test with an in-memory store + test URL.
@MainActor
public final class MessagingService {

    private let realtime: RealtimeClient
    /// Uploads/downloads end-to-end-encrypted media blobs. Its bearer token is
    /// refreshed from the session store before each transfer (see `syncMediaToken`).
    let media: MediaService

    // Accessed by the `MessagingService+Cache` / `+PreKeys` extensions (same
    // module, internal).
    let api: APIClient
    let engine: CryptoEngine
    let store: SecretStoring
    /// On-disk conversation cache, keyed by peer public id.
    let cacheURL: URL
    /// Seals/opens the conversation cache at rest (AES-GCM under the device-only
    /// Keychain cache key), so plaintext messages never touch the file system in
    /// the clear. Ratchet session state is sealed separately with the same cache key.
    let cipher: EncryptedFileStore
    let cacheLock = NSLock()
    var conversations: [String: Conversation] = [:]
    /// Envelope ids already decoded this session. A message is delivered via BOTH the
    /// realtime socket (push-only) AND the durable `/sync`, so without this an envelope
    /// would be fed to the ratchet TWICE, burning message keys and cascading into
    /// spurious "[Unable to decrypt message]". In-memory is enough: `/sync` marks an
    /// envelope delivered, so the server never re-delivers it across app launches.
    var processedEnvelopeIds: Set<String> = []
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()

    /// The native 1:1 ratchet-session store, built lazily from the current cache
    /// URL. Backed by an AES-GCM-sealed JSON file.
    var _ratchets: RatchetSessionStore?

    /// Optional sink for group control/transport messages that ride the pairwise
    /// channel. When a decrypted inbound 1:1 plaintext is a `"group_*"`
    /// `MessageContent`, `ingest` routes it here (with the sender's public id)
    /// instead of materializing a 1:1 `ChatMessage`. `GroupService` installs this
    /// so it can ingest sender-key setups, group messages, and rekeys. Returns
    /// nothing; the handler updates its own group state + caches.
    var groupHandler: ((MessageContent, String) -> Void)?

    /// Notified (with the gone account's public id) when an `account_deleted`
    /// system event is ingested, so `AppState` can drop that id from its
    /// contacts/conversations/profile cache. The local conversation + ratchet
    /// sessions for that peer are already purged before this fires.
    var accountDeletedHandler: ((String) -> Void)?

    /// Notified (with the sender's public id) when a `profile_updated` control is
    /// ingested, so `AppState` can re-fetch + re-decrypt that contact's private
    /// profile (name/photo). The new grant + encrypted profile are already on the
    /// server; this is just the "it changed, refresh it" ping.
    var profileUpdatedHandler: ((String) -> Void)?

    /// Public ids whose `account_deleted` system event we have processed this
    /// session. Lets a caller (or a test) confirm a deletion was handled even if
    /// no handler was installed at ingest time. Written by `handleSystem` (in the
    /// `+Cache` extension), read by callers.
    var deletedAccountIds: Set<String> = []

    /// Installs (or clears) the group control-message handler. Called by
    /// `GroupService` so inbound `group_setup` / `group_msg` / `group_rekey`
    /// pairwise messages are dispatched to it during `sync()` / realtime ingest.
    func setGroupHandler(_ handler: ((MessageContent, String) -> Void)?) {
        self.groupHandler = handler
    }

    /// Installs (or clears) the handler invoked when a peer's `account_deleted`
    /// system event is ingested. `AppState` wires this to refresh its published
    /// contacts/conversations and drop the deleted peer's cached profile.
    func setAccountDeletedHandler(_ handler: ((String) -> Void)?) {
        self.accountDeletedHandler = handler
    }

    /// Installs (or clears) the handler invoked when a peer's `profile_updated`
    /// control is ingested. `AppState` wires this to refresh the peer's cached
    /// profile so the new name/photo appears without a relaunch.
    func setProfileUpdatedHandler(_ handler: ((String) -> Void)?) {
        self.profileUpdatedHandler = handler
    }

    /// Sends an already-built `MessageContent` over the pairwise channel to a
    /// single peer (fanning out to all of their devices). Used by `GroupService`
    /// to ship `group_setup` / `group_msg` / `group_rekey` control messages, which
    /// are therefore pairwise-E2EE exactly like ordinary 1:1 messages. Returns the
    /// first device's receipt. Does NOT append anything to the 1:1 conversation
    /// cache (group state lives in the `GroupStore`).
    @discardableResult
    func sendControl(_ content: MessageContent, to peerPublicId: String) async throws -> SendMessageResponse {
        try await sealAndSend(content, contentType: "group", to: peerPublicId)
    }

    /// Tells each given contact (over the pairwise E2EE channel) that my private
    /// profile changed, so they re-fetch it. Best-effort per contact: failing to
    /// reach one (e.g. no session yet) doesn't block the others. No profile data is
    /// sent — only the ping; the name/photo stay sealed behind the per-contact grant.
    func broadcastProfileUpdate(to contactIds: [String]) async {
        for contactId in contactIds {
            _ = try? await sendControl(.profileUpdated(), to: contactId)
        }
    }

    init(api: APIClient,
                engine: CryptoEngine,
                store: SecretStoring,
                realtime: RealtimeClient,
                cacheURL: URL? = nil,
                media: MediaService? = nil) {
        self.api = api
        self.engine = engine
        self.store = store
        self.realtime = realtime
        // Default to a media service pointed at the same backend; its token is
        // primed below and refreshed before each transfer from the session store.
        self.media = media ?? MediaService(baseURL: AppEnvironment.current.apiBaseURL,
                                           token: store.loadSession()?.token)
        self.cipher = EncryptedFileStore(store: store)
        let resolvedCache = cacheURL ?? Self.defaultCacheURL()
        self.cacheURL = resolvedCache
        loadCache()
    }

    /// Refreshes the media service's bearer token from the current session so
    /// uploads/downloads stay authenticated even when the session is adopted or
    /// recovered after this service was constructed.
    func syncMediaToken() {
        media.setToken(store.loadSession()?.token)
    }

    // MARK: - Contacts

    /// Returns the current contact list from the server.
    func contacts() async throws -> [Contact] {
        let response = try await api.listContacts()
        return response.contacts.map {
            Contact(publicId: $0.publicId,
                    state: ContactState(from: $0.state),
                    direction: ContactDirection(rawValue: $0.direction) ?? .outgoing)
        }
    }

    /// Sends a contact request, first verifying the target user exists. Standard
    /// prekeys are uploaded at registration/recovery/device-link time.
    func requestContact(publicId: String) async throws {
        let lookup = try await api.lookupUser(publicId: publicId)
        guard lookup.exists else { throw MessagingError.userNotFound }
        _ = try await api.requestContact(toPublicId: publicId)
    }

    /// Accepts an incoming contact request.
    func acceptContact(fromPublicId: String) async throws {
        _ = try await api.acceptContact(fromPublicId: fromPublicId)
    }

    /// Looks up whether a user exists / has a device.
    func lookupUser(publicId: String) async throws -> UserLookupResponse {
        try await api.lookupUser(publicId: publicId)
    }

    // MARK: - Blocking & reporting

    /// Blocks a user (bidirectional). Returns the new blocked state.
    @discardableResult
    func block(publicId: String) async throws -> Bool {
        try await api.blockContact(publicId: publicId)
    }

    /// Unblocks a previously blocked user. Returns the new blocked state.
    @discardableResult
    func unblock(publicId: String) async throws -> Bool {
        try await api.unblockContact(publicId: publicId)
    }

    /// The public ids this account has blocked.
    func blocks() async throws -> [String] {
        try await api.listBlocks()
    }

    /// Reports a user for abuse with a free-text reason.
    @discardableResult
    func report(publicId: String, reason: String) async throws -> Bool {
        try await api.reportUser(publicId: publicId, reason: reason)
    }

    // MARK: - Sending

    /// Encrypts and sends `text` to `peerPublicId`. Appends the sent message to
    /// the local conversation and returns it. Throws `notMutualContact` if the
    /// server rejects because the contact is not accepted yet.
    @discardableResult
    func sendText(_ text: String, to peerPublicId: String) async throws -> ChatMessage {
        let clientId = UUID().uuidString
        var content = MessageContent.text(text)
        content.clientId = clientId
        let response = try await sealAndSend(content, contentType: "text", to: peerPublicId)
        let message = ChatMessage(id: response.messageId,
                                  peerPublicId: peerPublicId,
                                  isMine: true,
                                  body: text,
                                  createdAt: response.createdAt,
                                  clientId: clientId)
        append(message, to: peerPublicId)
        return message
    }

    // MARK: - Media upload helpers (shared by 1:1 and group send)

    /// Metadata-strips + thumbnails + chunk-encrypts an image and uploads it,
    /// returning its `MediaReference`. Refreshes the media token first.
    func uploadImageMedia(_ imageData: Data) async throws -> MediaReference {
        syncMediaToken()
        return try await media.uploadImage(imageData)
    }

    /// Size-gates a video against `MediaLimits.maxVideoBytes` (throws
    /// `MessagingError.mediaTooLarge` BEFORE any upload), then chunk-encrypts +
    /// uploads it, returning its `MediaReference`.
    func uploadVideoMedia(_ data: Data) async throws -> MediaReference {
        guard data.count <= MediaLimits.maxVideoBytes else {
            throw MessagingError.mediaTooLarge(maxBytes: MediaLimits.maxVideoBytes)
        }
        syncMediaToken()
        return try await media.uploadData(data, contentType: "video/mp4")
    }

    /// Encrypts an image end to end and sends it. The image is metadata-stripped,
    /// thumbnailed, and chunk-encrypted by `MediaService`; the resulting
    /// `MediaReference` (with the per-file key) travels INSIDE the E2EE plaintext.
    /// Appends a local image message and returns it.
    @discardableResult
    func sendImage(_ imageData: Data, caption: String?, to peerPublicId: String) async throws -> ChatMessage {
        let ref = try await uploadImageMedia(imageData)
        let clientId = UUID().uuidString
        var content = MessageContent.image(ref, caption: caption)
        content.clientId = clientId
        let response = try await sealAndSend(content, contentType: "media", to: peerPublicId)
        let message = ChatMessage(id: response.messageId,
                                  peerPublicId: peerPublicId,
                                  isMine: true,
                                  body: content.text ?? "",
                                  createdAt: response.createdAt,
                                  media: ref,
                                  mediaKind: "image",
                                  clientId: clientId)
        append(message, to: peerPublicId)
        return message
    }

    /// Encrypts a voice note (m4a) end to end and sends it. The audio is
    /// chunk-encrypted by `MediaService`; its `MediaReference` rides inside the
    /// E2EE plaintext. Appends a local voice message and returns it.
    @discardableResult
    func sendVoice(_ audioData: Data, durationMs: Int, to peerPublicId: String) async throws -> ChatMessage {
        syncMediaToken()
        let ref = try await media.uploadData(audioData, contentType: "audio/m4a")
        let clientId = UUID().uuidString
        var content = MessageContent.voice(ref, durationMs: durationMs)
        content.clientId = clientId
        let response = try await sealAndSend(content, contentType: "media", to: peerPublicId)
        let message = ChatMessage(id: response.messageId,
                                  peerPublicId: peerPublicId,
                                  isMine: true,
                                  body: "",
                                  createdAt: response.createdAt,
                                  media: ref,
                                  mediaKind: "voice",
                                  durationMs: durationMs,
                                  clientId: clientId)
        append(message, to: peerPublicId)
        return message
    }

    /// Encrypts a video (mp4) end to end and sends it, mirroring `sendImage`. The
    /// video is gated against `MediaLimits.maxVideoBytes` BEFORE any upload: an
    /// oversized video throws `MessagingError.mediaTooLarge` and posts nothing.
    /// Under the cap, the bytes are chunk-encrypted by `MediaService`; the resulting
    /// `MediaReference` (with the per-file key) travels INSIDE the E2EE plaintext.
    /// Appends a local video message and returns it.
    @discardableResult
    func sendVideo(_ data: Data, caption: String? = nil, to peerPublicId: String) async throws -> ChatMessage {
        let ref = try await uploadVideoMedia(data)
        let clientId = UUID().uuidString
        var content = MessageContent.video(ref, caption: caption)
        content.clientId = clientId
        let response = try await sealAndSend(content, contentType: "media", to: peerPublicId)
        let message = ChatMessage(id: response.messageId,
                                  peerPublicId: peerPublicId,
                                  isMine: true,
                                  body: content.text ?? "",
                                  createdAt: response.createdAt,
                                  media: ref,
                                  mediaKind: "video",
                                  clientId: clientId)
        append(message, to: peerPublicId)
        return message
    }

    /// Sends an internal sticker (a catalog id like "reactions/heart") end to end
    /// through the same encrypt + fan-out path. The sticker id rides inside the
    /// E2EE payload; the receiver renders it from the bundled `StickerCatalog`.
    /// Appends a local sticker message and returns it.
    @discardableResult
    func sendSticker(_ stickerId: String, to peerPublicId: String) async throws -> ChatMessage {
        let clientId = UUID().uuidString
        var content = MessageContent.sticker(stickerId)
        content.clientId = clientId
        let response = try await sealAndSend(content, contentType: "sticker", to: peerPublicId)
        let message = ChatMessage(id: response.messageId,
                                  peerPublicId: peerPublicId,
                                  isMine: true,
                                  body: "",
                                  createdAt: response.createdAt,
                                  mediaKind: "sticker",
                                  stickerId: stickerId,
                                  clientId: clientId)
        append(message, to: peerPublicId)
        return message
    }

    /// Ratchet-encrypts a `MessageContent` (JSON-encoded) and fans it out to EVERY
    /// device the recipient currently publishes, one `/v1/messages` POST per device
    /// (each on its own Triple Ratchet session keyed by `(peer, deviceId)`). Shared
    /// by `sendText`/`sendImage`/`sendVideo`/`sendVoice`/`sendSticker`. Returns the
    /// FIRST device's receipt, used to stamp the single local `ChatMessage`.
    private func sealAndSend(_ content: MessageContent,
                             contentType: String,
                             to peerPublicId: String) async throws -> SendMessageResponse {
        let plaintext = try encoder.encode(content)

        // 1. Fetch every active recipient device and its published standard
        //    prekey bundle. Empty => userNotFound.
        let devices = try await ratchetDevices(for: peerPublicId)

        // 2. Encrypt + POST one ratchet ciphertext per device.
        var firstReceipt: SendMessageResponse?
        for bundle in devices {
            let receipt = try await ratchetPost(plaintext,
                                                contentType: contentType,
                                                to: peerPublicId,
                                                bundle: bundle)
            if firstReceipt == nil { firstReceipt = receipt }
        }
        guard let receipt = firstReceipt else { throw MessagingError.userNotFound }

        // 3. Self-device sync: mirror the SAME content to my OWN other devices so
        //    every device I own keeps an identical history. The mirrored copy tags
        //    `syncPeer` with the recipient so the receiving device files it under the
        //    right conversation as `isMine`. Group control messages are not mirrored
        //    (the group layer reconciles its own state). Best-effort: never let a
        //    self-sync failure (e.g. a single offline device) fail the user's send.
        if contentType != "group" {
            try? await fanOutSelfSync(of: content, recipient: peerPublicId)
        }
        return receipt
    }

    /// Mirrors `content` (re-tagged with `syncPeer = recipient`) to every OTHER
    /// device on MY account, one ratchet-encrypted POST per device over a
    /// `(myPublicId|deviceId)` session. Skips my own current device. No-op when I
    /// only have one device. Throws are swallowed by the caller (best-effort).
    private func fanOutSelfSync(of content: MessageContent, recipient: String) async throws {
        guard let mySession = store.loadSession() else { return }
        var synced = content
        synced.syncPeer = recipient
        let plaintext = try encoder.encode(synced)
        let myDevices = (try? await ratchetDevices(for: mySession.publicId)) ?? []
        for bundle in myDevices where bundle.deviceId != mySession.deviceId {
            _ = try? await ratchetPost(plaintext, contentType: "sync",
                                       to: mySession.publicId, bundle: bundle)
        }
    }

    /// Fans a GROUP control envelope (Welcome / Commit / app message) out to every
    /// OTHER device on MY account — each is its own MLS leaf — so my own devices
    /// converge on the same group state. Unlike `fanOutSelfSync` this does NOT
    /// re-tag `syncPeer` (group messages route by their `group_*` type, and the
    /// receiving device treats one from my own public id as `isMine`). Best-effort.
    func sendGroupControlToOwnDevices(_ content: MessageContent) async throws {
        guard let mySession = store.loadSession() else { return }
        let plaintext = try encoder.encode(content)
        let myDevices = (try? await ratchetDevices(for: mySession.publicId)) ?? []
        for bundle in myDevices where bundle.deviceId != mySession.deviceId {
            _ = try? await ratchetPost(plaintext, contentType: "group",
                                       to: mySession.publicId, bundle: bundle)
        }
    }

    // MARK: - Deletion ("delete for everyone" / "delete conversation")

    /// Deletes a 1:1 conversation: sends a pairwise-E2EE `delete_conversation`
    /// control (which removes MY messages from the peer's copy and, mirrored to my
    /// own other devices, drops the whole thread there), then removes the thread —
    /// messages AND ratchet sessions — on this device. Transport is best-effort;
    /// the local removal always happens.
    func deleteConversation(_ peerPublicId: String) async {
        _ = try? await sealAndSend(.deleteConversation(), contentType: "control", to: peerPublicId)
        removeConversation(peerPublicId)
    }

    /// "Delete for everyone": removes one of MY OWN messages everywhere — here, on
    /// the peer, and on my other devices — keyed by its stable `clientId`. Returns
    /// false (no-op) for a received message or one without a `clientId`.
    @discardableResult
    func deleteMessageForEveryone(_ message: ChatMessage) async -> Bool {
        guard message.isMine, let clientId = message.clientId else { return false }
        _ = try? await sealAndSend(.deleteMessages([clientId]),
                                   contentType: "control", to: message.peerPublicId)
        removeMessage(clientId: clientId, in: message.peerPublicId)
        return true
    }

    /// "Delete for me": removes a message (any message) from THIS device only.
    func deleteMessageForMe(_ message: ChatMessage) {
        removeMessageLocally(id: message.id, in: message.peerPublicId)
    }


    // MARK: - Receiving

    /// Pulls new messages from the server, decrypts them, stores them, and
    /// returns the freshly received (decoded) messages. Opportunistically tops up
    /// the server's one-time-prekey pool afterwards (best-effort; errors swallowed).
    @discardableResult
    func sync(limit: Int = 100) async throws -> [ChatMessage] {
        let response = try await api.sync(limit: limit)
        let produced = ingest(response.messages)
        try? await replenishPreKeysIfNeeded()
        return produced
    }

    /// Opens the realtime socket using the current session token and streams
    /// decoded inbound messages as they arrive. Each yielded message is also
    /// appended to the local conversation cache.
    func realtimeMessages() throws -> AsyncStream<ChatMessage> {
        guard let session = store.loadSession() else { throw MessagingError.notSignedIn }
        let inbound = realtime.connect(token: session.token)
        return AsyncStream { continuation in
            let task = Task { [weak self] in
                for await raw in inbound {
                    guard let self else { break }
                    if let decoded = self.ingest([raw]).first {
                        continuation.yield(decoded)
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Stops the realtime socket.
    func stopRealtime() { realtime.stop() }

    // MARK: - Conversation access

    /// Returns the cached conversation for a peer (creating an empty one).
    func conversation(with peerPublicId: String) -> Conversation {
        cacheLock.lock(); defer { cacheLock.unlock() }
        return conversations[peerPublicId] ?? Conversation(peerPublicId: peerPublicId)
    }

    /// Returns all cached conversations, most-recent first.
    func allConversations() -> [Conversation] {
        cacheLock.lock(); defer { cacheLock.unlock() }
        return conversations.values.sorted {
            ($0.lastMessage?.createdAt ?? .distantPast) > ($1.lastMessage?.createdAt ?? .distantPast)
        }
    }

    /// Clears the local conversation cache and ratchet session state (used on
    /// logout) so no local trace of past conversations remains.
    func clearCache() {
        cacheLock.lock()
        conversations = [:]
        processedEnvelopeIds = []
        cacheLock.unlock()
        try? FileManager.default.removeItem(at: cacheURL)
        _ratchets?.clear()
    }

}
