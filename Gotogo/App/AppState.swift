//
//  AppState.swift
//  Gotogo
//
//  Root app state: owns the wiring of API/crypto/secret-store/realtime into the
//  two services, tracks the current session, and exposes high-level actions the
//  UI binds to. `@MainActor @Observable`.
//

import Foundation
import SwiftUI

/// Top-level observable application state. Holds the services and the session.
@MainActor
@Observable
final class AppState {

    /// The current authenticated session (nil = not registered).
    private(set) var session: Session?

    /// Live safety number for the local identity (self-comparison), shown in Me.
    private(set) var identityFingerprint: String = ""

    /// Cached conversations, kept in sync with the messaging service for the UI.
    private(set) var conversations: [Conversation] = []

    /// Latest contact list from the server.
    private(set) var contacts: [Contact] = []

    /// Public ids this account has blocked (drives the Me > Blocked list and the
    /// Block/Unblock toggle in conversations). Refreshed from `GET /v1/blocks`.
    private(set) var blockedIds: Set<String> = []

    /// Whether the realtime socket is currently believed to be connected.
    private(set) var isRealtimeConnected = false

    /// Background task consuming the realtime message stream.
    private var realtimeTask: Task<Void, Never>?

    /// Decrypted group list for the Groups tab, refreshed from the backend.
    private(set) var groups: [GroupInfo] = []

    /// The core services. Exposed so view models can call them.
    let auth: AuthService
    let messaging: MessagingService
    let profiles: ProfileService
    /// Group messaging with Signal Sender Keys, layered over `messaging`.
    let groupService: GroupService
    /// Verifies peers' identity keys against the RFC 6962 key-transparency log.
    let transparency: TransparencyService

    /// Observable cache of decrypted contact/owner profiles for the UI.
    let profileStore: ProfileStore

    /// The shared crypto engine (used for safety numbers in the UI).
    private let engine: CryptoEngine
    private let secretStore: SecretStoring

    init() {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: AppEnvironment.current.apiBaseURL)
        let store = KeychainSecretStore()
        let realtime = RealtimeClient(baseURL: AppEnvironment.current.webSocketBaseURL)

        self.engine = engine
        self.secretStore = store
        self.auth = AuthService(api: api, engine: engine, store: store)
        let messaging = MessagingService(api: api, engine: engine, store: store, realtime: realtime)
        self.messaging = messaging
        let profiles = ProfileService(api: api, engine: engine, store: store)
        self.profiles = profiles
        // Group messaging state persists alongside the messaging cache (cleared on
        // logout) and resolves "me" from the persisted session.
        let groupStore = GroupStore(cacheURL: messaging.cacheURL, cipher: messaging.cipher)
        let mlsKeyPackages = MLSKeyPackageStore(cacheURL: messaging.cacheURL, cipher: messaging.cipher)
        self.groupService = GroupService(messaging: messaging, store: groupStore,
                                         keyPackages: mlsKeyPackages,
                                         myPublicId: { store.loadSession()?.publicId },
                                         myDeviceId: { store.loadSession()?.deviceId })
        self.transparency = TransparencyService(api: api, engine: engine, store: store)
        self.profileStore = ProfileStore(service: profiles)

        // When a peer deletes their account, the messaging layer purges their local
        // conversation; here we also drop them from the published contacts list and
        // the profile cache so the UI updates immediately.
        self.messaging.setAccountDeletedHandler { [weak self] goneId in
            guard let self else { return }
            self.contacts.removeAll { $0.publicId == goneId }
            self.conversations = self.messaging.allConversations()
            self.profileStore.forget(goneId)
        }

        // When a contact re-publishes its profile, it pings us with a
        // `profile_updated` control; re-fetch + re-decrypt so the new name/photo
        // shows immediately (the ProfileStore is observed by the UI).
        self.messaging.setProfileUpdatedHandler { [weak self] senderId in
            Task { await self?.profileStore.refresh(senderId) }
        }

        // When an inbound group message/control is processed (including over the
        // realtime socket), refresh the published conversations + groups so an open
        // group view shows the new message/name in real time, not on next sync.
        self.groupService.onGroupsChanged = { [weak self] in
            guard let self else { return }
            self.conversations = self.messaging.allConversations()
            Task { await self.refreshGroups() }
        }

        // Restore any persisted session and prime the API + media tokens.
        if let existing = store.loadSession() {
            api.setToken(existing.token)
            self.messaging.syncMediaToken()
            self.session = existing
            updateFingerprint()
            self.profileStore.loadOwn(publicId: existing.publicId)
        }
    }

    /// True when a user is signed in.
    var isRegistered: Bool { session != nil }

    /// Adopts a freshly created/recovered session and starts realtime.
    func adopt(_ session: Session) {
        self.session = session
        messaging.syncMediaToken()
        updateFingerprint()
        profileStore.loadOwn(publicId: session.publicId)
        conversations = messaging.allConversations()
    }

    /// Clears the session locally (after logout/delete) and stops realtime.
    func clearSession() {
        realtimeTask?.cancel()
        realtimeTask = nil
        isRealtimeConnected = false
        messaging.stopRealtime()
        messaging.clearCache()
        groupService.clear()
        profileStore.clear()
        session = nil
        identityFingerprint = ""
        conversations = []
        contacts = []
        blockedIds = []
        groups = []
    }

    // MARK: - Groups

    /// Refreshes the decrypted group list from the backend (best-effort).
    func refreshGroups() async {
        do { groups = try await groupService.groups() }
        catch { /* keep the last known list on failure */ }
    }

    // MARK: - Device linking

    /// PRIMARY: provisions a new linked device and returns the payload to show as a
    /// QR / code on this device for the new one to scan or paste.
    func createDeviceLink(name: String) async throws -> DeviceLinkPayload {
        try await auth.createDeviceLink(deviceName: name)
    }

    /// NEW device: adopts a scanned/pasted link code, persists the session, and
    /// enters the app (the root view switches on `isRegistered`). The primary will
    /// retro-add this device to existing groups on its next sync.
    func adoptDeviceLink(code: String) async throws {
        guard let payload = DeviceLinkPayload(code: code) else { throw AuthError.invalidLinkCode }
        let session = try await auth.adoptDeviceLink(payload)
        adopt(session)
    }

    // MARK: - Messaging feed

    /// Loads cached conversations, performs an initial sync, refreshes contacts,
    /// and opens the realtime stream (idempotent — safe to call from `.task`).
    func startMessagingFeed() async {
        guard isRegistered else { return }
        conversations = messaging.allConversations()
        await refreshContacts()
        await refreshBlocks()
        await syncNow()
        await refreshGroups()
        startRealtime()
    }

    /// Pulls new messages once (including group control/transport messages, whose
    /// outbound responses are flushed by `groupService.sync()`) and refreshes the
    /// conversation list.
    func syncNow() async {
        do {
            _ = try await groupService.sync()
            conversations = messaging.allConversations()
        } catch {
            // Non-fatal; realtime / next sync will catch up.
        }
    }

    /// Deletes a 1:1 conversation everywhere: the peer drops MY messages and my own
    /// other devices drop the whole thread, then the local thread is removed and the
    /// list refreshed.
    func deleteConversation(_ peerPublicId: String) async {
        await messaging.deleteConversation(peerPublicId)
        conversations = messaging.allConversations()
    }

    /// Clears a GROUP conversation: removes the thread locally and asks every member
    /// to drop my messages (I remain a member). Refreshes the list.
    func clearGroupConversation(_ groupId: String) async {
        await groupService.deleteGroupConversation(groupId)
        conversations = messaging.allConversations()
    }

    /// Refreshes the contact list from the server.
    func refreshContacts() async {
        do {
            contacts = try await messaging.contacts()
        } catch {
            // Keep the last known list on failure.
        }
    }

    // MARK: - Blocking & reporting

    /// True when `publicId` is in the locally cached blocked set.
    func isBlocked(_ publicId: String) -> Bool { blockedIds.contains(publicId) }

    /// Refreshes the blocked-id set from the server.
    func refreshBlocks() async {
        do {
            blockedIds = Set(try await messaging.blocks())
        } catch {
            // Keep the last known set on failure.
        }
    }

    /// Blocks a contact and optimistically updates the published blocked set.
    func block(_ publicId: String) async throws {
        _ = try await messaging.block(publicId: publicId)
        blockedIds.insert(publicId)
        await refreshBlocks()
    }

    /// Unblocks a contact and optimistically updates the published blocked set.
    func unblock(_ publicId: String) async throws {
        _ = try await messaging.unblock(publicId: publicId)
        blockedIds.remove(publicId)
        await refreshBlocks()
    }

    /// Reports a user for abuse with a free-text reason.
    func report(_ publicId: String, reason: String) async throws {
        _ = try await messaging.report(publicId: publicId, reason: reason)
    }

    // MARK: - Key transparency

    /// Verifies a peer's identity key against the transparency log, computing the
    /// safety number versus the local identity. Throws if there is no local
    /// identity or the peer has no log entries.
    func verifyTransparency(of publicId: String) async throws -> TransparencyStatus {
        guard let identity = secretStore.loadIdentity() else {
            throw MessagingError.missingKeyMaterial
        }
        return try await transparency.verify(
            publicId: publicId,
            localIdentityKey: identity.publicKey)
    }

    /// Opens (or re-opens) the realtime message stream.
    private func startRealtime() {
        guard realtimeTask == nil else { return }
        realtimeTask = Task { [weak self] in
            guard let self else { return }
            do {
                let stream = try self.messaging.realtimeMessages()
                self.isRealtimeConnected = true
                for await _ in stream {
                    // A new message landed in the cache; refresh the published view.
                    self.conversations = self.messaging.allConversations()
                }
            } catch {
                self.isRealtimeConnected = false
            }
            self.isRealtimeConnected = false
        }
    }

    /// Refreshes the published conversation snapshot from the cache.
    func reloadConversations() {
        conversations = messaging.allConversations()
    }

    /// Saves the owner's profile, sealing the per-profile key to every current
    /// mutual contact, then refreshes the owner's entry in the profile store.
    func saveProfile(displayName: String, photo: Data?, sensitive: Bool) async throws {
        await refreshContacts()
        let mutualIds = contacts.filter { $0.direction == .mutual }.map(\.publicId)
        try await profiles.setProfile(displayName: displayName,
                                      photo: photo,
                                      sensitive: sensitive,
                                      mutualContacts: mutualIds)
        if let id = session?.publicId { profileStore.loadOwn(publicId: id) }
        // Ping each mutual contact so they re-fetch my new profile automatically
        // (like a message arriving), rather than only after their next relaunch.
        await messaging.broadcastProfileUpdate(to: mutualIds)
    }

    /// The local identity's safety number (self vs self) for display in Settings.
    private func updateFingerprint() {
        guard let identity = secretStore.loadIdentity() else {
            identityFingerprint = ""
            return
        }
        identityFingerprint = engine.safetyNumber(localIdentity: identity.publicKey,
                                                  remoteIdentity: identity.publicKey)
    }

    /// Computes the safety number between the local identity and a peer's key.
    func safetyNumber(withRemoteIdentity remote: Data) -> String? {
        guard let identity = secretStore.loadIdentity() else { return nil }
        return engine.safetyNumber(localIdentity: identity.publicKey, remoteIdentity: remote)
    }
}
