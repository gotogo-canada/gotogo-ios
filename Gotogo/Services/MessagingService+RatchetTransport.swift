//
//  MessagingService+RatchetTransport.swift
//  Gotogo
//
//  The 1:1 transport over Gotogo's own CryptoKit-backed PQXDH bootstrap and
//  Double Ratchet. Outbound fetches every active recipient device's published
//  prekey bundle, establishes a per-device ratchet session when needed, then
//  posts a ratchet ciphertext. Inbound bootstraps from an initial envelope or
//  advances an existing candidate session.
//

import Foundation

/// Initial-session data shipped only with the first message on a fresh ratchet
/// session. The KEM output is from `CryptoEngine.establishSender`.
public struct RatchetInitInfo: Codable, Sendable, Equatable {
    public var preKeyId: Int
    public var kem: Data

    public init(preKeyId: Int, kem: Data) {
        self.preKeyId = preKeyId
        self.kem = kem
    }
}

/// The 1:1 wire envelope used by Gotogo's native transport.
public struct RatchetWireEnvelope: Codable, Sendable, Equatable {
    public var v: Int
    public var initInfo: RatchetInitInfo?
    public var message: RatchetMessage

    public init(initInfo: RatchetInitInfo?, message: RatchetMessage, v: Int = 3) {
        self.v = v
        self.initInfo = initInfo
        self.message = message
    }

    public var isInitial: Bool { initInfo != nil }
}

/// Encrypted JSON persistence for per-device ratchet candidate sessions.
final class RatchetSessionStore: @unchecked Sendable {

    struct StoredSession: Codable, Sendable, Equatable {
        var id: String
        var initiatorAddress: String
        var session: RatchetSession
        var createdAt: Date
        var updatedAt: Date
    }

    private let url: URL
    private let cipher: EncryptedFileStore
    private let lock = NSLock()
    private var sessions: [String: [StoredSession]] = [:]
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(cacheURL: URL, cipher: EncryptedFileStore) {
        self.url = Self.sessionsURL(forCacheURL: cacheURL)
        self.cipher = cipher
        load()
    }

    func sessionForSending(peerPublicId: String,
                           deviceId: String,
                           localPublicId: String,
                           localDeviceId: String) -> StoredSession? {
        let key = Self.key(publicId: peerPublicId, deviceId: deviceId)
        let localAddress = Self.address(publicId: localPublicId, deviceId: localDeviceId)
        let peerAddress = Self.address(publicId: peerPublicId, deviceId: deviceId)
        lock.lock()
        let candidates = (sessions[key] ?? []).filter { $0.session.sendChainKey != nil }
        lock.unlock()
        guard !candidates.isEmpty else { return nil }

        let initiators = Set(candidates.map(\.initiatorAddress))
        if initiators.contains(localAddress), initiators.contains(peerAddress) {
            let preferred = min(localAddress, peerAddress)
            if let selected = newest(candidates.filter { $0.initiatorAddress == preferred }) {
                return selected
            }
        }
        return newest(candidates)
    }

    func sessionsForDecryption(peerPublicId: String, deviceId: String) -> [StoredSession] {
        let key = Self.key(publicId: peerPublicId, deviceId: deviceId)
        lock.lock()
        let items = sessions[key] ?? []
        lock.unlock()
        return items.sorted { $0.updatedAt > $1.updatedAt }
    }

    func insert(session: RatchetSession,
                initiatorAddress: String,
                peerPublicId: String,
                deviceId: String) -> StoredSession {
        let now = Date()
        let stored = StoredSession(id: UUID().uuidString,
                                   initiatorAddress: initiatorAddress,
                                   session: session,
                                   createdAt: now,
                                   updatedAt: now)
        save(stored, peerPublicId: peerPublicId, deviceId: deviceId)
        return stored
    }

    func save(_ stored: StoredSession, peerPublicId: String, deviceId: String) {
        let key = Self.key(publicId: peerPublicId, deviceId: deviceId)
        var updated = stored
        updated.updatedAt = Date()

        lock.lock()
        var items = sessions[key] ?? []
        if let idx = items.firstIndex(where: { $0.id == updated.id }) {
            items[idx] = updated
        } else {
            items.append(updated)
        }
        items.sort { $0.updatedAt > $1.updatedAt }
        if items.count > 8 { items.removeLast(items.count - 8) }
        sessions[key] = items
        let snapshot = sessions
        lock.unlock()
        persist(snapshot)
    }

    func removeSession(_ id: String, peerPublicId: String, deviceId: String) {
        let key = Self.key(publicId: peerPublicId, deviceId: deviceId)
        lock.lock()
        sessions[key]?.removeAll { $0.id == id }
        let snapshot = sessions
        lock.unlock()
        persist(snapshot)
    }

    func removeSessions(forPublicId publicId: String) {
        lock.lock()
        sessions = sessions.filter { !$0.key.hasPrefix("\(publicId)|") }
        let snapshot = sessions
        lock.unlock()
        persist(snapshot)
    }

    func clear() {
        lock.lock()
        sessions = [:]
        lock.unlock()
        try? FileManager.default.removeItem(at: url)
    }

    static func address(publicId: String, deviceId: String) -> String {
        "\(publicId)|\(deviceId)"
    }

    private func newest(_ sessions: [StoredSession]) -> StoredSession? {
        sessions.max { $0.updatedAt < $1.updatedAt }
    }

    private static func key(publicId: String, deviceId: String) -> String {
        address(publicId: publicId, deviceId: deviceId)
    }

    private func load() {
        guard let data = cipher.read(url),
              let decoded = try? decoder.decode([String: [StoredSession]].self, from: data) else { return }
        lock.lock()
        sessions = decoded
        lock.unlock()
    }

    private func persist(_ snapshot: [String: [StoredSession]]) {
        guard let data = try? encoder.encode(snapshot) else { return }
        try? cipher.write(data, to: url)
    }

    static func sessionsURL(forCacheURL cacheURL: URL) -> URL {
        let dir = cacheURL.deletingLastPathComponent()
        let base = cacheURL.deletingPathExtension().lastPathComponent
        return dir.appendingPathComponent("\(base)-ratchets.json")
    }
}

extension MessagingService {

    func ratchetSessionStore() -> RatchetSessionStore {
        if let store = _ratchets { return store }
        let store = RatchetSessionStore(cacheURL: cacheURL, cipher: cipher)
        _ratchets = store
        return store
    }

    /// Fetches the recipient's current active devices and their published standard
    /// prekey bundles. Empty means the account has no reachable device.
    func ratchetDevices(for peerPublicId: String) async throws -> [FetchedPreKeyBundle] {
        do {
            let devices = try await api.fetchAllPreKeyBundles(publicId: peerPublicId)
            guard !devices.isEmpty else { throw MessagingError.userNotFound }
            return devices
        } catch let error as APIError {
            if error.serverCode == "not_found" { throw MessagingError.userNotFound }
            throw error
        }
    }

    /// Encrypts `plaintext` for one peer device and posts it to the backend.
    func ratchetPost(_ plaintext: Data,
                     contentType: String,
                     to peerPublicId: String,
                     bundle: FetchedPreKeyBundle) async throws -> SendMessageResponse {
        guard let local = store.loadSession() else { throw MessagingError.notSignedIn }
        let envelope = try ratchetEnvelope(plaintext,
                                           to: peerPublicId,
                                           bundle: bundle,
                                           local: local)
        let request = SendMessageRequest(toPublicId: peerPublicId,
                                         toDeviceId: bundle.deviceId,
                                         ciphertext: try encoder.encode(envelope),
                                         contentType: contentType,
                                         clientMessageId: UUID().uuidString)
        do {
            return try await api.sendMessage(request)
        } catch let error as APIError {
            if error.serverCode == "not_contacts" { throw MessagingError.notMutualContact }
            if error.serverCode == "blocked" { throw MessagingError.blocked }
            throw error
        }
    }

    private func ratchetEnvelope(_ plaintext: Data,
                                 to peerPublicId: String,
                                 bundle: FetchedPreKeyBundle,
                                 local: Session) throws -> RatchetWireEnvelope {
        let sessions = ratchetSessionStore()
        if var stored = sessions.sessionForSending(peerPublicId: peerPublicId,
                                                   deviceId: bundle.deviceId,
                                                   localPublicId: local.publicId,
                                                   localDeviceId: local.deviceId) {
            do {
                let message = try DoubleRatchet.encrypt(plaintext, session: &stored.session)
                sessions.save(stored, peerPublicId: peerPublicId, deviceId: bundle.deviceId)
                return RatchetWireEnvelope(initInfo: nil, message: message)
            } catch {
                sessions.removeSession(stored.id, peerPublicId: peerPublicId, deviceId: bundle.deviceId)
            }
        }

        let established = try engine.establishSender(to: bundle.toPublicBundle())
        var session = DoubleRatchet.initiateSender(sharedSecret: established.sharedSecret,
                                                   remoteRatchetPublicKey: established.remoteRatchetKey)
        let message = try DoubleRatchet.encrypt(plaintext, session: &session)
        let initiator = RatchetSessionStore.address(publicId: local.publicId, deviceId: local.deviceId)
        _ = sessions.insert(session: session,
                            initiatorAddress: initiator,
                            peerPublicId: peerPublicId,
                            deviceId: bundle.deviceId)
        return RatchetWireEnvelope(initInfo: RatchetInitInfo(preKeyId: established.preKeyId,
                                                             kem: established.kem),
                                   message: message)
    }

    /// Opens one inbound ratchet envelope from `raw.fromPublicId|raw.fromDeviceId`.
    func openRatchetEnvelope(_ envelope: RatchetWireEnvelope,
                             raw: InboundMessage,
                             identity: IdentityKeyMaterial,
                             preKeyStore: PreKeyStore) throws -> Data {
        if let initInfo = envelope.initInfo {
            return try openInitialRatchetEnvelope(envelope,
                                                 initInfo: initInfo,
                                                 raw: raw,
                                                 preKeyStore: preKeyStore)
        }
        return try openExistingRatchetEnvelope(envelope, raw: raw)
    }

    private func openInitialRatchetEnvelope(_ envelope: RatchetWireEnvelope,
                                            initInfo: RatchetInitInfo,
                                            raw: InboundMessage,
                                            preKeyStore: PreKeyStore) throws -> Data {
        guard !preKeyStore.ratchetPrivateKey.isEmpty,
              !preKeyStore.ratchetPublicKey.isEmpty else {
            throw CryptoError.malformedKeyMaterial
        }
        let shared = try engine.establishReceiver(preKeyId: initInfo.preKeyId,
                                                  kem: initInfo.kem,
                                                  signedPreKey: preKeyStore.signedPreKey,
                                                  oneTimePreKeys: preKeyStore.oneTimePreKeys)
        var session = DoubleRatchet.initiateReceiver(sharedSecret: shared,
                                                     selfRatchetPrivateKey: preKeyStore.ratchetPrivateKey,
                                                     selfRatchetPublicKey: preKeyStore.ratchetPublicKey)
        let plaintext = try DoubleRatchet.decrypt(envelope.message, session: &session)
        let initiator = RatchetSessionStore.address(publicId: raw.fromPublicId,
                                                    deviceId: raw.fromDeviceId)
        _ = ratchetSessionStore().insert(session: session,
                                         initiatorAddress: initiator,
                                         peerPublicId: raw.fromPublicId,
                                         deviceId: raw.fromDeviceId)
        consumeOneTimePreKeyIfNeeded(initInfo.preKeyId, from: preKeyStore)
        return plaintext
    }

    private func openExistingRatchetEnvelope(_ envelope: RatchetWireEnvelope,
                                             raw: InboundMessage) throws -> Data {
        let sessions = ratchetSessionStore().sessionsForDecryption(peerPublicId: raw.fromPublicId,
                                                                   deviceId: raw.fromDeviceId)
        var lastError: Error = RatchetError.receiveChainNotEstablished
        for var stored in sessions {
            do {
                let plaintext = try DoubleRatchet.decrypt(envelope.message, session: &stored.session)
                ratchetSessionStore().save(stored,
                                           peerPublicId: raw.fromPublicId,
                                           deviceId: raw.fromDeviceId)
                return plaintext
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private func consumeOneTimePreKeyIfNeeded(_ preKeyId: Int, from preKeyStore: PreKeyStore) {
        guard preKeyId != 0 else { return }
        var updated = preKeyStore
        let before = updated.oneTimePreKeys.count
        updated.oneTimePreKeys.removeAll { $0.id == preKeyId }
        guard updated.oneTimePreKeys.count != before else { return }
        try? store.savePreKeyStore(updated)
    }
}
