//
//  SecretStore.swift
//  Gotogo
//
//  Persistence boundary for the session + private key material. A protocol so
//  tests can inject an in-memory store; the production impl is keychain-backed.
//  Foundation only.
//

import Foundation

/// The owner's own profile, persisted locally: the random per-profile AES key and
/// the plaintext `Profile`. The server never lets the owner fetch their own
/// profile (grants are stored only for mutual contacts), so the owner keeps this
/// locally to render their own name/photo and to re-seal grants for new contacts.
public struct OwnProfileRecord: Codable, Sendable, Equatable {
    /// Raw 32-byte AES-256 key that seals `encryptedProfile`.
    public var profileKey: Data
    /// The owner's plaintext profile.
    public var profile: Profile
    /// Whether the profile is sealed to contacts in "sensitive" (ML-KEM-1024) mode.
    public var sensitive: Bool

    public init(profileKey: Data, profile: Profile, sensitive: Bool) {
        self.profileKey = profileKey
        self.profile = profile
        self.sensitive = sensitive
    }
}

/// Stores the authenticated `Session` plus the device's private crypto material.
/// All methods are synchronous; callers may hop off the main actor if desired.
public protocol SecretStoring: Sendable {
    func loadSession() -> Session?
    func saveSession(_ session: Session) throws
    func loadIdentity() -> IdentityKeyMaterial?
    func saveIdentity(_ identity: IdentityKeyMaterial) throws
    func loadPreKeyStore() -> PreKeyStore?
    func savePreKeyStore(_ store: PreKeyStore) throws
    /// The owner's locally persisted profile + per-profile key (nil if unset).
    func loadOwnProfile() -> OwnProfileRecord?
    func saveOwnProfile(_ record: OwnProfileRecord) throws
    /// The last identity key seen for a peer device in the transparency log, used
    /// for trust-on-first-use + identity-key-change detection. Nil = never seen.
    func lastSeenIdentityKey(publicId: String, deviceId: String) -> Data?
    /// Records the identity key observed for a peer device (first sight, or after
    /// a deliberate key change the user has acknowledged).
    func setLastSeenIdentityKey(_ key: Data, publicId: String, deviceId: String) throws
    /// The persisted 32-byte AES-GCM key that seals the on-disk caches at rest
    /// (conversations, Double-Ratchet sessions, group state). Generated once and
    /// stored device-only; returns the same key on every call so previously written
    /// ciphertext stays readable. Survives `clear()` so a re-login can still decrypt
    /// any caches left behind (they are removed separately on logout).
    func cacheKey() -> Data?
    /// Removes all persisted secrets (logout / account deletion).
    func clear() throws
}

/// Keychain-backed implementation: each value is JSON-encoded under a stable key.
public struct KeychainSecretStore: SecretStoring {

    private enum Key {
        static let session = "gotogo.session"
        static let identity = "gotogo.identity"
        static let preKeyStore = "gotogo.prekeystore"
        static let ownProfile = "gotogo.ownprofile"
        /// JSON map `["<publicId>|<deviceId>": <identityKey base64 via Data coding>]`
        /// of the last identity key seen per peer device (transparency TOFU cache).
        static let lastSeenKeys = "gotogo.lastseenkeys"
        /// 32-byte AES-GCM key sealing the on-disk caches (device-only accessibility).
        static let cacheKey = "gotogo.cachekey"
    }

    /// The composite map key for a peer device's last-seen identity key.
    private static func lastSeenMapKey(publicId: String, deviceId: String) -> String {
        "\(publicId)|\(deviceId)"
    }

    private let keychain: Keychain
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(keychain: Keychain = Keychain()) {
        self.keychain = keychain
    }

    public func loadSession() -> Session? { load(Key.session) }
    public func saveSession(_ session: Session) throws { try save(session, Key.session) }

    public func loadIdentity() -> IdentityKeyMaterial? { load(Key.identity) }
    public func saveIdentity(_ identity: IdentityKeyMaterial) throws { try save(identity, Key.identity) }

    public func loadPreKeyStore() -> PreKeyStore? { load(Key.preKeyStore) }
    public func savePreKeyStore(_ store: PreKeyStore) throws { try save(store, Key.preKeyStore) }

    public func loadOwnProfile() -> OwnProfileRecord? { load(Key.ownProfile) }
    public func saveOwnProfile(_ record: OwnProfileRecord) throws { try save(record, Key.ownProfile) }

    public func lastSeenIdentityKey(publicId: String, deviceId: String) -> Data? {
        let map: [String: Data]? = load(Key.lastSeenKeys)
        return map?[Self.lastSeenMapKey(publicId: publicId, deviceId: deviceId)]
    }

    public func setLastSeenIdentityKey(_ key: Data, publicId: String, deviceId: String) throws {
        var map: [String: Data] = load(Key.lastSeenKeys) ?? [:]
        map[Self.lastSeenMapKey(publicId: publicId, deviceId: deviceId)] = key
        try save(map, Key.lastSeenKeys)
    }

    public func cacheKey() -> Data? {
        try? keychain.getOrCreateCacheKey(Key.cacheKey)
    }

    public func clear() throws {
        try keychain.delete(Key.session)
        try keychain.delete(Key.identity)
        try keychain.delete(Key.preKeyStore)
        try keychain.delete(Key.ownProfile)
        try keychain.delete(Key.lastSeenKeys)
    }

    // MARK: - Codable helpers

    private func load<T: Decodable>(_ key: String) -> T? {
        guard let data = try? keychain.get(key) else { return nil }
        return try? decoder.decode(T.self, from: data)
    }

    private func save<T: Encodable>(_ value: T, _ key: String) throws {
        let data = try encoder.encode(value)
        try keychain.set(data, for: key)
    }
}

/// In-memory `SecretStoring` for tests and previews.
public final class InMemorySecretStore: SecretStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var session: Session?
    private var identity: IdentityKeyMaterial?
    private var preKeyStore: PreKeyStore?
    private var ownProfile: OwnProfileRecord?
    private var lastSeenKeys: [String: Data] = [:]
    private var cacheKeyData: Data?

    public init() {}

    public func loadSession() -> Session? { sync { session } }
    public func saveSession(_ session: Session) throws { sync { self.session = session } }
    public func loadIdentity() -> IdentityKeyMaterial? { sync { identity } }
    public func saveIdentity(_ identity: IdentityKeyMaterial) throws { sync { self.identity = identity } }
    public func loadPreKeyStore() -> PreKeyStore? { sync { preKeyStore } }
    public func savePreKeyStore(_ store: PreKeyStore) throws { sync { self.preKeyStore = store } }
    public func loadOwnProfile() -> OwnProfileRecord? { sync { ownProfile } }
    public func saveOwnProfile(_ record: OwnProfileRecord) throws { sync { self.ownProfile = record } }
    public func lastSeenIdentityKey(publicId: String, deviceId: String) -> Data? {
        sync { lastSeenKeys["\(publicId)|\(deviceId)"] }
    }
    public func setLastSeenIdentityKey(_ key: Data, publicId: String, deviceId: String) throws {
        sync { lastSeenKeys["\(publicId)|\(deviceId)"] = key }
    }
    public func cacheKey() -> Data? {
        sync {
            if let existing = cacheKeyData { return existing }
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
            let key = Data(bytes)
            cacheKeyData = key
            return key
        }
    }
    public func clear() throws {
        // Keep `cacheKeyData` so ciphertext written before a re-login stays readable
        // (cache files are removed separately on logout).
        sync { session = nil; identity = nil; preKeyStore = nil; ownProfile = nil; lastSeenKeys = [:] }
    }

    private func sync<T>(_ block: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return block()
    }
}
