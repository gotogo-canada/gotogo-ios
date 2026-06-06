//
//  MLSKeyPackageStore.swift
//  Gotogo
//
//  On-disk store for this device's MLS KeyPackage material (RFC 9420 §10): a
//  stable Ed25519 signing identity for the device's KeyPackages, plus a pool of
//  unconsumed `MLSKeyPackagePrivate` (the init + leaf private keys) whose PUBLIC
//  KeyPackages are published to the server's key directory so other members can
//  Add this device to a group without a round trip.
//
//  When this device is Added, the committer claims one published KeyPackage and
//  sends a Welcome sealed to its init key; the device finds the matching private
//  KeyPackage here (by init key), uses it to join, and drops it from the pool.
//  Mirrors `GroupStore`: a per-user JSON file (AES-GCM at rest when a cipher is
//  supplied), guarded by a lock. Foundation + CryptoKit only.
//

import Foundation
import CryptoKit

/// JSON-backed store of the device's MLS signing identity + unconsumed KeyPackage
/// privates. Thread-safe.
final class MLSKeyPackageStore: @unchecked Sendable {

    private let url: URL
    private let lock = NSLock()
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let cipher: EncryptedFileStore?

    private struct Persisted: Codable {
        var signingPrivate: Data?
        var signingPublic: Data?
        var pool: [MLSKeyPackagePrivate]
    }
    private var state = Persisted(signingPrivate: nil, signingPublic: nil, pool: [])

    /// - Parameters:
    ///   - cacheURL: the messaging cache base path; the KeyPackage file is derived
    ///     from it so each user/test keeps its own file.
    ///   - cipher: when supplied, the file is AES-GCM ciphertext at rest.
    init(cacheURL: URL, cipher: EncryptedFileStore? = nil) {
        self.url = Self.fileURL(forCacheURL: cacheURL)
        self.cipher = cipher
        load()
    }

    /// The device's stable MLS signing identity (Ed25519 raw private + public),
    /// generated and persisted on first use so all of this device's KeyPackages
    /// share one identity key.
    func signingIdentity() -> (priv: Data, pub: Data) {
        lock.lock(); defer { lock.unlock() }
        if let priv = state.signingPrivate, let pub = state.signingPublic {
            return (priv, pub)
        }
        let key = Curve25519.Signing.PrivateKey()
        let priv = key.rawRepresentation
        let pub = key.publicKey.rawRepresentation
        state.signingPrivate = priv
        state.signingPublic = pub
        persistLocked()
        return (priv, pub)
    }

    /// Mints `count` fresh KeyPackages (signed by this device's identity), appends
    /// their privates to the pool, persists, and returns them so the caller can
    /// publish the PUBLIC KeyPackages to the key directory.
    func mint(count: Int) -> [MLSKeyPackagePrivate] {
        guard count > 0 else { return [] }
        let id = signingIdentity()
        var minted: [MLSKeyPackagePrivate] = []
        for _ in 0..<count {
            minted.append(MLSGroup.freshKeyPackage(signaturePublicKey: id.pub,
                                                   signaturePrivate: id.priv))
        }
        lock.lock()
        state.pool.append(contentsOf: minted)
        persistLocked()
        lock.unlock()
        return minted
    }

    /// A fresh, NON-published KeyPackage for being a group founder (its leaf key is
    /// used directly to seed the tree, never claimed by anyone else).
    func freshLocalKeyPackage() -> MLSKeyPackagePrivate {
        let id = signingIdentity()
        return MLSGroup.freshKeyPackage(signaturePublicKey: id.pub, signaturePrivate: id.priv)
    }

    /// Number of unconsumed KeyPackages currently in the pool.
    func count() -> Int {
        lock.lock(); defer { lock.unlock() }
        return state.pool.count
    }

    /// Finds a pooled private KeyPackage whose init key is one of `initKeys`
    /// (i.e. the one a Welcome was sealed to), removes it from the pool, and
    /// returns it. Returns nil when none matches (not for me / already consumed).
    func take(matchingInitKeys initKeys: Set<Data>) -> MLSKeyPackagePrivate? {
        lock.lock(); defer { lock.unlock() }
        guard let idx = state.pool.firstIndex(where: { initKeys.contains($0.keyPackage.initKey) }) else {
            return nil
        }
        let kp = state.pool.remove(at: idx)
        persistLocked()
        return kp
    }

    /// Drops all KeyPackage state and deletes the file (used on logout).
    func clear() {
        lock.lock()
        state = Persisted(signingPrivate: nil, signingPublic: nil, pool: [])
        lock.unlock()
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - Persistence

    private func load() {
        let raw: Data?
        if let cipher { raw = cipher.read(url) } else { raw = try? Data(contentsOf: url) }
        guard let data = raw, let decoded = try? decoder.decode(Persisted.self, from: data) else { return }
        lock.lock()
        state = decoded
        lock.unlock()
    }

    /// Persists the current state. Caller must hold `lock`.
    private func persistLocked() {
        guard let data = try? encoder.encode(state) else { return }
        if let cipher { try? cipher.write(data, to: url) }
        else { try? data.write(to: url, options: .atomic) }
    }

    /// Derives the KeyPackage file path from the cache path so distinct users keep
    /// distinct files.
    static func fileURL(forCacheURL cacheURL: URL) -> URL {
        let dir = cacheURL.deletingLastPathComponent()
        let base = cacheURL.deletingPathExtension().lastPathComponent
        return dir.appendingPathComponent("\(base)-mls-kp.json")
    }
}
