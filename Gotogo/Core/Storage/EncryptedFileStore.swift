//
//  EncryptedFileStore.swift
//  Gotogo
//
//  Encrypts the app's on-disk caches at rest. Every local cache that used to be
//  written as plaintext JSON (conversations, Double-Ratchet sessions, group state
//  + sender keys) is instead sealed with AES-256-GCM under a 32-byte device-only
//  cache key kept in the Keychain, so nothing readable touches the file system.
//  Foundation + CryptoKit only.
//

import Foundation
import CryptoKit

/// Seals/opens cache files with AES-GCM under the caller's cache key. The key is
/// supplied lazily by a `@Sendable` provider (backed by `SecretStoring.cacheKey()`)
/// so this type stays value-like and `Sendable` and can be shared across actors
/// (e.g. by the thread-safe `GroupStore`). The same key is returned on every call,
/// so ciphertext written earlier stays readable across app launches.
public struct EncryptedFileStore: Sendable {

    /// Errors surfaced when sealing a cache file.
    public enum EncryptedFileError: Error, Sendable {
        /// The cache key was unavailable (Keychain failure) so data could not be sealed.
        case missingKey
    }

    /// Resolves the current AES-GCM cache key (32 raw bytes), or nil if unavailable.
    private let keyProvider: @Sendable () -> Data?

    /// - Parameter keyProvider: returns the raw 32-byte cache key (same key each call).
    public init(keyProvider: @escaping @Sendable () -> Data?) {
        self.keyProvider = keyProvider
    }

    /// Convenience: derive the key from a `SecretStoring`'s `cacheKey()`.
    public init(store: SecretStoring) {
        self.init(keyProvider: { store.cacheKey() })
    }

    /// Seals `data` with AES-GCM under the cache key and writes the combined
    /// (nonce‖ciphertext‖tag) blob to `url` atomically. Throws `missingKey` when the
    /// cache key cannot be resolved, or rethrows a write/seal failure.
    public func write(_ data: Data, to url: URL) throws {
        guard let raw = keyProvider() else { throw EncryptedFileError.missingKey }
        let sealed = try AES.GCM.seal(data, using: SymmetricKey(data: raw))
        guard let combined = sealed.combined else { throw EncryptedFileError.missingKey }
        try combined.write(to: url, options: .atomic)
    }

    /// Reads and opens the sealed cache file at `url`. Returns the decrypted bytes,
    /// or `nil` when the file is absent, the key is unavailable, or the file does not
    /// decrypt — the latter tolerates a leftover *plaintext* cache from before
    /// encryption was introduced by treating it as empty (callers re-create it).
    public func read(_ url: URL) -> Data? {
        guard let raw = keyProvider(),
              let combined = try? Data(contentsOf: url) else { return nil }
        guard let box = try? AES.GCM.SealedBox(combined: combined),
              let plaintext = try? AES.GCM.open(box, using: SymmetricKey(data: raw)) else {
            return nil // corrupt or legacy-plaintext file: treat as empty.
        }
        return plaintext
    }
}
