//
//  Keychain.swift
//  Gotogo
//
//  Minimal raw `Security` wrapper: get/set/delete arbitrary `Data` by string key
//  in the app's generic-password keychain. Foundation + Security only.
//

import Foundation
import Security

/// Errors surfaced by `Keychain`.
public enum KeychainError: Error, Sendable {
    case unexpectedStatus(OSStatus)
}

/// A tiny keychain helper scoped by a `service` string. Stores opaque `Data`.
public struct Keychain: Sendable {

    private let service: String

    public init(service: String = "ca.gotogo.app") {
        self.service = service
    }

    /// Stores (or replaces) `value` under `key`.
    public func set(_ value: Data, for key: String) throws {
        // Delete any existing item first so we can do a clean add.
        SecItemDelete(baseQuery(for: key) as CFDictionary)

        var attributes = baseQuery(for: key)
        attributes[kSecValueData as String] = value
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    /// Returns the stored `Data` for `key`, or `nil` if absent.
    public func get(_ key: String) throws -> Data? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
        return result as? Data
    }

    /// Removes the item for `key` (no error if it was absent).
    public func delete(_ key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Returns the persisted 32-byte cache key for `key`, generating and storing it
    /// once on first use. Stored with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
    /// so it never syncs/migrates off this device and seals the local on-disk caches
    /// (conversations, Double-Ratchet sessions, group state). Subsequent calls return
    /// the same key, so ciphertext written earlier stays readable.
    public func getOrCreateCacheKey(_ key: String, byteCount: Int = 32) throws -> Data {
        if let existing = try get(key) { return existing }
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes) == errSecSuccess else {
            throw KeychainError.unexpectedStatus(errSecAllocate)
        }
        let value = Data(bytes)
        try setThisDeviceOnly(value, for: key)
        return value
    }

    /// Stores (or replaces) `value` under `key` with the stricter
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` accessibility.
    private func setThisDeviceOnly(_ value: Data, for key: String) throws {
        SecItemDelete(baseQuery(for: key) as CFDictionary)
        var attributes = baseQuery(for: key)
        attributes[kSecValueData as String] = value
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
    }
}
