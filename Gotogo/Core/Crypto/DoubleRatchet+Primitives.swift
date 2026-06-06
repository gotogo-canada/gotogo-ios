//
//  DoubleRatchet+Primitives.swift
//  Gotogo
//
//  Cryptographic primitives for the Double Ratchet: the two KDFs (KDF_RK,
//  KDF_CK), X25519 agreement, AES-256-GCM seal/open, and the deterministic
//  header serialization used as AEAD additional data. Split out of
//  `DoubleRatchet.swift` to keep each file focused (and under the size budget).
//  Pure Foundation + CryptoKit. `internal` (not `private`) so the protocol
//  logic in the sibling file can call across the file boundary.
//

import Foundation
import CryptoKit

extension DoubleRatchet {

    // MARK: - KDFs

    /// `KDF_RK`: HKDF-SHA256 with the root key as salt and the DH output as IKM,
    /// producing 64 bytes split into the next root key (32) and a chain key (32).
    static func kdfRootKey(rootKey: Data, dhOutput: Data) -> (rootKey: Data, chainKey: Data) {
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: dhOutput),
            salt: rootKey,
            info: rootKDFInfo,
            outputByteCount: 64)
        let bytes = rawKey(okm)
        return (Data(bytes.prefix(32)), Data(bytes.suffix(32)))
    }

    /// `KDF_CK`: derives the message key and the next chain key from a chain key
    /// using HMAC-SHA256 with single-byte constant inputs.
    static func kdfChainKey(chainKey: Data) -> (messageKey: SymmetricKey, nextChainKey: Data) {
        let ckKey = SymmetricKey(data: chainKey)
        let mk = HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: ckKey)
        let nextCK = HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: ckKey)
        return (SymmetricKey(data: Data(mk)), Data(nextCK))
    }

    // MARK: - DH

    /// X25519 agreement from raw private/public representations. Throws
    /// `malformedKeyMaterial` if either key fails to parse.
    static func diffieHellman(privateRaw: Data, publicRaw: Data) throws -> Data {
        let priv: Curve25519.KeyAgreement.PrivateKey
        let pub: Curve25519.KeyAgreement.PublicKey
        do {
            priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateRaw)
            pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicRaw)
        } catch {
            throw RatchetError.malformedKeyMaterial
        }
        do {
            let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
            return secret.withUnsafeBytes { Data($0) }
        } catch {
            throw RatchetError.malformedKeyMaterial
        }
    }

    // MARK: - AEAD

    /// AES-256-GCM seal returning the combined box (`nonce ‖ ct ‖ tag`).
    static func aeadSeal(plaintext: Data, key: SymmetricKey, aad: Data) throws -> Data {
        do {
            let box = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
            guard let combined = box.combined else { throw RatchetError.authenticationFailure }
            return combined
        } catch let e as RatchetError {
            throw e
        } catch {
            throw RatchetError.authenticationFailure
        }
    }

    /// AES-256-GCM open. Any parse/authentication failure maps to
    /// `authenticationFailure` so tampering is reported uniformly.
    static func aeadOpen(ciphertext: Data, key: SymmetricKey, aad: Data) throws -> Data {
        do {
            let box = try AES.GCM.SealedBox(combined: ciphertext)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw RatchetError.authenticationFailure
        }
    }

    // MARK: - Header serialization

    /// Deterministic header encoding used as AEAD additional data. A sorted-key
    /// JSON encoder gives a stable byte string independent of platform field
    /// ordering, so sender and receiver compute identical AAD.
    static func headerBytes(_ header: RatchetHeader) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            return try encoder.encode(header)
        } catch {
            throw RatchetError.malformedKeyMaterial
        }
    }

    // MARK: - Utilities

    /// Extracts the raw bytes of a `SymmetricKey`.
    static func rawKey(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }
}
