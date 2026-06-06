//
//  CryptoKitEngine+Helpers.swift
//  Gotogo
//
//  Internal key-parsing and key-derivation helpers for `CryptoKitEngine`.
//  Kept in an extension so the engine file stays focused on the protocol
//  surface. Pure Foundation + CryptoKit.
//

import Foundation
import CryptoKit

extension CryptoKitEngine {

    // MARK: Ed25519 parsing

    /// Reconstructs the Ed25519 signing private key from its raw representation.
    static func signingKey(from raw: Data) throws -> Curve25519.Signing.PrivateKey {
        do {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        } catch {
            throw CryptoError.malformedKeyMaterial
        }
    }

    /// Reconstructs the Ed25519 signing public key from its raw representation.
    static func signingPublicKey(from raw: Data) throws -> Curve25519.Signing.PublicKey {
        do {
            return try Curve25519.Signing.PublicKey(rawRepresentation: raw)
        } catch {
            throw CryptoError.malformedKeyMaterial
        }
    }

    // MARK: X-Wing parsing

    /// Reconstructs an X-Wing public key from its raw representation.
    static func xwingPublicKey(from raw: Data) throws -> XWingMLKEM768X25519.PublicKey {
        do {
            return try XWingMLKEM768X25519.PublicKey(rawRepresentation: raw)
        } catch {
            throw CryptoError.malformedKeyMaterial
        }
    }

    /// Reconstructs an X-Wing private key from its 32-byte seed. The public key
    /// is re-derived from the seed (`publicKey: nil`).
    static func xwingPrivateKey(from seed: Data) throws -> XWingMLKEM768X25519.PrivateKey {
        do {
            return try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
        } catch {
            throw CryptoError.malformedKeyMaterial
        }
    }

    // MARK: KEM (shared with seal/open and the Double Ratchet bootstrap)

    /// X-Wing-encapsulates a fresh shared secret to a raw recipient public key.
    /// The same step used by `seal`, factored out so the ratchet bootstrap
    /// (`establishSender`) agrees byte-for-byte with the per-message path.
    static func encapsulate(toRawPublicKey raw: Data) throws -> KEM.EncapsulationResult {
        let pub = try xwingPublicKey(from: raw)
        return try pub.encapsulate()
    }

    /// X-Wing-decapsulates a KEM ciphertext with the private key reconstructed
    /// from `seed`. The same step used by `open`, so `establishReceiver` recovers
    /// the identical shared secret the sender encapsulated.
    static func decapsulate(_ encapsulated: Data, withSeed seed: Data) throws -> SymmetricKey {
        let priv = try xwingPrivateKey(from: seed)
        return try priv.decapsulate(encapsulated)
    }

    // MARK: Derivation

    /// Derives the per-message AES-256 key from a KEM shared secret via HKDF-SHA256.
    static func deriveMessageKey(from sharedSecret: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: sharedSecret,
                               info: messageInfo,
                               outputByteCount: messageKeyByteCount)
    }

    /// Derives the Double Ratchet root shared secret from a KEM shared secret via
    /// HKDF-SHA256, domain-separated by `gotogo/dr/root`. Both `establishSender`
    /// and `establishReceiver` call this identically so the two sides agree.
    static func deriveRootSharedSecret(from sharedSecret: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: sharedSecret,
                               info: rootKDFInfo,
                               outputByteCount: 32)
    }

    // MARK: Utilities

    /// Constant-shape lexicographic comparison of two byte buffers, used to give
    /// the safety number a deterministic, order-independent input.
    static func lexicographicallyPrecedes(_ lhs: Data, _ rhs: Data) -> Bool {
        lhs.lexicographicallyPrecedes(rhs)
    }
}
