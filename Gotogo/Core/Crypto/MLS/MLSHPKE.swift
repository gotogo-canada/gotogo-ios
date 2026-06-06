//
//  MLSHPKE.swift  (MLS "HPKE" Seal/Open — X25519 + HKDF + AES-256-GCM)
//
//  A single-shot public-key encryption primitive in the shape of RFC 9180 HPKE
//  base mode, built from CryptoKit pieces: an ephemeral X25519 key agreement to
//  the recipient's public key, HKDF-SHA256 to derive a 32-byte AEAD key from the
//  shared secret (KEM "enc" plus an info label), and AES-256-GCM as the AEAD.
//  TreeKEM uses this to seal each parent path secret to a copath public key, and
//  Welcome uses it to seal the joiner secret to a member's init key.
//
//  Pure Foundation + CryptoKit.
//
import Foundation
import CryptoKit

/// A sealed HPKE box: the ephemeral public key (`enc`) carrying the KEM output,
/// and the AES-256-GCM combined box (`nonce ‖ ciphertext ‖ tag`).
public struct MLSHPKECiphertext: Codable, Sendable, Equatable {
    public var enc: Data         // ephemeral X25519 public key (32)
    public var ciphertext: Data  // AES-GCM combined box
    public init(enc: Data, ciphertext: Data) { self.enc = enc; self.ciphertext = ciphertext }
}

/// Stateless HPKE-style seal/open over X25519. Reused by TreeKEM and Welcome.
public enum MLSHPKE {

    /// Suite tag mixed into every derivation so this KDF is domain-separated.
    private static let suite = Data("MLS 1.0 HPKE X25519-HKDF-SHA256-AES256GCM".utf8)

    /// Seals `plaintext` to a recipient X25519 public key, binding `info` and
    /// `aad`. `info` separates uses (e.g. an epoch/label); `aad` is authenticated
    /// but not encrypted (e.g. the group context).
    public static func seal(_ plaintext: Data, toPublicKey recipientRaw: Data,
                            info: Data, aad: Data) throws -> MLSHPKECiphertext {
        let recipient: Curve25519.KeyAgreement.PublicKey
        do { recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientRaw) }
        catch { throw MLSError.malformedKeyMaterial }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let enc = ephemeral.publicKey.rawRepresentation
        let shared: SharedSecret
        do { shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient) }
        catch { throw MLSError.malformedKeyMaterial }

        let key = deriveKey(shared: shared, enc: enc, recipient: recipientRaw, info: info)
        do {
            let box = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
            guard let combined = box.combined else { throw MLSError.authenticationFailure }
            return MLSHPKECiphertext(enc: enc, ciphertext: combined)
        } catch let e as MLSError { throw e }
        catch { throw MLSError.authenticationFailure }
    }

    /// Opens a sealed box with the recipient's X25519 private key. A wrong or
    /// stale private key yields a different KEM secret, so the AEAD tag check
    /// turns that into `authenticationFailure` — exactly the lockout a removed
    /// member hits against a re-keyed UpdatePath.
    public static func open(_ box: MLSHPKECiphertext, privateKey recipientPrivRaw: Data,
                            info: Data, aad: Data) throws -> Data {
        let priv: Curve25519.KeyAgreement.PrivateKey
        do { priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivRaw) }
        catch { throw MLSError.malformedKeyMaterial }
        let recipientPub = priv.publicKey.rawRepresentation

        let ephemeral: Curve25519.KeyAgreement.PublicKey
        do { ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: box.enc) }
        catch { throw MLSError.malformedKeyMaterial }
        let shared: SharedSecret
        do { shared = try priv.sharedSecretFromKeyAgreement(with: ephemeral) }
        catch { throw MLSError.malformedKeyMaterial }

        let key = deriveKey(shared: shared, enc: box.enc, recipient: recipientPub, info: info)
        do {
            let sealed = try AES.GCM.SealedBox(combined: box.ciphertext)
            return try AES.GCM.open(sealed, using: key, authenticating: aad)
        } catch { throw MLSError.authenticationFailure }
    }

    /// HKDF-SHA256 to a 256-bit AEAD key. The KEM context (`enc ‖ recipient`) is
    /// folded in HPKE-style so the key is bound to this exact encapsulation.
    private static func deriveKey(shared: SharedSecret, enc: Data, recipient: Data, info: Data) -> SymmetricKey {
        var context = Data()
        context.append(enc)
        context.append(recipient)
        context.append(info)
        return shared.hkdfDerivedSymmetricKey(using: SHA256.self,
                                              salt: suite,
                                              sharedInfo: context,
                                              outputByteCount: 32)
    }
}
