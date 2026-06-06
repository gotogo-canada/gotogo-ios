//
//  MLKEM1024Seal.swift
//  Gotogo
//
//  Pure post-quantum sealing with ML-KEM-1024 (NIST FIPS 203, Level 5) for the
//  most sensitive payloads — e.g. a "sensitive profile" key. KEM-encapsulate to
//  the recipient's ML-KEM-1024 public key, derive an AES-256-GCM key via HKDF,
//  and seal. Foundation + CryptoKit only (plan section 3.2: ML-KEM-1024 for
//  very sensitive profiles).
//
import Foundation
import CryptoKit

/// Errors thrown by ML-KEM-1024 sealing.
public enum MLKEM1024Error: Error, Equatable, Sendable {
    case malformedKeyMaterial
    case authenticationFailure
}

/// A sealed ML-KEM-1024 payload: the KEM ciphertext plus the AEAD box.
public struct MLKEM1024Sealed: Codable, Sendable, Equatable {
    public var kem: Data        // ML-KEM-1024 encapsulation
    public var ciphertext: Data // AES-GCM combined (nonce|ct|tag)
    public init(kem: Data, ciphertext: Data) { self.kem = kem; self.ciphertext = ciphertext }
}

/// A persistable ML-KEM-1024 keypair (seed for the private side, raw public key).
public struct MLKEM1024KeyMaterial: Codable, Sendable, Equatable {
    public var seed: Data       // 64-byte ML-KEM-1024 seed
    public var publicKey: Data  // raw public key
    public init(seed: Data, publicKey: Data) { self.seed = seed; self.publicKey = publicKey }
}

/// Stateless ML-KEM-1024 seal/open.
public enum MLKEM1024Seal {

    private static let info = Data("gotogo/mlkem1024/seal".utf8)

    /// Generates a fresh ML-KEM-1024 keypair in persistable form.
    public static func generate() throws -> MLKEM1024KeyMaterial {
        let priv = try MLKEM1024.PrivateKey()
        return MLKEM1024KeyMaterial(seed: priv.seedRepresentation, publicKey: priv.publicKey.rawRepresentation)
    }

    /// Seals `payload` to a recipient ML-KEM-1024 public key.
    public static func seal(_ payload: Data, toPublicKey rawPublicKey: Data) throws -> MLKEM1024Sealed {
        guard let pub = try? MLKEM1024.PublicKey(rawRepresentation: rawPublicKey) else {
            throw MLKEM1024Error.malformedKeyMaterial
        }
        let result = try pub.encapsulate()
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: result.sharedSecret, info: info, outputByteCount: 32)
        let box = try AES.GCM.seal(payload, using: key)
        return MLKEM1024Sealed(kem: result.encapsulated, ciphertext: box.combined!)
    }

    /// Opens a sealed payload with the recipient's keypair.
    public static func open(_ sealed: MLKEM1024Sealed, using material: MLKEM1024KeyMaterial) throws -> Data {
        guard let priv = try? MLKEM1024.PrivateKey(seedRepresentation: material.seed, publicKey: nil) else {
            throw MLKEM1024Error.malformedKeyMaterial
        }
        // ML-KEM uses implicit rejection: a tampered kem yields a *different*
        // shared secret, so tamper detection is enforced by the AES-GCM tag.
        guard let shared = try? priv.decapsulate(sealed.kem) else {
            throw MLKEM1024Error.authenticationFailure
        }
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: shared, info: info, outputByteCount: 32)
        guard let box = try? AES.GCM.SealedBox(combined: sealed.ciphertext),
              let pt = try? AES.GCM.open(box, using: key) else {
            throw MLKEM1024Error.authenticationFailure
        }
        return pt
    }
}
