//
//  CryptoTypes.swift
//  Gotogo
//
//  Public wire types, persistable private-key containers, and typed errors for
//  the hybrid post-quantum E2EE engine. Pure Foundation — safe for iOS + macOS.
//

import Foundation

// MARK: - Errors

/// Typed errors thrown by the crypto engine. Distinct cases let callers map
/// failures to user-facing states (e.g. "untrusted contact" vs "corrupt message").
public enum CryptoError: Error, Equatable, Sendable {
    /// The signed prekey's signature did not verify against the identity key.
    case invalidSignedPreKeySignature
    /// `open` referenced a one-time prekey id that is not in local storage.
    case unknownPreKey(Int)
    /// The envelope version is not supported by this build.
    case unsupportedVersion(Int)
    /// Stored or wire key material had the wrong length / could not be parsed.
    case malformedKeyMaterial
    /// AEAD authentication failed (tampered `kem` or `ciphertext`, or wrong key).
    case authenticationFailure
}

// MARK: - Public wire types

/// Codable public bundle published to the server. The server treats every field
/// as an opaque public blob; only clients interpret the contents.
public struct PublicPreKeyBundle: Codable, Sendable, Equatable {
    /// Ed25519 raw public key (32 bytes).
    public var identityKey: Data
    /// Identifier of the signed prekey (>= 1 by convention; 0 is reserved on the wire).
    public var signedPreKeyId: Int
    /// X-Wing (ML-KEM-768 + X25519) raw public key (1216 bytes).
    public var signedPreKey: Data
    /// Ed25519 signature over `signedPreKey`, made with the identity key (64 bytes).
    public var signedPreKeySignature: Data
    /// Identifier of the included one-time prekey, when one is attached.
    public var oneTimePreKeyId: Int?
    /// X-Wing raw public key for the one-time prekey, when one is attached.
    public var oneTimePreKey: Data?
    /// X25519 raw public key (32 bytes) seeding the Double/Triple Ratchet's DH ratchet.
    public var ratchetKey: Data
    /// Ed25519 signature over `ratchetKey`, made with the identity key (64 bytes).
    public var ratchetKeySignature: Data
    /// ML-KEM-1024 (FIPS 203, Level 5) raw public key, published so contacts can
    /// seal "sensitive" payloads (e.g. a sensitive-profile key) with pure PQ KEM.
    public var mlkem1024Key: Data
    /// ML-KEM-768 (FIPS 203) raw public key (1184 bytes) seeding the *Triple*
    /// Ratchet's PQ ratchet. The initiator encapsulates to this when bootstrapping
    /// its sending chain so the continuous ratchet is post-quantum from message 1.
    public var mlkemRatchetKey: Data

    public init(identityKey: Data,
                signedPreKeyId: Int,
                signedPreKey: Data,
                signedPreKeySignature: Data,
                oneTimePreKeyId: Int? = nil,
                oneTimePreKey: Data? = nil,
                ratchetKey: Data = Data(),
                ratchetKeySignature: Data = Data(),
                mlkem1024Key: Data = Data(),
                mlkemRatchetKey: Data = Data()) {
        self.identityKey = identityKey
        self.signedPreKeyId = signedPreKeyId
        self.signedPreKey = signedPreKey
        self.signedPreKeySignature = signedPreKeySignature
        self.oneTimePreKeyId = oneTimePreKeyId
        self.oneTimePreKey = oneTimePreKey
        self.ratchetKey = ratchetKey
        self.ratchetKeySignature = ratchetKeySignature
        self.mlkem1024Key = mlkem1024Key
        self.mlkemRatchetKey = mlkemRatchetKey
    }
}

/// A sealed message produced by `seal` and consumed by `open`.
public struct SealedEnvelope: Codable, Sendable, Equatable {
    /// Scheme version. Always 1 for this build.
    public var v: Int
    /// Which recipient prekey was used: 0 == signed prekey, else a one-time prekey id.
    public var preKeyId: Int
    /// X-Wing KEM ciphertext (encapsulation, 1120 bytes).
    public var kem: Data
    /// AES-GCM combined sealed box (nonce ‖ ciphertext ‖ tag).
    public var ciphertext: Data

    public init(v: Int, preKeyId: Int, kem: Data, ciphertext: Data) {
        self.v = v
        self.preKeyId = preKeyId
        self.kem = kem
        self.ciphertext = ciphertext
    }
}

// MARK: - Persistable private-key containers

/// Persistable identity secret: the Ed25519 signing key in raw form, plus the
/// derived public key for convenience. Store `privateKey` in the Keychain.
public struct IdentityKeyMaterial: Codable, Sendable, Equatable {
    /// Ed25519 raw private key (32 bytes).
    public var privateKey: Data
    /// Ed25519 raw public key (32 bytes). Derivable from `privateKey`.
    public var publicKey: Data

    public init(privateKey: Data, publicKey: Data) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

/// One stored X-Wing prekey secret, keyed by its id. `seed` is the 32-byte
/// X-Wing seed representation, from which the full key pair is reconstructed.
public struct PreKeySecret: Codable, Sendable, Equatable {
    /// Prekey id. 0 is used in storage to denote the signed prekey.
    public var id: Int
    /// X-Wing 32-byte seed representation (private material).
    public var seed: Data
    /// X-Wing raw public key (1216 bytes), cached for republishing bundles.
    public var publicKey: Data

    public init(id: Int, seed: Data, publicKey: Data) {
        self.id = id
        self.seed = seed
        self.publicKey = publicKey
    }
}

/// The full set of private prekey material a device must persist: the reusable
/// signed prekey and the pool of unused one-time prekeys. Fully Codable so it
/// can be JSON-encoded into a single Keychain item.
public struct PreKeyStore: Codable, Sendable, Equatable {
    /// The reusable signed prekey secret (its `id` is the published signedPreKeyId).
    public var signedPreKey: PreKeySecret
    /// Ed25519 signature over the signed prekey's public key (republished as-is).
    public var signedPreKeySignature: Data
    /// Pool of unused one-time prekey secrets, addressable by id.
    public var oneTimePreKeys: [PreKeySecret]
    /// The device's X25519 ratchet seed private key (32 raw bytes). Used by the
    /// responder to initialize the Double Ratchet's DH ratchet.
    public var ratchetPrivateKey: Data
    /// The matching X25519 ratchet public key (32 raw bytes), republished in bundles.
    public var ratchetPublicKey: Data
    /// Ed25519 signature over `ratchetPublicKey` (republished as-is, like the
    /// signed-prekey signature).
    public var ratchetSignature: Data
    /// The device's ML-KEM-1024 64-byte seed (private side). Reconstructs the
    /// keypair needed to open "sensitive" sealed payloads addressed to this device.
    public var mlkem1024Seed: Data
    /// The matching ML-KEM-1024 raw public key, republished in bundles.
    public var mlkem1024Public: Data
    /// The device's ML-KEM-768 ratchet seed (64 raw bytes, private side). Used by
    /// the responder to initialize the *Triple* Ratchet's PQ ratchet: it
    /// decapsulates the initiator's first KEM ciphertext with the key regenerated
    /// from this seed.
    public var mlkemRatchetSeed: Data
    /// The matching ML-KEM-768 ratchet raw public key (1184 bytes), republished in
    /// bundles as `mlkemRatchetKey` so initiators can encapsulate to it.
    public var mlkemRatchetPublic: Data
    /// Ed25519 signature over `mlkemRatchetPublic` (republished as-is, like the
    /// X25519 ratchet-key signature).
    public var mlkemRatchetSignature: Data

    public init(signedPreKey: PreKeySecret,
                signedPreKeySignature: Data,
                oneTimePreKeys: [PreKeySecret],
                ratchetPrivateKey: Data = Data(),
                ratchetPublicKey: Data = Data(),
                ratchetSignature: Data = Data(),
                mlkem1024Seed: Data = Data(),
                mlkem1024Public: Data = Data(),
                mlkemRatchetSeed: Data = Data(),
                mlkemRatchetPublic: Data = Data(),
                mlkemRatchetSignature: Data = Data()) {
        self.signedPreKey = signedPreKey
        self.signedPreKeySignature = signedPreKeySignature
        self.oneTimePreKeys = oneTimePreKeys
        self.ratchetPrivateKey = ratchetPrivateKey
        self.ratchetPublicKey = ratchetPublicKey
        self.ratchetSignature = ratchetSignature
        self.mlkem1024Seed = mlkem1024Seed
        self.mlkem1024Public = mlkem1024Public
        self.mlkemRatchetSeed = mlkemRatchetSeed
        self.mlkemRatchetPublic = mlkemRatchetPublic
        self.mlkemRatchetSignature = mlkemRatchetSignature
    }

    /// The device's ML-KEM-1024 key material (seed + public), used to open
    /// "sensitive" sealed grants. Empty `seed`/`publicKey` if not yet generated.
    public var mlkem1024Material: MLKEM1024KeyMaterial {
        MLKEM1024KeyMaterial(seed: mlkem1024Seed, publicKey: mlkem1024Public)
    }

    /// Returns the secret for a given envelope `preKeyId` (0 == signed prekey),
    /// or `nil` if no matching one-time prekey is stored.
    public func secret(forPreKeyId preKeyId: Int) -> PreKeySecret? {
        if preKeyId == 0 { return signedPreKey }
        return oneTimePreKeys.first { $0.id == preKeyId }
    }
}
