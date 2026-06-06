//
//  CryptoKitEngine.swift
//  Gotogo
//
//  Production `CryptoEngine` backed by Apple CryptoKit. Implements a per-message
//  hybrid post-quantum sealed-message scheme:
//    identity = Ed25519, prekeys = X-Wing (ML-KEM-768 + X25519),
//    KDF = HKDF-SHA256, AEAD = AES-GCM.
//  Pure Foundation + CryptoKit — compiles for iOS and macOS.
//

import Foundation
import CryptoKit

public struct CryptoKitEngine: CryptoEngine {

    /// HKDF info string binding derived keys to this scheme/version.
    /// Internal (not private) so the helper extension in another file can read it.
    static let messageInfo = Data("gotogo/v1/msg".utf8)
    /// HKDF info string for the Double Ratchet root shared secret, domain-separating
    /// the ratchet bootstrap from the per-message key derivation.
    static let rootKDFInfo = Data("gotogo/dr/root".utf8)
    /// Derived message-key length in bytes (AES-256).
    static let messageKeyByteCount = 32
    /// Current envelope version.
    static let version = 1

    public init() {}

    // MARK: - Identity

    public func generateIdentity() -> IdentityKeyMaterial {
        let key = Curve25519.Signing.PrivateKey()
        return IdentityKeyMaterial(privateKey: key.rawRepresentation,
                                   publicKey: key.publicKey.rawRepresentation)
    }

    // MARK: - Prekeys

    public func generatePreKeys(identity: IdentityKeyMaterial,
                                signedPreKeyId: Int,
                                oneTimeCount: Int,
                                firstOneTimeId: Int) throws -> GeneratedPreKeys {
        let signingKey = try Self.signingKey(from: identity.privateKey)

        let signedPair = try XWingMLKEM768X25519.PrivateKey()
        let signedPub = signedPair.publicKey.rawRepresentation
        let signature = try signingKey.signature(for: signedPub)
        let signedSecret = PreKeySecret(id: signedPreKeyId,
                                        seed: signedPair.seedRepresentation,
                                        publicKey: signedPub)

        var oneTime: [PreKeySecret] = []
        oneTime.reserveCapacity(max(0, oneTimeCount))
        for offset in 0..<max(0, oneTimeCount) {
            let pair = try XWingMLKEM768X25519.PrivateKey()
            oneTime.append(PreKeySecret(id: firstOneTimeId + offset,
                                        seed: pair.seedRepresentation,
                                        publicKey: pair.publicKey.rawRepresentation))
        }

        // X25519 ratchet seed keypair for the Double/Triple Ratchet's DH ratchet,
        // signed with the identity key so peers can authenticate it.
        let ratchetPair = Curve25519.KeyAgreement.PrivateKey()
        let ratchetPub = ratchetPair.publicKey.rawRepresentation
        let ratchetSignature = try signingKey.signature(for: ratchetPub)

        // ML-KEM-768 ratchet keypair for the *Triple* Ratchet's PQ ratchet, signed
        // with the identity key (mirrors the X25519 ratchet key above). The private
        // side is persisted as its 64-byte seed; the public is published so an
        // initiator can encapsulate to it when bootstrapping its sending chain.
        let mlkemRatchet = try MLKEM768.PrivateKey()
        let mlkemRatchetPub = mlkemRatchet.publicKey.rawRepresentation
        let mlkemRatchetSignature = try signingKey.signature(for: mlkemRatchetPub)

        // ML-KEM-1024 (Level 5) keypair, published so contacts can seal the most
        // sensitive payloads (sensitive-profile keys) with a pure PQ KEM.
        let mlkem = try MLKEM1024Seal.generate()

        let store = PreKeyStore(signedPreKey: signedSecret,
                                signedPreKeySignature: signature,
                                oneTimePreKeys: oneTime,
                                ratchetPrivateKey: ratchetPair.rawRepresentation,
                                ratchetPublicKey: ratchetPub,
                                ratchetSignature: ratchetSignature,
                                mlkem1024Seed: mlkem.seed,
                                mlkem1024Public: mlkem.publicKey,
                                mlkemRatchetSeed: mlkemRatchet.seedRepresentation,
                                mlkemRatchetPublic: mlkemRatchetPub,
                                mlkemRatchetSignature: mlkemRatchetSignature)
        let bundle = publicBundle(identity: identity,
                                  store: store,
                                  oneTimePreKeyId: oneTime.first?.id)
        return GeneratedPreKeys(store: store, bundle: bundle)
    }

    public func generateMoreOneTimePreKeys(identity: IdentityKeyMaterial,
                                           store: PreKeyStore,
                                           count: Int) throws
        -> (store: PreKeyStore, newPublic: [(id: Int, key: Data)]) {
        // Continue ids past the highest already present (signed prekey or any
        // one-time prekey) so the new ids never collide with existing material.
        let highest = max(store.signedPreKey.id,
                          store.oneTimePreKeys.map(\.id).max() ?? 0)
        var updated = store
        var newPublic: [(id: Int, key: Data)] = []
        newPublic.reserveCapacity(max(0, count))
        for offset in 0..<max(0, count) {
            let id = highest + 1 + offset
            let pair = try XWingMLKEM768X25519.PrivateKey()
            let pub = pair.publicKey.rawRepresentation
            updated.oneTimePreKeys.append(PreKeySecret(id: id,
                                                       seed: pair.seedRepresentation,
                                                       publicKey: pub))
            newPublic.append((id: id, key: pub))
        }
        return (updated, newPublic)
    }

    public func publicBundle(identity: IdentityKeyMaterial,
                             store: PreKeyStore,
                             oneTimePreKeyId: Int?) -> PublicPreKeyBundle {
        let otp = oneTimePreKeyId.flatMap { id in store.oneTimePreKeys.first { $0.id == id } }
        return PublicPreKeyBundle(identityKey: identity.publicKey,
                                  signedPreKeyId: store.signedPreKey.id,
                                  signedPreKey: store.signedPreKey.publicKey,
                                  signedPreKeySignature: store.signedPreKeySignature,
                                  oneTimePreKeyId: otp?.id,
                                  oneTimePreKey: otp?.publicKey,
                                  ratchetKey: store.ratchetPublicKey,
                                  ratchetKeySignature: store.ratchetSignature,
                                  mlkem1024Key: store.mlkem1024Public,
                                  mlkemRatchetKey: store.mlkemRatchetPublic)
    }

    // MARK: - Seal

    public func seal(_ plaintext: Data, to bundle: PublicPreKeyBundle) throws -> SealedEnvelope {
        // 1. Verify the signed prekey signature against the recipient identity.
        let identityPub = try Self.signingPublicKey(from: bundle.identityKey)
        guard identityPub.isValidSignature(bundle.signedPreKeySignature,
                                           for: bundle.signedPreKey) else {
            throw CryptoError.invalidSignedPreKeySignature
        }

        // 2. Prefer the one-time prekey; fall back to the signed prekey (id 0).
        let targetRaw: Data
        let preKeyId: Int
        if let otpRaw = bundle.oneTimePreKey, let otpId = bundle.oneTimePreKeyId {
            targetRaw = otpRaw
            preKeyId = otpId
        } else {
            targetRaw = bundle.signedPreKey
            preKeyId = 0
        }

        // 3. KEM-encapsulate a fresh shared secret to the target public key.
        let encap = try Self.encapsulate(toRawPublicKey: targetRaw)

        // 4. Derive the AES-GCM message key from the shared secret.
        let messageKey = Self.deriveMessageKey(from: encap.sharedSecret)

        // 5. AES-GCM seal the plaintext into a combined box.
        let box = try AES.GCM.seal(plaintext, using: messageKey)
        guard let combined = box.combined else { throw CryptoError.authenticationFailure }

        // 6. Emit the envelope.
        return SealedEnvelope(v: Self.version,
                              preKeyId: preKeyId,
                              kem: encap.encapsulated,
                              ciphertext: combined)
    }

    // MARK: - Open

    public func open(_ env: SealedEnvelope,
                     identity: IdentityKeyMaterial,
                     signedPreKey: PreKeySecret,
                     oneTimePreKeys: [PreKeySecret]) throws -> Data {
        guard env.v == Self.version else { throw CryptoError.unsupportedVersion(env.v) }

        // 1. Resolve the X-Wing private key for the referenced prekey id.
        let secret: PreKeySecret
        if env.preKeyId == 0 {
            secret = signedPreKey
        } else if let match = oneTimePreKeys.first(where: { $0.id == env.preKeyId }) {
            secret = match
        } else {
            throw CryptoError.unknownPreKey(env.preKeyId)
        }
        // 2. KEM-decapsulate. Note: X-Wing/ML-KEM use implicit rejection — a
        //    tampered `kem` yields a *different* shared secret rather than
        //    throwing here. The AES-GCM tag below is what rejects tampering.
        let sharedSecret = try Self.decapsulate(env.kem, withSeed: secret.seed)

        // 3. Re-derive the message key and open the AES-GCM box.
        let messageKey = Self.deriveMessageKey(from: sharedSecret)
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(combined: env.ciphertext)
        } catch {
            throw CryptoError.authenticationFailure
        }
        do {
            return try AES.GCM.open(box, using: messageKey)
        } catch {
            // Wrong key (tampered kem) or tampered ciphertext -> tag mismatch.
            throw CryptoError.authenticationFailure
        }
    }

    // MARK: - Double Ratchet bootstrap

    public func establishSender(to bundle: PublicPreKeyBundle)
        throws -> (sharedSecret: SymmetricKey, kem: Data, preKeyId: Int, remoteRatchetKey: Data) {
        // 1. Verify both signatures against the recipient identity key.
        let identityPub = try Self.signingPublicKey(from: bundle.identityKey)
        guard identityPub.isValidSignature(bundle.signedPreKeySignature,
                                           for: bundle.signedPreKey) else {
            throw CryptoError.invalidSignedPreKeySignature
        }
        guard identityPub.isValidSignature(bundle.ratchetKeySignature,
                                           for: bundle.ratchetKey) else {
            throw CryptoError.invalidSignedPreKeySignature
        }

        // 2. Prefer the one-time prekey; fall back to the signed prekey (id 0).
        let targetRaw: Data
        let preKeyId: Int
        if let otpRaw = bundle.oneTimePreKey, let otpId = bundle.oneTimePreKeyId {
            targetRaw = otpRaw
            preKeyId = otpId
        } else {
            targetRaw = bundle.signedPreKey
            preKeyId = 0
        }

        // 3. X-Wing-encapsulate (same step as `seal`), then HKDF the KEM secret
        //    into the Double Ratchet root shared secret.
        let encap = try Self.encapsulate(toRawPublicKey: targetRaw)
        let sharedSecret = Self.deriveRootSharedSecret(from: encap.sharedSecret)
        return (sharedSecret, encap.encapsulated, preKeyId, bundle.ratchetKey)
    }

    public func establishReceiver(preKeyId: Int,
                                  kem: Data,
                                  signedPreKey: PreKeySecret,
                                  oneTimePreKeys: [PreKeySecret]) throws -> SymmetricKey {
        // 1. Resolve the X-Wing private key for the referenced prekey id.
        let secret: PreKeySecret
        if preKeyId == 0 {
            secret = signedPreKey
        } else if let match = oneTimePreKeys.first(where: { $0.id == preKeyId }) {
            secret = match
        } else {
            throw CryptoError.unknownPreKey(preKeyId)
        }

        // 2. Decapsulate (same step as `open`), then HKDF identically to the sender.
        let sharedSecret = try Self.decapsulate(kem, withSeed: secret.seed)
        return Self.deriveRootSharedSecret(from: sharedSecret)
    }

    // MARK: - Safety number

    public func safetyNumber(localIdentity: Data, remoteIdentity: Data) -> String {
        // Sort the two keys so both peers compute the same digest.
        let pair = [localIdentity, remoteIdentity].sorted { lhs, rhs in
            Self.lexicographicallyPrecedes(lhs, rhs)
        }
        var hasher = SHA256()
        hasher.update(data: pair[0])
        hasher.update(data: pair[1])
        let digest = Array(hasher.finalize())

        // Render the first 15 bytes as five 5-digit decimal groups (Signal-style).
        var groups: [String] = []
        var index = 0
        while index + 3 <= digest.count && groups.count < 5 {
            let value = (UInt32(digest[index]) << 16)
                | (UInt32(digest[index + 1]) << 8)
                | UInt32(digest[index + 2])
            groups.append(String(format: "%05u", value % 100_000))
            index += 3
        }
        return groups.joined(separator: " ")
    }

    public func safetyNumber(localIdentity: Data, localTransport: Data?,
                             remoteIdentity: Data, remoteTransport: Data?) -> String {
        safetyNumber(localIdentity: Self.bindTransport(localIdentity, localTransport),
                     remoteIdentity: Self.bindTransport(remoteIdentity, remoteTransport))
    }

    /// Folds an optional transport identity into its identity blob via a
    /// domain-separated SHA-256 commitment. With no transport key the identity is
    /// returned unchanged, so the bound safety number reduces exactly to the plain
    /// one (back-compatible). Both peers commit identically, so the resulting code
    /// stays symmetric and stable — but a swapped transport identity changes it.
    private static func bindTransport(_ identity: Data, _ transport: Data?) -> Data {
        guard let transport else { return identity }
        var hasher = SHA256()
        hasher.update(data: Data("gotogo/safety-number/v2".utf8))
        hasher.update(data: identity)
        hasher.update(data: transport)
        return Data(hasher.finalize())
    }
}
