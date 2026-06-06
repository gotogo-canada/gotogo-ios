//
//  AuthService+Crypto.swift
//  Gotogo
//
//  Recovery-key derivation, vault sealing/opening, and prekey-upload assembly for
//  `AuthService`, split out to keep each file focused. Foundation + CryptoKit.
//

import Foundation
import CryptoKit

extension AuthService {

    /// HKDF info strings, fixed by the account-creation spec.
    static var recoveryInfo: Data { Data("gotogo/recovery/ed25519".utf8) }
    static var vaultInfo: Data { Data("gotogo/recovery/vault".utf8) }

    /// Bundle of derived recovery material.
    struct DerivedRecovery {
        let recoverySeed: Data       // 32-byte Ed25519 seed
        let recoveryPublicKey: Data  // Ed25519 public key
        let vaultKey: SymmetricKey   // AES-GCM key for the vault
    }

    // MARK: - Recovery key derivation

    /// Derives the Ed25519 recovery key and the AES-GCM vault key from `entropy`.
    static func deriveRecovery(from entropy: Data) throws -> DerivedRecovery {
        let ikm = SymmetricKey(data: entropy)
        let seedKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm,
                                             info: recoveryInfo,
                                             outputByteCount: 32)
        let recoverySeed = seedKey.withUnsafeBytes { Data($0) }
        let recoveryPrivate: Curve25519.Signing.PrivateKey
        do {
            recoveryPrivate = try Curve25519.Signing.PrivateKey(rawRepresentation: recoverySeed)
        } catch {
            throw AuthError.recoveryKeyDerivationFailed
        }
        let vaultKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm,
                                              info: vaultInfo,
                                              outputByteCount: 32)
        return DerivedRecovery(recoverySeed: recoverySeed,
                               recoveryPublicKey: recoveryPrivate.publicKey.rawRepresentation,
                               vaultKey: vaultKey)
    }

    // MARK: - Vault sealing

    /// Seals the identity + prekey store into an AES-GCM combined blob.
    static func sealVault(identity: IdentityKeyMaterial,
                          store: PreKeyStore,
                          vaultKey: SymmetricKey) throws -> Data {
        let payload = VaultPayload(identity: identity, store: store)
        let plaintext = try JSONEncoder().encode(payload)
        let box = try AES.GCM.seal(plaintext, using: vaultKey)
        guard let combined = box.combined else { throw AuthError.vaultDecryptionFailed }
        return combined
    }

    /// Opens a sealed vault blob back into its payload.
    static func openVault(_ data: Data, vaultKey: SymmetricKey) throws -> VaultPayload {
        do {
            let box = try AES.GCM.SealedBox(combined: data)
            let plaintext = try AES.GCM.open(box, using: vaultKey)
            return try JSONDecoder().decode(VaultPayload.self, from: plaintext)
        } catch {
            throw AuthError.vaultDecryptionFailed
        }
    }

    // MARK: - Helpers

    /// Builds the prekey upload request from generated material.
    static func uploadRequest(identity: IdentityKeyMaterial,
                              store: PreKeyStore) -> UploadPreKeysRequest {
        let oneTimes = store.oneTimePreKeys.map {
            UploadPreKeysRequest.OneTime(id: $0.id, key: $0.publicKey)
        }
        return UploadPreKeysRequest(identityKey: identity.publicKey,
                                    signedPreKeyId: store.signedPreKey.id,
                                    signedPreKey: store.signedPreKey.publicKey,
                                    signedPreKeySignature: store.signedPreKeySignature,
                                    oneTimePreKeys: oneTimes,
                                    ratchetKey: store.ratchetPublicKey,
                                    ratchetSignature: store.ratchetSignature,
                                    mlkem1024Key: store.mlkem1024Public,
                                    mlkemRatchetKey: store.mlkemRatchetPublic,
                                    mlkemRatchetSignature: store.mlkemRatchetSignature)
    }

    /// 32 bytes of cryptographically secure entropy for the recovery phrase.
    static func randomEntropy(byteCount: Int = 32) -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return Data(bytes)
    }
}
