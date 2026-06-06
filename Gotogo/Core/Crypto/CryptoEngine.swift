//
//  CryptoEngine.swift
//  Gotogo
//
//  Protocol defining the hybrid post-quantum E2EE engine. The rest of the app
//  depends on these shapes; `CryptoKitEngine` is the production implementation.
//

import Foundation
import CryptoKit

/// Result of generating a fresh batch of prekeys: the private material to
/// persist locally and the public bundle to publish to the server.
public struct GeneratedPreKeys: Sendable {
    /// Private prekey material to store (e.g. in the Keychain).
    public var store: PreKeyStore
    /// Public bundle to upload. Carries the signed prekey and, optionally, the
    /// first one-time prekey. The server hands out one one-time prekey per fetch.
    public var bundle: PublicPreKeyBundle

    public init(store: PreKeyStore, bundle: PublicPreKeyBundle) {
        self.store = store
        self.bundle = bundle
    }
}

/// A per-message hybrid post-quantum E2EE engine (PQXDH-style sealed messages).
///
/// Identity keys are Ed25519; prekeys are X-Wing (ML-KEM-768 + X25519). Each
/// message encapsulates a fresh shared secret to a recipient prekey, derives an
/// AES-GCM key via HKDF-SHA256, and seals the plaintext. All key material is
/// exported as raw `Data` so it can be persisted in the Keychain.
public protocol CryptoEngine: Sendable {

    // MARK: Identity

    /// Generates a fresh Ed25519 identity key pair in persistable raw form.
    func generateIdentity() -> IdentityKeyMaterial

    // MARK: Prekeys

    /// Generates a signed prekey plus `oneTimeCount` one-time prekeys.
    /// - Parameters:
    ///   - identity: the device identity used to sign the signed prekey.
    ///   - signedPreKeyId: id to assign the signed prekey (>= 1).
    ///   - oneTimeCount: number of one-time prekeys to mint.
    ///   - firstOneTimeId: id assigned to the first one-time prekey; the rest
    ///     increment from there.
    /// - Returns: private material to store and the public bundle to publish.
    func generatePreKeys(identity: IdentityKeyMaterial,
                         signedPreKeyId: Int,
                         oneTimeCount: Int,
                         firstOneTimeId: Int) throws -> GeneratedPreKeys

    /// Builds the public bundle to publish for a given stored prekey set,
    /// attaching the one-time prekey with `oneTimePreKeyId` when supplied.
    func publicBundle(identity: IdentityKeyMaterial,
                      store: PreKeyStore,
                      oneTimePreKeyId: Int?) -> PublicPreKeyBundle

    /// Mints `count` additional one-time prekeys, continuing ids past the highest
    /// already present in `store`, appends their secrets to the store, and returns
    /// both the updated store and the new public ones to upload. Used to top the
    /// server's one-time-prekey pool back up as it is consumed by inbound sessions.
    func generateMoreOneTimePreKeys(identity: IdentityKeyMaterial,
                                    store: PreKeyStore,
                                    count: Int) throws
        -> (store: PreKeyStore, newPublic: [(id: Int, key: Data)])

    // MARK: Messaging

    /// Seals `plaintext` for the owner of `bundle`. Verifies the signed prekey
    /// signature first and throws `CryptoError.invalidSignedPreKeySignature` if
    /// it does not match `bundle.identityKey`.
    func seal(_ plaintext: Data, to bundle: PublicPreKeyBundle) throws -> SealedEnvelope

    /// Opens a sealed envelope using the recipient's stored private material.
    /// - Parameters:
    ///   - env: the sealed envelope received from the sender.
    ///   - identity: the recipient identity (carried for symmetry/audit).
    ///   - signedPreKey: the recipient's signed prekey secret (id 0 path).
    ///   - oneTimePreKeys: the recipient's pool of one-time prekey secrets.
    /// - Returns: the recovered plaintext. Throws on tampering or unknown prekey.
    func open(_ env: SealedEnvelope,
              identity: IdentityKeyMaterial,
              signedPreKey: PreKeySecret,
              oneTimePreKeys: [PreKeySecret]) throws -> Data

    // MARK: Double Ratchet bootstrap (PQXDH-derived root secret)

    /// Initiator side of the ratchet bootstrap. Verifies both the signed-prekey
    /// and ratchet-key signatures against `bundle.identityKey`, X-Wing-encapsulates
    /// to the chosen prekey (one-time if present, else the signed prekey), and
    /// derives the Double Ratchet root shared secret from the KEM output.
    /// - Returns: the root `sharedSecret`, the `kem` ciphertext to ship, the
    ///   `preKeyId` used (0 == signed prekey), and the peer's `remoteRatchetKey`.
    /// - Throws: `CryptoError.invalidSignedPreKeySignature` if either signature
    ///   fails to verify.
    func establishSender(to bundle: PublicPreKeyBundle)
        throws -> (sharedSecret: SymmetricKey, kem: Data, preKeyId: Int, remoteRatchetKey: Data)

    /// Responder side of the ratchet bootstrap. Selects the X-Wing private key for
    /// `preKeyId` (signed prekey for 0, else the matching one-time prekey),
    /// decapsulates `kem`, and derives the same root shared secret the sender did.
    /// - Throws: `CryptoError.unknownPreKey` if no matching one-time prekey exists.
    func establishReceiver(preKeyId: Int,
                           kem: Data,
                           signedPreKey: PreKeySecret,
                           oneTimePreKeys: [PreKeySecret]) throws -> SymmetricKey

    // MARK: Verification

    /// A stable short code derived from both identity public keys, for manual
    /// out-of-band verification (a "safety number"). Symmetric: the same pair of
    /// keys yields the same code regardless of argument order.
    func safetyNumber(localIdentity: Data, remoteIdentity: Data) -> String

    /// Safety number that can also bind an optional transport identity key into
    /// the code. Passing `nil` for a transport key degrades to the plain
    /// `safetyNumber(localIdentity:remoteIdentity:)` for that side. Symmetric in
    /// the same way.
    func safetyNumber(localIdentity: Data, localTransport: Data?,
                      remoteIdentity: Data, remoteTransport: Data?) -> String
}
