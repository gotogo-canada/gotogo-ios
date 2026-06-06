//
//  MLSGroup+Application.swift  (MLS application messages — RFC 9420 §9, §15)
//
//  The application-message layer on top of the proven MLS epoch key schedule.
//  Group-chat plaintext is encrypted/decrypted under the CURRENT epoch using a
//  per-sender application ratchet keyed from that epoch's `encryption_secret`
//  (RFC 9420 §9), indexed by the sender's leaf and a per-sender generation
//  counter. Every current member holds the identical `secrets.encryptionSecret`,
//  so any member can re-derive the same (sender, generation) key and decrypt —
//  that shared epoch secret is exactly what makes group decryption possible —
//  while a member of a different epoch (added/removed since) derives a different
//  key and is naturally locked out by the AEAD tag check.
//
//  Key derivation (deterministic, identical for sender and every receiver that
//  holds the same epoch secrets):
//
//      sender_secret = ExpandWithLabel(secrets.encryptionSecret,
//                                      "application sender",
//                                      ratchetLabel(groupId, epoch, sender),
//                                      32)
//      key_material  = ExpandWithLabel(sender_secret,
//                                      "application key",
//                                      generationLabel(groupId, epoch, sender,
//                                                      generation),
//                                      32 + 12)
//      AEAD key (32) = key_material[0 ..< 32]
//      AEAD nonce(12)= key_material[32 ..< 44]
//
//  where ratchetLabel binds the per-(epoch, sender) ratchet root and
//  generationLabel additionally binds the generation. Both run through the
//  module's own `MLSKeySchedule.expandWithLabel` (HKDF-Expand over the MLS-framed
//  label), so the scheme stays consistent with the rest of the key schedule.
//
//  The same context bytes are also fed to AES-GCM as additionally-authenticated
//  data (AAD = groupId ‖ epoch ‖ sender ‖ generation), so a ciphertext is bound
//  to its exact (group, epoch, sender, generation) slot and cannot be replayed
//  into another slot even if an attacker swaps the header fields.
//
//  Pure Foundation + CryptoKit.
//
import Foundation
import CryptoKit

/// One encrypted application (chat) message bound to a single MLS epoch.
/// A receiver MUST be in the same epoch as `epoch` to decrypt: it re-derives the
/// per-(sender, generation) key from its own copy of the epoch's encryption
/// secret. `generation` is the sender's per-epoch message counter, so each
/// message gets a distinct key+nonce.
public struct MLSApplicationMessage: Codable, Sendable, Equatable {
    /// The sender's epoch. The receiver must match (`==`) to decrypt.
    public var epoch: UInt64
    /// The sender's leaf index — selects the per-sender ratchet within the epoch.
    public var sender: MLSLeafIndex
    /// The sender's per-epoch message counter (0, 1, 2, …). Distinct keys per value.
    public var generation: UInt32
    /// AES-256-GCM combined box: `nonce ‖ ciphertext ‖ tag`.
    public var ciphertext: Data

    public init(epoch: UInt64, sender: MLSLeafIndex, generation: UInt32, ciphertext: Data) {
        self.epoch = epoch
        self.sender = sender
        self.generation = generation
        self.ciphertext = ciphertext
    }
}

extension MLSGroup {

    // MARK: - Application messages (RFC 9420 §9, §15)

    /// Encrypts `plaintext` for the group under the current epoch as if sent from
    /// this member's leaf at the given `generation`. Returns the wire message; the
    /// caller is responsible for persisting the next generation to use (this group
    /// object is a value type and cannot hold a mutable per-epoch counter), so the
    /// caller should pass `generation + 1` for its next message in this epoch.
    ///
    /// Every current member can `decryptApplication` the result because they all
    /// share `secrets.encryptionSecret` and re-derive the identical key.
    public func encryptApplication(_ plaintext: Data, generation: UInt32) throws -> MLSApplicationMessage {
        let (key, nonce) = try Self.applicationKey(encryptionSecret: secrets.encryptionSecret,
                                                   groupId: groupId,
                                                   epoch: epoch,
                                                   sender: myLeaf,
                                                   generation: generation)
        let aad = Self.applicationAAD(groupId: groupId, epoch: epoch,
                                      sender: myLeaf, generation: generation)
        do {
            let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
            guard let combined = box.combined else { throw MLSError.authenticationFailure }
            return MLSApplicationMessage(epoch: epoch, sender: myLeaf,
                                         generation: generation, ciphertext: combined)
        } catch let e as MLSError {
            throw e
        } catch {
            throw MLSError.authenticationFailure
        }
    }

    /// Decrypts an application `message`. Verifies the message's epoch matches this
    /// member's current epoch (throws `MLSError.invalidState` otherwise — a stale
    /// or future message cannot be read), re-derives the per-(sender, generation)
    /// key from this member's own epoch encryption secret, and opens the AEAD box.
    /// A tampered ciphertext, a wrong key, or mismatched header fields fail the
    /// AES-GCM tag and surface as `MLSError.authenticationFailure`.
    public func decryptApplication(_ message: MLSApplicationMessage) throws -> Data {
        guard message.epoch == epoch else { throw MLSError.invalidState }

        let (key, nonce) = try Self.applicationKey(encryptionSecret: secrets.encryptionSecret,
                                                   groupId: groupId,
                                                   epoch: message.epoch,
                                                   sender: message.sender,
                                                   generation: message.generation)
        let aad = Self.applicationAAD(groupId: groupId, epoch: message.epoch,
                                      sender: message.sender, generation: message.generation)
        do {
            // Reconstruct the sealed box from the combined `nonce ‖ ct ‖ tag`, then
            // re-pin the nonce we derived: AES.GCM.open does not check the nonce
            // against a key, so we verify it matches what we derived to keep the
            // (sender, generation) → nonce binding strict. (AES.GCM.Nonce isn't
            // Equatable, so compare the raw bytes.)
            let sealed = try AES.GCM.SealedBox(combined: message.ciphertext)
            guard Data(sealed.nonce) == Data(nonce) else { throw MLSError.authenticationFailure }
            return try AES.GCM.open(sealed, using: key, authenticating: aad)
        } catch let e as MLSError {
            throw e
        } catch {
            throw MLSError.authenticationFailure
        }
    }

    // MARK: - key derivation (deterministic; identical for sender and receivers)

    /// Derives the AES-256-GCM key (32 B) and nonce (12 B) for one
    /// (group, epoch, sender, generation) slot from the epoch's encryption secret.
    /// Two HKDF-Expand steps through the module's labeled KDF: first a per-(epoch,
    /// sender) ratchet root, then the per-generation key+nonce material. Pure
    /// function of public header fields + the shared `encryptionSecret`, so every
    /// member holding that secret derives the same bytes.
    private static func applicationKey(encryptionSecret: Data, groupId: Data, epoch: UInt64,
                                       sender: MLSLeafIndex, generation: UInt32)
        throws -> (key: SymmetricKey, nonce: AES.GCM.Nonce)
    {
        let senderSecret = MLSKeySchedule.expandWithLabel(
            secret: encryptionSecret,
            label: "application sender",
            context: ratchetLabel(groupId: groupId, epoch: epoch, sender: sender),
            length: MLSKeySchedule.secretSize)

        // 32-byte AES key followed by a 12-byte GCM nonce, both bound to generation.
        let keyAndNonce = MLSKeySchedule.expandWithLabel(
            secret: senderSecret,
            label: "application key",
            context: generationLabel(groupId: groupId, epoch: epoch,
                                     sender: sender, generation: generation),
            length: 32 + 12)
        guard keyAndNonce.count == 32 + 12 else { throw MLSError.malformedKeyMaterial }

        let key = SymmetricKey(data: keyAndNonce.prefix(32))
        let nonce: AES.GCM.Nonce
        do {
            nonce = try AES.GCM.Nonce(data: keyAndNonce.suffix(12))
        } catch {
            throw MLSError.malformedKeyMaterial
        }
        return (key, nonce)
    }

    /// Per-(epoch, sender) ratchet-root context: `groupId ‖ epoch ‖ sender`.
    private static func ratchetLabel(groupId: Data, epoch: UInt64, sender: MLSLeafIndex) -> Data {
        var d = Data()
        d.append(groupId)
        withUnsafeBytes(of: epoch.bigEndian) { d.append(contentsOf: $0) }
        withUnsafeBytes(of: sender.value.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    /// Per-(epoch, sender, generation) key context: `groupId ‖ epoch ‖ sender ‖ generation`.
    private static func generationLabel(groupId: Data, epoch: UInt64,
                                        sender: MLSLeafIndex, generation: UInt32) -> Data {
        var d = ratchetLabel(groupId: groupId, epoch: epoch, sender: sender)
        withUnsafeBytes(of: generation.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    /// AES-GCM additional authenticated data: `groupId ‖ epoch ‖ sender ‖ generation`.
    /// Binds the ciphertext to its exact slot so it cannot be replayed under a
    /// different epoch/sender/generation header even if the AEAD key collided.
    private static func applicationAAD(groupId: Data, epoch: UInt64,
                                       sender: MLSLeafIndex, generation: UInt32) -> Data {
        generationLabel(groupId: groupId, epoch: epoch, sender: sender, generation: generation)
    }
}
