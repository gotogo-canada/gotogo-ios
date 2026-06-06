//
//  MLSKeySchedule.swift  (MLS key schedule — RFC 9420 §8)
//
//  The labeled HKDF and the per-epoch secret derivations that turn a commit
//  secret + the previous epoch's init secret into a fresh epoch's secrets. All
//  expansions go through MLS `ExpandWithLabel` / `DeriveSecret`, so every output
//  is domain-separated by an ASCII label and bound to the group context.
//
//  Chain per epoch (forward secret + post-compromise secure across epochs):
//      joiner_secret   = ExpandWithLabel(Extract(init_secret_prev, commit_secret),
//                                        "joiner", group_context)
//      epoch_secret    = ExpandWithLabel(Extract(joiner_secret, psk=0),
//                                        "epoch",  group_context)
//      X_secret        = DeriveSecret(epoch_secret, "X")   for X in
//                        { encryption, exporter, confirm, init }
//  The next epoch consumes `init_secret`, so a compromise of one epoch's leaf
//  keys does not reveal past epochs, and a fresh commit heals future ones.
//
//  Pure Foundation + CryptoKit.
//
import Foundation
import CryptoKit

/// The full set of secrets derived for one epoch. `initSecret` seeds the *next*
/// epoch's key schedule; the rest are this epoch's working secrets.
public struct MLSEpochSecrets: Codable, Sendable, Equatable {
    public var joinerSecret: Data
    public var epochSecret: Data
    public var encryptionSecret: Data
    public var exporterSecret: Data
    public var confirmationKey: Data
    public var initSecret: Data
    public init(joinerSecret: Data, epochSecret: Data, encryptionSecret: Data,
                exporterSecret: Data, confirmationKey: Data, initSecret: Data) {
        self.joinerSecret = joinerSecret; self.epochSecret = epochSecret
        self.encryptionSecret = encryptionSecret; self.exporterSecret = exporterSecret
        self.confirmationKey = confirmationKey; self.initSecret = initSecret
    }
}

public enum MLSKeySchedule {

    /// MLS hash/KDF output size for the ciphersuite (SHA-256 ⇒ 32 bytes).
    public static let secretSize = 32

    // MARK: - Labeled KDF (RFC 9420 §8.1)

    /// `KDF.Extract` = HKDF-Extract(salt, ikm). Used to absorb the commit secret
    /// into the previous init secret (and a zero PSK into the joiner secret).
    public static func extract(salt: Data, ikm: Data) -> Data {
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: ikm),
                                       salt: salt)
        return prk.withUnsafeBytes { Data($0) }
    }

    /// `ExpandWithLabel(secret, label, context, length)`: HKDF-Expand over the
    /// MLS-framed label `"MLS 1.0 " ‖ label` and the bound `context`.
    public static func expandWithLabel(secret: Data, label: String, context: Data,
                                       length: Int = secretSize) -> Data {
        var fullLabel = Data("MLS 1.0 ".utf8)
        fullLabel.append(Data(label.utf8))
        // KDFLabel = length(2) ‖ vec(label) ‖ vec(context)  (vec = len-prefixed)
        var info = Data()
        appendU16(&info, UInt16(length))
        appendVar(&info, fullLabel)
        appendVar(&info, context)
        // `secret` is already a pseudo-random key (a PRK or a prior DeriveSecret
        // output), so this is HKDF-Expand only, matching MLS ExpandWithLabel.
        let okm = HKDF<SHA256>.expand(pseudoRandomKey: SymmetricKey(data: secret),
                                      info: info, outputByteCount: length)
        return okm.withUnsafeBytes { Data($0) }
    }

    /// `DeriveSecret(secret, label)` = `ExpandWithLabel(secret, label, "", Nh)`.
    public static func deriveSecret(secret: Data, label: String) -> Data {
        expandWithLabel(secret: secret, label: label, context: Data(), length: secretSize)
    }

    // MARK: - Epoch derivation (RFC 9420 §8)

    /// Derives a full epoch from the previous epoch's `initSecret`, this commit's
    /// `commitSecret` (root path secret of the UpdatePath, or zero for a path-less
    /// commit), and the `groupContext` (group id ‖ epoch ‖ tree/transcript hash).
    public static func deriveEpoch(initSecret: Data, commitSecret: Data,
                                   groupContext: Data) -> MLSEpochSecrets {
        // joiner_secret = ExpandWithLabel(Extract(init_secret, commit_secret),
        //                                 "joiner", group_context)
        let joinerPRK = extract(salt: initSecret, ikm: commitSecret)
        let joinerSecret = expandWithLabel(secret: joinerPRK, label: "joiner", context: groupContext)
        return deriveEpoch(fromJoinerSecret: joinerSecret, groupContext: groupContext)
    }

    /// Derives a full epoch from a known `joinerSecret` — the path a Welcome'd
    /// member takes, since it receives the joiner secret directly and never sees
    /// the previous init secret or the commit secret.
    public static func deriveEpoch(fromJoinerSecret joinerSecret: Data,
                                   groupContext: Data) -> MLSEpochSecrets {
        // epoch_secret = ExpandWithLabel(Extract(joiner_secret, 0), "epoch", ctx)
        let zeroPSK = Data(repeating: 0, count: secretSize)
        let memberPRK = extract(salt: joinerSecret, ikm: zeroPSK)
        let epochSecret = expandWithLabel(secret: memberPRK, label: "epoch", context: groupContext)
        return MLSEpochSecrets(
            joinerSecret: joinerSecret,
            epochSecret: epochSecret,
            encryptionSecret: deriveSecret(secret: epochSecret, label: "encryption"),
            exporterSecret: deriveSecret(secret: epochSecret, label: "exporter"),
            confirmationKey: deriveSecret(secret: epochSecret, label: "confirm"),
            initSecret: deriveSecret(secret: epochSecret, label: "init"))
    }

    /// MLS exporter (RFC 9420 §8.5): a labeled, context-bound secret applications
    /// can pull from an epoch without touching the epoch secret itself.
    public static func exporter(exporterSecret: Data, label: String, context: Data,
                                length: Int = secretSize) -> Data {
        let derived = deriveSecret(secret: exporterSecret, label: label)
        let ctxHash = Data(SHA256.hash(data: context))
        return expandWithLabel(secret: derived, label: "exported", context: ctxHash, length: length)
    }

    // MARK: - encoding helpers

    private static func appendU16(_ d: inout Data, _ v: UInt16) {
        withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) }
    }
    /// Length-prefixed vector (2-byte big-endian length). Used to frame the label
    /// and context so the HKDF info is unambiguous; the exact prefix width is an
    /// internal convention (this core does not target byte-level RFC interop).
    private static func appendVar(_ d: inout Data, _ v: Data) {
        appendU16(&d, UInt16(v.count)); d.append(v)
    }
}
