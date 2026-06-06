//
//  RatchetSession.swift
//  Gotogo
//
//  State, wire types, and typed errors for the Signal Double Ratchet
//  (per the "Double Ratchet" spec, revision 4). Pure Foundation — the
//  persistable session state; the algorithm lives in `DoubleRatchet.swift`.
//
//  This implements the RATCHET ONLY. The shared secret (from PQXDH) and the
//  initial X25519 ratchet keys are provided by the integrator as raw material.
//

import Foundation

// MARK: - Errors

/// Typed errors thrown by the Double Ratchet. Distinct cases let callers map
/// failures to user-facing states (e.g. "corrupt/tampered message" vs a logic
/// bug in supplied key material).
public enum RatchetError: Error, Equatable, Sendable {
    /// AEAD authentication failed: the ciphertext or its header (AAD) was
    /// tampered with, or the wrong message key was derived.
    case authenticationFailure
    /// Stored or wire key material had the wrong length / could not be parsed
    /// into an X25519 key.
    case malformedKeyMaterial
    /// The message references a skipped key that has already been used or was
    /// evicted from the bounded skipped-key cache (replay or too-old message).
    case skippedKeyUnavailable
    /// Decrypt was attempted before the receiver has established any receiving
    /// chain and the message carries no usable DH ratchet step.
    case receiveChainNotEstablished
}

// MARK: - Wire types

/// The plaintext header that travels (in the clear) with every ratchet message.
/// It is also serialized and fed to AES-GCM as additional authenticated data,
/// so any tampering with these fields fails decryption.
public struct RatchetHeader: Codable, Sendable, Equatable {
    /// Sender's current X25519 ratchet public key (32 raw bytes).
    public var dhPub: Data
    /// Number of messages in the sender's *previous* sending chain (`PN`).
    public var pn: Int
    /// Message number within the sender's *current* sending chain (`N`).
    public var n: Int

    public init(dhPub: Data, pn: Int, n: Int) {
        self.dhPub = dhPub
        self.pn = pn
        self.n = n
    }
}

/// A sealed ratchet message: the cleartext header plus the AEAD output. The
/// serialized header is the AAD, binding the ciphertext to its routing fields.
public struct RatchetMessage: Codable, Sendable, Equatable {
    public var header: RatchetHeader
    /// AES-GCM combined box (`nonce ‖ ciphertext ‖ tag`).
    public var ciphertext: Data

    public init(header: RatchetHeader, ciphertext: Data) {
        self.header = header
        self.ciphertext = ciphertext
    }
}

// MARK: - Session state

/// The full Double Ratchet state for one conversation. Every field is `Codable`
/// so the app can persist (and restore) the session per-conversation.
///
/// Naming follows the spec's state variables:
/// - `rootKey`            → `RK`
/// - `dhSelf*`            → `DHs` (our current ratchet key pair)
/// - `dhRemotePublic`     → `DHr` (their current ratchet public key, if known)
/// - `sendChainKey`       → `CKs`
/// - `recvChainKey`       → `CKr`
/// - `sendCount`          → `Ns`
/// - `recvCount`          → `Nr`
/// - `prevSendCount`      → `PN`
/// - `skippedKeys`        → `MKSKIPPED` (bounded)
public struct RatchetSession: Codable, Sendable, Equatable {

    /// 32-byte root key (`RK`). Stored raw; rotated on every DH ratchet step.
    public var rootKey: Data

    /// Our current ratchet key pair (`DHs`), stored as raw X25519 material.
    public var dhSelfPrivate: Data
    public var dhSelfPublic: Data

    /// Their current ratchet public key (`DHr`), 32 raw bytes. `nil` until the
    /// responder has seen the initiator's first header.
    public var dhRemotePublic: Data?

    /// Sending chain key (`CKs`), 32 raw bytes, or `nil` when no sending chain
    /// has been derived yet (responder before its first ratchet step).
    public var sendChainKey: Data?

    /// Receiving chain key (`CKr`), 32 raw bytes, or `nil` when no receiving
    /// chain exists yet (initiator before receiving anything).
    public var recvChainKey: Data?

    /// Message number in the current sending chain (`Ns`).
    public var sendCount: Int

    /// Message number in the current receiving chain (`Nr`).
    public var recvCount: Int

    /// Number of messages in the previous sending chain (`PN`).
    public var prevSendCount: Int

    /// Bounded store of skipped message keys, addressed by `(dhPub, n)`. Keeps
    /// out-of-order and skipped messages decryptable. Encoded as an array so the
    /// whole session round-trips through `Codable`.
    public var skippedKeys: [SkippedMessageKey]

    /// Maximum number of skipped message keys to retain across all chains. Once
    /// exceeded, the oldest entries are evicted (FIFO). Bounds memory and limits
    /// how far out-of-order delivery can reach back.
    public var maxSkip: Int

    public init(rootKey: Data,
                dhSelfPrivate: Data,
                dhSelfPublic: Data,
                dhRemotePublic: Data?,
                sendChainKey: Data?,
                recvChainKey: Data?,
                sendCount: Int,
                recvCount: Int,
                prevSendCount: Int,
                skippedKeys: [SkippedMessageKey],
                maxSkip: Int) {
        self.rootKey = rootKey
        self.dhSelfPrivate = dhSelfPrivate
        self.dhSelfPublic = dhSelfPublic
        self.dhRemotePublic = dhRemotePublic
        self.sendChainKey = sendChainKey
        self.recvChainKey = recvChainKey
        self.sendCount = sendCount
        self.recvCount = recvCount
        self.prevSendCount = prevSendCount
        self.skippedKeys = skippedKeys
        self.maxSkip = maxSkip
    }
}

// MARK: - Skipped key store entry

/// One cached message key for a message that has not yet arrived, keyed by the
/// sender ratchet public key it belongs to and its index in that chain.
public struct SkippedMessageKey: Codable, Sendable, Equatable {
    /// The sender ratchet public key (`DHr`) the skipped key was derived under.
    public var dhPub: Data
    /// Message index (`n`) within that receiving chain.
    public var n: Int
    /// The 32-byte message key itself.
    public var messageKey: Data

    public init(dhPub: Data, n: Int, messageKey: Data) {
        self.dhPub = dhPub
        self.n = n
        self.messageKey = messageKey
    }
}
