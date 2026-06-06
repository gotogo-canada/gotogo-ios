//
//  MLSTypes.swift  (MLS / RFC 9420 TreeKEM — shared types)
//
//  Public wire-style types and persistable key containers for the MLS group
//  key-agreement core. This is an MLS-FAITHFUL design on Apple CryptoKit, NOT a
//  byte-for-byte RFC 9420 TLS-presentation codec: structs are Codable rather
//  than serialized with the TLS encoding (the one documented deviation). Every
//  cryptographic operation — labeled HKDF, X25519 + AES-256-GCM "HPKE", the
//  ratchet tree, the key schedule — follows RFC 9420 semantics.
//
//  Pure Foundation + CryptoKit. All identifiers carry the `MLS` prefix.
//
import Foundation

/// Typed errors thrown across the MLS core. Distinct cases let callers tell a
/// corrupt/tampered message apart from a stale-key lockout (a removed member).
public enum MLSError: Error, Equatable, Sendable {
    /// Stored or wire key material had the wrong length / failed to parse.
    case malformedKeyMaterial
    /// AES-GCM authentication failed (tampered ciphertext, or a stale/wrong key).
    case authenticationFailure
    /// A leaf or node index addressed a slot outside the tree.
    case indexOutOfRange
    /// A proposal/commit referenced a member that is not in the group.
    case unknownMember
    /// The UpdatePath could not be applied (no decryptable copath node).
    case cannotDecryptPath
    /// A Welcome referenced a key package this member does not hold the secret for.
    case noMatchingKeyPackage
    /// The group is empty or the requested epoch state is unavailable.
    case invalidState
}

/// A leaf index in the ratchet tree: the public identity of one group member.
/// Leaf `i` occupies node index `2*i` in the array-packed tree.
public struct MLSLeafIndex: Hashable, Codable, Sendable, Comparable {
    public var value: UInt32
    public init(_ value: UInt32) { self.value = value }
    public init(_ value: Int) { self.value = UInt32(value) }
    public static func < (a: MLSLeafIndex, b: MLSLeafIndex) -> Bool { a.value < b.value }
}

/// A KeyPackage: the public material a prospective member publishes so others
/// can Add it. `initKey` is the HPKE (X25519) public key a Welcome is sealed to;
/// `leafKey` is the member's current leaf HPKE public key in the tree;
/// `signaturePublicKey` is its long-term Ed25519 identity (signs nothing in this
/// core's reduced flow but is carried so the design stays MLS-shaped).
public struct MLSKeyPackage: Codable, Sendable, Equatable {
    public var initKey: Data            // X25519 raw public (32)
    public var leafKey: Data            // X25519 raw public (32)
    public var signaturePublicKey: Data // Ed25519 raw public (32)
    public init(initKey: Data, leafKey: Data, signaturePublicKey: Data) {
        self.initKey = initKey; self.leafKey = leafKey
        self.signaturePublicKey = signaturePublicKey
    }
}

/// The private half of a KeyPackage, held only by the owning member: the X25519
/// secret behind `initKey` (opens a Welcome) and behind the current `leafKey`
/// (opens UpdatePath nodes on the member's direct path). Persistable.
public struct MLSKeyPackagePrivate: Codable, Sendable, Equatable {
    public var initPrivate: Data        // X25519 raw private (32)
    public var leafPrivate: Data        // X25519 raw private (32)
    public var signaturePrivate: Data   // Ed25519 raw private (32)
    public var keyPackage: MLSKeyPackage
    public init(initPrivate: Data, leafPrivate: Data, signaturePrivate: Data, keyPackage: MLSKeyPackage) {
        self.initPrivate = initPrivate; self.leafPrivate = leafPrivate
        self.signaturePrivate = signaturePrivate; self.keyPackage = keyPackage
    }
}

/// One ciphertext entry of an UpdatePath: a parent node's path secret sealed to
/// exactly one public key in the copath resolution defined by RFC 9420.
public struct MLSPathCiphertext: Codable, Sendable, Equatable {
    public var sealed: MLSHPKECiphertext
    public init(sealed: MLSHPKECiphertext) { self.sealed = sealed }
}

/// One node level of an UpdatePath: the fresh public key for a node on the
/// committer's direct path, plus the path secret sealed to each resolved
/// public key of that node's copath child.
public struct MLSUpdatePathNode: Codable, Sendable, Equatable {
    public var publicKey: Data                 // new node X25519 public (32)
    public var encryptedPathSecret: [MLSPathCiphertext]
    public init(publicKey: Data, encryptedPathSecret: [MLSPathCiphertext]) {
        self.publicKey = publicKey; self.encryptedPathSecret = encryptedPathSecret
    }
}

/// A full UpdatePath: the committer's refreshed leaf key package and the chain
/// of node levels from the leaf's parent up to the root.
public struct MLSUpdatePath: Codable, Sendable, Equatable {
    public var leafKeyPackage: MLSKeyPackage
    public var nodes: [MLSUpdatePathNode]
    public init(leafKeyPackage: MLSKeyPackage, nodes: [MLSUpdatePathNode]) {
        self.leafKeyPackage = leafKeyPackage; self.nodes = nodes
    }
}

/// The three MLS proposal kinds handled by this core.
public enum MLSProposal: Codable, Sendable, Equatable {
    case add(MLSKeyPackage)        // admit a new member at the next free leaf
    case update(MLSKeyPackage)     // committer rotates its own leaf (carried in path)
    case remove(MLSLeafIndex)      // blank a member's leaf + direct path
}

/// A Commit: the ordered proposals it applies plus the UpdatePath that re-keys
/// the committer's direct path (and thus the whole tree above the joins/removes).
public struct MLSCommit: Codable, Sendable, Equatable {
    public var proposals: [MLSProposal]
    public var path: MLSUpdatePath
    public init(proposals: [MLSProposal], path: MLSUpdatePath) {
        self.proposals = proposals; self.path = path
    }
}

/// One secret a Welcome carries to a single joiner: the `joiner_secret` (and the
/// committer's path secret entry, if the joiner sits on the committer's copath)
/// sealed to the joiner's KeyPackage `initKey`. The joiner is told its leaf index
/// and is handed the full public tree separately (the `ratchetTreePublic`).
public struct MLSWelcomeSecret: Codable, Sendable, Equatable {
    public var leaf: MLSLeafIndex
    public var initKeyHint: Data            // joiner initKey this is sealed to (32)
    public var sealed: MLSHPKECiphertext    // seals the GroupSecrets blob
    public init(leaf: MLSLeafIndex, initKeyHint: Data, sealed: MLSHPKECiphertext) {
        self.leaf = leaf; self.initKeyHint = initKeyHint; self.sealed = sealed
    }
}

/// A Welcome message: per-joiner sealed secrets plus the public ratchet tree and
/// the group context needed to recompute the epoch from the joiner secret.
public struct MLSWelcome: Codable, Sendable, Equatable {
    public var groupId: Data
    public var epoch: UInt64
    public var ratchetTreePublic: [Data?]   // node public keys (nil == blank)
    public var confirmedTranscriptHash: Data
    public var secrets: [MLSWelcomeSecret]
    public init(groupId: Data, epoch: UInt64, ratchetTreePublic: [Data?],
                confirmedTranscriptHash: Data, secrets: [MLSWelcomeSecret]) {
        self.groupId = groupId; self.epoch = epoch
        self.ratchetTreePublic = ratchetTreePublic
        self.confirmedTranscriptHash = confirmedTranscriptHash; self.secrets = secrets
    }
}
