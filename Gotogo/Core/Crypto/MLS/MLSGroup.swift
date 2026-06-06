//
//  MLSGroup.swift  (MLS high-level group — RFC 9420 §8, §12)
//
//  The member-facing group object: create a group, build Add/Update/Remove
//  proposals, Commit them (producing an UpdatePath + a Welcome for new members),
//  process an incoming Commit, and read the epoch's `epochSecret` / `exporter`.
//  It ties the ratchet tree (key material), TreeKEM (the path re-key), and the
//  key schedule (epoch secrets) together, advancing one EPOCH per Commit so the
//  group ratchet provides forward secrecy and post-compromise security.
//
//  Group context (bound into every derivation and HPKE seal):
//      group_context = group_id ‖ epoch ‖ tree_hash ‖ confirmed_transcript_hash
//  The confirmed transcript hash chains every commit, so two members converge to
//  the same epoch secret iff they applied the identical commit history.
//
//  Pure Foundation + CryptoKit. Commit/Welcome construction lives in
//  `MLSGroup+Commit.swift`.
//
import Foundation
import CryptoKit

public struct MLSGroup: Codable, Sendable, Equatable {

    // MARK: - state

    public let groupId: Data
    public internal(set) var epoch: UInt64
    public internal(set) var tree: MLSRatchetTree
    /// This member's leaf index.
    public let myLeaf: MLSLeafIndex
    /// This member's KeyPackage secrets (init + current leaf private keys).
    public internal(set) var myKeyPackage: MLSKeyPackagePrivate
    /// Running confirmed transcript hash (chains commits across epochs).
    public internal(set) var confirmedTranscriptHash: Data
    /// The current epoch's derived secrets.
    public internal(set) var secrets: MLSEpochSecrets

    // MARK: - read accessors

    /// The epoch secret every current member converges to. Distinct each epoch.
    public var epochSecret: Data { secrets.epochSecret }
    /// MLS exporter (RFC 9420 §8.5): reproducible by every current member.
    public func exporter(label: String, context: Data, length: Int = 32) -> Data {
        MLSKeySchedule.exporter(exporterSecret: secrets.exporterSecret,
                                label: label, context: context, length: length)
    }

    // MARK: - group context (RFC 9420 §8.1)

    /// Binds id ‖ epoch ‖ tree hash ‖ transcript hash. Recomputed whenever the
    /// tree or epoch changes so it always reflects the *current* group state.
    public func groupContext() -> Data {
        MLSGroup.groupContext(groupId: groupId, epoch: epoch, tree: tree,
                              transcriptHash: confirmedTranscriptHash)
    }
    static func groupContext(groupId: Data, epoch: UInt64, tree: MLSRatchetTree,
                             transcriptHash: Data) -> Data {
        var d = Data()
        d.append(groupId)
        withUnsafeBytes(of: epoch.bigEndian) { d.append(contentsOf: $0) }
        d.append(treeHash(tree))
        d.append(transcriptHash)
        return d
    }

    /// A hash over the tree's public node keys — folds the whole membership /
    /// key state into the group context so any tree divergence changes the epoch.
    static func treeHash(_ tree: MLSRatchetTree) -> Data {
        var h = SHA256()
        withUnsafeBytes(of: UInt32(tree.nodeCount).bigEndian) { h.update(data: Data($0)) }
        for node in tree.nodes {
            if let pk = node.publicKey { h.update(data: Data([1])); h.update(data: pk) }
            else { h.update(data: Data([0])) }
        }
        return Data(h.finalize())
    }

    /// Updates the confirmed transcript hash with one commit:
    /// `H(prev_transcript ‖ proposals ‖ committer_leaf_key)`. Hashes only fields
    /// known to BOTH the committer (before it derives the path) and every
    /// receiver: the ordered proposals and the committer's fresh leaf key. The
    /// per-node path public keys are deliberately excluded so the committer's
    /// pre-path provisional transcript and a receiver's post-path transcript are
    /// identical — they must be, since the transcript feeds the path-seal context.
    static func updateTranscript(_ prev: Data, commit: MLSCommit) -> Data {
        var h = SHA256()
        h.update(data: prev)
        for p in commit.proposals {
            switch p {
            case .add(let kp): h.update(data: Data([0x01])); h.update(data: kp.leafKey)
            case .update(let kp): h.update(data: Data([0x02])); h.update(data: kp.leafKey)
            case .remove(let leaf):
                h.update(data: Data([0x03]))
                withUnsafeBytes(of: leaf.value.bigEndian) { h.update(data: Data($0)) }
            }
        }
        h.update(data: commit.path.leafKeyPackage.leafKey)
        return Data(h.finalize())
    }

    // MARK: - create (founder, epoch 0)

    /// Founds a group from the founder's KeyPackage and the other members' public
    /// KeyPackages (placed at leaves 1..k). The founder seeds every leaf's public
    /// key and derives epoch 0 from a fresh init secret; members reach the same
    /// epoch-0 secret by reconstructing this exact tree from the Welcome and the
    /// shared `epoch0JoinerSecret` the founder distributes.
    public static func create(groupId: Data, founder: MLSKeyPackagePrivate,
                              members: [MLSKeyPackage]) -> (group: MLSGroup, welcome: MLSWelcome) {
        var tree = MLSRatchetTree(leafCount: max(1, members.count + 1))
        // Founder at leaf 0 (it alone holds the leaf private key).
        tree.setLeaf(MLSLeafIndex(0), publicKey: founder.keyPackage.leafKey,
                     privateKey: founder.leafPrivate)
        for (i, kp) in members.enumerated() {
            tree.setLeaf(MLSLeafIndex(i + 1), publicKey: kp.leafKey, privateKey: nil)
        }

        let epoch: UInt64 = 0
        let transcript = Data(SHA256.hash(data: groupId))   // genesis transcript
        let ctx = groupContext(groupId: groupId, epoch: epoch, tree: tree, transcriptHash: transcript)

        // A fresh random joiner secret defines epoch 0; everyone derives from it.
        var joiner = Data(count: MLSKeySchedule.secretSize)
        joiner.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, MLSKeySchedule.secretSize, $0.baseAddress!) }
        let secrets = MLSKeySchedule.deriveEpoch(fromJoinerSecret: joiner, groupContext: ctx)

        let group = MLSGroup(groupId: groupId, epoch: epoch, tree: tree, myLeaf: MLSLeafIndex(0),
                             myKeyPackage: founder, confirmedTranscriptHash: transcript, secrets: secrets)

        // Welcome the initial members: seal the epoch-0 joiner secret to each.
        var welcomeSecrets: [MLSWelcomeSecret] = []
        let info = welcomeInfo(ctx)
        for (i, kp) in members.enumerated() {
            if let sealed = try? MLSHPKE.seal(joiner, toPublicKey: kp.initKey, info: info, aad: ctx) {
                welcomeSecrets.append(MLSWelcomeSecret(leaf: MLSLeafIndex(i + 1),
                                                       initKeyHint: kp.initKey, sealed: sealed))
            }
        }
        let welcome = MLSWelcome(groupId: groupId, epoch: epoch, ratchetTreePublic: tree.publicView(),
                                 confirmedTranscriptHash: transcript, secrets: welcomeSecrets)
        return (group, welcome)
    }

    /// HKDF info label for Welcome HPKE seals (separate from path seals).
    static func welcomeInfo(_ groupContext: Data) -> Data {
        var d = Data("MLS 1.0 Welcome".utf8); d.append(groupContext); return d
    }

    // MARK: - proposals (RFC 9420 §12.1)

    /// Add proposal: admit a member with this public KeyPackage.
    public func proposeAdd(_ kp: MLSKeyPackage) -> MLSProposal { .add(kp) }
    /// Update proposal: this member rotates its own leaf (new key in `kp`).
    public func proposeUpdate(_ kp: MLSKeyPackage) -> MLSProposal { .update(kp) }
    /// Remove proposal: evict the member at `leaf`.
    public func proposeRemove(_ leaf: MLSLeafIndex) -> MLSProposal { .remove(leaf) }
}
