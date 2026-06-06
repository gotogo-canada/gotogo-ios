//
//  MLSGroup+Commit.swift  (MLS Commit / Process / Welcome-join — RFC 9420 §12)
//
//  Commit applies a batch of proposals and re-keys the committer's direct path in
//  one shot, advancing the group by one epoch. Every other current member calls
//  `process` with the same Commit and converges to the identical epoch secret by
//  re-deriving the tree and running the key schedule over the same group context.
//  A freshly Added member instead calls `join` with the Welcome: it never sees
//  the old init secret, so it is handed the new epoch's `joiner_secret` directly
//  (HPKE-sealed to its init key) and derives the epoch from that.
//
//  Removal lockout: a Remove blanks the target's leaf and its whole direct path
//  BEFORE the UpdatePath is built, so the committer re-keys every node above the
//  removed leaf and seals the new path secrets only to the *remaining* members'
//  resolutions. The removed member's stale private keys agree to none of the new
//  ephemeral KEM keys, so `MLSHPKE.open` fails its AEAD tag — it cannot recover
//  the commit secret and is locked out of the new epoch.
//
//  Pure Foundation + CryptoKit.
//
import Foundation
import CryptoKit

extension MLSGroup {

    /// Builds a fresh KeyPackage (+ private) for re-keying a leaf on Update/Commit.
    public static func freshKeyPackage(signaturePublicKey: Data = Data(count: 32),
                                       signaturePrivate: Data = Data(count: 32)) -> MLSKeyPackagePrivate {
        let initK = Curve25519.KeyAgreement.PrivateKey()
        let leafK = Curve25519.KeyAgreement.PrivateKey()
        let kp = MLSKeyPackage(initKey: initK.publicKey.rawRepresentation,
                               leafKey: leafK.publicKey.rawRepresentation,
                               signaturePublicKey: signaturePublicKey)
        return MLSKeyPackagePrivate(initPrivate: initK.rawRepresentation,
                                    leafPrivate: leafK.rawRepresentation,
                                    signaturePrivate: signaturePrivate, keyPackage: kp)
    }

    // MARK: - Commit (committer side)

    /// Commits `proposals`, re-keying this member's direct path. Mutates the group
    /// into the next epoch and returns the wire `MLSCommit` (for existing members
    /// to `process`) plus a `MLSWelcome` for any Added members. The committer's own
    /// leaf is rotated as part of the path (this is the Update component).
    public mutating func commit(_ proposals: [MLSProposal]) throws -> (commit: MLSCommit, welcome: MLSWelcome?) {
        var working = tree
        var addedLeaves: [(MLSLeafIndex, MLSKeyPackage)] = []

        // 1) Apply membership changes to the working tree (pre-path).
        for p in proposals {
            switch p {
            case .add(let kp):
                let leaf = working.freeLeaf()
                working.setLeaf(leaf, publicKey: kp.leafKey, privateKey: nil)
                // Blank the new leaf's direct path so its (still-private-less) parents
                // don't appear in resolutions until this commit re-keys them.
                for n in working.directPath(of: leaf) { working.blank(n) }
                addedLeaves.append((leaf, kp))
            case .remove(let leaf):
                working.blank(MLSRatchetTree.nodeIndex(ofLeaf: leaf))
                for n in working.directPath(of: leaf) { working.blank(n) }
            case .update:
                break   // committer's own update is the fresh leaf below
            }
        }

        // 2) Rotate the committer's leaf (fresh key package) and re-key the path.
        let fresh = MLSGroup.freshKeyPackage(signaturePublicKey: myKeyPackage.keyPackage.signaturePublicKey,
                                             signaturePrivate: myKeyPackage.signaturePrivate)
        working.setLeaf(myLeaf, publicKey: fresh.keyPackage.leafKey, privateKey: fresh.leafPrivate)

        let prevInit = secrets.initSecret
        let nextEpoch = epoch + 1

        // Path HPKE seals are bound to a context BOTH sides can compute before the
        // new path keys exist: the working tree with the committer's whole direct
        // path blanked (so the hash doesn't depend on the not-yet-known path keys).
        let provisionalCommit = MLSCommit(proposals: proposals,
                                          path: MLSUpdatePath(leafKeyPackage: fresh.keyPackage, nodes: []))
        let newTranscript = MLSGroup.updateTranscript(confirmedTranscriptHash, commit: provisionalCommit)
        let pathCtx = MLSGroup.groupContext(groupId: groupId, epoch: nextEpoch,
                                            tree: MLSGroup.pathContextTree(working, committer: myLeaf),
                                            transcriptHash: newTranscript)

        let built = MLSTreeKEM.createUpdatePath(tree: working, committer: myLeaf,
                                                leafKeyPackage: fresh.keyPackage, groupContext: pathCtx)
        var newTree = built.tree
        // Re-inject the committer's fresh leaf private key (createUpdatePath leaves
        // the published leaf public-only).
        newTree.setLeaf(myLeaf, publicKey: fresh.keyPackage.leafKey, privateKey: fresh.leafPrivate)

        // 3) Advance the key schedule into the new epoch.
        let finalCtx = MLSGroup.groupContext(groupId: groupId, epoch: nextEpoch,
                                             tree: newTree, transcriptHash: newTranscript)
        let newSecrets = MLSKeySchedule.deriveEpoch(initSecret: prevInit,
                                                    commitSecret: built.commitSecret,
                                                    groupContext: finalCtx)

        // 4) Commit local state.
        self.tree = newTree
        self.epoch = nextEpoch
        self.confirmedTranscriptHash = newTranscript
        self.secrets = newSecrets
        self.myKeyPackage = MLSKeyPackagePrivate(initPrivate: myKeyPackage.initPrivate,
                                                 leafPrivate: fresh.leafPrivate,
                                                 signaturePrivate: myKeyPackage.signaturePrivate,
                                                 keyPackage: fresh.keyPackage)

        let commit = MLSCommit(proposals: proposals, path: built.path)

        // 5) Welcome the Added members with the new epoch's joiner secret.
        var welcome: MLSWelcome? = nil
        if !addedLeaves.isEmpty {
            var ws: [MLSWelcomeSecret] = []
            let info = MLSGroup.welcomeInfo(finalCtx)
            for (leaf, kp) in addedLeaves {
                if let sealed = try? MLSHPKE.seal(newSecrets.joinerSecret, toPublicKey: kp.initKey,
                                                  info: info, aad: finalCtx) {
                    ws.append(MLSWelcomeSecret(leaf: leaf, initKeyHint: kp.initKey, sealed: sealed))
                }
            }
            welcome = MLSWelcome(groupId: groupId, epoch: nextEpoch, ratchetTreePublic: newTree.publicView(),
                                 confirmedTranscriptHash: newTranscript, secrets: ws)
        }
        return (commit, welcome)
    }

    /// The tree state both committer and receiver hash for the PATH context: the
    /// post-membership-change tree with the committer's entire direct path blanked
    /// (the committer's leaf keeps its fresh public key). Identical on both sides
    /// and independent of the freshly-derived path keys, breaking the circular
    /// "context needs path, path needs context" dependency.
    static func pathContextTree(_ tree: MLSRatchetTree, committer: MLSLeafIndex) -> MLSRatchetTree {
        var t = tree
        for n in t.directPath(of: committer) { t.blank(n) }
        return t
    }

    // MARK: - process (existing member side)

    /// Processes a Commit produced by `committer`, advancing this member to the
    /// next epoch. Re-applies the same membership changes, applies the UpdatePath
    /// (recovering the commit secret), and re-runs the key schedule. Throws if the
    /// UpdatePath cannot be opened with this member's keys (e.g. it was removed).
    public mutating func process(_ commit: MLSCommit, from committer: MLSLeafIndex) throws {
        var working = tree
        for p in commit.proposals {
            switch p {
            case .add(let kp):
                let leaf = working.freeLeaf()
                working.setLeaf(leaf, publicKey: kp.leafKey, privateKey: nil)
                for n in working.directPath(of: leaf) { working.blank(n) }
            case .remove(let leaf):
                working.blank(MLSRatchetTree.nodeIndex(ofLeaf: leaf))
                for n in working.directPath(of: leaf) { working.blank(n) }
            case .update:
                break
            }
        }

        let prevInit = secrets.initSecret
        let nextEpoch = epoch + 1
        let newTranscript = MLSGroup.updateTranscript(confirmedTranscriptHash, commit: commit)
        // Same path context the committer sealed against: working tree with the
        // committer's direct path blanked, the committer's fresh leaf public key,
        // next epoch, updated transcript.
        var pathBase = working
        pathBase.setLeaf(committer, publicKey: commit.path.leafKeyPackage.leafKey, privateKey: nil)
        let pathCtx = MLSGroup.groupContext(groupId: groupId, epoch: nextEpoch,
                                            tree: MLSGroup.pathContextTree(pathBase, committer: committer),
                                            transcriptHash: newTranscript)

        let applied = try MLSTreeKEM.applyUpdatePath(tree: working, committer: committer,
                                                     path: commit.path, myLeaf: myLeaf, groupContext: pathCtx)
        let newTree = applied.tree
        let finalCtx = MLSGroup.groupContext(groupId: groupId, epoch: nextEpoch,
                                             tree: newTree, transcriptHash: newTranscript)
        let newSecrets = MLSKeySchedule.deriveEpoch(initSecret: prevInit,
                                                    commitSecret: applied.commitSecret,
                                                    groupContext: finalCtx)
        self.tree = newTree
        self.epoch = nextEpoch
        self.confirmedTranscriptHash = newTranscript
        self.secrets = newSecrets
    }

    // MARK: - join (newly added member side)

    /// Joins via a Welcome: recovers the epoch's joiner secret (sealed to this
    /// member's init key), rebuilds the public tree, injects its own leaf private
    /// key, and derives the epoch. After this the member shares the epoch secret
    /// and can `process` subsequent commits (its leaf key opens the paths sealed
    /// to it while its parents remain blank).
    public static func join(welcome: MLSWelcome, keyPackage: MLSKeyPackagePrivate) throws -> MLSGroup {
        guard let mine = welcome.secrets.first(where: { $0.initKeyHint == keyPackage.keyPackage.initKey })
        else { throw MLSError.noMatchingKeyPackage }

        var tree = MLSRatchetTree.fromPublicView(welcome.ratchetTreePublic)
        // Inject our own leaf private key so we can decrypt future UpdatePaths.
        tree.setLeaf(mine.leaf, publicKey: keyPackage.keyPackage.leafKey, privateKey: keyPackage.leafPrivate)

        let ctx = MLSGroup.groupContext(groupId: welcome.groupId, epoch: welcome.epoch, tree: tree,
                                        transcriptHash: welcome.confirmedTranscriptHash)
        let info = MLSGroup.welcomeInfo(ctx)
        let joiner = try MLSHPKE.open(mine.sealed, privateKey: keyPackage.initPrivate, info: info, aad: ctx)
        let secrets = MLSKeySchedule.deriveEpoch(fromJoinerSecret: joiner, groupContext: ctx)

        return MLSGroup(groupId: welcome.groupId, epoch: welcome.epoch, tree: tree, myLeaf: mine.leaf,
                        myKeyPackage: keyPackage, confirmedTranscriptHash: welcome.confirmedTranscriptHash,
                        secrets: secrets)
    }
}
