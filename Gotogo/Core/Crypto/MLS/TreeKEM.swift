//
//  TreeKEM.swift  (MLS TreeKEM — UpdatePath create/apply, RFC 9420 §7.4–§7.5)
//
//  TreeKEM re-keys a member's whole direct path in one Commit. The committer
//  draws a fresh leaf secret, then walks up to the root deriving a chain of PATH
//  SECRETS — `path_secret[i+1] = DeriveSecret(path_secret[i], "path")`. Each path
//  secret deterministically yields that node's HPKE key pair via
//  `DeriveKeyPair(DeriveSecret(path_secret, "node"))`, so every member that
//  learns a node's path secret can reproduce its private key. The committer then
//  seals each parent's path secret to the RESOLUTION of the matching copath node
//  — i.e. to exactly the members in the sibling subtree — producing an
//  UpdatePath. The top path secret becomes the epoch's COMMIT SECRET.
//
//  Applying an UpdatePath: a receiver finds the lowest node on its own direct
//  path whose copath resolution contains a key it holds, opens that ciphertext to
//  recover the path secret, and re-derives every node from there to the root.
//
//  Pure Foundation + CryptoKit.
//
import Foundation
import CryptoKit

public enum MLSTreeKEM {

    /// HKDF info label binding TreeKEM HPKE seals to the group context.
    private static func pathInfo(_ groupContext: Data) -> Data {
        var d = Data("MLS 1.0 UpdatePathNode".utf8); d.append(groupContext); return d
    }

    // MARK: - path-secret → key pair (RFC 9420 §7.4)

    /// Derives a node X25519 key pair deterministically from a path secret:
    /// `node_secret = DeriveSecret(path_secret, "node")`, used as the X25519 seed.
    public static func deriveKeyPair(fromPathSecret pathSecret: Data) -> (priv: Data, pub: Data) {
        let nodeSecret = MLSKeySchedule.deriveSecret(secret: pathSecret, label: "node")
        // Use the 32-byte node secret directly as the X25519 private scalar; CryptoKit
        // clamps internally. Deterministic ⇒ every holder of the secret agrees.
        let priv = (try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: nodeSecret))
            ?? Curve25519.KeyAgreement.PrivateKey()
        return (priv.rawRepresentation, priv.publicKey.rawRepresentation)
    }

    /// Next path secret up the tree: `DeriveSecret(path_secret, "path")`.
    public static func nextPathSecret(_ pathSecret: Data) -> Data {
        MLSKeySchedule.deriveSecret(secret: pathSecret, label: "path")
    }

    // MARK: - create UpdatePath (committer side, RFC 9420 §7.5)

    /// Re-keys `tree` along `committer`'s direct path. Returns the rebuilt tree
    /// (with the committer's fresh private keys merged in), the UpdatePath to ship
    /// to everyone else, the COMMIT SECRET (root path secret), and the per-level
    /// path secrets keyed by node index (so Welcome can hand the right entry to a
    /// brand-new joiner sitting on the committer's copath).
    public static func createUpdatePath(tree: MLSRatchetTree, committer: MLSLeafIndex,
                                        leafKeyPackage: MLSKeyPackage,
                                        groupContext: Data)
        -> (tree: MLSRatchetTree, path: MLSUpdatePath, commitSecret: Data,
            pathSecrets: [Int: Data]) {

        var t = tree
        let leafNode = MLSRatchetTree.nodeIndex(ofLeaf: committer)
        let dirPath = t.directPath(of: committer)
        let coPath = t.copath(of: committer)

        // Fresh leaf secret seeds the chain. The committer's leaf key pair is
        // taken from the (already freshly generated) leafKeyPackage so its private
        // half is the one the caller persists.
        var leafSecret = Data(count: 32)
        leafSecret.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        var pathSecretByNode: [Int: Data] = [:]
        var current = leafSecret
        var nodes: [MLSUpdatePathNode] = []
        let info = pathInfo(groupContext)

        for (idx, node) in dirPath.enumerated() {
            current = nextPathSecret(current)            // path_secret for this node
            pathSecretByNode[node] = current
            let kp = deriveKeyPair(fromPathSecret: current)
            t[node] = MLSTreeNode(publicKey: kp.pub, privateKey: kp.priv)

            // Seal this path secret to every public key in the copath sibling's
            // resolution (the members who must learn it).
            let sibling = coPath[idx]
            let recipients = t.resolution(of: sibling)
            var cts: [MLSPathCiphertext] = []
            for r in recipients {
                guard let pub = t[r].publicKey else { continue }
                let sealed = try? MLSHPKE.seal(current, toPublicKey: pub, info: info, aad: groupContext)
                if let sealed { cts.append(MLSPathCiphertext(sealed: sealed)) }
            }
            nodes.append(MLSUpdatePathNode(publicKey: kp.pub, encryptedPathSecret: cts))
        }

        // Merge the committer's fresh leaf key pair into the tree. The committer
        // keeps the leaf private key out-of-band (in its KeyPackagePrivate); only
        // the public key is published here.
        t[leafNode] = MLSTreeNode(publicKey: leafKeyPackage.leafKey, privateKey: nil)
        // `current` now holds the ROOT node's path secret. The commit secret is one
        // DeriveSecret step above the root (matches the receiver's apply step).
        let commitSecret = nextPathSecret(current)

        let path = MLSUpdatePath(leafKeyPackage: leafKeyPackage, nodes: nodes)
        return (t, path, commitSecret, pathSecretByNode)
    }

    // MARK: - apply UpdatePath (receiver side)

    /// Applies `path` (committed by leaf `committer`) to the receiver's `tree`.
    /// `myLeaf` and `myLeafPrivate` are the receiver's leaf index and the X25519
    /// private keys it can try (its current leaf key, plus any parent keys it
    /// already holds along its own direct path). Returns the updated tree and the
    /// recovered COMMIT SECRET. Throws `cannotDecryptPath` if no ciphertext opens
    /// — exactly what a removed member experiences.
    public static func applyUpdatePath(tree: MLSRatchetTree, committer: MLSLeafIndex,
                                       path: MLSUpdatePath, myLeaf: MLSLeafIndex,
                                       groupContext: Data) throws
        -> (tree: MLSRatchetTree, commitSecret: Data) {

        var t = tree
        let dirPath = t.directPath(of: committer)
        let coPath = t.copath(of: committer)
        let info = pathInfo(groupContext)

        // 1) Install the committer's new public keys along its direct path, and
        //    set its new leaf key. (Private halves stay nil for the receiver.)
        let committerLeafNode = MLSRatchetTree.nodeIndex(ofLeaf: committer)
        t[committerLeafNode] = MLSTreeNode(publicKey: path.leafKeyPackage.leafKey, privateKey: nil)
        for (idx, node) in dirPath.enumerated() {
            t[node] = MLSTreeNode(publicKey: path.nodes[idx].publicKey,
                                  privateKey: t[node].privateKey)
        }

        // 2) Find the lowest path node whose copath sibling subtree CONTAINS the
        //    receiver — that node's ciphertext list holds a secret we can open.
        let myNode = MLSRatchetTree.nodeIndex(ofLeaf: myLeaf)
        var recovered: (level: Int, secret: Data)? = nil

        for (idx, _) in dirPath.enumerated() {
            let sibling = coPath[idx]
            guard subtreeContains(sibling, leafNode: myNode, in: t) else { continue }
            // The receiver is somewhere under this copath node; one of its
            // resolution members is a key we hold. Try each ciphertext against the
            // private keys we have for that resolution.
            let recipients = t.resolution(of: sibling)
            for (rIdx, r) in recipients.enumerated() {
                guard rIdx < path.nodes[idx].encryptedPathSecret.count,
                      let priv = t[r].privateKey else { continue }
                let ct = path.nodes[idx].encryptedPathSecret[rIdx].sealed
                if let secret = try? MLSHPKE.open(ct, privateKey: priv, info: info, aad: groupContext) {
                    recovered = (idx, secret); break
                }
            }
            if recovered != nil { break }
        }
        guard let start = recovered else { throw MLSError.cannotDecryptPath }

        // 3) Re-derive every node from the recovery point up to the root, filling
        //    in private keys (and checking the public keys match what was shipped).
        var secret = start.secret
        var idx = start.level
        while idx < dirPath.count {
            let node = dirPath[idx]
            let kp = deriveKeyPair(fromPathSecret: secret)
            t[node] = MLSTreeNode(publicKey: kp.pub, privateKey: kp.priv)
            if idx + 1 < dirPath.count { secret = nextPathSecret(secret) }
            idx += 1
        }
        // The commit secret is the path secret one step past the root node.
        let commitSecret = nextPathSecret(secret)
        return (t, commitSecret)
    }

    /// True if the subtree rooted at `node` contains the leaf at `leafNode`.
    static func subtreeContains(_ node: Int, leafNode: Int, in tree: MLSRatchetTree) -> Bool {
        if MLSRatchetTree.isLeaf(node) { return node == leafNode }
        let k = MLSRatchetTree.level(node)
        let span = 1 << k                      // leaves under this node
        let firstLeafNode = (node - (span - 1))
        let lastLeafNode = (node + (span - 1))
        return leafNode >= firstLeafNode && leafNode <= lastLeafNode
    }
}
