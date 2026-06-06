//
//  RatchetTree.swift  (MLS ratchet tree — RFC 9420 §7.1, §4.2)
//
//  A left-balanced binary tree of node key pairs, packed into a flat array using
//  the MLS array representation: for `n` leaves the tree has `2*n - 1` nodes,
//  leaf `i` lives at node index `2*i`, and parents sit at odd indices. This file
//  owns the node index arithmetic (left/right/parent/sibling/root, level), the
//  per-node storage (a public key, plus a private key for nodes this member can
//  open), and the two MLS tree queries TreeKEM needs: the DIRECT PATH (a leaf up
//  to the root) and a node's RESOLUTION (the set of non-blank public keys that
//  represent the subtree, used as HPKE recipients on the copath).
//
//  Pure Foundation. No crypto here beyond holding key bytes — derivation and
//  sealing live in TreeKEM / MLSHPKE.
//
import Foundation

/// One node of the ratchet tree. A blank node (removed member, unmerged parent)
/// has `publicKey == nil`. `privateKey` is present only for nodes the local
/// member sits below and has the secret for.
public struct MLSTreeNode: Codable, Sendable, Equatable {
    public var publicKey: Data?
    public var privateKey: Data?
    public init(publicKey: Data? = nil, privateKey: Data? = nil) {
        self.publicKey = publicKey; self.privateKey = privateKey
    }
    public var isBlank: Bool { publicKey == nil }
}

/// The packed ratchet tree plus the pure node-index math over it.
public struct MLSRatchetTree: Codable, Sendable, Equatable {
    /// `2*leafCount - 1` slots; blanks are `MLSTreeNode()`.
    public private(set) var nodes: [MLSTreeNode]

    public init(leafCount: Int) {
        let n = max(1, leafCount)
        nodes = Array(repeating: MLSTreeNode(), count: 2 * n - 1)
    }
    public init(nodes: [MLSTreeNode]) { self.nodes = nodes }

    // MARK: - sizes / conversions

    /// Number of leaf slots = (nodeCount + 1) / 2.
    public var leafCount: Int { (nodes.count + 1) / 2 }
    public var nodeCount: Int { nodes.count }
    /// Node index for a leaf index (leaf `i` ⇒ node `2*i`).
    public static func nodeIndex(ofLeaf leaf: MLSLeafIndex) -> Int { Int(leaf.value) * 2 }
    /// Leaf index for an even node index.
    public static func leafIndex(ofNode node: Int) -> MLSLeafIndex { MLSLeafIndex(node / 2) }
    public static func isLeaf(_ node: Int) -> Bool { node % 2 == 0 }

    // MARK: - node math (RFC 9420 §7.1 — "Array-Based Trees")

    /// Level of a node: leaves are level 0; a parent is one above its children.
    /// Equals the number of trailing 1-bits in the index.
    public static func level(_ x: Int) -> Int {
        if x & 1 == 0 { return 0 }
        var k = 0, v = x
        while (v >> k) & 1 == 1 { k += 1 }
        return k
    }
    /// Left child of an internal node (undefined for leaves).
    public static func left(_ x: Int) -> Int {
        let k = level(x); return x ^ (1 << (k - 1))
    }
    /// Right child of an internal node, descended into a non-full tree of
    /// `nodeCount` nodes. In the array layout the formula right child may not exist
    /// when the tree isn't a perfect power-of-two (e.g. the root of a 3-leaf tree),
    /// so walk down-left until it lands on a real node — RFC 9420 §7.1 `right`.
    public static func right(_ x: Int, nodeCount: Int) -> Int {
        let k = level(x)
        var r = x ^ (3 << (k - 1))
        while r >= nodeCount { r = left(r) }
        return r
    }
    /// Parent of a node within a tree of `nodeCount` nodes.
    public static func parent(_ x: Int, nodeCount: Int) -> Int {
        let k = level(x)
        var p = (x & ~(1 << (k + 1))) | (1 << k)
        // Walk up if the computed parent overflows this (non-full) tree.
        while p >= nodeCount { p = (p & ~(1 << (level(p) + 1))) | (1 << level(p)) }
        return p
    }
    /// Sibling of a node: the other child of its parent.
    public static func sibling(_ x: Int, nodeCount: Int) -> Int {
        let p = parent(x, nodeCount: nodeCount)
        return x < p ? right(p, nodeCount: nodeCount) : left(p)
    }
    /// Root of a tree with `leafCount` leaves: the single node at the top level.
    public static func root(leafCount: Int) -> Int {
        let n = 2 * leafCount - 1
        return (1 << Int(log2(Double(n)))) - 1
    }
    public var root: Int { Self.root(leafCount: leafCount) }

    // MARK: - paths (RFC 9420 §4.2)

    /// DIRECT PATH of a leaf: the ordered node indices from the leaf's parent up
    /// to (and including) the root. These are the nodes a Commit re-keys.
    public func directPath(of leaf: MLSLeafIndex) -> [Int] {
        let start = Self.nodeIndex(ofLeaf: leaf)
        guard start < nodes.count else { return [] }
        var path: [Int] = []
        var x = start
        let r = root
        while x != r {
            x = Self.parent(x, nodeCount: nodes.count)
            path.append(x)
        }
        return path
    }

    /// COPATH of a leaf: the sibling of the leaf, then the sibling of each node on
    /// the direct path. Each copath node's resolution is the recipient set for the
    /// matching path secret.
    public func copath(of leaf: MLSLeafIndex) -> [Int] {
        let start = Self.nodeIndex(ofLeaf: leaf)
        guard start < nodes.count else { return [] }
        var result: [Int] = []
        var x = start
        let r = root
        while x != r {
            result.append(Self.sibling(x, nodeCount: nodes.count))
            x = Self.parent(x, nodeCount: nodes.count)
        }
        return result
    }

    /// RESOLUTION of a node (RFC 9420 §4.2): the minimal ordered set of non-blank
    /// node indices that "cover" the subtree rooted at `x`. A non-blank node
    /// resolves to itself; a blank leaf resolves to nothing; a blank parent
    /// resolves to the concatenation of its children's resolutions. TreeKEM seals
    /// a path secret to each public key in the copath node's resolution.
    public func resolution(of x: Int) -> [Int] {
        guard x < nodes.count else { return [] }
        if !nodes[x].isBlank { return [x] }
        if Self.isLeaf(x) { return [] }       // blank leaf → empty
        return resolution(of: Self.left(x)) + resolution(of: Self.right(x, nodeCount: nodes.count))
    }

    // MARK: - mutation

    public subscript(node: Int) -> MLSTreeNode {
        get { nodes[node] }
        set { nodes[node] = newValue }
    }
    /// Convenience accessor by leaf index.
    public func leafNode(_ leaf: MLSLeafIndex) -> MLSTreeNode { nodes[Self.nodeIndex(ofLeaf: leaf)] }

    /// Sets a leaf's public key (and optional private key), growing the tree by
    /// one level if the leaf index is beyond the current capacity.
    public mutating func setLeaf(_ leaf: MLSLeafIndex, publicKey: Data?, privateKey: Data? = nil) {
        ensureCapacity(forLeaf: leaf)
        nodes[Self.nodeIndex(ofLeaf: leaf)] = MLSTreeNode(publicKey: publicKey, privateKey: privateKey)
    }

    /// Blanks a node (drops both keys). Used along a removed member's direct path.
    public mutating func blank(_ node: Int) {
        guard node < nodes.count else { return }
        nodes[node] = MLSTreeNode()
    }

    /// First leaf index whose slot is blank, or a fresh leaf appended past the end.
    public func freeLeaf() -> MLSLeafIndex {
        for i in 0..<leafCount where nodes[Self.nodeIndex(ofLeaf: MLSLeafIndex(i))].isBlank {
            return MLSLeafIndex(i)
        }
        return MLSLeafIndex(leafCount)
    }

    /// Grows the array so `leaf` is addressable, doubling leaf capacity as needed
    /// (the tree stays left-balanced: capacity is always 2^k leaves).
    public mutating func ensureCapacity(forLeaf leaf: MLSLeafIndex) {
        var leaves = leafCount
        let needed = Int(leaf.value) + 1
        if needed <= leaves { return }
        while leaves < needed { leaves *= 2 }
        var grown = Array(repeating: MLSTreeNode(), count: 2 * leaves - 1)
        // Re-place existing leaves at their new node indices; parents re-derive on
        // the next commit, so internal nodes start blank after a grow.
        for i in 0..<leafCount {
            let old = nodes[Self.nodeIndex(ofLeaf: MLSLeafIndex(i))]
            grown[i * 2] = old
        }
        nodes = grown
    }

    // MARK: - public-tree export/import (for Welcome)

    /// The public-only view: each node's public key (or nil), no private material.
    public func publicView() -> [Data?] { nodes.map { $0.publicKey } }

    /// Rebuilds a tree from a public view (a joiner's starting point — it then
    /// fills in private keys it can derive from its Welcome).
    public static func fromPublicView(_ view: [Data?]) -> MLSRatchetTree {
        MLSRatchetTree(nodes: view.map { MLSTreeNode(publicKey: $0, privateKey: nil) })
    }
}
