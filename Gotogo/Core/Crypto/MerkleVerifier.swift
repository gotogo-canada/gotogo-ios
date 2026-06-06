//
//  MerkleVerifier.swift
//  Gotogo
//
//  Client-side RFC 6962 Merkle-tree verifier for the key-transparency log. The
//  backend publishes one leaf per (publicId, deviceId, identityKey) and, on
//  lookup, returns each leaf's inclusion proof (`auditPath`) against a signed
//  tree head (`rootHash`, `treeSize`). `verifyInclusion` is the RFC 6962 §2.1.1
//  audit-path algorithm; if it reproduces `root`, the entry is provably present
//  in that tree, so the server cannot equivocate about which identity keys an
//  account has published. Pure Foundation + CryptoKit.
//

import Foundation
import CryptoKit

/// RFC 6962 Certificate-Transparency-style Merkle hashing + inclusion-proof
/// verification, specialized to the Gotogo transparency log's leaf encoding.
enum MerkleVerifier {

    /// Leaf hash for one published identity key:
    /// `SHA256(0x00 || publicId.utf8 || deviceId.utf8 || identityKey)`.
    /// The `0x00` domain-separation prefix distinguishes leaves from interior
    /// nodes so a leaf can never be reinterpreted as an inner node (RFC 6962 §2.1).
    static func leafHash(publicId: String, deviceId: String, identityKey: Data) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data([0x00]))
        hasher.update(data: Data(publicId.utf8))
        hasher.update(data: Data(deviceId.utf8))
        hasher.update(data: identityKey)
        return Data(hasher.finalize())
    }

    /// Interior node hash: `SHA256(0x01 || left || right)`. The `0x01` prefix
    /// domain-separates inner nodes from leaves (RFC 6962 §2.1).
    static func nodeHash(_ l: Data, _ r: Data) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data([0x01]))
        hasher.update(data: l)
        hasher.update(data: r)
        return Data(hasher.finalize())
    }

    /// Verifies an RFC 6962 §2.1.1 inclusion proof: walks `path` from the leaf at
    /// `index` (in a tree of `treeSize` leaves) up to the root, hashing siblings
    /// in on the correct side, and returns whether the reconstructed root equals
    /// `root` — and that the proof had exactly the expected length (no extra or
    /// missing nodes). Ported byte-for-byte from the backend's Go verifier.
    static func verifyInclusion(leafHash: Data, index: Int, treeSize: Int, path: [Data], root: Data) -> Bool {
        guard index >= 0, index < treeSize, treeSize >= 1 else { return false }
        var hash = leafHash
        var fn = index
        var sn = treeSize - 1
        var step = 0
        while sn > 0 {
            guard step < path.count else { return false }
            let sib = path[step]
            if fn & 1 == 1 || fn == sn {
                hash = nodeHash(sib, hash)
                while fn & 1 == 0 {
                    fn >>= 1
                    sn >>= 1
                }
            } else {
                hash = nodeHash(hash, sib)
            }
            fn >>= 1
            sn >>= 1
            step += 1
        }
        return step == path.count && hash == root
    }
}
