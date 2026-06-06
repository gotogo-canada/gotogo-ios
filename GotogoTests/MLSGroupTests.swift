//
//  MLSGroupTests.swift
//  GotogoTests
//
//  Pure in-simulator proof that the app's MLS module (RFC 9420-faithful TreeKEM
//  on Apple CryptoKit) runs in the iOS runtime — NO backend required. It drives
//  `MLSGroup` directly: found a 4-member group (every member converges on the
//  epoch-0 secret), Commit{Add a 5th member} (all five — including the Welcome'd
//  joiner — converge on a NEW epoch-1 secret that differs from epoch 0), and
//  Commit{Remove a member} (the remaining members converge on epoch 2 while the
//  removed member is cryptographically locked out and cannot derive it).
//
import XCTest
import CryptoKit
@testable import Gotogo

final class MLSGroupTests: XCTestCase {

    /// One participant: its long-term KeyPackage secret and (once it is in the
    /// group) its live `MLSGroup` view. A pending joiner has `group == nil` until
    /// it processes its Welcome.
    private struct Member {
        let name: String
        let secret: MLSKeyPackagePrivate
        var group: MLSGroup?
    }

    /// Mints a fresh member with its own init + leaf X25519 key pairs. We give each
    /// a distinct Ed25519 signature key pair so their KeyPackages are independent.
    private func makeMember(_ name: String) -> Member {
        let sig = Curve25519.Signing.PrivateKey()
        let secret = MLSGroup.freshKeyPackage(signaturePublicKey: sig.publicKey.rawRepresentation,
                                              signaturePrivate: sig.rawRepresentation)
        return Member(name: name, secret: secret, group: nil)
    }

    // MARK: - The full MLS lifecycle proof

    func testFourMemberGroupAddThenRemoveEpochConvergence() throws {
        let groupId = Data("gotogo-mls-test-group".utf8)

        // --- Found a 4-member group: founder (leaf 0) + three initial members. ---
        var founder = makeMember("founder")
        var m1 = makeMember("m1")
        var m2 = makeMember("m2")
        var m3 = makeMember("m3")

        let (createdGroup, welcome0) = MLSGroup.create(
            groupId: groupId,
            founder: founder.secret,
            members: [m1.secret.keyPackage, m2.secret.keyPackage, m3.secret.keyPackage])
        founder.group = createdGroup

        // Each Welcome'd member joins from the SAME Welcome and recovers the epoch.
        m1.group = try MLSGroup.join(welcome: welcome0, keyPackage: m1.secret)
        m2.group = try MLSGroup.join(welcome: welcome0, keyPackage: m2.secret)
        m3.group = try MLSGroup.join(welcome: welcome0, keyPackage: m3.secret)

        // Epoch-0 secret converges across all four founding members.
        let epoch0 = founder.group!.epochSecret
        XCTAssertFalse(epoch0.isEmpty, "epoch-0 secret must be non-empty")
        XCTAssertEqual(founder.group!.epoch, 0, "founding group is at epoch 0")
        for m in [m1, m2, m3] {
            XCTAssertEqual(m.group!.epoch, 0, "\(m.name) joins at epoch 0")
            XCTAssertEqual(m.group!.epochSecret, epoch0,
                           "\(m.name) must converge on the founder's epoch-0 secret")
        }
        // The exporter (a derived secret) must also converge — a second, independent
        // check that the whole key schedule matches, not just the raw epoch secret.
        let ctx = Data("label-ctx".utf8)
        let exp0 = founder.group!.exporter(label: "gotogo/test", context: ctx)
        for m in [m1, m2, m3] {
            XCTAssertEqual(m.group!.exporter(label: "gotogo/test", context: ctx), exp0,
                           "\(m.name) must derive the same exporter as the founder")
        }

        // --- Commit{Add a 5th member}: founder commits, epoch advances to 1. ---
        var m4 = makeMember("m4")
        let addProposal = founder.group!.proposeAdd(m4.secret.keyPackage)
        let (addCommit, addWelcome) = try founder.group!.commit([addProposal])
        let welcome1 = try XCTUnwrap(addWelcome, "adding a member must produce a Welcome")

        // Existing members process the same Commit; the new member joins via Welcome.
        try m1.group!.process(addCommit, from: founder.group!.myLeaf)
        try m2.group!.process(addCommit, from: founder.group!.myLeaf)
        try m3.group!.process(addCommit, from: founder.group!.myLeaf)
        m4.group = try MLSGroup.join(welcome: welcome1, keyPackage: m4.secret)

        let epoch1 = founder.group!.epochSecret
        XCTAssertEqual(founder.group!.epoch, 1, "Commit{Add} advances the founder to epoch 1")
        XCTAssertNotEqual(epoch1, epoch0, "epoch-1 secret must differ from epoch-0 (the ratchet advanced)")
        for m in [m1, m2, m3, m4] {
            XCTAssertEqual(m.group!.epoch, 1, "\(m.name) is at epoch 1 after the Add")
            XCTAssertEqual(m.group!.epochSecret, epoch1,
                           "\(m.name) (incl. the Welcome'd 5th member) converges on epoch-1")
        }

        // --- Commit{Remove a member}: founder removes m2; epoch advances to 2. ---
        let removedLeaf = m2.group!.myLeaf
        let removeProposal = founder.group!.proposeRemove(removedLeaf)
        let (removeCommit, _) = try founder.group!.commit([removeProposal])

        // The remaining members process and converge on epoch 2.
        try m1.group!.process(removeCommit, from: founder.group!.myLeaf)
        try m3.group!.process(removeCommit, from: founder.group!.myLeaf)
        try m4.group!.process(removeCommit, from: founder.group!.myLeaf)

        let epoch2 = founder.group!.epochSecret
        XCTAssertEqual(founder.group!.epoch, 2, "Commit{Remove} advances the founder to epoch 2")
        XCTAssertNotEqual(epoch2, epoch1, "epoch-2 secret must differ from epoch-1")
        XCTAssertNotEqual(epoch2, epoch0, "epoch-2 secret must differ from epoch-0")
        for m in [m1, m3, m4] {
            XCTAssertEqual(m.group!.epoch, 2, "\(m.name) is at epoch 2 after the Remove")
            XCTAssertEqual(m.group!.epochSecret, epoch2,
                           "remaining member \(m.name) converges on epoch-2")
        }

        // The removed member is locked out: applying the same Commit must FAIL (its
        // stale leaf key decrypts none of the re-keyed path), so it cannot reach the
        // new epoch secret.
        XCTAssertThrowsError(try m2.group!.process(removeCommit, from: founder.group!.myLeaf),
                             "removed member must NOT be able to process the Commit that evicts it") { error in
            XCTAssertTrue(error is MLSError, "removal lockout should surface as an MLSError")
        }
        // And even if it somehow advanced, its (pre-removal) epoch secret differs
        // from the remaining members' new epoch-2 secret.
        XCTAssertNotEqual(m2.group!.epochSecret, epoch2,
                          "removed member cannot derive the post-removal epoch secret")
    }
}
