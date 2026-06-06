//
//  MLSAdversarialTests.swift
//  GotogoTests
//
//  Hardening of the live MLS group transport: large groups, multi-device Adds
//  (one member contributing several leaves), tampered/fuzzed handshakes, and
//  concurrent commits. These are pure-module tests (no backend) that drive the
//  same MLSGroup / TreeKEM the app ships — the suite that surfaced (and now guards
//  against) the non-power-of-two tree-arithmetic bug.
//
import XCTest
@testable import Gotogo

final class MLSAdversarialTests: XCTestCase {

    // MARK: - Large group

    /// A 40-member group: everyone converges and decrypts the founder's message;
    /// removing a middle member Commits a new epoch the remaining 39 converge to
    /// while the removed member is locked out.
    func testLargeGroupConvergenceAndRemovalLockout() throws {
        let n = 40
        let kps = (0..<n).map { _ in MLSGroup.freshKeyPackage() }
        let founderKP = MLSGroup.freshKeyPackage()
        let created = MLSGroup.create(groupId: Data("big".utf8), founder: founderKP,
                                      members: kps.map { $0.keyPackage })
        var founder = created.group
        let members = try kps.map { try MLSGroup.join(welcome: created.welcome, keyPackage: $0) }

        let app = try founder.encryptApplication(Data("hi-all".utf8), generation: 0)
        for m in members {
            var g = m
            XCTAssertEqual(String(decoding: try g.decryptApplication(app), as: UTF8.self), "hi-all")
        }

        let (commit, _) = try founder.commit([founder.proposeRemove(MLSLeafIndex(20))])
        for (i, m) in members.enumerated() {
            var g = m
            if i + 1 == 20 {
                XCTAssertThrowsError(try g.process(commit, from: MLSLeafIndex(0)),
                                     "removed member (leaf 20) must be locked out")
            } else {
                try g.process(commit, from: MLSLeafIndex(0))
                XCTAssertEqual(g.epochSecret, founder.epochSecret, "remaining member \(i) must converge")
            }
        }
    }

    // MARK: - Multi-device Add

    /// One member contributing TWO device leaves in a single Commit: both join and
    /// decrypt under the shared epoch, and removing both leaves locks the member
    /// out entirely. This is the multi-device path GroupService maps via the
    /// Welcome's authoritative per-leaf secrets.
    func testMultiDeviceAddTwoLeavesAndBothRemovedLockout() throws {
        let founderKP = MLSGroup.freshKeyPackage()
        let seed = MLSGroup.freshKeyPackage()
        var founder = MLSGroup.create(groupId: Data("md".utf8), founder: founderKP,
                                      members: [seed.keyPackage]).group

        let d1 = MLSGroup.freshKeyPackage(); let d2 = MLSGroup.freshKeyPackage()
        let (_, welcome) = try founder.commit([founder.proposeAdd(d1.keyPackage),
                                               founder.proposeAdd(d2.keyPackage)])
        let w = try XCTUnwrap(welcome)
        XCTAssertEqual(w.secrets.count, 2, "Welcome carries one secret per device leaf")
        XCTAssertEqual(Set(w.secrets.map { $0.leaf.value }).count, 2, "the two device leaves are distinct")

        var g1 = try MLSGroup.join(welcome: w, keyPackage: d1)
        var g2 = try MLSGroup.join(welcome: w, keyPackage: d2)
        let app = try founder.encryptApplication(Data("md".utf8), generation: 0)
        XCTAssertNoThrow(try g1.decryptApplication(app))
        XCTAssertNoThrow(try g2.decryptApplication(app))

        let (commit2, _) = try founder.commit(w.secrets.map { founder.proposeRemove($0.leaf) })
        XCTAssertThrowsError(try g1.process(commit2, from: MLSLeafIndex(0)), "device 1 must be locked out")
        XCTAssertThrowsError(try g2.process(commit2, from: MLSLeafIndex(0)), "device 2 must be locked out")
    }

    // MARK: - Tamper rejection

    /// A single flipped byte in an encoded Welcome or Commit must fail to apply —
    /// never crash, never silently succeed.
    func testTamperedWelcomeAndCommitRejected() throws {
        let a = MLSGroup.freshKeyPackage(); let b = MLSGroup.freshKeyPackage()
        let created = MLSGroup.create(groupId: Data("t".utf8), founder: a, members: [b.keyPackage])

        var welcomeBytes = try JSONEncoder().encode(created.welcome)
        welcomeBytes[welcomeBytes.count / 2] ^= 0xFF
        if let bad = try? JSONDecoder().decode(MLSWelcome.self, from: welcomeBytes) {
            XCTAssertNil(try? MLSGroup.join(welcome: bad, keyPackage: b),
                         "tampered Welcome must not yield a valid join")
        }

        var founder = created.group
        let (commit, _) = try founder.commit([founder.proposeUpdate(founder.myKeyPackage.keyPackage)])
        var commitBytes = try JSONEncoder().encode(commit)
        commitBytes[commitBytes.count / 3] ^= 0xAA
        var bJoin = try MLSGroup.join(welcome: created.welcome, keyPackage: b)
        if let badC = try? JSONDecoder().decode(MLSCommit.self, from: commitBytes) {
            XCTAssertThrowsError(try bJoin.process(badC, from: MLSLeafIndex(0)),
                                 "tampered Commit must be rejected")
        }
    }

    // MARK: - Fuzz

    /// 800 random blobs fed into the MLS decoders and entry points must never crash
    /// — they decode-fail or throw, but the process stays up.
    func testFuzzDecodersNeverCrash() throws {
        let a = MLSGroup.freshKeyPackage(); let b = MLSGroup.freshKeyPackage()
        let created = MLSGroup.create(groupId: Data("f".utf8), founder: a, members: [b.keyPackage])
        var bJoin = try MLSGroup.join(welcome: created.welcome, keyPackage: b)
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<800 {
            let len = Int.random(in: 0...256, using: &rng)
            let d = Data((0..<len).map { _ in UInt8.random(in: 0...255, using: &rng) })
            if let w = try? JSONDecoder().decode(MLSWelcome.self, from: d) {
                _ = try? MLSGroup.join(welcome: w, keyPackage: b)
            }
            if let c = try? JSONDecoder().decode(MLSCommit.self, from: d) {
                _ = try? bJoin.process(c, from: MLSLeafIndex(UInt32.random(in: 0...64, using: &rng)))
            }
            if let m = try? JSONDecoder().decode(MLSApplicationMessage.self, from: d) {
                _ = try? bJoin.decryptApplication(m)
            }
        }
        XCTAssertTrue(true, "fuzzing completed without a crash")
    }

    // MARK: - Concurrent commits

    /// Two members committing independently from the same epoch must not crash when
    /// one applies the other's commit: MLS without a server total-order diverges
    /// (expected), and the implementation surfaces that as a clean throw or a
    /// non-matching secret — never a silent merge.
    func testConcurrentCommitsDivergeWithoutCrash() throws {
        let a = MLSGroup.freshKeyPackage(); let b = MLSGroup.freshKeyPackage()
        let created = MLSGroup.create(groupId: Data("c".utf8), founder: a, members: [b.keyPackage])
        var ga = created.group
        var gb = try MLSGroup.join(welcome: created.welcome, keyPackage: b)

        _ = try ga.commit([ga.proposeUpdate(ga.myKeyPackage.keyPackage)])
        let (commitB, _) = try gb.commit([gb.proposeUpdate(gb.myKeyPackage.keyPackage)])

        var converged = false
        do {
            try ga.process(commitB, from: MLSLeafIndex(1))
            converged = (ga.epochSecret == gb.epochSecret)
        } catch {
            // clean rejection is acceptable
        }
        XCTAssertFalse(converged, "concurrent commits must not silently merge into one epoch")
    }
}
