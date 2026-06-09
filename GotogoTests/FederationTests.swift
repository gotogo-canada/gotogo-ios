//
//  FederationTests.swift
//  GotogoTests
//
//  Locks in the federation client's interop with the Go backend: address parsing,
//  the byte-exact transparency head canonicalization, and that CryptoKit's
//  Curve25519.Signing (Ed25519) verifies a head signed the same way the backend
//  signs it (federation.headCanonical + crypto/ed25519).
//

import XCTest
import CryptoKit
@testable import Gotogo

final class FederationTests: XCTestCase {

    func testAddressParsingAndFolding() {
        XCTAssertEqual(Address("bob@b-server.com")?.localpart, "bob")
        XCTAssertEqual(Address("bob@b-server.com")?.domain, "b-server.com")
        XCTAssertEqual(Address("Bob@B.COM")?.folded, "bob@b.com")
        XCTAssertEqual(Address("Bob@B.COM")?.display, "Bob@B.COM".replacingOccurrences(of: "B.COM", with: "b.com"))
        XCTAssertTrue(Address("A0BS2MA1@b.com")!.isRandomID)
        XCTAssertFalse(Address("bob@b.com")!.isRandomID)
        XCTAssertTrue(Address("alice@a.com")!.isLocal(to: "A.com"))
        XCTAssertFalse(Address("alice@a.com")!.isLocal(to: "b.com"))
        for bad in ["", "nodomain", "@b.com", "bob@", "bo..b@c.com", "-bob@c.com", "a b@c.com"] {
            XCTAssertNil(Address(bad), "should reject \(bad)")
        }
    }

    /// Client-side sealed-sender blocking: the server can't see a sealed sender,
    /// so the client drops a decrypted message from a locally-blocked sender (V2-C).
    func testSealedClientSideBlocking() {
        let blocked: Set<String> = ["evil@x.com", "spam@y.com"]
        XCTAssertTrue(SealedSender.shouldDrop(senderAddress: "Evil@x.com", blocked: blocked))
        XCTAssertTrue(SealedSender.shouldDrop(senderAddress: "spam@y.com", blocked: blocked))
        XCTAssertFalse(SealedSender.shouldDrop(senderAddress: "friend@z.com", blocked: blocked))
    }

    /// The sealed-sender access key round-trips through the E2EE Profile so mutual
    /// contacts learn it on decrypt (the sharing mechanism, V2-C).
    func testProfileCarriesSealedSenderKey() throws {
        let key = Data([1, 2, 3, 4, 5, 6, 7, 8])
        let profile = Profile(displayName: "Alice", sealedSenderKey: key)
        let encoded = try JSONEncoder().encode(profile)
        let back = try JSONDecoder().decode(Profile.self, from: encoded)
        XCTAssertEqual(back.sealedSenderKey, key)
        // Backward compatible: an old profile without the field decodes to nil.
        let legacy = try JSONDecoder().decode(Profile.self, from: Data(#"{"displayName":"Bob"}"#.utf8))
        XCTAssertNil(legacy.sealedSenderKey)
    }

    /// iOS Punycode/IDNA must produce the SAME A-label as the Go backend
    /// (idna.Lookup.ToASCII), since the folded domain is part of pin/leaf/routing
    /// keys. These expected values are confirmed by the Go test TestCanonicalDomainIDN.
    func testIDNAMatchesBackend() {
        XCTAssertEqual(IDNA.toASCII("münchen.de"), "xn--mnchen-3ya.de")
        XCTAssertEqual(IDNA.toASCII("bücher.example"), "xn--bcher-kva.example")
        XCTAssertEqual(IDNA.toASCII("Example.COM"), "example.com")
        XCTAssertEqual(IDNA.punycodeEncode("bücher"), "bcher-kva")
        // Address routes non-ASCII domains through IDNA, matching the server.
        XCTAssertEqual(Address("bob@münchen.de")?.domain, "xn--mnchen-3ya.de")
        XCTAssertEqual(Address("bob@münchen.de")?.folded, "bob@xn--mnchen-3ya.de")
        XCTAssertNotNil(Address("bob@münchen.de"), "IDN domains must now be accepted")
    }

    /// Must equal Go `federation.headCanonical` byte-for-byte:
    /// "gotogo-transparency-head-v1\n<treeSize>\n<base64 root>\n<timestamp>" with
    /// NO trailing newline. `rootHash` is the same base64 string sent on the wire.
    func testHeadCanonicalMatchesBackendFormat() {
        let head = FederationDirectory.SignedHead(treeSize: 42,
                                                  rootHash: "AAAAAA==",
                                                  timestamp: 1781049600,
                                                  keyId: "kt-ed25519:1",
                                                  signature: "")
        let expected = "gotogo-transparency-head-v1\n42\nAAAAAA==\n1781049600"
        XCTAssertEqual(FederationDirectory.headCanonical(head), Data(expected.utf8))
    }

    /// Proves CryptoKit's Ed25519 (Curve25519.Signing) interoperates with the
    /// backend's signing format: sign the canonical head, verify it back.
    func testSignedHeadEd25519RoundTrip() {
        let key = Curve25519.Signing.PrivateKey()
        let head = FederationDirectory.SignedHead(treeSize: 7, rootHash: "AAAAAA==",
                                                  timestamp: 1_700_000_000, keyId: "k", signature: "")
        let msg = FederationDirectory.headCanonical(head)
        let sig = try! key.signature(for: msg)
        XCTAssertTrue(key.publicKey.isValidSignature(sig, for: msg))
        // A tampered message must NOT verify.
        let tampered = FederationDirectory.SignedHead(treeSize: 8, rootHash: "AAAAAA==",
                                                      timestamp: 1_700_000_000, keyId: "k", signature: "")
        XCTAssertFalse(key.publicKey.isValidSignature(sig, for: FederationDirectory.headCanonical(tampered)))
    }
}
