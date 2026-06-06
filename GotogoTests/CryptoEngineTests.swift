//
//  CryptoEngineTests.swift
//  GotogoTests
//
//  In-simulator unit tests for the post-quantum CryptoEngine: seal/open
//  round-trip, tamper rejection, and the safety number.
//
import XCTest
@testable import Gotogo

final class CryptoEngineTests: XCTestCase {

    private let engine = CryptoKitEngine()

    private func makePeer() throws -> (IdentityKeyMaterial, PreKeyStore, PublicPreKeyBundle) {
        let id = engine.generateIdentity()
        let gp = try engine.generatePreKeys(identity: id, signedPreKeyId: 1, oneTimeCount: 3, firstOneTimeId: 1)
        return (id, gp.store, gp.bundle)
    }

    func testSealOpenRoundTrip() throws {
        let (bobId, bobStore, bobBundle) = try makePeer()
        let plaintext = Data("the quantum fox jumps 🦊".utf8)
        let env = try engine.seal(plaintext, to: bobBundle)
        let opened = try engine.open(env, identity: bobId,
                                     signedPreKey: bobStore.signedPreKey,
                                     oneTimePreKeys: bobStore.oneTimePreKeys)
        XCTAssertEqual(opened, plaintext)
    }

    func testTamperedCiphertextRejected() throws {
        let (bobId, bobStore, bobBundle) = try makePeer()
        var env = try engine.seal(Data("secret".utf8), to: bobBundle)
        env.ciphertext[env.ciphertext.startIndex] ^= 0xFF
        XCTAssertThrowsError(try engine.open(env, identity: bobId,
                                             signedPreKey: bobStore.signedPreKey,
                                             oneTimePreKeys: bobStore.oneTimePreKeys))
    }

    func testTamperedKemRejected() throws {
        let (bobId, bobStore, bobBundle) = try makePeer()
        var env = try engine.seal(Data("secret".utf8), to: bobBundle)
        env.kem[env.kem.startIndex] ^= 0xFF
        XCTAssertThrowsError(try engine.open(env, identity: bobId,
                                             signedPreKey: bobStore.signedPreKey,
                                             oneTimePreKeys: bobStore.oneTimePreKeys))
    }

    func testSafetyNumberSymmetric() throws {
        let a = engine.generateIdentity()
        let b = engine.generateIdentity()
        let ab = engine.safetyNumber(localIdentity: a.publicKey, remoteIdentity: b.publicKey)
        let ba = engine.safetyNumber(localIdentity: b.publicKey, remoteIdentity: a.publicKey)
        XCTAssertEqual(ab, ba)
        XCTAssertFalse(ab.isEmpty)
    }

    func testMnemonicRoundTrip() throws {
        var entropy = Data(count: 32)
        entropy.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let words = Mnemonic.encode(entropy)
        XCTAssertEqual(words.count, 24)
        let decoded = try Mnemonic.decode(words)
        XCTAssertEqual(decoded, entropy)
    }
}
