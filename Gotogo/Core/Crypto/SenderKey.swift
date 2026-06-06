//
//  SenderKey.swift  (Signal "Sender Keys" for group messaging)
//
//  Each group sender holds a SenderKeyState: a symmetric chain key (ratcheted
//  forward per message) plus an Ed25519 signing key. The sender distributes the
//  current chain key + signing public key to each member over the PAIRWISE
//  Double Ratchet channel (a SenderKeyDistribution), then encrypts each group
//  message ONCE with a chain-derived message key and signs it. Members ratchet
//  the stored chain key forward and verify the signature. On membership change
//  the group rotates (new SenderKeyState, redistributed) so removed members
//  cannot read future messages. Foundation + CryptoKit only.
//
import Foundation
import CryptoKit

public enum SenderKeyError: Error, Equatable, Sendable {
    case badSignature, authenticationFailure, tooOld, malformed
}

/// Per-(group, sender) state. The sender keeps `signingPrivateKey`; receivers do not.
public struct SenderKeyState: Codable, Sendable, Equatable {
    public var chainKey: Data
    public var iteration: Int
    public var signingPrivateKey: Data?
    public var signingPublicKey: Data
    public var skipped: [Int: Data]   // iteration -> message key, for out-of-order
    public init(chainKey: Data, iteration: Int, signingPrivateKey: Data?, signingPublicKey: Data, skipped: [Int: Data] = [:]) {
        self.chainKey = chainKey; self.iteration = iteration
        self.signingPrivateKey = signingPrivateKey; self.signingPublicKey = signingPublicKey; self.skipped = skipped
    }
}

/// What the sender ships to each member over the pairwise channel.
public struct SenderKeyDistribution: Codable, Sendable, Equatable {
    public var chainKey: Data
    public var iteration: Int
    public var signingPublicKey: Data
    public init(chainKey: Data, iteration: Int, signingPublicKey: Data) {
        self.chainKey = chainKey; self.iteration = iteration; self.signingPublicKey = signingPublicKey
    }
}

/// A group message: which iteration, the AEAD box, and the sender's signature.
public struct GroupMessage: Codable, Sendable, Equatable {
    public var iteration: Int
    public var ciphertext: Data
    public var signature: Data
    public init(iteration: Int, ciphertext: Data, signature: Data) {
        self.iteration = iteration; self.ciphertext = ciphertext; self.signature = signature
    }
}

public enum SenderKey {
    private static let maxSkip = 2000

    /// Generates a fresh sender key (random 32-byte chain key + Ed25519 signer).
    public static func generate() -> SenderKeyState {
        let signer = Curve25519.Signing.PrivateKey()
        var ck = Data(count: 32)
        ck.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        return SenderKeyState(chainKey: ck, iteration: 0,
                              signingPrivateKey: signer.rawRepresentation,
                              signingPublicKey: signer.publicKey.rawRepresentation)
    }

    /// The distribution message a member needs to start decrypting this sender.
    public static func distribution(_ s: SenderKeyState) -> SenderKeyDistribution {
        SenderKeyDistribution(chainKey: s.chainKey, iteration: s.iteration, signingPublicKey: s.signingPublicKey)
    }

    /// Builds a receiver-side state from a distribution (no private signing key).
    public static func receiver(from d: SenderKeyDistribution) -> SenderKeyState {
        SenderKeyState(chainKey: d.chainKey, iteration: d.iteration, signingPrivateKey: nil, signingPublicKey: d.signingPublicKey)
    }

    /// Encrypts and signs one group message, advancing the sender's chain.
    public static func encrypt(_ plaintext: Data, state: inout SenderKeyState) throws -> GroupMessage {
        guard let privRaw = state.signingPrivateKey,
              let signer = try? Curve25519.Signing.PrivateKey(rawRepresentation: privRaw) else { throw SenderKeyError.malformed }
        let iter = state.iteration
        let mk = messageKey(state.chainKey)
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: mk))
        let ct = box.combined!
        let sig = try signer.signature(for: signed(iter, ct))
        state.chainKey = nextChainKey(state.chainKey)
        state.iteration = iter + 1
        return GroupMessage(iteration: iter, ciphertext: ct, signature: sig)
    }

    /// Verifies and decrypts a group message, ratcheting the stored chain forward
    /// (and caching skipped keys) as needed.
    public static func decrypt(_ m: GroupMessage, state: inout SenderKeyState) throws -> Data {
        guard let verifier = try? Curve25519.Signing.PublicKey(rawRepresentation: state.signingPublicKey) else { throw SenderKeyError.malformed }
        guard verifier.isValidSignature(m.signature, for: signed(m.iteration, m.ciphertext)) else { throw SenderKeyError.badSignature }

        let mk: Data
        if m.iteration < state.iteration {
            guard let cached = state.skipped[m.iteration] else { throw SenderKeyError.tooOld }
            mk = cached
        } else {
            guard m.iteration - state.iteration <= maxSkip else { throw SenderKeyError.tooOld }
            while state.iteration < m.iteration {
                state.skipped[state.iteration] = messageKey(state.chainKey)
                state.chainKey = nextChainKey(state.chainKey)
                state.iteration += 1
            }
            mk = messageKey(state.chainKey)
            state.chainKey = nextChainKey(state.chainKey)
            state.iteration += 1
        }
        do {
            let box = try AES.GCM.SealedBox(combined: m.ciphertext)
            let pt = try AES.GCM.open(box, using: SymmetricKey(data: mk))
            state.skipped[m.iteration] = nil
            return pt
        } catch { throw SenderKeyError.authenticationFailure }
    }

    // MARK: - primitives
    private static func messageKey(_ ck: Data) -> Data { hmac(ck, 0x01) }
    private static func nextChainKey(_ ck: Data) -> Data { hmac(ck, 0x02) }
    private static func hmac(_ key: Data, _ b: UInt8) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data([b]), using: SymmetricKey(data: key)))
    }
    private static func signed(_ iter: Int, _ ct: Data) -> Data {
        var d = Data(); withUnsafeBytes(of: UInt64(iter).bigEndian) { d.append(contentsOf: $0) }; d.append(ct); return d
    }
}
