//
//  DoubleRatchet.swift
//  Gotogo
//
//  The Signal Double Ratchet (spec "Double Ratchet", rev 4) over Apple
//  CryptoKit: forward secrecy (one-way-derived message keys, dropped after use)
//  + post-compromise security (the DH ratchet heals state after a compromise).
//
//  This file is the protocol logic (init / encrypt / decrypt / DH ratchet /
//  skipped keys); the crypto primitives live in `DoubleRatchet+Primitives.swift`.
//  Algorithm only — no networking or prekey-bundle parsing: callers pass the
//  PQXDH-derived shared secret and X25519 ratchet keys as raw material.
//

import Foundation
import CryptoKit

public enum DoubleRatchet {

    // MARK: - Constants

    /// Default bound on retained skipped message keys (`MAX_SKIP`).
    public static let defaultMaxSkip = 1000

    /// HKDF info for `KDF_RK`, domain-separating this HKDF use. `internal` so the
    /// primitives extension (sibling file) can reference it.
    static let rootKDFInfo = Data("Gotogo-DoubleRatchet-RootKDF".utf8)

    // MARK: - Initialization

    /// Alice (initiator), per `RatchetInitAlice`. She holds the PQXDH shared
    /// secret and Bob's published X25519 ratchet public key; we mint her first
    /// ratchet key pair and run one DH ratchet step so she has a sending chain.
    public static func initiateSender(sharedSecret: SymmetricKey,
                                      remoteRatchetPublicKey: Data) -> RatchetSession {
        let selfPriv = Curve25519.KeyAgreement.PrivateKey()
        let selfPrivRaw = selfPriv.rawRepresentation
        let selfPubRaw = selfPriv.publicKey.rawRepresentation

        var session = RatchetSession(
            rootKey: rawKey(sharedSecret),
            dhSelfPrivate: selfPrivRaw,
            dhSelfPublic: selfPubRaw,
            dhRemotePublic: remoteRatchetPublicKey,
            sendChainKey: nil,
            recvChainKey: nil,
            sendCount: 0,
            recvCount: 0,
            prevSendCount: 0,
            skippedKeys: [],
            maxSkip: defaultMaxSkip)

        // First half-step: RK, CKs = KDF_RK(SK, DH(DHs, DHr)). Best-effort; on
        // malformed input the sending chain stays nil and encrypt() will throw.
        if let dh = try? diffieHellman(privateRaw: selfPrivRaw, publicRaw: remoteRatchetPublicKey) {
            let (rk, ck) = kdfRootKey(rootKey: session.rootKey, dhOutput: dh)
            session.rootKey = rk
            session.sendChainKey = ck
        }
        return session
    }

    /// Bob (responder), per `RatchetInitBob`. He holds the same shared secret and
    /// the X25519 ratchet key pair Alice used. He has no chains yet — they are
    /// established when Alice's first header triggers a DH ratchet step.
    public static func initiateReceiver(sharedSecret: SymmetricKey,
                                        selfRatchetPrivateKey: Data,
                                        selfRatchetPublicKey: Data) -> RatchetSession {
        return RatchetSession(
            rootKey: rawKey(sharedSecret),
            dhSelfPrivate: selfRatchetPrivateKey,
            dhSelfPublic: selfRatchetPublicKey,
            dhRemotePublic: nil,
            sendChainKey: nil,
            recvChainKey: nil,
            sendCount: 0,
            recvCount: 0,
            prevSendCount: 0,
            skippedKeys: [],
            maxSkip: defaultMaxSkip)
    }

    // MARK: - Encrypt

    /// Advances the sending chain, derives the next message key, and seals
    /// `plaintext` with AES-256-GCM using the serialized header as AAD.
    public static func encrypt(_ plaintext: Data,
                               session: inout RatchetSession) throws -> RatchetMessage {
        guard let ck = session.sendChainKey else {
            // No sending chain: responder sending before any receive, or sender
            // init failed on malformed remote key material.
            throw RatchetError.malformedKeyMaterial
        }

        let (messageKey, nextCK) = kdfChainKey(chainKey: ck)
        session.sendChainKey = nextCK

        let header = RatchetHeader(dhPub: session.dhSelfPublic,
                                   pn: session.prevSendCount,
                                   n: session.sendCount)
        session.sendCount += 1

        let aad = try headerBytes(header)
        let ciphertext = try aeadSeal(plaintext: plaintext, key: messageKey, aad: aad)
        return RatchetMessage(header: header, ciphertext: ciphertext)
    }

    // MARK: - Decrypt

    /// Decrypts a ratchet message, in spec order: (1) use a cached skipped key if
    /// one matches; else (2) if the header has a new ratchet key, run a DH ratchet
    /// step (stashing the old chain's gap); then (3) advance the receiving chain
    /// to `header.n` (stashing skipped keys) and decrypt.
    public static func decrypt(_ message: RatchetMessage,
                               session: inout RatchetSession) throws -> Data {
        let header = message.header
        let aad = try headerBytes(header)

        // Case 1: a previously skipped (cached) message key.
        if let pt = try trySkippedKey(message: message, aad: aad, session: &session) {
            return pt
        }

        // Case 2: new remote ratchet key → DH ratchet step (stash old-chain gap).
        if session.dhRemotePublic != header.dhPub {
            try skipReceiveKeys(until: header.pn, session: &session)
            try dhRatchet(header: header, session: &session)
        }

        // Case 3: advance to header.n (stashing skipped keys); chain key now at n.
        try skipReceiveKeys(until: header.n, session: &session)
        guard let ck = session.recvChainKey else {
            // No chain, and no ratchet step established one (responder's first
            // message lacked a usable DHr).
            throw RatchetError.receiveChainNotEstablished
        }
        let (messageKey, nextCK) = kdfChainKey(chainKey: ck)
        session.recvChainKey = nextCK
        session.recvCount += 1

        return try aeadOpen(ciphertext: message.ciphertext, key: messageKey, aad: aad)
    }

    // MARK: - Skipped-key handling

    /// If `message` matches a cached skipped key, decrypt with it and remove it.
    /// Returns `nil` when no cached key matches (caller proceeds normally).
    private static func trySkippedKey(message: RatchetMessage,
                                      aad: Data,
                                      session: inout RatchetSession) throws -> Data? {
        let header = message.header
        guard let idx = session.skippedKeys.firstIndex(where: {
            $0.dhPub == header.dhPub && $0.n == header.n
        }) else { return nil }

        let entry = session.skippedKeys[idx]
        let key = SymmetricKey(data: entry.messageKey)
        // Authenticate before consuming: a tampered message must not burn the key.
        let pt = try aeadOpen(ciphertext: message.ciphertext, key: key, aad: aad)
        session.skippedKeys.remove(at: idx)
        return pt
    }

    /// Advances the receiving chain to index `until`, caching each passed-over
    /// message key (messages not yet arrived). No-op without a chain or when
    /// caught up; enforces `maxSkip` to bound the gap we will fill.
    private static func skipReceiveKeys(until: Int, session: inout RatchetSession) throws {
        guard session.recvChainKey != nil, let dhPub = session.dhRemotePublic else { return }
        guard until > session.recvCount else { return }

        if until - session.recvCount > session.maxSkip {
            throw RatchetError.skippedKeyUnavailable
        }

        while session.recvCount < until {
            guard let ck = session.recvChainKey else { break }
            let (messageKey, nextCK) = kdfChainKey(chainKey: ck)
            session.recvChainKey = nextCK
            storeSkippedKey(dhPub: dhPub, n: session.recvCount, key: rawKey(messageKey), session: &session)
            session.recvCount += 1
        }
    }

    /// Inserts a skipped key, evicting the oldest (FIFO) if over `maxSkip`.
    private static func storeSkippedKey(dhPub: Data, n: Int, key: Data,
                                        session: inout RatchetSession) {
        session.skippedKeys.append(SkippedMessageKey(dhPub: dhPub, n: n, messageKey: key))
        if session.skippedKeys.count > session.maxSkip {
            session.skippedKeys.removeFirst(session.skippedKeys.count - session.maxSkip)
        }
    }

    // MARK: - DH ratchet step

    /// DH ratchet step on a new remote ratchet key: adopt their `DHr`, derive a
    /// fresh receiving chain, rotate our key pair, derive a fresh sending chain.
    private static func dhRatchet(header: RatchetHeader, session: inout RatchetSession) throws {
        // Carry over PN, reset chain counters (start of two new chains).
        session.prevSendCount = session.sendCount
        session.sendCount = 0
        session.recvCount = 0
        session.dhRemotePublic = header.dhPub

        // New receiving chain: RK, CKr = KDF_RK(RK, DH(DHs, DHr_new)).
        let dhRecv = try diffieHellman(privateRaw: session.dhSelfPrivate, publicRaw: header.dhPub)
        let (rk1, ckr) = kdfRootKey(rootKey: session.rootKey, dhOutput: dhRecv)
        session.rootKey = rk1
        session.recvChainKey = ckr

        // Rotate our ratchet key pair, then derive the new sending chain.
        let newPriv = Curve25519.KeyAgreement.PrivateKey()
        session.dhSelfPrivate = newPriv.rawRepresentation
        session.dhSelfPublic = newPriv.publicKey.rawRepresentation
        // New sending chain: RK, CKs = KDF_RK(RK, DH(DHs_new, DHr_new)).
        let dhSend = try diffieHellman(privateRaw: session.dhSelfPrivate, publicRaw: header.dhPub)
        let (rk2, cks) = kdfRootKey(rootKey: session.rootKey, dhOutput: dhSend)
        session.rootKey = rk2
        session.sendChainKey = cks
    }
}
