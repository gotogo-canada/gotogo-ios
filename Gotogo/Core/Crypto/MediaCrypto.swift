//
//  MediaCrypto.swift
//  Gotogo
//
//  Chunked AES-256-GCM encryption for media blobs (photos, voice, video). Each
//  file gets a fresh random key; each chunk a fresh nonce; the chunk index is
//  authenticated to prevent reordering. The key + the ciphertext SHA-256 are
//  carried inside the E2EE message; the ciphertext blob goes to object storage.
//  Pure Foundation + CryptoKit (plan section 3.3).
//
import Foundation
import CryptoKit

/// Errors thrown by media encryption/decryption.
public enum MediaCryptoError: Error, Equatable, Sendable {
    case badHeader
    case truncated
    case authenticationFailure
    case badKey
}

/// Stateless chunked AEAD for media files.
public enum MediaCrypto {

    /// Default 64 KiB plaintext chunk size.
    public static let defaultChunkSize = 64 * 1024

    private static let magic: [UInt8] = [0x47, 0x4D, 0x45, 0x44] // "GMED"
    private static let version: UInt8 = 1

    /// Encrypts `plaintext` under a fresh 256-bit key.
    /// - Returns: the raw key (32 bytes) to send in the E2EE message, the
    ///   ciphertext blob to upload, and the SHA-256 of that blob for verification.
    public static func encrypt(_ plaintext: Data,
                               chunkSize: Int = defaultChunkSize) throws -> (key: Data, ciphertext: Data, sha256: Data) {
        let key = SymmetricKey(size: .bits256)
        var out = Data()
        out.append(contentsOf: magic)
        out.append(version)
        out.append(uint32(UInt32(chunkSize)))
        out.append(uint64(UInt64(plaintext.count)))

        var index: UInt32 = 0
        var offset = plaintext.startIndex
        while offset < plaintext.endIndex {
            let end = plaintext.index(offset, offsetBy: chunkSize, limitedBy: plaintext.endIndex) ?? plaintext.endIndex
            let chunk = plaintext[offset..<end]
            let sealed = try AES.GCM.seal(chunk, using: key, authenticating: uint32(index))
            out.append(sealed.combined!) // 12-byte nonce ‖ ciphertext ‖ 16-byte tag
            index &+= 1
            offset = end
        }
        if plaintext.isEmpty { // still emit a single empty authenticated chunk
            let sealed = try AES.GCM.seal(Data(), using: key, authenticating: uint32(0))
            out.append(sealed.combined!)
        }
        let digest = SHA256.hash(data: out)
        return (key: key.rawData, ciphertext: out, sha256: Data(digest))
    }

    /// Decrypts a ciphertext blob produced by `encrypt`, verifying every chunk's tag.
    public static func decrypt(_ ciphertext: Data, key keyData: Data) throws -> Data {
        guard keyData.count == 32 else { throw MediaCryptoError.badKey }
        let key = SymmetricKey(data: keyData)

        var p = ciphertext.startIndex
        func take(_ n: Int) throws -> Data {
            guard ciphertext.distance(from: p, to: ciphertext.endIndex) >= n else { throw MediaCryptoError.truncated }
            let end = ciphertext.index(p, offsetBy: n)
            defer { p = end }
            return ciphertext[p..<end]
        }

        guard Array(try take(4)) == magic, try take(1).first == version else { throw MediaCryptoError.badHeader }
        let chunkSize = Int(uint32(try take(4)))
        let total = Int(uint64(try take(8)))
        guard chunkSize > 0 else { throw MediaCryptoError.badHeader }

        var plaintext = Data()
        var index: UInt32 = 0
        var remaining = total
        repeat {
            let ptLen = min(chunkSize, remaining)
            let ctLen = 12 + ptLen + 16 // nonce + ciphertext + tag
            let frame = try take(ctLen)
            do {
                let box = try AES.GCM.SealedBox(combined: frame)
                let opened = try AES.GCM.open(box, using: key, authenticating: uint32(index))
                plaintext.append(opened)
            } catch {
                throw MediaCryptoError.authenticationFailure
            }
            index &+= 1
            remaining -= ptLen
        } while remaining > 0
        return plaintext
    }

    /// SHA-256 helper for verifying a downloaded ciphertext blob before decrypting.
    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    // MARK: - byte helpers
    private static func uint32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }
    private static func uint32(_ d: Data) -> UInt32 { d.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } }
    private static func uint64(_ v: UInt64) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }
    private static func uint64(_ d: Data) -> UInt64 { d.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } }
}

private extension SymmetricKey {
    var rawData: Data { withUnsafeBytes { Data($0) } }
}
