//
//  Mnemonic.swift
//  Gotogo
//
//  BIP-39 mnemonic encode/decode over `BIP39WordList`. Used to turn 32 bytes of
//  recovery entropy into a 24-word phrase and back. Pure Foundation + CryptoKit.
//

import Foundation
import CryptoKit

/// Errors thrown while decoding a recovery phrase.
public enum MnemonicError: Error, Equatable, Sendable {
    /// A word in the phrase is not in the BIP-39 list.
    case unknownWord(String)
    /// The word count is not a supported multiple (must be 12/15/18/21/24).
    case invalidWordCount(Int)
    /// The trailing checksum bits did not match the entropy.
    case checksumMismatch
}

/// BIP-39 mnemonic codec backed by `BIP39WordList.words` (2048 words, 11 bits each).
public enum Mnemonic {

    /// Encodes raw `entropy` (16/20/24/28/32 bytes) into BIP-39 words.
    /// For 32-byte entropy this yields 24 words.
    public static func encode(_ entropy: Data) -> [String] {
        let entropyBits = entropy.count * 8
        let checksumBits = entropyBits / 32
        let digest = Data(SHA256.hash(data: entropy))

        // Build a bit string: entropy bits followed by `checksumBits` of the digest.
        var bits = bitString(from: entropy)
        bits += bitString(from: digest).prefix(checksumBits)

        let words = BIP39WordList.words
        var result: [String] = []
        result.reserveCapacity(bits.count / 11)
        var index = bits.startIndex
        while index < bits.endIndex {
            let end = bits.index(index, offsetBy: 11)
            let chunk = bits[index..<end]
            result.append(words[Int(value(of: chunk))])
            index = end
        }
        return result
    }

    /// Decodes a phrase back to entropy, validating each word and the checksum.
    public static func decode(_ words: [String]) throws -> Data {
        guard [12, 15, 18, 21, 24].contains(words.count) else {
            throw MnemonicError.invalidWordCount(words.count)
        }

        // Map every word to its 11-bit index.
        let lookup = wordIndex
        var bits: [UInt8] = []
        bits.reserveCapacity(words.count * 11)
        for raw in words {
            let word = raw.lowercased()
            guard let idx = lookup[word] else { throw MnemonicError.unknownWord(raw) }
            for shift in stride(from: 10, through: 0, by: -1) {
                bits.append(UInt8((idx >> shift) & 1))
            }
        }

        let totalBits = bits.count
        let checksumBits = totalBits / 33      // entropyBits = 32 * checksumBits
        let entropyBits = totalBits - checksumBits

        let entropy = data(fromBits: Array(bits[0..<entropyBits]))
        let expected = Data(SHA256.hash(data: entropy))
        let expectedBits = Array(bitString(from: expected).prefix(checksumBits))
        let actualBits = Array(bits[entropyBits..<totalBits])
        guard expectedBits == actualBits else { throw MnemonicError.checksumMismatch }
        return entropy
    }

    // MARK: - Bit helpers

    /// Cached word -> index map for decode.
    private static let wordIndex: [String: Int] = {
        var map: [String: Int] = [:]
        map.reserveCapacity(BIP39WordList.words.count)
        for (i, w) in BIP39WordList.words.enumerated() { map[w] = i }
        return map
    }()

    private static func bitString(from data: Data) -> [UInt8] {
        var bits: [UInt8] = []
        bits.reserveCapacity(data.count * 8)
        for byte in data {
            for shift in stride(from: 7, through: 0, by: -1) {
                bits.append((byte >> shift) & 1)
            }
        }
        return bits
    }

    private static func value(of bits: ArraySlice<UInt8>) -> UInt32 {
        var v: UInt32 = 0
        for bit in bits { v = (v << 1) | UInt32(bit) }
        return v
    }

    private static func data(fromBits bits: [UInt8]) -> Data {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(bits.count / 8)
        var index = 0
        while index + 8 <= bits.count {
            var byte: UInt8 = 0
            for offset in 0..<8 { byte = (byte << 1) | bits[index + offset] }
            bytes.append(byte)
            index += 8
        }
        return Data(bytes)
    }
}
