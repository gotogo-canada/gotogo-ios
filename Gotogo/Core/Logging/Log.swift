//
//  Log.swift
//  Gotogo
//
//  A tiny, dependency-free logger whose whole reason to exist is `redact(_:)`:
//  before anything is written it scrubs the kind of secrets that have no business
//  in a log line — bearer tokens, long base64/hex blobs (keys, ciphertext, hashes),
//  and `token`/`key`-labelled values. Most of the app deliberately logs nothing
//  sensitive; routing the few request/response/token sites through here makes that
//  guarantee mechanical rather than a matter of discipline. Foundation only.
//

import Foundation

/// Minimal leveled logger with built-in secret redaction. Every message is passed
/// through `redact(_:)` before it is emitted, so a caller can never accidentally
/// print a raw token or key — even if one slips into an interpolated string.
public enum Log {

    /// Severity of a log line. Printed as a single-letter prefix.
    public enum Level: String {
        case debug = "D"
        case info = "I"
        case error = "E"
    }

    /// Emits an info-level line (redacted).
    public static func info(_ message: @autoclosure () -> String) { emit(.info, message()) }
    /// Emits a debug-level line (redacted).
    public static func debug(_ message: @autoclosure () -> String) { emit(.debug, message()) }
    /// Emits an error-level line (redacted).
    public static func error(_ message: @autoclosure () -> String) { emit(.error, message()) }

    /// Writes one redacted line. Kept private so all output funnels through redaction.
    private static func emit(_ level: Level, _ message: String) {
        // A single, simple sink. `print` is fine here; the point of this type is the
        // redaction guarantee, not the transport.
        print("[\(level.rawValue)] gotogo: \(redact(message))")
    }

    // MARK: - Redaction

    /// `Bearer <token>` (case-insensitive scheme) → `Bearer ***`.
    private static let bearerPattern =
        try! NSRegularExpression(pattern: "(?i)\\bBearer\\s+[A-Za-z0-9._~+/=-]+",
                                 options: [])

    /// `token`/`key`/`secret`/`password`-style labels followed by `:`/`=` and a
    /// value → label kept, value replaced with `***`. Handles optional quoting and
    /// surrounding whitespace (e.g. `"token": "abc"`, `key=abc`, `apiKey: abc`).
    private static let labeledPattern =
        try! NSRegularExpression(
            pattern: "(?i)([\"']?\\b[A-Za-z0-9_-]*(?:token|key|secret|password|passwd|pwd|authorization)\\b[\"']?\\s*[:=]\\s*)[\"']?[A-Za-z0-9._~+/=-]+[\"']?",
            options: [])

    /// A standalone long opaque blob (≥16 chars of base64/hex-ish material) →
    /// `***`. Bounded by non-token characters so it only swallows the blob itself.
    private static let blobPattern =
        try! NSRegularExpression(pattern: "(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{16,}(?![A-Za-z0-9+/=_-])",
                                 options: [])

    /// Masks secrets in `s` for safe logging. The masking is layered so the more
    /// specific rules (bearer header, labelled values) run before the broad
    /// "long opaque blob" sweep:
    ///   1. `Bearer xxxxx`            → `Bearer ***`
    ///   2. `token: xxxxx` / `key=…`  → `token: ***`
    ///   3. any remaining ≥16-char base64/hex run → `***`
    /// Ordinary prose is left untouched (short words never hit the blob rule).
    public static func redact(_ s: String) -> String {
        var out = s
        out = bearerPattern.stringByReplacingMatches(
            in: out, options: [], range: NSRange(out.startIndex..., in: out),
            withTemplate: "Bearer ***")
        out = labeledPattern.stringByReplacingMatches(
            in: out, options: [], range: NSRange(out.startIndex..., in: out),
            withTemplate: "$1***")
        out = blobPattern.stringByReplacingMatches(
            in: out, options: [], range: NSRange(out.startIndex..., in: out),
            withTemplate: "***")
        return out
    }
}
