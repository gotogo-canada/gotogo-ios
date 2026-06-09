import Foundation

/// A federated identity of the form `localpart@domain` (docs/federation/02).
///
/// Mirrors the backend `internal/address` package. The localpart is either a
/// server-assigned random id (e.g. `A0BS2MA1`) or a user-chosen username; the
/// domain is the user's home server. An `Address` is only a handle — the
/// cryptographic identity is the device's Ed25519 key, so reassigning a handle
/// never moves a key.
///
/// Routing/persistence keys use ``folded`` (lowercased localpart + domain). For a
/// **local** contact the backend emits a bare localpart, which the app keeps using
/// as-is (no migration); only **remote** peers carry an explicit `@domain`.
public struct Address: Hashable, Sendable {
    public let localpart: String
    public let domain: String

    public init(localpart: String, domain: String) {
        self.localpart = localpart
        self.domain = Address.canonicalDomain(domain) ?? domain.lowercased()
    }

    /// Parses `"localpart@domain"`. Returns nil if malformed. A non-ASCII domain
    /// is canonicalized to its IDNA A-label (`xn--…`), matching the backend.
    public init?(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let at = trimmed.lastIndex(of: "@") else { return nil }
        let lp = String(trimmed[trimmed.startIndex..<at])
        let dom = String(trimmed[trimmed.index(after: at)...])
        guard Address.isValidLocalpart(lp), let canon = Address.canonicalDomain(dom) else { return nil }
        self.localpart = lp
        self.domain = canon
    }

    /// IDNA-canonicalizes a domain to its lowercased ASCII A-label form, or nil if
    /// invalid after encoding (mirrors the backend's idna.Lookup.ToASCII).
    static func canonicalDomain(_ dom: String) -> String? {
        let trimmed = dom.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, let ascii = IDNA.toASCII(trimmed), isValidDomain(ascii) else { return nil }
        return ascii
    }

    /// Builds an address from a wire identifier that may be bare (`bob`, local) or
    /// full (`bob@b.com`, remote), defaulting a bare id to `localDomain`.
    public init(wire: String, localDomain: String) {
        if let parsed = Address(wire) {
            self = parsed
        } else {
            self.localpart = wire
            self.domain = localDomain.lowercased()
        }
    }

    /// Display/wire form `localpart@domain`.
    public var display: String { "\(localpart)@\(domain)" }

    /// Canonical key for maps, TOFU pins and persistence.
    public var folded: String { "\(localpart.lowercased())@\(domain)" }

    /// True when the localpart is a server-assigned random id (`^[A-Z0-9]{8}$`).
    public var isRandomID: Bool {
        localpart.count == 8 && localpart.allSatisfy { c in
            c.isASCII && (("A"..."Z").contains(c) || ("0"..."9").contains(c))
        }
    }

    /// Whether this address is hosted on `localDomain` (a local contact).
    public func isLocal(to localDomain: String) -> Bool {
        domain.lowercased() == localDomain.lowercased()
    }

    // MARK: - Validation (mirrors the Go grammar; ASCII-only)

    static func isValidLocalpart(_ lp: String) -> Bool {
        guard (1...64).contains(lp.count) else { return false }
        let allowed = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard lp.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return false }
        let seps: Set<Character> = [".", "_", "-"]
        guard let first = lp.first, let last = lp.last,
              !seps.contains(first), !seps.contains(last) else { return false }
        // No two consecutive separators.
        var prevSep = false
        for c in lp {
            let isSep = seps.contains(c)
            if isSep && prevSep { return false }
            prevSep = isSep
        }
        return true
    }

    static func isValidDomain(_ dom: String) -> Bool {
        let d = dom.trimmingCharacters(in: .whitespaces)
        guard (1...255).contains(d.count) else { return false }
        if d.contains(where: { " /@:\t\r\n".contains($0) }) { return false }
        let allowed = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        return d.unicodeScalars.allSatisfy { allowed.contains($0) }
    }
}

extension Address: Codable {
    public init(from decoder: Decoder) throws {
        let s = try decoder.singleValueContainer().decode(String.self)
        guard let a = Address(s) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                debugDescription: "invalid address \(s)"))
        }
        self = a
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(display)
    }
}
