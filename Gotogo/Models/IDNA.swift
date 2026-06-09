import Foundation

/// Minimal IDNA-to-ASCII for domain names: NFC + lowercase, then RFC 3492
/// Punycode-encode any label containing non-ASCII as an `xn--` A-label. This
/// brings the iOS client to parity with the backend's `golang.org/x/net/idna`
/// (`idna.Lookup.ToASCII`) so that `münchen.example` folds to the same A-label
/// on both sides — essential because the folded domain is part of pin, leaf and
/// routing keys. Full UTS-46 mapping tables are out of scope; NFC + lowercase +
/// Punycode covers real-world IDNs, and the server canonicalizes authoritatively.
enum IDNA {

    /// Converts a (possibly internationalized) domain to its ASCII A-label form.
    /// Returns nil if a non-ASCII label cannot be encoded.
    static func toASCII(_ domain: String) -> String? {
        let normalized = domain.precomposedStringWithCanonicalMapping.lowercased()
        var labels: [String] = []
        for piece in normalized.split(separator: ".", omittingEmptySubsequences: false) {
            let label = String(piece)
            if label.unicodeScalars.allSatisfy({ $0.isASCII }) {
                labels.append(label)
            } else {
                guard let encoded = punycodeEncode(label) else { return nil }
                labels.append("xn--" + encoded)
            }
        }
        return labels.joined(separator: ".")
    }

    // RFC 3492 parameters.
    private static let base = 36, tmin = 1, tmax = 26
    private static let skew = 38, damp = 700, initialBias = 72, initialN = 128

    /// RFC 3492 Punycode encoding of a single label's Unicode scalars.
    static func punycodeEncode(_ input: String) -> String? {
        let scalars = input.unicodeScalars.map { Int($0.value) }
        var output = ""

        var basicCount = 0
        for c in scalars where c < 0x80 {
            guard let u = UnicodeScalar(c) else { return nil }
            output.unicodeScalars.append(u)
            basicCount += 1
        }
        let b = basicCount
        var h = basicCount
        if b > 0 { output.append("-") }

        var n = initialN
        var delta = 0
        var bias = initialBias

        while h < scalars.count {
            var m = Int.max
            for c in scalars where c >= n && c < m { m = c }
            // Guard the (rare) overflow path defensively.
            if m - n > (Int.max - delta) / (h + 1) { return nil }
            delta += (m - n) * (h + 1)
            n = m
            for c in scalars {
                if c < n {
                    delta += 1
                    if delta == 0 { return nil }
                }
                if c == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                        if q < t { break }
                        output.append(digit(t + ((q - t) % (base - t))))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, h + 1, h == b)
                    delta = 0
                    h += 1
                }
            }
            delta += 1
            n += 1
        }
        return output
    }

    private static func digit(_ d: Int) -> Character {
        // 0..25 -> 'a'..'z', 26..35 -> '0'..'9'
        if d < 26 { return Character(UnicodeScalar(UInt8(97 + d))) }
        return Character(UnicodeScalar(UInt8(48 + d - 26)))
    }

    private static func adapt(_ delta0: Int, _ numPoints: Int, _ firstTime: Bool) -> Int {
        var delta = firstTime ? delta0 / damp : delta0 / 2
        delta += delta / numPoints
        var k = 0
        while delta > ((base - tmin) * tmax) / 2 {
            delta /= (base - tmin)
            k += base
        }
        return k + (((base - tmin + 1) * delta) / (delta + skew))
    }
}
