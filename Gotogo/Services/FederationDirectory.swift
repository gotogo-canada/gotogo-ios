import Foundation
import CryptoKit

/// Discovers and TOFU-pins a peer domain's transparency-signing key, and verifies
/// a server-signed transparency head (docs/federation/01 §4, 06 §Key transparency).
///
/// In the home-server-relay model the client fetches a remote contact's proofs via
/// its own server, but the proofs carry a `signedHead` signed by the **contact's**
/// home server. This type fetches that server's `.well-known/gotogo/server` over
/// HTTPS (TLS authenticates the domain), pins its transparency key on first sight,
/// and verifies the head — so a relaying server cannot forge a contact's keys.
public actor FederationDirectory {

    /// The server-signed head carried on remote transparency responses. The bytes
    /// signed are reproduced exactly in ``headCanonical(_:)``.
    public struct SignedHead: Decodable, Sendable {
        public let treeSize: Int
        public let rootHash: String   // base64 of the raw Merkle root
        public let timestamp: Int
        public let keyId: String
        public let signature: String  // base64 Ed25519 signature
    }

    public enum DirectoryError: Error { case discoveryFailed, keyNotFound, conflictingKey }

    private struct ServerKey: Decodable { let key_id: String; let public_key: String }
    private struct Descriptor: Decodable {
        let federation_endpoint: String?
        let server_keys: [ServerKey]?
        let transparency_keys: [ServerKey]?
    }

    private let session: URLSession
    /// TOFU pins: "domain|keyId" -> raw 32-byte Ed25519 public key.
    private var pins: [String: Data]

    public init(session: URLSession = .shared, pinned: [String: Data] = [:]) {
        self.session = session
        self.pins = pinned
    }

    /// Returns the current TOFU pin set (so the app can persist it across launches).
    public func pinnedKeys() -> [String: Data] { pins }

    /// Verifies a remote transparency head against the contact domain's pinned
    /// transparency key. Returns true only when the Ed25519 signature is valid.
    public func verify(head: SignedHead, domain: String) async -> Bool {
        guard let keyData = try? await transparencyKey(domain: domain, keyId: head.keyId),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData),
              let sig = Data(base64Encoded: head.signature),
              sig.count == 64 else { // Ed25519 signature size; reject anything else
            return false
        }
        // CryptoKit's `Curve25519.Signing` IS Ed25519 (Edwards-curve), matching the
        // backend's crypto/ed25519. The 32-byte raw key + 64-byte sig are verified
        // over the byte-exact `headCanonical` message.
        return key.isValidSignature(sig, for: Self.headCanonical(head))
    }

    /// The exact bytes the backend signs (`federation.headCanonical`):
    /// `"gotogo-transparency-head-v1\n<treeSize>\n<base64 rootHash>\n<timestamp>"`
    /// with no trailing newline. `rootHash` is the same base64 string sent on the
    /// wire, so this reproduces the signed message byte-for-byte.
    static func headCanonical(_ h: SignedHead) -> Data {
        Data("gotogo-transparency-head-v1\n\(h.treeSize)\n\(h.rootHash)\n\(h.timestamp)".utf8)
    }

    /// Resolves a domain's transparency public key for a key id, pinning it on
    /// first sight. A different key for an already-pinned id is a conflict (a
    /// possible attack) and is rejected rather than silently replaced.
    private func transparencyKey(domain: String, keyId: String) async throws -> Data {
        let pin = "\(domain.lowercased())|\(keyId)"
        let desc = try await fetchDescriptor(domain: domain)
        // Backend may publish the KT key under transparency_keys, or fall back to
        // the request-signing key (server_keys) when none is configured.
        let candidates = (desc.transparency_keys ?? []) + (desc.server_keys ?? [])
        guard let entry = candidates.first(where: { $0.key_id == keyId }),
              let raw = Data(base64Encoded: entry.public_key), raw.count == 32 else {
            if let pinned = pins[pin] { return pinned }
            throw DirectoryError.keyNotFound
        }
        if let pinned = pins[pin] {
            guard pinned == raw else { throw DirectoryError.conflictingKey }
            return pinned
        }
        pins[pin] = raw
        return raw
    }

    private func fetchDescriptor(domain: String) async throws -> Descriptor {
        guard let url = URL(string: "https://\(domain)/.well-known/gotogo/server") else {
            throw DirectoryError.discoveryFailed
        }
        var req = URLRequest(url: url)
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
            throw DirectoryError.discoveryFailed
        }
        return try JSONDecoder().decode(Descriptor.self, from: data)
    }
}
