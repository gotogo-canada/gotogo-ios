//
//  TransparencyService.swift
//  Gotogo
//
//  UI-free key-transparency verification. Fetches a peer's published identity-key
//  entries from the backend's RFC 6962 transparency log and, for each entry,
//  (1) recomputes the leaf hash and checks it matches what the server signed over,
//  and (2) verifies the inclusion proof against the response's signed tree head —
//  so a peer's identity key is provably present in a globally consistent log the
//  server cannot equivocate about. It also compares the observed key against the
//  last key seen for that device (trust-on-first-use) to flag identity-key changes
//  ("verify in person"). Foundation + CryptoKit only.
//

import Foundation

/// Outcome of verifying a peer's transparency-log entry.
public struct TransparencyStatus: Sendable, Equatable {
    /// True iff the entry's leaf hash recomputes correctly AND its RFC 6962
    /// inclusion proof verifies against the log's signed root.
    public var included: Bool
    /// True iff the published identity key differs from the last one seen for this
    /// device (a key change worth verifying out of band). False on first sight.
    public var keyChanged: Bool
    /// The safety number between the local identity and this entry's identity key.
    public var safetyNumber: String
    /// The peer's published identity key (as found in the verified entry).
    public var identityKey: Data
    /// The peer device id this entry belongs to.
    public var deviceId: String

    public init(included: Bool,
                keyChanged: Bool,
                safetyNumber: String,
                identityKey: Data,
                deviceId: String) {
        self.included = included
        self.keyChanged = keyChanged
        self.safetyNumber = safetyNumber
        self.identityKey = identityKey
        self.deviceId = deviceId
    }
}

/// Errors specific to transparency verification.
public enum TransparencyError: Error, Sendable, LocalizedError {
    /// The account has no entries in the transparency log (never published prekeys).
    case noEntries
    /// A remote contact's server-signed transparency head failed signature
    /// verification against that domain's pinned transparency key.
    case headSignatureInvalid

    public var errorDescription: String? {
        switch self {
        case .noEntries: return "This account has not published any identity keys yet."
        case .headSignatureInvalid: return "The contact server's transparency head did not verify."
        }
    }
}

/// Verifies key-transparency inclusion proofs and detects identity-key changes.
/// `@MainActor` (the module default); its `async` method suspends on `await`, so
/// network/crypto work does not block the UI thread. Constructed like the other
/// services (api + engine + store) so an XCTest can drive it with an in-memory
/// store + test URL.
@MainActor
public final class TransparencyService {

    private let api: APIClient
    private let engine: CryptoEngine
    private let store: SecretStoring
    /// Resolves + verifies remote contacts' server-signed heads. nil on a
    /// single-server build (then only local, bare-localpart ids are verifiable).
    private let directory: FederationDirectory?

    init(api: APIClient, engine: CryptoEngine, store: SecretStoring, directory: FederationDirectory? = nil) {
        self.api = api
        self.engine = engine
        self.store = store
        self.directory = directory
    }

    /// Verifies the most-recently-published identity key for `publicId` against the
    /// transparency log, computing its safety number versus `localIdentityKey` and
    /// flagging whether the key changed since it was last seen on this device.
    ///
    /// An account may have several entries (one per device, or older rotated keys);
    /// each is verified independently, and the *newest* (highest `seq`) entry is
    /// returned as the headline status. Trust-on-first-use: the first time a
    /// device's key is seen it is recorded and reported as unchanged; a later
    /// different key for the same device is recorded and reported as changed.
    ///
    /// - Throws: `TransparencyError.noEntries` if the account has no log entries.
    @discardableResult
    func verify(publicId: String,
                localIdentityKey: Data,
                localTransportKey: Data? = nil,
                remoteTransportKey: ((_ deviceId: String) -> Data?)? = nil) async throws -> TransparencyStatus {
        guard let log = try await api.transparencyLog(publicId: publicId), !log.entries.isEmpty else {
            throw TransparencyError.noEntries
        }

        // The transparency leaf binds the BARE localpart (the backend stores
        // public_id = localpart). For a remote contact `localpart@domain`, split it:
        // the leaf hash uses the localpart, while pins/sessions key by the full id.
        let atParts = publicId.split(separator: "@", maxSplits: 1)
        let localpart = String(atParts.first ?? Substring(publicId))
        let domain = atParts.count == 2 ? String(atParts[1]) : ""

        // Remote contact: verify the contact server's signed head against its
        // TOFU-pinned transparency key BEFORE trusting any inclusion proof, so a
        // relaying server cannot forge a remote contact's key history.
        if let signedHead = log.signedHead {
            guard let directory, await directory.verify(head: signedHead, domain: domain) else {
                throw TransparencyError.headSignatureInvalid
            }
        }
        let effTreeSize = log.effectiveTreeSize
        let effRoot = log.effectiveRoot

        // Verify EVERY entry's leaf hash + inclusion proof against the response's
        // signed tree head. The headline status uses the newest entry (max seq),
        // which is the identity key a sender would actually use today.
        var statuses: [TransparencyStatus] = []
        statuses.reserveCapacity(log.entries.count)
        for entry in log.entries {
            // 1. Recompute the leaf hash and require it to match what the server
            //    committed to — guards against a server swapping the identity key
            //    while keeping a valid-looking proof for a different leaf.
            let recomputedLeaf = MerkleVerifier.leafHash(publicId: localpart,
                                                         deviceId: entry.deviceId,
                                                         identityKey: entry.identityKey)
            let leafMatches = recomputedLeaf == entry.leafHash

            // 2. Verify the RFC 6962 inclusion proof against the (verified) root.
            let proofValid = MerkleVerifier.verifyInclusion(leafHash: entry.leafHash,
                                                            index: entry.leafIndex,
                                                            treeSize: effTreeSize,
                                                            path: entry.auditPath,
                                                            root: effRoot)
            let included = leafMatches && proofValid

            // 3. Trust-on-first-use / key-change detection, per (publicId, deviceId).
            //    Only records/updates the last-seen key for entries that actually
            //    verified, so a forged entry can't poison the TOFU cache.
            let keyChanged: Bool
            if included {
                let lastSeen = store.lastSeenIdentityKey(publicId: publicId, deviceId: entry.deviceId)
                if let lastSeen {
                    keyChanged = lastSeen != entry.identityKey
                } else {
                    keyChanged = false // first sight
                }
                if lastSeen != entry.identityKey {
                    try store.setLastSeenIdentityKey(entry.identityKey,
                                                     publicId: publicId,
                                                     deviceId: entry.deviceId)
                }
            } else {
                keyChanged = false
            }

            let safetyNumber = engine.safetyNumber(localIdentity: localIdentityKey,
                                                   localTransport: localTransportKey,
                                                   remoteIdentity: entry.identityKey,
                                                   remoteTransport: remoteTransportKey?(entry.deviceId))
            statuses.append(TransparencyStatus(included: included,
                                               keyChanged: keyChanged,
                                               safetyNumber: safetyNumber,
                                               identityKey: entry.identityKey,
                                               deviceId: entry.deviceId))
        }

        // Headline = newest published entry (highest seq).
        guard let newest = zip(log.entries, statuses).max(by: { $0.0.seq < $1.0.seq })?.1 else {
            throw TransparencyError.noEntries
        }
        return newest
    }
}
