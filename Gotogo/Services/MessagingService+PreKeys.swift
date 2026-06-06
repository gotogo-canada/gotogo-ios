//
//  MessagingService+PreKeys.swift
//  Gotogo
//
//  One-time prekey auto-replenishment, split out of `MessagingService` to keep
//  each file focused. As inbound `"init"` sessions consume one-time prekeys on the
//  server, the local pool published there shrinks; this tops it back up so new
//  contacts can always reach a fresh one-time prekey. Foundation only.
//

import Foundation

extension MessagingService {

    /// Tops up the server's one-time-prekey pool when it runs low.
    ///
    /// Calls `GET /v1/prekeys/me/count`; if the count is below `minimum`, mints
    /// `(topUpTo - count)` fresh one-time prekeys from the persisted identity +
    /// prekey store (continuing ids past the highest existing one), `PUT`s them
    /// (alongside the unchanged identity/signed/ratchet/mlkem fields), and persists
    /// the updated store. Best-effort: intended to be called opportunistically
    /// after `sync()`, swallowing errors. Returns the number newly uploaded (0 if
    /// no top-up was needed).
    @discardableResult
    func replenishPreKeysIfNeeded(minimum: Int = 5, topUpTo: Int = 20) async throws -> Int {
        let available = try await api.prekeyCount()
        guard available < minimum else { return 0 }

        guard let identity = store.loadIdentity(),
              let existing = store.loadPreKeyStore() else {
            throw MessagingError.missingKeyMaterial
        }

        let needed = max(0, topUpTo - available)
        guard needed > 0 else { return 0 }

        let result = try engine.generateMoreOneTimePreKeys(identity: identity,
                                                           store: existing,
                                                           count: needed)

        // Republish the bundle: identity/signed/ratchet/mlkem unchanged, with the
        // freshly minted one-time prekeys appended to the pool.
        let oneTimes = result.store.oneTimePreKeys.map {
            UploadPreKeysRequest.OneTime(id: $0.id, key: $0.publicKey)
        }
        let request = UploadPreKeysRequest(
            identityKey: identity.publicKey,
            signedPreKeyId: result.store.signedPreKey.id,
            signedPreKey: result.store.signedPreKey.publicKey,
            signedPreKeySignature: result.store.signedPreKeySignature,
            oneTimePreKeys: oneTimes,
            ratchetKey: result.store.ratchetPublicKey,
            ratchetSignature: result.store.ratchetSignature,
            mlkem1024Key: result.store.mlkem1024Public,
            mlkemRatchetKey: result.store.mlkemRatchetPublic,
            mlkemRatchetSignature: result.store.mlkemRatchetSignature)
        try await api.uploadPreKeys(request)

        // Persist the updated store so the new prekeys' secrets survive locally.
        try store.savePreKeyStore(result.store)
        return result.newPublic.count
    }
}
