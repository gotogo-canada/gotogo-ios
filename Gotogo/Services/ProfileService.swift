//
//  ProfileService.swift
//  Gotogo
//
//  UI-free private-profile core. A profile (display name + optional photo) is
//  JSON-encoded and AES-256-GCM-sealed under a random per-profile key. That key
//  is then sealed INDIVIDUALLY to each mutual contact's published key:
//    - normal   : X-Wing (ML-KEM-768 + X25519) via the message engine, and
//    - sensitive: pure ML-KEM-1024 (FIPS 203, Level 5).
//  Each sealed key is wrapped in a small tagged struct so the recipient knows
//  which scheme to use to open it. The server only stores grants whose
//  `granteePublicId` is a mutual contact, and only hands a profile to a requester
//  that holds a grant. The owner can never fetch its own profile, so it persists
//  the key + plaintext locally (see `OwnProfileRecord`).
//
//  Constructed like the other services (api + engine + store), so an XCTest can
//  drive it from a `@MainActor` test with an in-memory store + test URL.
//

import Foundation
import CryptoKit

/// Errors specific to the profile flows.
public enum ProfileError: Error, Sendable, LocalizedError {
    case notSignedIn
    case missingKeyMaterial
    case missingSensitiveKey
    case sealFailed
    case openFailed

    public var errorDescription: String? {
        switch self {
        case .notSignedIn: return "You are not signed in."
        case .missingKeyMaterial: return "Local key material is missing."
        case .missingSensitiveKey: return "This contact has not published a sensitive-mode key."
        case .sealFailed: return "Could not encrypt the profile."
        case .openFailed: return "Could not decrypt the profile."
        }
    }
}

/// The wire shape of a sealed `profileKey` inside a grant's `sealedKey`. `mode`
/// tags which scheme sealed `payload`, so the recipient opens it correctly:
///   - `"xwing"`     : `payload` is a JSON-encoded `SealedEnvelope`.
///   - `"mlkem1024"` : `payload` is a JSON-encoded `MLKEM1024Sealed`.
public struct TaggedSealedKey: Codable, Sendable, Equatable {
    public var mode: String
    public var payload: Data

    public init(mode: String, payload: Data) {
        self.mode = mode
        self.payload = payload
    }

    public enum Mode {
        public static let xwing = "xwing"
        public static let mlkem1024 = "mlkem1024"
    }
}

/// Drives setting, fetching, and deleting the private profile. `@MainActor` (the
/// module default); its `async` methods suspend on `await`, so network/crypto
/// work does not block the UI thread.
@MainActor
public final class ProfileService {

    private let api: APIClient
    let engine: CryptoEngine
    let store: SecretStoring

    /// Max photo edge after downscaling, in pixels (spec: 512).
    static let photoMaxDimension = 512

    /// In-memory cache of decrypted contact profiles, keyed by public id.
    private var cache: [String: Profile] = [:]

    init(api: APIClient, engine: CryptoEngine, store: SecretStoring) {
        self.api = api
        self.engine = engine
        self.store = store
    }

    // MARK: - Set

    /// Builds, encrypts, and publishes the owner's profile, sealing the per-profile
    /// key to each mutual contact (X-Wing normally, ML-KEM-1024 when `sensitive`).
    /// The owner's key + plaintext are persisted locally so the profile can be
    /// re-granted to future contacts and shown in the owner's own UI.
    func setProfile(displayName: String,
                    photo: Data?,
                    sensitive: Bool,
                    mutualContacts: [String]) async throws {
        guard store.loadSession() != nil else { throw ProfileError.notSignedIn }

        // 1. Clean + downscale the photo before it is ever encrypted.
        let photoJPEG = Self.processPhoto(photo)
        let profile = Profile(displayName: displayName, photoJPEG: photoJPEG)

        // 2. Random per-profile AES-256 key; AES-GCM-seal the encoded profile.
        let profileKey = SymmetricKey(size: .bits256)
        let profileKeyData = profileKey.withUnsafeBytes { Data($0) }
        let encodedProfile = try JSONEncoder().encode(profile)
        let box = try AES.GCM.seal(encodedProfile, using: profileKey)
        guard let encryptedProfile = box.combined else { throw ProfileError.sealFailed }

        // 3. Seal the profile key to every mutual contact and build the grants.
        let grants = try await buildGrants(profileKeyData: profileKeyData,
                                           sensitive: sensitive,
                                           mutualContacts: mutualContacts)

        // 4. Publish, then persist the owner's record locally (server never lets
        //    the owner fetch its own profile back).
        _ = try await api.putProfile(PutProfileRequest(encryptedProfile: encryptedProfile,
                                                       grants: grants))
        try store.saveOwnProfile(OwnProfileRecord(profileKey: profileKeyData,
                                                  profile: profile,
                                                  sensitive: sensitive))
        cache[store.loadSession()?.publicId ?? ""] = profile
    }

    /// Seals `profileKeyData` to each mutual contact's published key, tagging the
    /// scheme used so the recipient can open it. Contacts whose bundle lacks the
    /// required key are skipped (sensitive needs an `mlkem1024Key`).
    private func buildGrants(profileKeyData: Data,
                             sensitive: Bool,
                             mutualContacts: [String]) async throws -> [ProfileGrant] {
        var grants: [ProfileGrant] = []
        grants.reserveCapacity(mutualContacts.count)
        for contactId in mutualContacts {
            let bundle: PublicPreKeyBundle
            do {
                bundle = try await api.fetchPreKeyBundle(publicId: contactId).toPublicBundle()
            } catch {
                continue // No bundle yet for this contact — skip; re-grant later.
            }

            let tagged: TaggedSealedKey
            if sensitive {
                guard !bundle.mlkem1024Key.isEmpty else { continue }
                let sealed = try MLKEM1024Seal.seal(profileKeyData, toPublicKey: bundle.mlkem1024Key)
                tagged = TaggedSealedKey(mode: TaggedSealedKey.Mode.mlkem1024,
                                         payload: try JSONEncoder().encode(sealed))
            } else {
                let envelope = try engine.seal(profileKeyData, to: bundle)
                tagged = TaggedSealedKey(mode: TaggedSealedKey.Mode.xwing,
                                         payload: try JSONEncoder().encode(envelope))
            }
            let sealedKey = try JSONEncoder().encode(tagged)
            grants.append(ProfileGrant(granteePublicId: contactId, sealedKey: sealedKey))
        }
        return grants
    }

    // MARK: - Fetch

    /// Fetches and decrypts `publicId`'s profile. Returns `nil` when there is no
    /// profile or the caller holds no grant (server 404). Recovers the profile key
    /// from the tagged grant (X-Wing or ML-KEM-1024), AES-GCM-opens the profile,
    /// and caches the result.
    @discardableResult
    func fetchProfile(of publicId: String) async throws -> Profile? {
        // The owner's own profile is never served back — read it locally.
        if publicId == store.loadSession()?.publicId,
           let own = store.loadOwnProfile() {
            cache[publicId] = own.profile
            return own.profile
        }

        guard let fetched = try await api.fetchProfile(publicId: publicId) else { return nil }
        let profile = try open(fetched)
        cache[publicId] = profile
        return profile
    }

    /// Opens a fetched profile: recover the profile key from the tagged grant,
    /// then AES-GCM-open the sealed profile and decode it.
    private func open(_ fetched: FetchedProfile) throws -> Profile {
        guard let identity = store.loadIdentity(),
              let preKeyStore = store.loadPreKeyStore() else {
            throw ProfileError.missingKeyMaterial
        }
        let tagged: TaggedSealedKey
        do {
            tagged = try JSONDecoder().decode(TaggedSealedKey.self, from: fetched.grant)
        } catch {
            throw ProfileError.openFailed
        }

        // 1. Recover the per-profile key by opening the tagged sealed key.
        let profileKeyData: Data
        switch tagged.mode {
        case TaggedSealedKey.Mode.mlkem1024:
            guard !preKeyStore.mlkem1024Seed.isEmpty else { throw ProfileError.missingSensitiveKey }
            let sealed = try JSONDecoder().decode(MLKEM1024Sealed.self, from: tagged.payload)
            profileKeyData = try MLKEM1024Seal.open(sealed, using: preKeyStore.mlkem1024Material)
        case TaggedSealedKey.Mode.xwing:
            let envelope = try JSONDecoder().decode(SealedEnvelope.self, from: tagged.payload)
            profileKeyData = try engine.open(envelope,
                                             identity: identity,
                                             signedPreKey: preKeyStore.signedPreKey,
                                             oneTimePreKeys: preKeyStore.oneTimePreKeys)
        default:
            throw ProfileError.openFailed
        }

        // 2. AES-GCM-open the sealed profile with the recovered key.
        do {
            let key = SymmetricKey(data: profileKeyData)
            let box = try AES.GCM.SealedBox(combined: fetched.encryptedProfile)
            let plaintext = try AES.GCM.open(box, using: key)
            return try JSONDecoder().decode(Profile.self, from: plaintext)
        } catch {
            throw ProfileError.openFailed
        }
    }

    // MARK: - Delete

    /// Deletes the owner's profile server-side and clears the local record + cache.
    func deleteProfile() async throws {
        try await api.deleteProfile()
        try store.saveOwnProfile(OwnProfileRecord(profileKey: Data(),
                                                  profile: Profile(displayName: ""),
                                                  sensitive: false))
        cache.removeAll()
    }

    // MARK: - Local access

    /// The owner's locally persisted profile, if one has been set.
    func ownProfile() -> Profile? {
        guard let record = store.loadOwnProfile(), !record.profileKey.isEmpty else { return nil }
        return record.profile
    }

    /// Whether the owner's profile is currently sealed in sensitive mode.
    func ownProfileIsSensitive() -> Bool {
        store.loadOwnProfile()?.sensitive ?? false
    }

    /// A cached profile for `publicId`, without hitting the network.
    func cachedProfile(of publicId: String) -> Profile? { cache[publicId] }

    // MARK: - Photo hygiene

    /// Strips metadata, then downscales the photo to `photoMaxDimension`. Returns
    /// `nil` for a nil/undecodable input.
    static func processPhoto(_ photo: Data?) -> Data? {
        guard let photo else { return nil }
        let cleaned = MediaProcessing.stripMetadata(photo) ?? photo
        return MediaProcessing.thumbnail(cleaned, maxDimension: photoMaxDimension) ?? cleaned
    }
}
