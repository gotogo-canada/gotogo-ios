//
//  APIModels.swift
//  Gotogo
//
//  Request/response DTOs mirroring the backend REST contract. Binary fields are
//  `Data` and encode/decode as base64 via the default JSON coders. Pure Foundation.
//

import Foundation

// MARK: - Accounts

struct RegisterRequest: Encodable {
    let deviceName: String
    let recoveryPublicKey: Data
    let recoveryVault: Data
}

/// Response for register and recover/finish — both return the same fields.
struct AccountCredentials: Decodable {
    let publicId: String
    let accountId: String
    let deviceId: String
    let token: String
}

/// `GET /v1/server` — public server info used to validate a chosen home server
/// and learn the home `@domain` for `id@domain` addressing.
struct ServerInfoResponse: Decodable {
    let domain: String
    let name: String?
    let federationMode: String?
    let federated: Bool?
}

/// `GET /v1/usernames/{name}/available` — username availability check.
struct UsernameAvailabilityResponse: Decodable {
    let available: Bool
    let reason: String?
}

/// `PUT /v1/account/username` request + response.
struct SetUsernameRequest: Encodable {
    let username: String
}
struct SetUsernameResponse: Decodable {
    /// The new `localpart@domain` address the server assigned.
    let address: String
}

struct RecoverStartRequest: Encodable {
    let publicId: String
}

struct RecoverStartResponse: Decodable {
    let challenge: Data
    let challengeTag: Data
    let vault: Data
}

struct RecoverFinishRequest: Encodable {
    let publicId: String
    let challenge: Data
    let challengeTag: Data
    let signature: Data
    let deviceName: String
}

// MARK: - Devices

/// `POST /v1/devices` body: provisions an ADDITIONAL device on the *current*
/// account (authenticated with an existing device's token).
struct AddDeviceRequest: Encodable {
    let deviceName: String
}

/// `POST /v1/devices` response: the new device's id and its own bearer token.
struct AddDeviceResponse: Decodable {
    let deviceId: String
    let token: String
}

// MARK: - Prekeys

struct UploadPreKeysRequest: Encodable {
    struct OneTime: Encodable {
        let id: Int
        let key: Data
    }
    let identityKey: Data
    let signedPreKeyId: Int
    let signedPreKey: Data
    let signedPreKeySignature: Data
    let oneTimePreKeys: [OneTime]
    /// X25519 ratchet public key seeding the Double/Triple Ratchet's DH ratchet.
    let ratchetKey: Data
    /// Ed25519 signature over `ratchetKey`, made with the identity key.
    let ratchetSignature: Data
    /// ML-KEM-1024 raw public key, published for "sensitive" sealed payloads.
    let mlkem1024Key: Data
    /// ML-KEM-768 ratchet public key seeding the *Triple* Ratchet's PQ ratchet.
    let mlkemRatchetKey: Data
    /// Ed25519 signature over `mlkemRatchetKey`, made with the identity key.
    let mlkemRatchetSignature: Data
}

struct UploadPreKeysResponse: Decodable {
    let uploaded: Int
    let oneTimeAvailable: Int
}

/// Response of `GET /v1/prekeys/{publicID}` — a fetched bundle for one device.
struct FetchedPreKeyBundle: Decodable {
    let publicId: String
    let deviceId: String
    let identityKey: Data
    let signedPreKeyId: Int
    let signedPreKey: Data
    let signedPreKeySignature: Data
    let oneTimePreKeyId: Int?
    let oneTimePreKey: Data?
    /// X25519 ratchet public key (backend JSON key: `ratchetKey`).
    let ratchetKey: Data
    /// Ed25519 signature over `ratchetKey` (backend JSON key: `ratchetSignature`).
    let ratchetSignature: Data
    /// ML-KEM-1024 raw public key (backend JSON key: `mlkem1024Key`).
    let mlkem1024Key: Data
    /// ML-KEM-768 ratchet public key for the *Triple* Ratchet (backend JSON key:
    /// `mlkemRatchetKey`). Optional-decoded so older bundles without it still parse.
    let mlkemRatchetKey: Data
    /// Ed25519 signature over `mlkemRatchetKey` (backend JSON key: `mlkemRatchetSignature`).
    let mlkemRatchetSignature: Data

    private enum CodingKeys: String, CodingKey {
        case publicId, deviceId, identityKey, signedPreKeyId, signedPreKey
        case signedPreKeySignature, oneTimePreKeyId, oneTimePreKey
        case ratchetKey
        // The bundle's `ratchetKeySignature` decodes from the backend's `ratchetSignature`.
        case ratchetSignature
        case mlkem1024Key
        case mlkemRatchetKey
        case mlkemRatchetSignature
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        publicId = try c.decode(String.self, forKey: .publicId)
        deviceId = try c.decode(String.self, forKey: .deviceId)
        identityKey = try c.decode(Data.self, forKey: .identityKey)
        signedPreKeyId = try c.decode(Int.self, forKey: .signedPreKeyId)
        signedPreKey = try c.decode(Data.self, forKey: .signedPreKey)
        signedPreKeySignature = try c.decode(Data.self, forKey: .signedPreKeySignature)
        oneTimePreKeyId = try c.decodeIfPresent(Int.self, forKey: .oneTimePreKeyId)
        oneTimePreKey = try c.decodeIfPresent(Data.self, forKey: .oneTimePreKey)
        ratchetKey = try c.decodeIfPresent(Data.self, forKey: .ratchetKey) ?? Data()
        ratchetSignature = try c.decodeIfPresent(Data.self, forKey: .ratchetSignature) ?? Data()
        mlkem1024Key = try c.decodeIfPresent(Data.self, forKey: .mlkem1024Key) ?? Data()
        mlkemRatchetKey = try c.decodeIfPresent(Data.self, forKey: .mlkemRatchetKey) ?? Data()
        mlkemRatchetSignature = try c.decodeIfPresent(Data.self, forKey: .mlkemRatchetSignature) ?? Data()
    }

    /// Builds the crypto-layer bundle used by `engine.seal` / `establishSender`.
    func toPublicBundle() -> PublicPreKeyBundle {
        PublicPreKeyBundle(identityKey: identityKey,
                           signedPreKeyId: signedPreKeyId,
                           signedPreKey: signedPreKey,
                           signedPreKeySignature: signedPreKeySignature,
                           oneTimePreKeyId: oneTimePreKeyId,
                           oneTimePreKey: oneTimePreKey,
                           ratchetKey: ratchetKey,
                           ratchetKeySignature: ratchetSignature,
                           mlkem1024Key: mlkem1024Key,
                           mlkemRatchetKey: mlkemRatchetKey)
    }
}

/// Response of `GET /v1/prekeys/{publicID}/devices` — one session bundle per
/// device the account currently has published prekeys for. Used by multi-device
/// fan-out: the sender encrypts a separate ratchet session to each device.
struct AllPreKeyBundlesResponse: Decodable {
    let publicId: String
    let devices: [FetchedPreKeyBundle]
}

/// Response of `GET /v1/prekeys/me/count` — how many of this device's one-time
/// prekeys remain unconsumed on the server, driving auto-replenishment.
struct PreKeyCountResponse: Decodable {
    let oneTimeAvailable: Int
}

// MARK: - Key directory (MLS KeyPackages and opaque one-time key blobs)

/// Body of `PUT /v1/keydir/{namespace}` — publish a batch of opaque key blobs for
/// the calling device. `blob` is base64 (Swift `Data`); the server never parses it.
struct PublishKeysRequest: Encodable {
    struct Entry: Encodable {
        let keyId: String
        let blob: Data
        let lastResort: Bool
    }
    let keys: [Entry]
}

/// Response of `PUT /v1/keydir/{namespace}` — one-time entries now available.
struct PublishKeysResponse: Decodable {
    let available: Int
}

/// Response of `GET /v1/keydir/{namespace}/{publicId}/devices` — one claimed key
/// blob per active device of the target account.
struct ClaimedKeysResponse: Decodable {
    struct Device: Decodable {
        let deviceId: String
        let keyId: String
        let blob: Data
    }
    let publicId: String
    let devices: [Device]
}

/// Response of `GET /v1/keydir/{namespace}/me/count` — unconsumed one-time entries.
struct KeyCountResponse: Decodable {
    let available: Int
}

// MARK: - Group commit ordering (MLS Delivery-Service compare-and-swap)

/// Body of `POST /v1/groups/{groupId}/commitlog` — an opaque compare-and-swap of
/// the group's ordering head. `prevToken` is the head this commit builds on
/// (empty = genesis); `newToken` is the random opaque token to install on success.
struct SubmitCommitRequest: Encodable {
    let prevToken: Data
    let newToken: Data
}

/// Response of the commit-ordering submit/head endpoints. `accepted` reports
/// whether the compare-and-swap won the slot; `token` + `seq` are the resulting
/// head on success, or the CURRENT head (to rebase onto) on a lost race.
struct CommitHeadResponse: Decodable {
    let accepted: Bool
    let token: Data
    let seq: Int
}

// MARK: - Contacts

struct ContactRequestBody: Encodable {
    // Federation-aware: bare localpart for a local recipient, or `toAddress`
    // (localpart@domain) for a remote one. nil optionals are omitted on the wire.
    var toPublicId: String? = nil
    var toAddress: String? = nil
}

struct ContactAcceptBody: Encodable {
    var fromPublicId: String? = nil
    var fromAddress: String? = nil
}

struct ContactStateResponse: Decodable {
    let state: String
}

struct ContactsListResponse: Decodable {
    struct Entry: Decodable {
        let publicId: String
        let state: String
        let direction: String
    }
    let contacts: [Entry]
}

struct UserLookupResponse: Decodable {
    let publicId: String
    let exists: Bool
    let hasDevice: Bool
    /// New address if the user moved servers (account portability); follow it.
    let movedTo: String?
}

// MARK: - Messages

struct SendMessageRequest: Encodable {
    let toPublicId: String
    let toDeviceId: String
    let ciphertext: Data
    let contentType: String
    let clientMessageId: String
    /// Federation-aware recipient (localpart@domain). Set for a remote recipient;
    /// the backend prefers it over `toPublicId`. Omitted on the wire when nil.
    var toAddress: String? = nil
}

struct SendMessageResponse: Decodable {
    let messageId: String
    let createdAt: Date
}

/// One inbound message from sync or the realtime socket.
struct InboundMessage: Decodable, Sendable, Equatable {
    let id: String
    let fromPublicId: String
    /// Federation-aware sender: bare localpart for a local sender, localpart@domain
    /// for a remote one. Prefer this as the conversation/session key (see
    /// `senderAddress`); absent on older servers. Decoded as optional for back-compat.
    let fromAddress: String?
    let fromDeviceId: String
    let ciphertext: Data
    let contentType: String
    let createdAt: Date

    /// The routing identity: the full address when present, else the bare localpart
    /// (so local conversations keep their existing bare key — no migration needed).
    var senderAddress: String { fromAddress ?? fromPublicId }
}

struct SyncResponse: Decodable {
    let messages: [InboundMessage]
    let count: Int
}

// MARK: - Blocking & reporting

/// `POST /v1/contacts/block` and `/v1/contacts/unblock` body.
struct BlockRequest: Encodable {
    let publicId: String
}

/// `POST /v1/contacts/block` → `{"blocked":true}` / unblock → `{"blocked":false}`.
struct BlockResponse: Decodable {
    let blocked: Bool
}

/// `GET /v1/blocks` → `{"blocked":[{"publicId":String}]}`.
struct BlocksListResponse: Decodable {
    struct Entry: Decodable {
        let publicId: String
    }
    let blocked: [Entry]
}

/// `POST /v1/reports` body.
struct ReportRequest: Encodable {
    let publicId: String
    let reason: String
}

/// `POST /v1/reports` → 201 `{"reported":true}`.
struct ReportResponse: Decodable {
    let reported: Bool
}

// MARK: - Groups

/// A member entry as returned by the group endpoints: `{publicId, role}`.
struct GroupMemberDTO: Decodable {
    let publicId: String
    let role: String
}

/// `POST /v1/groups` body: the AES-GCM-sealed group name plus the initial member
/// public ids. The creator is added server-side as an admin.
struct CreateGroupRequest: Encodable {
    let encryptedName: Data
    let memberPublicIds: [String]
}

/// `POST /v1/groups` response and `GET /v1/groups/{groupId}` response: the new
/// group id and its member roster.
struct GroupResponse: Decodable {
    let groupId: String
    let members: [GroupMemberDTO]
    let encryptedName: Data?
    let createdAt: Date?
}

/// One entry in `GET /v1/groups`.
struct GroupListEntry: Decodable {
    let groupId: String
    let encryptedName: Data
    let members: [GroupMemberDTO]
    let createdAt: Date?
}

/// `GET /v1/groups` response.
struct GroupListResponse: Decodable {
    let groups: [GroupListEntry]
}

/// `POST /v1/groups/{groupId}/members` body.
struct AddGroupMemberRequest: Encodable {
    let publicId: String
}

/// `POST /v1/groups/{groupId}/members` → `{"added":true}`.
struct AddGroupMemberResponse: Decodable {
    let added: Bool
}

// MARK: - Transparency (key transparency log)

/// `GET /v1/transparency/head` → the current signed tree head.
struct TransparencyHeadResponse: Decodable {
    let treeSize: Int
    let rootHash: Data
}

/// `GET /v1/transparency/{publicId}` → the account's published identity-key
/// entries, each with an RFC 6962 inclusion proof.
///
/// For a LOCAL id the response carries top-level `treeSize`/`rootHash` (trusted via
/// TLS to our own server). For a REMOTE `localpart@domain` it carries a
/// `signedHead` signed by the contact's home server, which the client verifies
/// against that domain's pinned transparency key (see `FederationDirectory`).
struct TransparencyLogResponse: Decodable {
    struct Entry: Decodable {
        let deviceId: String
        let identityKey: Data
        let seq: Int
        let leafIndex: Int
        let leafHash: Data
        let auditPath: [Data]
    }
    let publicId: String
    let treeSize: Int?
    let rootHash: Data?
    let signedHead: FederationDirectory.SignedHead?
    let entries: [Entry]

    /// Effective tree size — from the signed head (remote) or the top level (local).
    var effectiveTreeSize: Int { signedHead?.treeSize ?? treeSize ?? 0 }

    /// Effective Merkle root bytes — decoded from the signed head (remote) or the
    /// top-level base64 field (local).
    var effectiveRoot: Data {
        if let sh = signedHead { return Data(base64Encoded: sh.rootHash) ?? Data() }
        return rootHash ?? Data()
    }
}

// MARK: - Profiles

/// One access grant in a profile upload: the encrypted-profile key, sealed to a
/// mutual contact's published key. The backend only stores grants whose
/// `granteePublicId` is a mutual contact (others are silently dropped).
struct ProfileGrant: Encodable {
    let granteePublicId: String
    /// The tagged, sealed `profileKey` (JSON `TaggedSealedKey`) as opaque bytes.
    let sealedKey: Data
}

/// `PUT /v1/profile` body: the AES-GCM-sealed profile blob plus per-contact grants.
struct PutProfileRequest: Encodable {
    let encryptedProfile: Data
    let grants: [ProfileGrant]
}

/// `PUT /v1/profile` response: the new profile version and how many grants stuck.
struct PutProfileResponse: Decodable {
    let version: Int
    let grantsStored: Int
}

/// `GET /v1/profile/{publicId}` response (200): the sealed profile, its version,
/// and the requester's own sealed-key grant. Returned only when the requester
/// holds a stored grant; the server 404s otherwise.
struct FetchedProfile: Decodable {
    let publicId: String
    let encryptedProfile: Data
    let version: Int
    /// The requester's grant: the tagged, sealed `profileKey` as opaque bytes.
    let grant: Data
}
