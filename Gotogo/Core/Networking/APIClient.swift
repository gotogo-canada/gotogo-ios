//
//  APIClient.swift
//  Gotogo
//
//  Async HTTP client for the Gotogo backend. One method per endpoint in the REST
//  contract. Injectable base URL + bearer token so it can target the local dev
//  server or be stubbed in tests. Foundation only.
//

import Foundation

/// Thin async wrapper over `URLSession` implementing the Gotogo REST contract.
public final class APIClient: @unchecked Sendable {

    private let baseURL: URL
    private let session: URLSession
    /// Bearer token; protected by `tokenLock` for safe cross-task mutation.
    private var token: String?
    private let tokenLock = NSLock()

    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    /// - Parameters:
    ///   - baseURL: REST root (default: the active environment's `apiBaseURL`).
    ///   - token: optional initial bearer token.
    ///   - session: injectable `URLSession` (default `.shared`).
    init(baseURL: URL = AppEnvironment.current.apiBaseURL,
                token: String? = nil,
                session: URLSession = .shared) {
        self.baseURL = baseURL
        self.token = token
        self.session = session

        let enc = JSONEncoder()
        self.encoder = enc

        let dec = JSONDecoder()
        // Server emits ISO-8601 with fractional seconds and a TZ offset, e.g.
        // "2026-06-03T21:23:33.305801-04:00". Decode leniently.
        dec.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            if let date = Self.flexibleDate(from: raw) { return date }
            throw DecodingError.dataCorruptedError(in: container,
                                                   debugDescription: "Unparseable date: \(raw)")
        }
        self.decoder = dec
    }

    /// Updates (or clears) the bearer token used for authenticated calls.
    func setToken(_ token: String?) {
        tokenLock.lock(); defer { tokenLock.unlock() }
        self.token = token
    }

    private var currentToken: String? {
        tokenLock.lock(); defer { tokenLock.unlock() }
        return token
    }

    // MARK: - Accounts

    func register(deviceName: String,
                         recoveryPublicKey: Data,
                         recoveryVault: Data) async throws -> AccountCredentials {
        let body = RegisterRequest(deviceName: deviceName,
                                   recoveryPublicKey: recoveryPublicKey,
                                   recoveryVault: recoveryVault)
        return try await send("/v1/accounts/register", method: "POST", body: body, authed: false)
    }

    func recoverStart(publicId: String) async throws -> RecoverStartResponse {
        try await send("/v1/accounts/recover/start", method: "POST",
                       body: RecoverStartRequest(publicId: publicId), authed: false)
    }

    func recoverFinish(_ request: RecoverFinishRequest) async throws -> AccountCredentials {
        try await send("/v1/accounts/recover/finish", method: "POST", body: request, authed: false)
    }

    func deleteAccount() async throws {
        try await sendNoContent("/v1/accounts/me", method: "DELETE", authed: true)
    }

    // MARK: - Devices

    /// Provisions an additional device on the current account, returning its own
    /// device id + bearer token. Authenticated with an existing device's token.
    func addDevice(deviceName: String) async throws -> AddDeviceResponse {
        try await send("/v1/devices", method: "POST",
                       body: AddDeviceRequest(deviceName: deviceName), authed: true)
    }

    // MARK: - Prekeys

    @discardableResult
    func uploadPreKeys(_ request: UploadPreKeysRequest) async throws -> UploadPreKeysResponse {
        try await send("/v1/prekeys", method: "PUT", body: request, authed: true)
    }

    func fetchPreKeyBundle(publicId: String) async throws -> FetchedPreKeyBundle {
        try await send("/v1/prekeys/\(publicId)", method: "GET",
                       body: Optional<Empty>.none, authed: true)
    }

    /// Fetches a session bundle for EVERY device the account has published prekeys
    /// for, so the sender can fan a message out to each device. One bundle per
    /// device (each carries its own `deviceId`, identity, prekeys, ratchet key…).
    func fetchAllPreKeyBundles(publicId: String) async throws -> [FetchedPreKeyBundle] {
        let response: AllPreKeyBundlesResponse =
            try await send("/v1/prekeys/\(publicId)/devices", method: "GET",
                           body: Optional<Empty>.none, authed: true)
        return response.devices
    }

    /// Returns how many of this device's one-time prekeys remain on the server.
    func prekeyCount() async throws -> Int {
        let response: PreKeyCountResponse =
            try await send("/v1/prekeys/me/count", method: "GET",
                           body: Optional<Empty>.none, authed: true)
        return response.oneTimeAvailable
    }

    // MARK: - Key directory (MLS KeyPackages and opaque one-time key blobs)

    /// Publishes a batch of opaque key blobs for the calling device in `namespace`
    /// ("mls-kp" for MLS KeyPackages). Returns the one-time count now available.
    @discardableResult
    func publishKeys(namespace: String, entries: [PublishKeysRequest.Entry]) async throws -> Int {
        let response: PublishKeysResponse =
            try await send("/v1/keydir/\(namespace)", method: "PUT",
                           body: PublishKeysRequest(keys: entries), authed: true)
        return response.available
    }

    /// Claims one key blob per active device of the target account in `namespace`
    /// (a one-time entry, consumed; else the device's last-resort entry).
    func claimKeys(namespace: String, publicId: String) async throws -> [ClaimedKeysResponse.Device] {
        let response: ClaimedKeysResponse =
            try await send("/v1/keydir/\(namespace)/\(publicId)/devices", method: "GET",
                           body: Optional<Empty>.none, authed: true)
        return response.devices
    }

    /// Returns how many of this device's one-time entries remain in `namespace`.
    func keyCount(namespace: String) async throws -> Int {
        let response: KeyCountResponse =
            try await send("/v1/keydir/\(namespace)/me/count", method: "GET",
                           body: Optional<Empty>.none, authed: true)
        return response.available
    }

    // MARK: - Contacts

    @discardableResult
    func requestContact(toPublicId: String) async throws -> ContactStateResponse {
        try await send("/v1/contacts/request", method: "POST",
                       body: ContactRequestBody(toPublicId: toPublicId), authed: true)
    }

    @discardableResult
    func acceptContact(fromPublicId: String) async throws -> ContactStateResponse {
        try await send("/v1/contacts/accept", method: "POST",
                       body: ContactAcceptBody(fromPublicId: fromPublicId), authed: true)
    }

    func listContacts() async throws -> ContactsListResponse {
        try await send("/v1/contacts", method: "GET", body: Optional<Empty>.none, authed: true)
    }

    func lookupUser(publicId: String) async throws -> UserLookupResponse {
        try await send("/v1/users/\(publicId)", method: "GET", body: Optional<Empty>.none, authed: true)
    }

    // MARK: - Blocking & reporting

    /// Blocks a user. Blocking is bidirectional: afterwards neither side can send
    /// to the other (the server rejects with code `"blocked"`).
    @discardableResult
    func blockContact(publicId: String) async throws -> Bool {
        let response: BlockResponse = try await send("/v1/contacts/block", method: "POST",
                                                     body: BlockRequest(publicId: publicId), authed: true)
        return response.blocked
    }

    /// Removes a block previously placed by this account.
    @discardableResult
    func unblockContact(publicId: String) async throws -> Bool {
        let response: BlockResponse = try await send("/v1/contacts/unblock", method: "POST",
                                                     body: BlockRequest(publicId: publicId), authed: true)
        return response.blocked
    }

    /// Lists the public ids this account has blocked.
    func listBlocks() async throws -> [String] {
        let response: BlocksListResponse = try await send("/v1/blocks", method: "GET",
                                                          body: Optional<Empty>.none, authed: true)
        return response.blocked.map(\.publicId)
    }

    /// Reports a user for abuse with a free-text reason.
    @discardableResult
    func reportUser(publicId: String, reason: String) async throws -> Bool {
        let response: ReportResponse = try await send("/v1/reports", method: "POST",
                                                      body: ReportRequest(publicId: publicId, reason: reason),
                                                      authed: true)
        return response.reported
    }

    // MARK: - Transparency

    /// Fetches the current signed tree head of the key-transparency log.
    func transparencyHead() async throws -> TransparencyHeadResponse {
        try await send("/v1/transparency/head", method: "GET", body: Optional<Empty>.none, authed: true)
    }

    /// Fetches an account's published identity-key entries plus inclusion proofs.
    /// Returns `nil` when the account has no log entries yet (server 404).
    func transparencyLog(publicId: String) async throws -> TransparencyLogResponse? {
        do {
            return try await send("/v1/transparency/\(publicId)", method: "GET",
                                  body: Optional<Empty>.none, authed: true)
        } catch let error as APIError {
            if case .server(let status, _, _) = error, status == 404 { return nil }
            throw error
        }
    }

    // MARK: - Messages

    func sendMessage(_ request: SendMessageRequest) async throws -> SendMessageResponse {
        try await send("/v1/messages", method: "POST", body: request, authed: true)
    }

    func sync(limit: Int) async throws -> SyncResponse {
        try await send("/v1/messages/sync?limit=\(limit)", method: "GET",
                       body: Optional<Empty>.none, authed: true)
    }

    // MARK: - Groups

    /// Creates a group with a sealed name + initial members; the creator is added
    /// server-side as an admin. Returns the new group id and roster.
    func createGroup(encryptedName: Data, memberPublicIds: [String]) async throws -> GroupResponse {
        try await send("/v1/groups", method: "POST",
                       body: CreateGroupRequest(encryptedName: encryptedName,
                                                memberPublicIds: memberPublicIds),
                       authed: true)
    }

    /// Lists every group this account belongs to (each with its sealed name + roster).
    func listGroups() async throws -> GroupListResponse {
        try await send("/v1/groups", method: "GET", body: Optional<Empty>.none, authed: true)
    }

    /// Fetches one group's roster.
    func fetchGroup(groupId: String) async throws -> GroupResponse {
        try await send("/v1/groups/\(groupId)", method: "GET", body: Optional<Empty>.none, authed: true)
    }

    /// Adds a member to a group. Returns `{"added":true}`.
    @discardableResult
    func addGroupMember(groupId: String, publicId: String) async throws -> AddGroupMemberResponse {
        try await send("/v1/groups/\(groupId)/members", method: "POST",
                       body: AddGroupMemberRequest(publicId: publicId), authed: true)
    }

    /// Removes a member from a group (204 on success).
    func removeGroupMember(groupId: String, publicId: String) async throws {
        try await sendNoContent("/v1/groups/\(groupId)/members/\(publicId)", method: "DELETE", authed: true)
    }

    /// Deletes a group (204 on success).
    func deleteGroup(groupId: String) async throws {
        try await sendNoContent("/v1/groups/\(groupId)", method: "DELETE", authed: true)
    }

    // MARK: - Group commit ordering (MLS Delivery-Service compare-and-swap)

    /// Submits an MLS Commit's ordering transition to the per-group CAS register:
    /// install `newToken` as the head ONLY if `prevToken` is still the current head.
    /// The server never sees the Commit bytes — only this opaque token swap. Returns
    /// `accepted` plus the resulting head (on win) or the current head (on a lost
    /// race, so the caller can rebase and retry).
    @discardableResult
    func submitCommit(groupId: String, prevToken: Data, newToken: Data) async throws -> CommitHeadResponse {
        try await send("/v1/groups/\(groupId)/commitlog", method: "POST",
                       body: SubmitCommitRequest(prevToken: prevToken, newToken: newToken), authed: true)
    }

    /// Reads the group's current commit-ordering head (opaque token + seq).
    func commitHead(groupId: String) async throws -> CommitHeadResponse {
        try await send("/v1/groups/\(groupId)/commitlog/head", method: "GET",
                       body: Optional<Empty>.none, authed: true)
    }

    // MARK: - Profiles

    @discardableResult
    func putProfile(_ request: PutProfileRequest) async throws -> PutProfileResponse {
        try await send("/v1/profile", method: "PUT", body: request, authed: true)
    }

    /// Fetches a contact's encrypted profile. Returns `nil` when the server 404s
    /// (no profile, or the caller holds no grant for it).
    func fetchProfile(publicId: String) async throws -> FetchedProfile? {
        do {
            return try await send("/v1/profile/\(publicId)", method: "GET",
                                  body: Optional<Empty>.none, authed: true)
        } catch let error as APIError {
            if case .server(let status, _, _) = error, status == 404 { return nil }
            throw error
        }
    }

    func deleteProfile() async throws {
        try await sendNoContent("/v1/profile", method: "DELETE", authed: true)
    }

    // MARK: - Core request plumbing

    /// Empty placeholder for GET/DELETE bodies.
    private struct Empty: Codable {}

    private func makeRequest(_ path: String, method: String, authed: Bool) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: baseURL) else { throw APIError.invalidURL }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if authed {
            guard let token = currentToken else { throw APIError.unauthenticated }
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return req
    }

    /// Sends a request with an optional JSON body and decodes a JSON response.
    private func send<Body: Encodable, Response: Decodable>(
        _ path: String, method: String, body: Body?, authed: Bool
    ) async throws -> Response {
        var req = try makeRequest(path, method: method, authed: authed)
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try encoder.encode(body)
        }
        let (data, response) = try await perform(req)
        try Self.validate(response, data: data, decoder: decoder)
        do {
            return try decoder.decode(Response.self, from: data)
        } catch {
            throw APIError.decoding(String(describing: error))
        }
    }

    /// Sends a request expecting an empty (204) body.
    private func sendNoContent(_ path: String, method: String, authed: Bool) async throws {
        let req = try makeRequest(path, method: method, authed: authed)
        let (data, response) = try await perform(req)
        try Self.validate(response, data: data, decoder: decoder)
    }

    private func perform(_ req: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await session.data(for: req)
        } catch {
            throw APIError.transport(error.localizedDescription)
        }
    }

    private static func validate(_ response: URLResponse, data: Data, decoder: JSONDecoder) throws {
        guard let http = response as? HTTPURLResponse else {
            throw APIError.transport("Non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let envelope = try? decoder.decode(ServerErrorEnvelope.self, from: data)
            throw APIError.server(status: http.statusCode,
                                  code: envelope?.error.code,
                                  message: envelope?.error.message)
        }
    }

    // MARK: - Date parsing

    // `ISO8601DateFormatter` is safe for concurrent reads; mark nonisolated so the
    // nonisolated `flexibleDate` (also used by the background RealtimeClient) can read it.
    nonisolated(unsafe) private static let isoFractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    nonisolated(unsafe) private static let isoPlain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    nonisolated static func flexibleDate(from raw: String) -> Date? {
        if let d = isoFractional.date(from: raw) { return d }
        if let d = isoPlain.date(from: raw) { return d }
        return nil
    }
}
