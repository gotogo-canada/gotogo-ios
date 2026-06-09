//
//  AuthService.swift
//  Gotogo
//
//  UI-free account lifecycle: register (with recovery phrase + vault), recover
//  from a phrase, logout, and delete account. Persists the session + private key
//  material via `SecretStoring`. Foundation + CryptoKit only.
//

import Foundation
import CryptoKit
import UIKit

/// Errors specific to the auth flows.
public enum AuthError: Error, Sendable, LocalizedError {
    case noSession
    case vaultDecryptionFailed
    case missingVault
    case recoveryKeyDerivationFailed
    case invalidLinkCode

    public var errorDescription: String? {
        switch self {
        case .noSession: return "No active account."
        case .vaultDecryptionFailed: return "Could not decrypt your recovery vault."
        case .missingVault: return "The server did not return a recovery vault."
        case .recoveryKeyDerivationFailed: return "Could not derive the recovery key."
        case .invalidLinkCode: return "That isn't a valid device-link code."
        }
    }
}

/// Result of registering: the new session plus the one-time recovery phrase to
/// show the user. The phrase is never persisted.
public struct RegistrationResult: Sendable {
    public let session: Session
    public let recoveryPhrase: [String]
}

/// Drives account creation, recovery, and teardown. `@MainActor` (the module
/// default); its `async` methods suspend on `await`, so they do not block the UI.
/// Construct with an `APIClient`, a `CryptoEngine`, and a `SecretStoring`; an
/// XCTest can drive it from a `@MainActor` test with an in-memory store + test URL.
@MainActor
public final class AuthService {

    private let api: APIClient
    private let engine: CryptoEngine
    private let store: SecretStoring

    private let deviceName: String

    init(api: APIClient,
                engine: CryptoEngine,
                store: SecretStoring,
                deviceName: String? = nil) {
        self.api = api
        self.engine = engine
        self.store = store
        self.deviceName = deviceName ?? Self.defaultDeviceName()
    }

    static func defaultDeviceName() -> String {
        defaultDeviceName(isSimulator: Self.isSimulatorBuild,
                          userInterfaceIdiom: UIDevice.current.userInterfaceIdiom)
    }

    nonisolated static func defaultDeviceName(isSimulator: Bool,
                                              userInterfaceIdiom: UIUserInterfaceIdiom) -> String {
        if isSimulator {
            switch userInterfaceIdiom {
            case .pad: return "iPad Simulator"
            default: return "iPhone Simulator"
            }
        }

        switch userInterfaceIdiom {
        case .phone: return "iPhone"
        case .pad: return "iPad"
        case .mac: return "Mac"
        case .tv: return "Apple TV"
        case .carPlay: return "CarPlay"
        case .vision: return "Apple Vision"
        default: return "iOS Device"
        }
    }

    private nonisolated static var isSimulatorBuild: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    static func normalizedDeviceName(_ storedName: String) -> String {
        normalizedDeviceName(storedName,
                             isSimulator: Self.isSimulatorBuild,
                             userInterfaceIdiom: UIDevice.current.userInterfaceIdiom)
    }

    nonisolated static func normalizedDeviceName(_ storedName: String,
                                                 isSimulator: Bool,
                                                 userInterfaceIdiom: UIUserInterfaceIdiom) -> String {
        let runtimeName = defaultDeviceName(isSimulator: isSimulator,
                                            userInterfaceIdiom: userInterfaceIdiom)
        if !isSimulator && (storedName == "iPhone Simulator" || storedName == "iPad Simulator") {
            return runtimeName
        }
        return storedName
    }

    /// The persisted session, if the user is signed in.
    func currentSession() -> Session? { store.loadSession() }

    // MARK: - Register

    /// Creates a new account end to end and persists all material.
    ///
    /// Steps: generate identity + prekeys, derive a 24-word recovery phrase and
    /// recovery key + sealed vault, register, upload prekeys, persist, and return
    /// the phrase to display once.
    func register() async throws -> RegistrationResult {
        // 1. Identity + prekeys.
        let identity = engine.generateIdentity()
        let generated = try engine.generatePreKeys(identity: identity,
                                                   signedPreKeyId: 1,
                                                   oneTimeCount: 20,
                                                   firstOneTimeId: 1)

        // 2. Recovery entropy -> phrase, recovery key, and sealed vault.
        let entropy = Self.randomEntropy()
        let phrase = Mnemonic.encode(entropy)
        let derived = try Self.deriveRecovery(from: entropy)
        let vault = try Self.sealVault(identity: identity,
                                       store: generated.store,
                                       vaultKey: derived.vaultKey)

        // 3. Register with the server.
        let creds = try await api.register(deviceName: deviceName,
                                           recoveryPublicKey: derived.recoveryPublicKey,
                                           recoveryVault: vault)
        api.setToken(creds.token)

        let session = Session(publicId: creds.publicId,
                              accountId: creds.accountId,
                              deviceId: creds.deviceId,
                              token: creds.token,
                              deviceName: deviceName)

        // 4. Upload prekeys.
        try await api.uploadPreKeys(Self.uploadRequest(identity: identity, store: generated.store))

        // 5. Persist.
        try store.saveIdentity(identity)
        try store.savePreKeyStore(generated.store)
        try store.saveSession(session)

        return RegistrationResult(session: session, recoveryPhrase: phrase)
    }

    // MARK: - Recover

    /// Recovers an existing account from its 24-word phrase and persists it.
    ///
    /// `recover/start` requires the account's public id (it is not derivable from
    /// the phrase alone), so the caller supplies it alongside the phrase. The
    /// recovery UI collects both. Returns the restored session.
    @discardableResult
    func recoverAccount(publicId: String, phrase: [String]) async throws -> Session {
        // 1. Phrase -> entropy -> recovery key + vault key.
        let entropy = try Mnemonic.decode(phrase)
        let derived = try Self.deriveRecovery(from: entropy)

        // 2. recover/start -> challenge + tag + sealed vault.
        let start = try await api.recoverStart(publicId: publicId)

        // 3. Sign the challenge with the recovery key.
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: derived.recoverySeed)
        let signature = try signingKey.signature(for: start.challenge)

        // 4. recover/finish -> new credentials for this device.
        let creds = try await api.recoverFinish(
            RecoverFinishRequest(publicId: publicId,
                                 challenge: start.challenge,
                                 challengeTag: start.challengeTag,
                                 signature: signature,
                                 deviceName: deviceName))
        api.setToken(creds.token)

        // 5. Decrypt the vault to restore identity + prekey store.
        let payload = try Self.openVault(start.vault, vaultKey: derived.vaultKey)

        let session = Session(publicId: creds.publicId,
                              accountId: creds.accountId,
                              deviceId: creds.deviceId,
                              token: creds.token,
                              deviceName: deviceName)

        // 6. Re-publish prekeys for the (new) device, then persist everything.
        try await api.uploadPreKeys(Self.uploadRequest(identity: payload.identity,
                                                        store: payload.store))
        try store.saveIdentity(payload.identity)
        try store.savePreKeyStore(payload.store)
        try store.saveSession(session)

        return session
    }

    // MARK: - Username

    /// Checks whether a username is available on the home server (public call).
    func checkUsername(_ name: String) async throws -> UsernameAvailabilityResponse {
        try await api.usernameAvailable(name)
    }

    /// Claims (or changes) the account's username and returns the new
    /// `localpart@domain` address. Updates the persisted session's username so the
    /// app shows the federated address after relaunch.
    @discardableResult
    func claimUsername(_ name: String) async throws -> String {
        let resp = try await api.setUsername(name)
        if var session = store.loadSession() {
            session.username = Address(resp.address)?.localpart ?? name.lowercased()
            try store.saveSession(session)
        }
        return resp.address
    }

    // MARK: - Account portability

    /// The exact bytes the backend's move attestation verifies
    /// (`account.moveCanonical`): a fixed prefix + from/to addresses + timestamp.
    nonisolated static func moveCanonical(fromAddress: String, toAddress: String, signedAt: Int64) -> Data {
        Data("gotogo-account-move-v1\n\(fromAddress)\n\(toAddress)\n\(signedAt)".utf8)
    }

    /// Moves this account to another server (account portability): signs the move
    /// statement with the RECOVERY key (derived from the 24-word phrase — proof
    /// the account owner, not just a stolen device token, authorized it), then
    /// tombstones the account here with a forwarding pointer contacts can verify.
    /// `fromAddress` must be the canonical `publicId@homeDomain`.
    func moveAccount(fromAddress: String, toAddress: String, phrase: [String]) async throws -> String {
        let entropy = try Mnemonic.decode(phrase)
        let derived = try Self.deriveRecovery(from: entropy)
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: derived.recoverySeed)
        let signedAt = Int64(Date().timeIntervalSince1970)
        let signature = try signingKey.signature(
            for: Self.moveCanonical(fromAddress: fromAddress, toAddress: toAddress, signedAt: signedAt))
        let resp = try await api.moveAccount(toAddress: toAddress, signature: signature, signedAt: signedAt)
        return resp.movedTo
    }

    // MARK: - Device linking

    /// PRIMARY device: registers a NEW device for THIS account on the server and
    /// returns a link payload (the new device's credentials) to hand to that device
    /// out-of-band as a QR / code. The new device generates its OWN identity keys —
    /// nothing private is transferred here beyond the new device's bearer token.
    func createDeviceLink(deviceName: String) async throws -> DeviceLinkPayload {
        guard let session = store.loadSession() else { throw AuthError.noSession }
        let added = try await api.addDevice(deviceName: deviceName)
        return DeviceLinkPayload(publicId: session.publicId,
                                 accountId: session.accountId,
                                 deviceId: added.deviceId,
                                 token: added.token,
                                 deviceName: deviceName)
    }

    /// NEW device: adopts a link payload. Generates THIS device's own identity +
    /// prekeys, persists the session, and publishes the prekeys — mirroring register
    /// but WITHOUT creating a new account (the device row already exists). The device
    /// then becomes its own MLS leaf; the primary retro-adds it to existing groups on
    /// its next sync. Returns the restored session.
    @discardableResult
    func adoptDeviceLink(_ payload: DeviceLinkPayload) async throws -> Session {
        api.setToken(payload.token)
        let identity = engine.generateIdentity()
        let generated = try engine.generatePreKeys(identity: identity,
                                                   signedPreKeyId: 1,
                                                   oneTimeCount: 20,
                                                   firstOneTimeId: 1)
        let session = Session(publicId: payload.publicId,
                              accountId: payload.accountId,
                              deviceId: payload.deviceId,
                              token: payload.token,
                              deviceName: payload.deviceName)
        try await api.uploadPreKeys(Self.uploadRequest(identity: identity, store: generated.store))
        try store.saveIdentity(identity)
        try store.savePreKeyStore(generated.store)
        try store.saveSession(session)
        return session
    }

    // MARK: - Teardown

    /// Clears local secrets (does not call the server).
    func logout() throws {
        api.setToken(nil)
        try store.clear()
    }

    /// Deletes the account server-side then clears local secrets.
    func deleteAccount() async throws {
        guard store.loadSession() != nil else { throw AuthError.noSession }
        try await api.deleteAccount()
        api.setToken(nil)
        try store.clear()
    }
}
