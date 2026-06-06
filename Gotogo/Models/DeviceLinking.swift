//
//  DeviceLinking.swift
//  Gotogo
//
//  The payload that links a NEW device to an existing account. The PRIMARY device
//  registers a new device server-side (`POST /v1/devices`) and packages the new
//  device's credentials (account public id + account id + the new device id +
//  bearer token + chosen name) into a `DeviceLinkPayload`, which it shows as a QR
//  code + a copyable code. The NEW device imports that payload and provisions
//  itself: it generates its OWN identity + prekeys (private keys never leave the
//  device), persists the session, and publishes its prekeys + MLS KeyPackages — so
//  it becomes its own MLS leaf and converges into the account's groups.
//
//  The token rides the QR/code out-of-band (exactly the Signal/WhatsApp linking
//  model). It is short-lived per device and only grants that one new device.
//

import Foundation

/// Opaque, shareable credentials handed from a primary device to a new device to
/// link it to the same account. Codable so it round-trips through a QR/paste code.
public struct DeviceLinkPayload: Codable, Sendable, Equatable {
    /// Payload format version (forward-compat).
    public var v: Int
    /// The account's short public id (shared across all the account's devices).
    public var publicId: String
    /// The account's server UUID.
    public var accountId: String
    /// The NEW device's server UUID (freshly created by the primary).
    public var deviceId: String
    /// The NEW device's bearer token.
    public var token: String
    /// The display name chosen for the new device.
    public var deviceName: String

    public init(publicId: String,
                accountId: String,
                deviceId: String,
                token: String,
                deviceName: String,
                v: Int = 1) {
        self.v = v
        self.publicId = publicId
        self.accountId = accountId
        self.deviceId = deviceId
        self.token = token
        self.deviceName = deviceName
    }
}

public extension DeviceLinkPayload {
    /// The URL-ish scheme prefix that marks a Gotogo link code, so a paste/scan of
    /// arbitrary text isn't mistaken for a link.
    static let scheme = "gotogo-link:"

    /// Encodes the payload to a single shareable string (scheme + base64 JSON),
    /// suitable for a QR code or a copy/paste code.
    func encoded() -> String {
        let data = (try? JSONEncoder().encode(self)) ?? Data()
        return Self.scheme + data.base64EncodedString()
    }

    /// Decodes a payload from a scanned/pasted code (tolerates a missing scheme
    /// prefix and surrounding whitespace). Returns nil if the code is malformed.
    init?(code raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let b64 = trimmed.hasPrefix(Self.scheme) ? String(trimmed.dropFirst(Self.scheme.count)) : trimmed
        guard let data = Data(base64Encoded: b64),
              let payload = try? JSONDecoder().decode(DeviceLinkPayload.self, from: data) else { return nil }
        self = payload
    }
}
