//
//  Profile.swift
//  Gotogo
//
//  A user's private profile: a display name and an optional JPEG photo. The whole
//  struct is JSON-encoded and AES-GCM-sealed under a per-profile key before it
//  ever leaves the device; the key is then sealed individually to each mutual
//  contact (X-Wing normally, or ML-KEM-1024 in "sensitive" mode). Pure Foundation
//  so the profile service + tests stay UI-free.
//

import Foundation

/// The plaintext profile payload sealed end to end and shared with mutual contacts.
public struct Profile: Codable, Sendable, Equatable {
    /// Chosen display name (may contain emoji, etc.).
    public var displayName: String
    /// Optional profile photo as JPEG bytes (metadata-stripped + downscaled).
    public var photoJPEG: Data?

    public init(displayName: String, photoJPEG: Data? = nil) {
        self.displayName = displayName
        self.photoJPEG = photoJPEG
    }
}
