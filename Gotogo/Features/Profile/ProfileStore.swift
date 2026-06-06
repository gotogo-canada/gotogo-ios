//
//  ProfileStore.swift
//  Gotogo
//
//  Observable façade over `ProfileService` for the UI: it lazily fetches + caches
//  each mutual contact's decrypted profile (display name + photo) and the owner's
//  own profile, so rows/titles can show a friendly name + avatar with a public-ID
//  fallback. Decoded `UIImage`s are memoized so list scrolling stays cheap.
//

import SwiftUI
import Observation

/// A decrypted, display-ready profile: a name and an optional decoded avatar.
struct DisplayProfile: Equatable {
    var displayName: String
    var image: UIImage?
}

@MainActor
@Observable
final class ProfileStore {

    private let service: ProfileService

    /// Decrypted, decoded profiles keyed by public id. Observed by the UI.
    private(set) var profiles: [String: DisplayProfile] = [:]

    /// Public ids with an in-flight fetch, so we don't request the same one twice.
    private var inFlight: Set<String> = []

    init(service: ProfileService) {
        self.service = service
    }

    /// The decrypted profile for `publicId`, if already loaded.
    func profile(for publicId: String) -> DisplayProfile? { profiles[publicId] }

    /// Ensures a contact's profile is fetched + decoded (idempotent, deduplicated).
    /// Safe to call from `.task`/`onAppear`; no-ops if already loaded or loading.
    func load(_ publicId: String) async {
        guard profiles[publicId] == nil, !inFlight.contains(publicId) else { return }
        inFlight.insert(publicId)
        defer { inFlight.remove(publicId) }
        guard let profile = try? await service.fetchProfile(of: publicId) else { return }
        profiles[publicId] = Self.display(from: profile)
    }

    /// Loads the owner's own profile from local persistence (no network).
    func loadOwn(publicId: String) {
        guard let own = service.ownProfile() else { return }
        profiles[publicId] = Self.display(from: own)
    }

    /// Forces a refresh of `publicId` (e.g. after the owner saves a new profile).
    func refresh(_ publicId: String) async {
        profiles[publicId] = nil
        await load(publicId)
    }

    /// Forgets one cached profile (e.g. after a peer deletes their account).
    func forget(_ publicId: String) { profiles[publicId] = nil; inFlight.remove(publicId) }

    /// Drops all cached profiles (used on logout).
    func clear() { profiles.removeAll(); inFlight.removeAll() }

    private static func display(from profile: Profile) -> DisplayProfile {
        let image = profile.photoJPEG.flatMap { UIImage(data: $0) }
        return DisplayProfile(displayName: profile.displayName, image: image)
    }
}
