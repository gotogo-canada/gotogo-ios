//
//  ProfileTests.swift
//  GotogoTests
//
//  In-simulator end-to-end test of the private encrypted profile feature against
//  the live local backend. Two accounts register (publishing prekeys INCLUDING
//  their ML-KEM-1024 public key) and become mutual contacts; one sets a profile
//  (display name + photo) and the other fetches + decrypts it. Exercises both the
//  normal (X-Wing) and the sensitive (ML-KEM-1024) sealing paths, and verifies a
//  non-mutual third account cannot fetch the profile.
//
import XCTest
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers
@testable import Gotogo

@MainActor
final class ProfileTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let profiles: ProfileService
    }

    /// Builds a fully-wired stack with its OWN in-memory store + distinct cache,
    /// sharing one `APIClient` (so the bearer token threads through register).
    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-profile-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store, realtime: realtime, cacheURL: cache)
        let profiles = ProfileService(api: api, engine: engine, store: store)
        return Stack(auth: auth, messaging: messaging, profiles: profiles)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run `docker compose up` in gotogo-service")
    }

    /// Encodes a small solid-color JPEG that decodes back to a real image.
    private func makeJPEG(width: Int = 64, height: Int = 64) -> Data {
        let space = CGColorSpaceCreateDeviceRGB()
        let ctx = CGContext(data: nil, width: width, height: height,
                            bitsPerComponent: 8, bytesPerRow: 0, space: space,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.setFillColor(CGColor(red: 0.2, green: 0.6, blue: 0.9, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let image = ctx.makeImage()!
        let out = NSMutableData()
        let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, image, [kCGImageDestinationLossyCompressionQuality: 0.9] as CFDictionary)
        XCTAssertTrue(CGImageDestinationFinalize(dest), "test JPEG must encode")
        return out as Data
    }

    /// True if `data` decodes as an image (i.e. the round-tripped photo is valid).
    private func decodesAsImage(_ data: Data) -> Bool {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil) else { return false }
        return CGImageSourceCreateImageAtIndex(src, 0, nil) != nil
    }

    /// Registers A and B and makes them mutual contacts; returns the stacks + ids.
    private func registerMutualPair(_ a: String, _ b: String) async throws
        -> (a: Stack, aId: String, b: Stack, bId: String) {
        let alice = makeStack(a)
        let bob = makeStack(b)
        let aliceReg = try await alice.auth.register()
        let bobReg = try await bob.auth.register()
        try await alice.messaging.requestContact(publicId: bobReg.session.publicId)
        try await bob.messaging.acceptContact(fromPublicId: aliceReg.session.publicId)
        return (alice, aliceReg.session.publicId, bob, bobReg.session.publicId)
    }

    // MARK: - Normal (X-Wing) round trip

    func testProfileRoundTripNormal() async throws {
        try await requireBackend()
        let pair = try await registerMutualPair("n-alice", "n-bob")

        let photo = makeJPEG()
        try await pair.a.profiles.setProfile(displayName: "Alice 🛰️",
                                             photo: photo,
                                             sensitive: false,
                                             mutualContacts: [pair.bId])

        let fetched = try await pair.b.profiles.fetchProfile(of: pair.aId)
        let profile = try XCTUnwrap(fetched, "Bob should fetch Alice's profile")
        XCTAssertEqual(profile.displayName, "Alice 🛰️", "display name round-trips (incl. emoji)")
        let photoJPEG = try XCTUnwrap(profile.photoJPEG, "profile carries a photo")
        XCTAssertTrue(decodesAsImage(photoJPEG), "decrypted photo decodes to an image")
    }

    // MARK: - Sensitive (ML-KEM-1024) round trip

    func testProfileRoundTripSensitive() async throws {
        try await requireBackend()
        let pair = try await registerMutualPair("s-alice", "s-bob")

        let photo = makeJPEG()
        try await pair.a.profiles.setProfile(displayName: "Alice 🛰️",
                                             photo: photo,
                                             sensitive: true,
                                             mutualContacts: [pair.bId])

        let fetched = try await pair.b.profiles.fetchProfile(of: pair.aId)
        let profile = try XCTUnwrap(fetched, "Bob should fetch Alice's sensitive profile")
        XCTAssertEqual(profile.displayName, "Alice 🛰️", "sensitive display name round-trips")
        let photoJPEG = try XCTUnwrap(profile.photoJPEG, "sensitive profile carries a photo")
        XCTAssertTrue(decodesAsImage(photoJPEG), "decrypted sensitive photo decodes to an image")
    }

    // MARK: - Non-mutual third party is denied

    func testNonMutualCannotFetchProfile() async throws {
        try await requireBackend()
        let pair = try await registerMutualPair("d-alice", "d-bob")

        try await pair.a.profiles.setProfile(displayName: "Alice 🛰️",
                                             photo: makeJPEG(),
                                             sensitive: false,
                                             mutualContacts: [pair.bId])

        // C registers but is NOT a contact of A — must not receive a grant.
        let carol = makeStack("d-carol")
        _ = try await carol.auth.register()
        let fetched = try await carol.profiles.fetchProfile(of: pair.aId)
        XCTAssertNil(fetched, "a non-mutual account cannot fetch A's profile (404 -> nil)")
    }

    // MARK: - Profile updates propagate to contacts (the "like a message" ping)

    /// A contact who already cached A's profile sees A's NEW name after A
    /// re-publishes, because A pings them with a `profile_updated` control that drives
    /// a re-fetch — instead of the contact keeping the stale cached profile until a
    /// relaunch. Mirrors `AppState`'s handler wiring.
    func testProfileUpdatePropagatesToContacts() async throws {
        try await requireBackend()
        let pair = try await registerMutualPair("u-alice", "u-bob")

        // A publishes profile v1; B caches it in a ProfileStore (as the UI does).
        try await pair.a.profiles.setProfile(displayName: "Alice v1", photo: nil,
                                             sensitive: false, mutualContacts: [pair.bId])
        let bStore = ProfileStore(service: pair.b.profiles)
        await bStore.load(pair.aId)
        XCTAssertEqual(bStore.profile(for: pair.aId)?.displayName, "Alice v1",
                       "B caches A's initial profile")

        // A changes its profile to v2 and pings its contacts (like AppState.saveProfile).
        try await pair.a.profiles.setProfile(displayName: "Alice v2", photo: nil,
                                             sensitive: false, mutualContacts: [pair.bId])
        await pair.a.messaging.broadcastProfileUpdate(to: [pair.bId])

        // Wire B's handler exactly as AppState does: record the pinged id.
        var pinged: [String] = []
        pair.b.messaging.setProfileUpdatedHandler { id in pinged.append(id) }

        // B syncs and ingests the `profile_updated` control over the E2EE channel.
        _ = try await pair.b.messaging.sync()
        XCTAssertTrue(pinged.contains(pair.aId),
                      "B received A's profile_updated ping over the pairwise channel")

        // THE BUG: a plain load() keeps the stale cache (this is why a ping is needed).
        await bStore.load(pair.aId)
        XCTAssertEqual(bStore.profile(for: pair.aId)?.displayName, "Alice v1",
                       "load() alone never refreshes — the cached profile stays stale")

        // THE FIX: the ping drives a refresh, which re-fetches A's NEW profile.
        await bStore.refresh(pair.aId)
        XCTAssertEqual(bStore.profile(for: pair.aId)?.displayName, "Alice v2",
                       "after the ping-driven refresh, B sees A's updated profile")
    }
}
