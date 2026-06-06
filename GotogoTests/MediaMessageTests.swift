//
//  MediaMessageTests.swift
//  GotogoTests
//
//  In-simulator end-to-end test for encrypted media messages, driving the app's
//  OWN AuthService + MessagingService against the live local backend: register
//  two accounts, become mutual contacts, then Alice sends a JPEG (generated
//  in-test WITH GPS EXIF). Bob syncs and decrypts the E2EE message, asserts it
//  is an image attachment, then downloads + decrypts the blob and verifies the
//  bytes are a valid image with the GPS metadata stripped before encryption.
//
import XCTest
import ImageIO
import UniformTypeIdentifiers
import CoreGraphics
@testable import Gotogo

@MainActor
final class MediaMessageTests: XCTestCase {

    private let apiURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080")!
    private let wsURL = URL(string: ProcessInfo.processInfo.environment["GOTOGO_WS"] ?? "ws://localhost:8080")!

    private struct Stack {
        let auth: AuthService
        let messaging: MessagingService
        let store: SecretStoring
        let media: MediaService
    }

    private func makeStack(_ tag: String) -> Stack {
        let engine = CryptoKitEngine()
        let api = APIClient(baseURL: apiURL)
        let store = InMemorySecretStore()
        let realtime = RealtimeClient(baseURL: wsURL)
        let auth = AuthService(api: api, engine: engine, store: store)
        // A media service pointed at the SAME backend the test's APIClient uses
        // (the default would read AppEnvironment, which may differ in CI).
        let media = MediaService(baseURL: apiURL)
        let cache = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-media-test-\(tag)-\(UUID().uuidString).json")
        let messaging = MessagingService(api: api, engine: engine, store: store,
                                         realtime: realtime, cacheURL: cache, media: media)
        return Stack(auth: auth, messaging: messaging, store: store, media: media)
    }

    private func requireBackend() async throws {
        var ok = false
        if let (_, resp) = try? await URLSession.shared.data(from: apiURL.appendingPathComponent("v1/health")) {
            ok = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(ok, "backend not reachable at \(apiURL) — run `docker compose up` in gotogo-service")
    }

    func testSendImageStripsGPSAndDeliversEncrypted() async throws {
        try await requireBackend()

        let alice = makeStack("alice")
        let bob = makeStack("bob")

        let aliceReg = try await alice.auth.register()
        let bobReg = try await bob.auth.register()

        // Become mutual contacts.
        try await alice.messaging.requestContact(publicId: bobReg.session.publicId)
        try await bob.messaging.acceptContact(fromPublicId: aliceReg.session.publicId)

        // Build a JPEG that carries GPS EXIF, and sanity-check it really has GPS.
        let original = Self.makeJPEGWithGPS()
        XCTAssertTrue(Self.hasGPS(original), "the generated source JPEG should carry GPS metadata")

        // Alice encrypts + sends the image (caption included).
        let caption = "from the quarry 🛰️"
        let sent = try await alice.messaging.sendImage(original, caption: caption, to: bobReg.session.publicId)
        XCTAssertTrue(sent.isMine)
        XCTAssertEqual(sent.mediaKind, "image")
        XCTAssertNotNil(sent.media)

        // Bob syncs + decrypts the E2EE message.
        let received = try await bob.messaging.sync()
        guard let got = received.first(where: { $0.peerPublicId == aliceReg.session.publicId }) else {
            return XCTFail("Bob received no message from Alice")
        }
        XCTAssertTrue(got.decrypted, "the message envelope should decrypt")
        XCTAssertFalse(got.isMine)
        XCTAssertEqual(got.mediaKind, "image", "received message is an image attachment")
        XCTAssertEqual(got.body, caption, "caption rides inside the E2EE plaintext")
        guard let ref = got.media else { return XCTFail("received image carries no MediaReference") }
        XCTAssertEqual(ref.contentType, "image/jpeg")

        // Bob downloads + decrypts the blob via a MediaService (verifies the
        // ciphertext hash, then AES-GCM decrypts) and checks the result.
        bob.media.setToken(bob.store.loadSession()?.token)
        let plaintext = try await bob.media.download(ref)
        XCTAssertGreaterThan(plaintext.count, 0)

        // The decrypted bytes must be a valid, decodable image...
        guard let src = CGImageSourceCreateWithData(plaintext as CFData, nil),
              CGImageSourceCreateImageAtIndex(src, 0, nil) != nil else {
            return XCTFail("decrypted media is not a decodable image")
        }
        // ...with NO GPS metadata (EXIF stripped before encryption).
        XCTAssertFalse(Self.hasGPS(plaintext), "decrypted image must have GPS metadata stripped")

        // The decrypted thumbnail (if present) must also be a valid image.
        if ref.thumbMediaId != nil {
            let thumb = try await bob.media.downloadThumbnail(ref)
            XCTAssertNotNil(thumb, "thumbnail should download + decrypt")
            if let thumb {
                XCTAssertNotNil(CGImageSourceCreateWithData(thumb as CFData, nil),
                                "decrypted thumbnail is a valid image")
            }
        }
    }

    /// The path the composer's video picker now triggers end to end: Alice sends a
    /// video via `MessagingService.sendVideo`, Bob syncs + decrypts it to a "video"
    /// attachment and downloads the blob back to the exact original bytes. (Until the
    /// picker was wired to allow movies, this send path was unreachable from the UI;
    /// the picker simply hands these bytes to the same `sendVideo`.)
    func testSendVideoDeliversEncrypted() async throws {
        try await requireBackend()

        let alice = makeStack("alice-vid")
        let bob = makeStack("bob-vid")

        let aliceReg = try await alice.auth.register()
        let bobReg = try await bob.auth.register()

        // Become mutual contacts.
        try await alice.messaging.requestContact(publicId: bobReg.session.publicId)
        try await bob.messaging.acceptContact(fromPublicId: aliceReg.session.publicId)

        // A small "video" payload — the bytes are opaque to the encrypted media path
        // (playback isn't exercised here; the send/receive/decrypt path is).
        let original = Data((0..<20_000).map { UInt8($0 & 0xFF) })
        XCTAssertLessThanOrEqual(original.count, MediaLimits.maxVideoBytes)

        let caption = "first dive of the season 🤿"
        let sent = try await alice.messaging.sendVideo(original, caption: caption, to: bobReg.session.publicId)
        XCTAssertTrue(sent.isMine)
        XCTAssertEqual(sent.mediaKind, "video")
        XCTAssertNotNil(sent.media)

        // Bob syncs + decrypts the E2EE message.
        let received = try await bob.messaging.sync()
        guard let got = received.first(where: { $0.peerPublicId == aliceReg.session.publicId }) else {
            return XCTFail("Bob received no message from Alice")
        }
        XCTAssertTrue(got.decrypted, "the message envelope should decrypt")
        XCTAssertFalse(got.isMine)
        XCTAssertEqual(got.mediaKind, "video", "received message is a video attachment")
        XCTAssertEqual(got.body, caption, "caption rides inside the E2EE plaintext")
        guard let ref = got.media else { return XCTFail("received video carries no MediaReference") }
        XCTAssertEqual(ref.contentType, "video/mp4")

        // Bob downloads + decrypts the blob and recovers the exact bytes.
        bob.media.setToken(bob.store.loadSession()?.token)
        let plaintext = try await bob.media.download(ref)
        XCTAssertEqual(plaintext, original, "video round-trips through chunked AES-GCM E2EE")
    }

    // MARK: - In-test JPEG generation (with GPS EXIF)

    /// Builds a small JPEG that embeds a GPS metadata dictionary, so the test can
    /// prove `MediaProcessing.stripMetadata` removed it after the round trip.
    private static func makeJPEGWithGPS(width: Int = 64, height: Int = 64) -> Data {
        let cs = CGColorSpaceCreateDeviceRGB()
        let ctx = CGContext(data: nil, width: width, height: height,
                            bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.setFillColor(red: 0.2, green: 0.6, blue: 0.9, alpha: 1)
        ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
        ctx.setFillColor(red: 1, green: 0.85, blue: 0.1, alpha: 1)
        ctx.fillEllipse(in: CGRect(x: 12, y: 12, width: 40, height: 40))
        let image = ctx.makeImage()!

        let gps: [CFString: Any] = [
            kCGImagePropertyGPSLatitude: 45.5017,
            kCGImagePropertyGPSLatitudeRef: "N",
            kCGImagePropertyGPSLongitude: 73.5673,
            kCGImagePropertyGPSLongitudeRef: "W",
        ]
        let props: [CFString: Any] = [
            kCGImagePropertyGPSDictionary: gps,
            kCGImagePropertyExifDictionary: [kCGImagePropertyExifUserComment: "gotogo-test"],
        ]
        let out = NSMutableData()
        let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, image, props as CFDictionary)
        precondition(CGImageDestinationFinalize(dest), "failed to encode test JPEG")
        return out as Data
    }

    /// True if the image data carries a GPS metadata dictionary.
    private static func hasGPS(_ data: Data) -> Bool {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil),
              let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any] else {
            return false
        }
        return props[kCGImagePropertyGPSDictionary] != nil
    }
}
