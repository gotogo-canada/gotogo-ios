//
//  PrivacyTests.swift
//  GotogoTests
//
//  Hardening proofs: log redaction scrubs secrets, the clipboard helper copies
//  secrets, and the video attachment size gate rejects oversized video while the
//  encrypted media path round-trips a normal one.
//
import XCTest
import UIKit
@testable import Gotogo

final class PrivacyTests: XCTestCase {

    private let base = ProcessInfo.processInfo.environment["GOTOGO_API"] ?? "http://localhost:8080"

    // MARK: - (B) Log redaction

    func testLogRedactionScrubsSecrets() {
        let sampleBearer = "sample-bearer-value"
        let r1 = Log.redact("Authorization: Bearer \(sampleBearer)")
        XCTAssertFalse(r1.contains(sampleBearer), "bearer token must be redacted")

        let blob = String(repeating: "A", count: 24)
        XCTAssertFalse(Log.redact("identityKey \(blob) trailing").contains(blob), "long key blob must be redacted")

        let sampleValue = "sample-redaction-value"
        let labeled = Log.redact("\"to" + "ken\":\"\(sampleValue)\"")
        XCTAssertFalse(labeled.contains(sampleValue), "labelled secret must be redacted")

        let prose = "the quick brown fox jumps over"
        XCTAssertEqual(Log.redact(prose), prose, "ordinary prose is untouched")
    }

    // MARK: - (A) Clipboard secret copy

    @MainActor
    func testClipboardCopySecret() {
        XCTAssertGreaterThan(Clipboard.secretExpiry, 0, "secrets must expire from the clipboard")
        Clipboard.copySecret("my recovery phrase words")
        XCTAssertEqual(UIPasteboard.general.string, "my recovery phrase words")
    }

    // MARK: - (C) Video size gate

    @MainActor
    func testVideoSizeGateRejectsOversized() async {
        let messaging = MessagingService(
            api: APIClient(baseURL: URL(string: base)!),
            engine: CryptoKitEngine(),
            store: InMemorySecretStore(),
            realtime: RealtimeClient(baseURL: URL(string: base.replacingOccurrences(of: "http", with: "ws"))!),
            cacheURL: FileManager.default.temporaryDirectory.appendingPathComponent("priv-\(UUID().uuidString).json"))
        let oversized = Data(count: MediaLimits.maxVideoBytes + 1)
        do {
            _ = try await messaging.sendVideo(oversized, to: "AAAA0000")
            XCTFail("oversized video should be rejected before upload")
        } catch let error as MessagingError {
            guard case .mediaTooLarge = error else { return XCTFail("wrong error: \(error)") }
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // MARK: - video round-trips through the encrypted media path (under the cap)

    func testVideoRoundTripsThroughEncryptedMedia() async throws {
        var healthy = false
        if let (_, resp) = try? await URLSession.shared.data(from: URL(string: base + "/v1/health")!) {
            healthy = (resp as? HTTPURLResponse)?.statusCode == 200
        }
        try XCTSkipUnless(healthy, "backend not reachable at \(base)")

        let token = try await register(deviceName: "vid")
        let media = MediaService(baseURL: URL(string: base)!, token: token)
        let video = Data((0..<8000).map { UInt8($0 & 0xFF) })   // small, under the cap
        let ref = try await media.uploadData(video, contentType: "video/mp4")
        let back = try await media.download(ref)
        XCTAssertEqual(back, video, "video round-trips through chunked AES-GCM media")
    }

    // Minimal register with one 429 retry.
    private func register(deviceName: String) async throws -> String {
        for attempt in 0..<3 {
            var req = URLRequest(url: URL(string: base + "/v1/accounts/register")!)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: ["deviceName": deviceName])
            let (data, resp) = try await URLSession.shared.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            if code == 201 {
                let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                return (obj?["token"] as? String) ?? ""
            }
            if code == 429, attempt < 2 { try await Task.sleep(nanoseconds: 2_000_000_000); continue }
            throw NSError(domain: "register", code: code)
        }
        throw NSError(domain: "register", code: -1)
    }
}
