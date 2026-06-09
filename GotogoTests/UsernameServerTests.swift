//
//  UsernameServerTests.swift
//  GotogoTests
//
//  Unit tests for the federated id@domain onboarding: server-address parsing,
//  client-side username validation (mirroring the backend grammar), and the
//  backward-compatible Session.username field.
//

import XCTest
@testable import Gotogo

final class UsernameServerTests: XCTestCase {

    // MARK: - ServerStore candidate parsing

    func testCandidateFromBareDomainDefaultsToHTTPS() {
        let cfg = ServerStore.candidate(from: "gotogo.ca")
        XCTAssertNotNil(cfg)
        XCTAssertEqual(cfg?.apiBaseURL.scheme, "https")
        XCTAssertEqual(cfg?.apiBaseURL.host, "gotogo.ca")
        XCTAssertEqual(cfg?.webSocketBaseURL.scheme, "wss")
        XCTAssertEqual(cfg?.domain, "gotogo.ca")
    }

    func testCandidateFromLocalHTTPURL() {
        let cfg = ServerStore.candidate(from: "http://localhost:8080")
        XCTAssertEqual(cfg?.apiBaseURL.absoluteString, "http://localhost:8080")
        XCTAssertEqual(cfg?.webSocketBaseURL.scheme, "ws")
        XCTAssertEqual(cfg?.webSocketBaseURL.host, "localhost")
        XCTAssertEqual(cfg?.webSocketBaseURL.port, 8080)
        XCTAssertEqual(cfg?.domain, "localhost")
    }

    func testCandidateStripsApiPrefixForDomainHeuristic() {
        let cfg = ServerStore.candidate(from: "https://api.gotogo.ca")
        XCTAssertEqual(cfg?.domain, "gotogo.ca") // api. stripped
    }

    func testCandidateRejectsGarbage() {
        XCTAssertNil(ServerStore.candidate(from: ""))
        XCTAssertNil(ServerStore.candidate(from: "   "))
        XCTAssertNil(ServerStore.candidate(from: "ftp://nope")) // non-http(s) scheme
    }

    func testServerStorePersistsAndLoads() {
        let defaults = UserDefaults(suiteName: "test.\(UUID().uuidString)")!
        let store = ServerStore(defaults: defaults)
        XCTAssertNil(store.load())
        let cfg = ServerStore.candidate(from: "https://gotogo.ca")!
        store.save(cfg)
        XCTAssertEqual(store.load()?.domain, "gotogo.ca")
        store.clear()
        XCTAssertNil(store.load())
    }

    // MARK: - Username validation (mirrors backend grammar: 3..32, [a-z0-9._-])

    func testUsernameValidationAccepts() {
        for name in ["alice", "bob_smith", "a.b-c", "user123", "abc"] {
            XCTAssertEqual(UsernamePicker.validate(name), .valid(name), "\(name) should be valid")
        }
    }

    func testUsernameValidationFolds() {
        XCTAssertEqual(UsernamePicker.validate("Alice"), .valid("alice"))
        XCTAssertEqual(UsernamePicker.validate("  BoB  "), .valid("bob"))
    }

    func testUsernameValidationRejects() {
        // too short, too long, bad charset, leading/trailing/repeated separators
        XCTAssertNotValid("ab")
        XCTAssertNotValid(String(repeating: "a", count: 33))
        XCTAssertNotValid("alice!")
        XCTAssertNotValid("alice space")
        XCTAssertNotValid("_alice")
        XCTAssertNotValid("alice_")
        XCTAssertNotValid("a..b")
        XCTAssertNotValid("a._b")
    }

    private func XCTAssertNotValid(_ name: String, file: StaticString = #filePath, line: UInt = #line) {
        if case .valid = UsernamePicker.validate(name) {
            XCTFail("\(name) should be invalid", file: file, line: line)
        }
    }

    // MARK: - Session backward compatibility

    func testSessionDecodesWithoutUsername() throws {
        // A session persisted before the username field must still decode (username nil).
        let json = """
        {"publicId":"A0BS2MA1","accountId":"acc","deviceId":"dev","token":"t","deviceName":"iPhone"}
        """.data(using: .utf8)!
        let session = try JSONDecoder().decode(Session.self, from: json)
        XCTAssertEqual(session.publicId, "A0BS2MA1")
        XCTAssertNil(session.username)
    }

    func testSessionRoundTripsUsername() throws {
        let session = Session(publicId: "A0BS2MA1", accountId: "acc", deviceId: "dev",
                              token: "t", deviceName: "iPhone", username: "alice")
        let data = try JSONEncoder().encode(session)
        let decoded = try JSONDecoder().decode(Session.self, from: data)
        XCTAssertEqual(decoded.username, "alice")
    }

    // MARK: - Address building

    func testAddressParsesUsernameAtDomain() {
        let addr = Address("alice@gotogo.ca")
        XCTAssertEqual(addr?.localpart, "alice")
        XCTAssertEqual(addr?.domain, "gotogo.ca")
    }
}
