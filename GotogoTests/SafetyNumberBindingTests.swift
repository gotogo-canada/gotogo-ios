//
//  SafetyNumberBindingTests.swift
//  GotogoTests
//
//  Unit coverage for safety-number derivation and optional transport-key binding.
//

import XCTest
@testable import Gotogo

final class SafetyNumberBindingTests: XCTestCase {

    func testOptionalTransportBindingChangesSafetyNumber() throws {
        let engine = CryptoKitEngine()

        let aliceIdentity = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let bobIdentity = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let aliceTransport = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let bobTransport = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let imposterTransport = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        XCTAssertNotEqual(bobTransport, imposterTransport)

        let plain = engine.safetyNumber(localIdentity: aliceIdentity,
                                        remoteIdentity: bobIdentity)
        let boundHonest = engine.safetyNumber(localIdentity: aliceIdentity,
                                              localTransport: aliceTransport,
                                              remoteIdentity: bobIdentity,
                                              remoteTransport: bobTransport)
        let boundAttacked = engine.safetyNumber(localIdentity: aliceIdentity,
                                                localTransport: aliceTransport,
                                                remoteIdentity: bobIdentity,
                                                remoteTransport: imposterTransport)

        XCTAssertNotEqual(boundHonest, boundAttacked)
        XCTAssertNotEqual(boundHonest, plain)

        let bobSide = engine.safetyNumber(localIdentity: bobIdentity,
                                          localTransport: bobTransport,
                                          remoteIdentity: aliceIdentity,
                                          remoteTransport: aliceTransport)
        XCTAssertEqual(boundHonest, bobSide)

        let boundNil = engine.safetyNumber(localIdentity: aliceIdentity,
                                           localTransport: nil,
                                           remoteIdentity: bobIdentity,
                                           remoteTransport: nil)
        XCTAssertEqual(boundNil, plain)
    }
}
