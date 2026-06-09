//
//  AuthServiceDeviceNameTests.swift
//  GotogoTests
//
//  Device names sent to the backend should identify the device class without
//  leaking a personal device name.
//

import XCTest
import UIKit
@testable import Gotogo

final class AuthServiceDeviceNameTests: XCTestCase {

    func testDefaultDeviceNameForRealPhoneIsPrivacySafe() {
        XCTAssertEqual(AuthService.defaultDeviceName(isSimulator: false, userInterfaceIdiom: .phone), "iPhone")
    }

    func testDefaultDeviceNameForRealPadIsPrivacySafe() {
        XCTAssertEqual(AuthService.defaultDeviceName(isSimulator: false, userInterfaceIdiom: .pad), "iPad")
    }

    func testDefaultDeviceNameKeepsSimulatorLabelOnlyForSimulatorBuilds() {
        XCTAssertEqual(AuthService.defaultDeviceName(isSimulator: true, userInterfaceIdiom: .phone), "iPhone Simulator")
    }

    func testLegacySimulatorLabelIsNormalizedOnRealPhone() {
        XCTAssertEqual(
            AuthService.normalizedDeviceName("iPhone Simulator", isSimulator: false, userInterfaceIdiom: .phone),
            "iPhone"
        )
    }

    func testCustomDeviceNameIsPreserved() {
        XCTAssertEqual(
            AuthService.normalizedDeviceName("Work phone", isSimulator: false, userInterfaceIdiom: .phone),
            "Work phone"
        )
    }
}
