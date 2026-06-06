//
//  AppEnvironment.swift
//  Gotogo
//
//  Selects the backend endpoints per build. Local uses cleartext HTTP for a
//  development backend; Stage/Production are HTTPS/WSS only.
//

import Foundation

/// The deployment environment the app talks to.
public enum AppEnvironment: String, Sendable {
    case local
    case stage
    case production

    /// Active environment for this build. Set GOTOGO_ENV=local in an Xcode
    /// scheme when testing against a local backend.
    public static let current: AppEnvironment = {
        if let raw = ProcessInfo.processInfo.environment["GOTOGO_ENV"],
           let env = AppEnvironment(rawValue: raw) {
            return env
        }
        return .production
    }()

    /// Base URL for REST calls.
    public var apiBaseURL: URL {
        switch self {
        case .local:      return url("GOTOGO_API", "http://localhost:8080")
        case .stage:      return URL(string: "https://api-stage.gotogo.ca")!
        case .production: return URL(string: "https://api.gotogo.ca")!
        }
    }

    /// Base URL for the realtime WebSocket.
    public var webSocketBaseURL: URL {
        switch self {
        case .local:      return url("GOTOGO_WS", "ws://localhost:8080")
        case .stage:      return URL(string: "wss://api-stage.gotogo.ca")!
        case .production: return URL(string: "wss://api.gotogo.ca")!
        }
    }

    private func url(_ envKey: String, _ fallback: String) -> URL {
        if let raw = ProcessInfo.processInfo.environment[envKey], let u = URL(string: raw) {
            return u
        }
        return URL(string: fallback)!
    }
}
