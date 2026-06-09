//
//  ServerStore.swift
//  Gotogo
//
//  Persists the user's chosen HOME SERVER (the `@domain` of their `id@domain`).
//  Federation means anyone can self-host: the app is not pinned to one backend, so
//  the REST/WebSocket roots + the home domain are stored here and read at launch to
//  build the API/realtime clients. Defaults to the build's `AppEnvironment`.
//

import Foundation

/// The selected home server: where this account lives and the domain on its address.
public struct ServerConfig: Codable, Equatable, Sendable {
    /// REST root, e.g. `https://gotogo.ca` or `http://localhost:8080`.
    public var apiBaseURL: URL
    /// WebSocket root, e.g. `wss://gotogo.ca`.
    public var webSocketBaseURL: URL
    /// The server's `@domain` suffix on local addresses (authoritative once fetched
    /// from `GET /v1/server`; a heuristic before that).
    public var domain: String
    /// Optional human-facing server name.
    public var name: String?

    public init(apiBaseURL: URL, webSocketBaseURL: URL, domain: String, name: String? = nil) {
        self.apiBaseURL = apiBaseURL
        self.webSocketBaseURL = webSocketBaseURL
        self.domain = domain
        self.name = name
    }
}

/// UserDefaults-backed persistence for the chosen `ServerConfig`.
public final class ServerStore: @unchecked Sendable {

    private let defaults: UserDefaults
    private let key = "gotogo.server.config.v1"

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// The persisted server, or nil if the user has never chosen one.
    public func load() -> ServerConfig? {
        guard let data = defaults.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(ServerConfig.self, from: data)
    }

    /// Persists the chosen server.
    public func save(_ config: ServerConfig) {
        if let data = try? JSONEncoder().encode(config) {
            defaults.set(data, forKey: key)
        }
    }

    /// Clears the selection (used on full account teardown).
    public func clear() {
        defaults.removeObject(forKey: key)
    }

    /// The persisted server, or the build default if none was chosen yet.
    public func loadOrDefault() -> ServerConfig {
        load() ?? Self.buildDefault()
    }

    /// The default server for this build (from `AppEnvironment`). The domain is a
    /// best-effort heuristic (host minus a leading `api.`) until `GET /v1/server`
    /// supplies the authoritative value.
    public static func buildDefault() -> ServerConfig {
        let api = AppEnvironment.current.apiBaseURL
        let ws = AppEnvironment.current.webSocketBaseURL
        return ServerConfig(apiBaseURL: api, webSocketBaseURL: ws,
                            domain: heuristicDomain(from: api), name: nil)
    }

    /// Derives a likely `@domain` from a REST URL: the host with any leading `api.`
    /// stripped (so `api.gotogo.ca` → `gotogo.ca`). `localhost` is kept verbatim.
    public static func heuristicDomain(from url: URL) -> String {
        guard var host = url.host, !host.isEmpty else { return "localhost" }
        if host.hasPrefix("api.") { host = String(host.dropFirst(4)) }
        return host
    }

    // MARK: - Parsing user input into a candidate server

    /// Builds a candidate `ServerConfig` from free-text input: a full URL
    /// (`http://localhost:8080`, `https://gotogo.ca`) or a bare domain (`gotogo.ca`,
    /// defaulted to HTTPS). Returns nil if it can't form a valid http(s) URL.
    public static func candidate(from input: String) -> ServerConfig? {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let apiURL: URL
        if trimmed.contains("://") {
            // An explicit scheme was given: it must be http(s).
            guard let u = URL(string: trimmed), let scheme = u.scheme?.lowercased(),
                  scheme == "http" || scheme == "https", u.host != nil else { return nil }
            apiURL = u
        } else if let u = URL(string: "https://\(trimmed)"), u.host != nil {
            // A bare host/domain: default to HTTPS.
            apiURL = u
        } else {
            return nil
        }

        guard let wsURL = webSocketURL(for: apiURL) else { return nil }
        return ServerConfig(apiBaseURL: apiURL, webSocketBaseURL: wsURL,
                            domain: heuristicDomain(from: apiURL), name: nil)
    }

    /// Maps a REST URL to its WebSocket counterpart (`https`→`wss`, `http`→`ws`),
    /// preserving host + port.
    public static func webSocketURL(for apiURL: URL) -> URL? {
        guard var comps = URLComponents(url: apiURL, resolvingAgainstBaseURL: false) else { return nil }
        switch comps.scheme?.lowercased() {
        case "https": comps.scheme = "wss"
        case "http":  comps.scheme = "ws"
        default:      return nil
        }
        return comps.url
    }
}
