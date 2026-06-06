//
//  APIError.swift
//  Gotogo
//
//  Typed errors surfaced by `APIClient`, mapped to friendly messages for the UI.
//  Pure Foundation.
//

import Foundation

/// Errors thrown by `APIClient`.
public enum APIError: Error, Sendable {
    /// The URL could not be constructed from the base + path.
    case invalidURL
    /// Transport failure (no connection, timeout, etc.).
    case transport(String)
    /// Server returned a non-2xx status. Carries status and any decoded server code/message.
    case server(status: Int, code: String?, message: String?)
    /// The response body could not be decoded into the expected type.
    case decoding(String)
    /// A required auth token was missing for an authenticated call.
    case unauthenticated
}

extension APIError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Could not build the request URL."
        case .transport(let detail):
            return "Network error: \(detail)"
        case .server(let status, let code, let message):
            if let message, !message.isEmpty { return message }
            if let code, !code.isEmpty { return "Server error (\(code))." }
            return "Server error (HTTP \(status))."
        case .decoding(let detail):
            return "Unexpected response: \(detail)"
        case .unauthenticated:
            return "You are not signed in."
        }
    }

    /// The server-provided error code, when present (e.g. "not_found").
    public var serverCode: String? {
        if case .server(_, let code, _) = self { return code }
        return nil
    }
}

/// Shape of the backend's error envelope: `{ "error": { "code", "message" } }`.
struct ServerErrorEnvelope: Decodable {
    struct Body: Decodable {
        let code: String?
        let message: String?
    }
    let error: Body
}
