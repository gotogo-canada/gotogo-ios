//
//  RealtimeClient.swift
//  Gotogo
//
//  `URLSessionWebSocketTask` wrapper for the `/v1/ws` realtime feed. Exposes
//  inbound messages as an `AsyncStream<InboundMessage>` and auto-reconnects.
//  Foundation only.
//
//  This module defaults to `@MainActor` isolation. The socket's `receive`
//  completion handler fires on a background queue, so it immediately hops back to
//  the main actor (frames are tiny) where all state lives — no extra locking.
//

import Foundation

/// Connects to the realtime WebSocket and yields decoded inbound messages.
///
/// The server sends a `{"type":"connected"}` frame, then per delivered message a
/// `{"type":"message","message":{...}}` frame. We ignore the former and decode
/// the latter into `InboundMessage`.
@MainActor
public final class RealtimeClient {

    /// Envelope wrapping each realtime text frame.
    private struct Frame: Decodable {
        let type: String
        let message: InboundMessage?
    }

    /// WebSocket root. Mutable so the user can switch home servers before
    /// registering (mirrors `APIClient.setBaseURL`). All state is main-actor
    /// isolated, so no extra locking is needed.
    private var baseURL: URL
    private let session: URLSession
    private let decoder: JSONDecoder

    private var task: URLSessionWebSocketTask?
    private var continuation: AsyncStream<InboundMessage>.Continuation?
    private var isStopped = false
    private var token = ""

    init(baseURL: URL,
         session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            if let date = APIClient.flexibleDate(from: raw) { return date }
            throw DecodingError.dataCorruptedError(in: container,
                                                   debugDescription: "Unparseable date: \(raw)")
        }
        self.decoder = dec
    }

    /// Switches the WebSocket root (the user's chosen home server). Only meaningful
    /// before a connection is opened (i.e. before registering).
    func setBaseURL(_ url: URL) {
        self.baseURL = url
    }

    /// Opens the socket for `token` and returns a stream of inbound messages.
    /// Calling `connect` again replaces the previous connection.
    func connect(token: String) -> AsyncStream<InboundMessage> {
        stop()
        self.token = token
        isStopped = false

        return AsyncStream { continuation in
            self.continuation = continuation
            self.openSocket()
            continuation.onTermination = { [weak self] _ in
                Task { @MainActor [weak self] in self?.stop() }
            }
        }
    }

    /// Closes the socket and finishes the stream.
    func stop() {
        isStopped = true
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        continuation?.finish()
        continuation = nil
    }

    // MARK: - Internals

    private func openSocket() {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else { return }
        components.path = "/v1/ws"
        components.queryItems = [URLQueryItem(name: "token", value: token)]
        guard let url = components.url else { return }

        let newTask = session.webSocketTask(with: url)
        task = newTask
        newTask.resume()
        receiveNext()
    }

    private func receiveNext() {
        guard let current = task else { return }
        current.receive { result in
            // Completion fires on a background queue; hop to the main actor.
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch result {
                case .success(let message):
                    self.handle(message)
                    if !self.isStopped { self.receiveNext() }
                case .failure:
                    // Connection dropped; attempt a delayed reconnect unless stopped.
                    if !self.isStopped { self.scheduleReconnect() }
                }
            }
        }
    }

    private func handle(_ message: URLSessionWebSocketTask.Message) {
        let data: Data?
        switch message {
        case .string(let text): data = text.data(using: .utf8)
        case .data(let raw): data = raw
        @unknown default: data = nil
        }
        guard let data, let frame = try? decoder.decode(Frame.self, from: data) else { return }
        if frame.type == "message", let inbound = frame.message {
            continuation?.yield(inbound)
        }
    }

    private func scheduleReconnect() {
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            guard let self, !self.isStopped else { return }
            self.openSocket()
        }
    }
}
