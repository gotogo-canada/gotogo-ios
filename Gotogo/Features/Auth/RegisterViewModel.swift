//
//  RegisterViewModel.swift
//  Gotogo
//
//  Drives account creation and recovery for the auth screens. Talks to
//  `AuthService`; reports progress/errors and the freshly-minted recovery phrase.
//

import Foundation
import Observation

/// View model for `RegisterView` and the recovery flow.
@MainActor
@Observable
final class RegisterViewModel {

    enum Phase: Equatable {
        case idle
        case working
        /// Registration succeeded; run the post-create flow (recovery phrase →
        /// choose a username) before entering the app.
        case registered
        case failed(String)
    }

    private(set) var phase: Phase = .idle

    /// The session produced by a successful register/recover, awaiting adoption.
    private(set) var pendingSession: Session?

    /// The one-time recovery phrase to show during the post-create flow.
    private(set) var recoveryWords: [String] = []

    // Recovery inputs.
    var recoveryPublicId: String = ""
    var recoveryPhraseInput: String = ""

    private let auth: AuthService

    init(auth: AuthService) {
        self.auth = auth
    }

    var isWorking: Bool {
        if case .working = phase { return true }
        return false
    }

    /// Creates a new account; on success moves to `.registered` (post-create flow).
    func createAccount() async {
        phase = .working
        do {
            let result = try await auth.register()
            pendingSession = result.session
            recoveryWords = result.recoveryPhrase
            phase = .registered
        } catch {
            phase = .failed(Self.message(for: error))
        }
    }

    // MARK: - Username (post-create)

    /// Live availability check for the username picker (nil on a check error).
    func checkUsername(_ name: String) async -> Bool? {
        (try? await auth.checkUsername(name))?.available
    }

    /// Claims a username for the freshly-registered account and records it on the
    /// pending session so the app shows `username@domain` on entry.
    func claimUsername(_ name: String) async throws {
        let address = try await auth.claimUsername(name)
        pendingSession?.username = Address(address)?.localpart ?? name.lowercased()
    }

    /// Recovers an existing account from a public id + 24-word phrase.
    /// On success, `pendingSession` is set and `onComplete` is invoked.
    func recover(onComplete: (Session) -> Void) async {
        let words = recoveryPhraseInput
            .split(whereSeparator: { $0 == " " || $0.isNewline })
            .map(String.init)
        let publicId = recoveryPublicId.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !publicId.isEmpty else {
            phase = .failed("Enter your public ID.")
            return
        }
        guard words.count == 24 else {
            phase = .failed("Enter all 24 recovery words.")
            return
        }
        phase = .working
        do {
            let session = try await auth.recoverAccount(publicId: publicId, phrase: words)
            pendingSession = session
            onComplete(session)
        } catch {
            phase = .failed(Self.message(for: error))
        }
    }

    /// Resets a failure back to idle so the user can retry.
    func reset() { phase = .idle }

    private static func message(for error: Error) -> String {
        if let local = error as? LocalizedError, let desc = local.errorDescription {
            return desc
        }
        return error.localizedDescription
    }
}
