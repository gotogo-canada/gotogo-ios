//
//  PostCreateView.swift
//  Gotogo
//
//  The flow shown right after an account is created: first the one-time recovery
//  phrase, then choosing a username (username@domain) — or skipping to keep the
//  server-assigned random id. Completing it enters the app.
//

import SwiftUI

struct PostCreateView: View {
    let model: RegisterViewModel
    /// The home `@domain` to display in the username step.
    let domain: String
    /// Called when the user finishes onboarding (claimed a username or skipped).
    let onComplete: () -> Void

    @State private var showUsername = false

    var body: some View {
        Group {
            if showUsername {
                ChooseUsernameStep(
                    domain: domain,
                    check: { await model.checkUsername($0) },
                    claim: { try await model.claimUsername($0) },
                    onFinish: onComplete)
            } else {
                RecoveryPhraseView(words: model.recoveryWords) { showUsername = true }
            }
        }
        .animation(.default, value: showUsername)
    }
}

/// The "choose a username" step (also reused conceptually by Settings, which has
/// its own entry point). Wraps the shared `UsernamePicker` with intro copy.
struct ChooseUsernameStep: View {
    let domain: String
    let check: (String) async -> Bool?
    let claim: (String) async throws -> Void
    let onFinish: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
            VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
                Text("Choose a username")
                    .font(.title2.bold())
                Text("Pick a username so people can reach you at username@\(domain). You can skip and use your random ID instead, and change this anytime in Settings.")
                    .font(.subheadline)
                    .foregroundStyle(Theme.Palette.secondaryText)
            }
            UsernamePicker(domain: domain, allowSkip: true,
                           check: check, claim: claim, onFinish: onFinish)
        }
        .padding(Theme.Spacing.lg)
        .navigationTitle("Username")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
    }
}
