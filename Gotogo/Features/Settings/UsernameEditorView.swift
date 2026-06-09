//
//  UsernameEditorView.swift
//  Gotogo
//
//  Claim or change your username (the `localpart` of `username@domain`) at any
//  time from Settings. Backed by the shared `UsernamePicker`.
//

import SwiftUI

struct UsernameEditorView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                if let address = appState.myAddress {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Current address")
                            .font(.subheadline).foregroundStyle(Theme.Palette.secondaryText)
                        Text(address)
                            .font(.title3.monospaced())
                            .textSelection(.enabled)
                    }
                }

                Text(appState.hasUsername
                     ? "Pick a new username. Your old one is freed for others."
                     : "Pick a username so people can reach you at username@\(appState.homeDomain) instead of your random ID.")
                    .font(.subheadline)
                    .foregroundStyle(Theme.Palette.secondaryText)

                UsernamePicker(
                    domain: appState.homeDomain,
                    allowSkip: false,
                    check: { name in (try? await appState.checkUsername(name))?.available },
                    claim: { try await appState.claimUsername($0) },
                    onFinish: { dismiss() })
            }
            .padding(Theme.Spacing.lg)
        }
        .navigationTitle(appState.hasUsername ? "Change username" : "Choose a username")
        .navigationBarTitleDisplayMode(.inline)
    }
}
