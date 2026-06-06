//
//  RecoveryPhraseView.swift
//  Gotogo
//
//  Shows the 24-word recovery phrase once, in a numbered grid, with a required
//  "I've saved it" confirmation before continuing into the app. The phrase itself
//  is rendered inside a `ScreenshotProtectedView` so it is excluded from
//  screenshots / screen recordings, the screen is registered as sensitive (so a
//  screenshot here surfaces a warning), and the only way the phrase reaches the
//  clipboard is an explicit Copy tap that routes through `Clipboard.copySecret`
//  (auto-expiring, local-only).
//

import SwiftUI

struct RecoveryPhraseView: View {
    let words: [String]
    let onConfirm: () -> Void

    @Environment(ScreenshotMonitor.self) private var screenshotMonitor
    @State private var confirmed = false
    @State private var copied = false

    private let columns = [GridItem(.flexible()), GridItem(.flexible())]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                header
                // The phrase lives inside the secure (capture-excluded) layer so it
                // never appears in a screenshot or screen recording.
                ScreenshotProtectedView { grid }
                copyButton
                warning
            }
            .padding(Theme.Spacing.lg)
        }
        .safeAreaInset(edge: .bottom) { footer }
        .navigationTitle("Recovery phrase")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        .interactiveDismissDisabled(true)
        .sensitiveScreen(screenshotMonitor)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            Text("Write down these 24 words")
                .font(.title2.bold())
            Text("This is the only way to recover your account on a new device. Store it somewhere safe and private. We can't show it again.")
                .font(.subheadline)
                .foregroundStyle(Theme.Palette.secondaryText)
        }
    }

    private var grid: some View {
        LazyVGrid(columns: columns, spacing: Theme.Spacing.sm) {
            ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                HStack(spacing: Theme.Spacing.sm) {
                    Text("\(index + 1)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(Theme.Palette.secondaryText)
                        .frame(width: 24, alignment: .trailing)
                    Text(word)
                        .font(.callout.weight(.medium))
                    Spacer()
                }
                .padding(.vertical, Theme.Spacing.sm)
                .padding(.horizontal, Theme.Spacing.md)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.chip, style: .continuous))
            }
        }
    }

    /// Explicit, user-initiated copy. Routes through `Clipboard.copySecret` so the
    /// phrase is placed on the pasteboard local-only and auto-expires; nothing
    /// auto-copies the phrase.
    private var copyButton: some View {
        Button {
            Clipboard.copySecret(words.joined(separator: " "))
            copied = true
            Task { try? await Task.sleep(nanoseconds: 2_000_000_000); copied = false }
        } label: {
            Label(copied ? "Copied (clears in 90s)" : "Copy phrase",
                  systemImage: copied ? "checkmark" : "doc.on.doc")
                .font(.subheadline)
                .foregroundStyle(Theme.Palette.accent)
        }
    }

    private var warning: some View {
        Label("Anyone with these words can access your account.", systemImage: "exclamationmark.triangle.fill")
            .font(.footnote)
            .foregroundStyle(Theme.Palette.destructive)
    }

    private var footer: some View {
        VStack(spacing: Theme.Spacing.md) {
            Toggle(isOn: $confirmed) {
                Text("I've saved my recovery phrase").font(.subheadline)
            }
            .tint(Theme.Palette.accent)

            Button {
                onConfirm()
            } label: {
                Text("Continue").primaryButtonStyle(enabled: confirmed)
            }
            .disabled(!confirmed)
        }
        .padding(Theme.Spacing.lg)
        .background(.bar)
    }
}
