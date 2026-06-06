//
//  SafetyVerificationView.swift
//  Gotogo
//
//  "Safety & verification" screen for a single conversation. Shows the safety
//  number to compare out of band, and the result of verifying the peer's identity
//  key against the RFC 6962 key-transparency log: a ✓/⚠/✗ status plus the peer's
//  device id(s). Reached from the conversation's toolbar menu.
//

import SwiftUI

struct SafetyVerificationView: View {
    let peerPublicId: String

    @Environment(AppState.self) private var appState

    /// The verification outcome: nil while loading, `.failure` if the log lookup
    /// failed or could not be verified.
    @State private var result: Result<TransparencyStatus, Error>?
    @State private var loading = false

    var body: some View {
        List {
            statusSection
            safetyNumberSection
            deviceSection
            explanationSection
        }
        .navigationTitle("Safety & verification")
        .navigationBarTitleDisplayMode(.inline)
        .task { await verify() }
        .refreshable { await verify() }
    }

    // MARK: - Sections

    private var statusSection: some View {
        Section {
            HStack(spacing: Theme.Spacing.md) {
                if loading {
                    ProgressView()
                } else {
                    Image(systemName: statusIcon)
                        .font(.title2)
                        .foregroundStyle(statusColor)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(statusTitle).font(.headline)
                    Text(statusDetail)
                        .font(.caption)
                        .foregroundStyle(Theme.Palette.secondaryText)
                }
            }
            .padding(.vertical, Theme.Spacing.xs)
        }
    }

    private var safetyNumberSection: some View {
        Section("Safety number") {
            Text(safetyNumber.isEmpty ? "—" : safetyNumber)
                .font(.body.monospaced())
                .textSelection(.enabled)
            Text("Compare this with your contact's safety number, in person or over a trusted channel, to confirm no one is intercepting your messages.")
                .font(.caption)
                .foregroundStyle(Theme.Palette.secondaryText)
        }
    }

    @ViewBuilder private var deviceSection: some View {
        if case .success(let status) = result {
            Section("Verified device") {
                Text(status.deviceId)
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
            }
        }
    }

    private var explanationSection: some View {
        Section {
            Text("Gotogo publishes every device's identity key to a tamper-evident transparency log. We check a cryptographic inclusion proof so the server can't quietly swap in a different key.")
                .font(.caption)
                .foregroundStyle(Theme.Palette.secondaryText)
        }
    }

    // MARK: - Derived state

    /// `verified` = included && !keyChanged → ✓; `changed` = included && keyChanged
    /// → ⚠; otherwise (not included / lookup failed) → ✗.
    private enum Outcome { case verified, changed, failed }

    private var outcome: Outcome {
        switch result {
        case .success(let status):
            if !status.included { return .failed }
            return status.keyChanged ? .changed : .verified
        case .failure, .none:
            return .failed
        }
    }

    private var statusIcon: String {
        switch outcome {
        case .verified: return "checkmark.seal.fill"
        case .changed: return "exclamationmark.triangle.fill"
        case .failed: return "xmark.seal.fill"
        }
    }

    private var statusColor: Color {
        switch outcome {
        case .verified: return Theme.Palette.success
        case .changed: return .orange
        case .failed: return .red
        }
    }

    private var statusTitle: String {
        if loading { return "Verifying…" }
        switch outcome {
        case .verified: return "Verified in transparency log"
        case .changed: return "Key changed — verify in person"
        case .failed: return "Could not verify"
        }
    }

    private var statusDetail: String {
        if loading { return "Checking the transparency log…" }
        switch outcome {
        case .verified:
            return "This contact's identity key is published and unchanged."
        case .changed:
            return "This contact's identity key changed since you last verified. This is normal after reinstalling, but confirm it's really them."
        case .failed:
            if case .failure(let error) = result {
                return (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            return "We couldn't confirm this contact's identity key."
        }
    }

    private var safetyNumber: String {
        if case .success(let status) = result { return status.safetyNumber }
        return ""
    }

    // MARK: - Actions

    private func verify() async {
        loading = true
        do {
            let status = try await appState.verifyTransparency(of: peerPublicId)
            result = .success(status)
        } catch {
            result = .failure(error)
        }
        loading = false
    }
}
