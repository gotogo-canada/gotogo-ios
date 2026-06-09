//
//  UsernamePicker.swift
//  Gotogo
//
//  Reusable username chooser: a `username@domain` field with live, debounced
//  availability checking, client-side validation mirroring the backend grammar
//  (docs/federation/02), and claim/skip actions. Used both in onboarding and in
//  Settings (change username anytime).
//

import SwiftUI

struct UsernamePicker: View {
    /// The home `@domain` shown as a suffix (e.g. `gotogo.ca`).
    let domain: String
    /// Whether to offer a "Skip for now" action (onboarding) or not (settings).
    let allowSkip: Bool
    /// Returns availability for an already client-valid name, or nil on a check
    /// error (treated as "unknown", claim still allowed to surface the real error).
    let check: (String) async -> Bool?
    /// Claims the (folded) name; throws on failure (e.g. taken / reserved).
    let claim: (String) async throws -> Void
    /// Called once the user has claimed a name or skipped.
    let onFinish: () -> Void

    @State private var text = ""
    @State private var status: Status = .empty
    @State private var working = false
    @State private var errorMessage: String?

    enum Status: Equatable {
        case empty
        case invalid(String)
        case checking
        case available
        case taken
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.lg) {
            field
            statusLine
            if let errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(Theme.Palette.destructive)
            }
            Spacer(minLength: 0)
            actions
        }
        .onChange(of: text) { _, _ in revalidate() }
        // Debounced availability check keyed on the current text.
        .task(id: text) { await runCheck() }
    }

    private var field: some View {
        HStack(spacing: 4) {
            Text("@").foregroundStyle(Theme.Palette.secondaryText)
            TextField("username", text: $text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textContentType(.username)
                .font(.title3.monospaced())
            Text("@\(domain)")
                .font(.subheadline.monospaced())
                .foregroundStyle(Theme.Palette.secondaryText)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
        }
        .padding(Theme.Spacing.md)
        .background(Theme.Palette.incomingBubble,
                    in: RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
    }

    @ViewBuilder private var statusLine: some View {
        switch status {
        case .empty:
            Text("Letters, numbers, and . _ - · 3–32 characters.")
                .font(.footnote).foregroundStyle(Theme.Palette.secondaryText)
        case .invalid(let why):
            Label(why, systemImage: "exclamationmark.circle")
                .font(.footnote).foregroundStyle(Theme.Palette.destructive)
        case .checking:
            HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Checking…") }
                .font(.footnote).foregroundStyle(Theme.Palette.secondaryText)
        case .available:
            Label("@\(folded) is available", systemImage: "checkmark.circle.fill")
                .font(.footnote).foregroundStyle(Theme.Palette.success)
        case .taken:
            Label("@\(folded) is taken", systemImage: "xmark.circle.fill")
                .font(.footnote).foregroundStyle(Theme.Palette.destructive)
        }
    }

    private var actions: some View {
        VStack(spacing: Theme.Spacing.md) {
            Button {
                Task { await doClaim() }
            } label: {
                if working {
                    ProgressView().tint(.white).frame(maxWidth: .infinity)
                        .padding(.vertical, Theme.Spacing.md)
                        .background(Theme.Palette.accent)
                        .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
                } else {
                    Text("Claim @\(folded.isEmpty ? "username" : folded)")
                        .primaryButtonStyle(enabled: status == .available && !working)
                }
            }
            .disabled(status != .available || working)

            if allowSkip {
                Button("Skip for now") { onFinish() }
                    .font(.subheadline)
                    .foregroundStyle(Theme.Palette.accent)
                    .disabled(working)
            }
        }
    }

    // MARK: - Logic

    /// The folded (lowercased, trimmed) form sent to the server.
    private var folded: String {
        text.trimmingCharacters(in: .whitespaces).lowercased()
    }

    /// Re-runs synchronous client validation on each keystroke.
    private func revalidate() {
        errorMessage = nil
        switch Self.validate(text) {
        case .invalid(let why):
            status = why.isEmpty ? .empty : .invalid(why)
        case .valid:
            // Mark as checking; the .task(id:) will resolve availability.
            if status != .available && status != .taken { status = .checking }
        }
    }

    /// Debounced availability check (runs whenever `text` changes).
    private func runCheck() async {
        guard case .valid(let name) = Self.validate(text) else { return }
        status = .checking
        try? await Task.sleep(nanoseconds: 350_000_000) // debounce
        if Task.isCancelled { return }
        let available = await check(name)
        if Task.isCancelled { return }
        // Only apply if the field hasn't changed under us.
        guard folded == name else { return }
        switch available {
        case .some(true):  status = .available
        case .some(false): status = .taken
        case .none:        status = .available // unknown: let the claim surface errors
        }
    }

    private func doClaim() async {
        guard case .valid(let name) = Self.validate(text) else { return }
        working = true
        errorMessage = nil
        do {
            try await claim(name)
            working = false
            onFinish()
        } catch {
            working = false
            status = .taken
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    // MARK: - Validation (mirrors the backend username grammar)

    /// Outcome of client-side username validation: the folded name, or a reason
    /// (empty string means simply "not entered yet").
    enum Validation: Equatable {
        case valid(String)
        case invalid(String)
    }

    static func validate(_ raw: String) -> Validation {
        let folded = raw.trimmingCharacters(in: .whitespaces).lowercased()
        guard !folded.isEmpty else { return .invalid("") }
        guard folded.count >= 3 else { return .invalid("At least 3 characters.") }
        guard folded.count <= 32 else { return .invalid("At most 32 characters.") }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._-")
        guard folded.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            return .invalid("Use letters, numbers, and . _ -")
        }
        let seps: Set<Character> = [".", "_", "-"]
        guard let first = folded.first, let last = folded.last,
              !seps.contains(first), !seps.contains(last) else {
            return .invalid("Can't start or end with . _ -")
        }
        var prev: Character?
        for c in folded {
            if let p = prev, seps.contains(p), seps.contains(c) {
                return .invalid("No repeated . _ -")
            }
            prev = c
        }
        return .valid(folded)
    }
}
