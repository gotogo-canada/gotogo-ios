//
//  ReportUserView.swift
//  Gotogo
//
//  A small sheet for reporting a user for abuse. Collects a reason (a quick pick
//  or free text) and posts it via `AppState.report`. Optionally blocks the user
//  in the same step.
//

import SwiftUI

struct ReportUserView: View {
    let peerPublicId: String
    /// Called after a successful report so the caller can refresh / dismiss.
    var onReported: () -> Void = {}

    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var reason: String = ""
    @State private var alsoBlock = true
    @State private var submitting = false
    @State private var errorMessage: String?

    /// Common quick-pick reasons; tapping one fills the text field.
    private let presets = ["Spam", "Harassment", "Impersonation", "Inappropriate content"]

    var body: some View {
        NavigationStack {
            Form {
                Section("Reason") {
                    ForEach(presets, id: \.self) { preset in
                        Button {
                            reason = preset
                        } label: {
                            HStack {
                                Text(preset).foregroundStyle(Color.primary)
                                Spacer()
                                if reason == preset {
                                    Image(systemName: "checkmark").foregroundStyle(Theme.Palette.accent)
                                }
                            }
                        }
                    }
                    TextField("Add details (optional)", text: $reason, axis: .vertical)
                        .lineLimit(2...4)
                }

                Section {
                    Toggle("Also block this contact", isOn: $alsoBlock)
                } footer: {
                    Text("Reports are sent to Gotogo for review. Blocking stops messages in both directions.")
                }
            }
            .navigationTitle("Report contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if submitting {
                        ProgressView()
                    } else {
                        Button("Submit") { submit() }
                            .disabled(reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
            }
            .alert("Couldn't report", isPresented: errorBinding) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
    }

    private func submit() {
        let trimmed = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        submitting = true
        Task {
            do {
                try await appState.report(peerPublicId, reason: trimmed)
                if alsoBlock { try await appState.block(peerPublicId) }
                onReported()
                dismiss()
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            submitting = false
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }
}
