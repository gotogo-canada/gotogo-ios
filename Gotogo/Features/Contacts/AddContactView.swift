//
//  AddContactView.swift
//  Gotogo
//
//  Sheet to add a contact by their public ID: validates existence, then sends a
//  contact request. Shows clear "user not found" / error states.
//

import SwiftUI

struct AddContactView: View {
    /// Called after a request is sent so the caller can refresh its list.
    let onSent: () async -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    @State private var publicId = ""
    @State private var phase: Phase = .idle

    private enum Phase: Equatable {
        case idle, working, sent, failed(String)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Public ID (e.g. 91JLGNSJ)", text: $publicId)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .font(.body.monospaced())
                } header: {
                    Text("Add by public ID")
                } footer: {
                    Text("Ask your contact for the 8-character ID shown on their Me tab.")
                }

                switch phase {
                case .failed(let message):
                    Section {
                        Label(message, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(Theme.Palette.destructive).font(.footnote)
                    }
                case .sent:
                    Section {
                        Label("Request sent. They need to accept it.", systemImage: "checkmark.circle")
                            .foregroundStyle(Theme.Palette.success).font(.footnote)
                    }
                default:
                    EmptyView()
                }

                Section {
                    Button {
                        send()
                    } label: {
                        if phase == .working {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Send request").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(phase == .working || trimmed.isEmpty)
                }
            }
            .navigationTitle("Add contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private var trimmed: String {
        publicId.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
    }

    private func send() {
        let target = trimmed
        guard !target.isEmpty else { return }
        if target == appState.session?.publicId {
            phase = .failed("That's your own ID.")
            return
        }
        phase = .working
        Task {
            do {
                try await appState.messaging.requestContact(publicId: target)
                phase = .sent
                await onSent()
            } catch {
                phase = .failed((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
            }
        }
    }
}
