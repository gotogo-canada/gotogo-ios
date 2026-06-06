//
//  RecoveryView.swift
//  Gotogo
//
//  Secondary screen to recover an existing account from a public ID + the
//  24-word recovery phrase. Calls `RegisterViewModel.recover`.
//

import SwiftUI

struct RecoveryView: View {
    @Bindable var model: RegisterViewModel
    let onComplete: (Session) -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Public ID (e.g. 91JLGNSJ)", text: $model.recoveryPublicId)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .font(.body.monospaced())
                } header: {
                    Text("Your public ID")
                } footer: {
                    Text("The 8-character ID you were shown when you created the account.")
                }

                Section {
                    TextEditor(text: $model.recoveryPhraseInput)
                        .frame(minHeight: 120)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.body)
                } header: {
                    Text("Recovery phrase")
                } footer: {
                    Text("Enter all 24 words separated by spaces.")
                }

                if case .failed(let message) = model.phase {
                    Section {
                        Label(message, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(Theme.Palette.destructive)
                            .font(.footnote)
                    }
                }

                Section {
                    Button {
                        Task { await model.recover(onComplete: onComplete) }
                    } label: {
                        if model.isWorking {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Recover account").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(model.isWorking)
                }
            }
            .navigationTitle("Recover account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { model.reset(); dismiss() }
                }
            }
        }
    }
}
