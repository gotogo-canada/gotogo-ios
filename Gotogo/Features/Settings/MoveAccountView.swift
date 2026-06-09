//
//  MoveAccountView.swift
//  Gotogo
//
//  Account portability: move this account to another server. The user enters
//  their NEW address (created on the target server first) and their 24-word
//  recovery phrase; the move statement is signed with the recovery key so
//  contacts can cryptographically verify the redirect — a server can't forge it.
//

import SwiftUI

struct MoveAccountView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @Environment(ScreenshotMonitor.self) private var screenshotMonitor

    @State private var toAddress = ""
    @State private var phraseInput = ""
    @State private var working = false
    @State private var errorMessage: String?
    @State private var movedTo: String?

    var body: some View {
        Form {
            Section {
                Text("Moving points your old address at a new account you've already created on another server. Contacts verify the move with your recovery key and follow you automatically.")
                    .font(.footnote)
                    .foregroundStyle(Theme.Palette.secondaryText)
            }

            Section {
                TextField("you@new-server.example", text: $toAddress)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.emailAddress)
                    .font(.body.monospaced())
            } header: {
                Text("New address")
            } footer: {
                Text("Create the account on the new server first, then enter its address here.")
            }

            Section {
                TextEditor(text: $phraseInput)
                    .frame(minHeight: 100)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            } header: {
                Text("Recovery phrase")
            } footer: {
                Text("Your 24 words sign the move so contacts can verify it really came from you.")
            }

            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(Theme.Palette.destructive)
                        .font(.footnote)
                }
            }

            if let movedTo {
                Section {
                    Label {
                        Text("Your account now forwards to \(movedTo). You can log out of this device and recover on the new server.")
                    } icon: {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.Palette.success)
                    }
                    .font(.footnote)
                }
            }

            Section {
                Button(role: .destructive) {
                    Task { await move() }
                } label: {
                    if working {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text("Move account").frame(maxWidth: .infinity)
                    }
                }
                .disabled(working || movedTo != nil || !inputsValid)
            } footer: {
                Text("This tombstones your account on the current server. It cannot be undone here.")
            }
        }
        .navigationTitle("Move to another server")
        .navigationBarTitleDisplayMode(.inline)
        .sensitiveScreen(screenshotMonitor)
    }

    private var inputsValid: Bool {
        Address(toAddress) != nil && phraseWords.count == 24
    }

    private var phraseWords: [String] {
        phraseInput.split(whereSeparator: { $0 == " " || $0.isNewline }).map(String.init)
    }

    private func move() async {
        guard let target = Address(toAddress) else {
            errorMessage = "Enter the full new address, like you@new-server.example."
            return
        }
        working = true
        errorMessage = nil
        do {
            let forwarded = try await appState.moveAccount(toAddress: target.display, phrase: phraseWords)
            movedTo = forwarded
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        working = false
    }
}
