//
//  ServerSelectView.swift
//  Gotogo
//
//  Choose the HOME SERVER before creating an account. Federation means anyone can
//  self-host, so the user can keep the default server or point the app at their
//  own. We validate by fetching `GET /v1/server` (confirming it's a Gotogo server
//  and learning the authoritative `@domain`). Only available before registering.
//

import SwiftUI

struct ServerSelectView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var text = ""
    @State private var working = false
    @State private var errorMessage: String?
    @State private var confirmed: ServerConfig?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("https://gotogo.ca", text: $text)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .textContentType(.URL)
                        .font(.body.monospaced())
                } header: {
                    Text("Server address")
                } footer: {
                    Text("The server that hosts your account. Enter a domain (gotogo.ca) or a full URL (http://localhost:8080). This becomes the @domain on your address.")
                }

                if let confirmed {
                    Section {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(confirmed.name ?? confirmed.domain).font(.headline)
                                Text("You'll be  …@\(confirmed.domain)")
                                    .font(.subheadline.monospaced())
                                    .foregroundStyle(Theme.Palette.secondaryText)
                            }
                        } icon: {
                            Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.Palette.success)
                        }
                    }
                }

                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(Theme.Palette.destructive)
                    }
                }

                Section {
                    Button {
                        Task { await use() }
                    } label: {
                        HStack {
                            Text(confirmed == nil ? "Check server" : "Use this server")
                            Spacer()
                            if working { ProgressView() }
                        }
                    }
                    .disabled(working || text.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .navigationTitle("Home server")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onAppear {
                if text.isEmpty { text = appState.currentServer().apiBaseURL.absoluteString }
            }
        }
    }

    private func use() async {
        working = true
        errorMessage = nil
        do {
            let cfg = try await appState.selectServer(input: text)
            confirmed = cfg
            working = false
            // Once confirmed, a second tap dismisses; or dismiss immediately if the
            // user already saw the confirmation.
            if confirmed != nil { dismiss() }
        } catch {
            working = false
            confirmed = nil
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}
