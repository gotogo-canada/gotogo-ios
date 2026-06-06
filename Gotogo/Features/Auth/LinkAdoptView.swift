//
//  LinkAdoptView.swift
//  Gotogo
//
//  NEW-device side of device linking. The user pastes the link code shown on their
//  existing device; this provisions THIS device (its own identity + prekeys) and
//  enters the app. Reachable from the first-launch screen via "Link to an existing
//  account".
//

import SwiftUI

struct LinkAdoptView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    /// Called after a successful link so the host can dismiss / enter the app.
    let onComplete: () -> Void

    @State private var code: String = ""
    @State private var working = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Paste link code", text: $code, axis: .vertical)
                        .lineLimit(3...6)
                        .font(.caption.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(working)
                } header: {
                    Text("Link code")
                } footer: {
                    Text("On your existing device: Me → Link a device. Scan the QR with your camera, or copy the code and paste it here.")
                }

                Section {
                    Button {
                        link()
                    } label: {
                        if working {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Link this device").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(working || code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .navigationTitle("Link to account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(working)
                }
            }
            .alert("Couldn't link device", isPresented: errorBinding) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
    }

    private func link() {
        working = true
        Task {
            do {
                try await appState.adoptDeviceLink(code: code)
                onComplete()
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            working = false
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }
}
