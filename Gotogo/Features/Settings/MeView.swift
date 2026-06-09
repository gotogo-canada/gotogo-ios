//
//  MeView.swift
//  Gotogo
//
//  The "Me" tab: prominently shows YOUR public ID (to share with others) and your
//  identity safety number, with copy + share, plus Logout and Delete account.
//

import SwiftUI

struct MeView: View {
    @Environment(AppState.self) private var appState

    @State private var showLogoutConfirm = false
    @State private var showDeleteConfirm = false
    @State private var working = false
    @State private var errorMessage: String?
    /// The public id currently being unblocked (shows a spinner on its row).
    @State private var unblocking: String?
    /// Brief "copied" confirmation state for the safety-number copy button.
    @State private var safetyCopied = false

    var body: some View {
        NavigationStack {
            List {
                profileSection
                identitySection
                safetySection
                blockedSection
                privacySection
                realtimeSection
                deviceSection
                dangerSection
            }
            .navigationTitle("Me")
            .task { await appState.refreshBlocks() }
            .alert("Log out?", isPresented: $showLogoutConfirm) {
                Button("Log out", role: .destructive) { logout() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("You'll need your recovery phrase to sign back in on this or another device.")
            }
            .alert("Delete account?", isPresented: $showDeleteConfirm) {
                Button("Delete", role: .destructive) { deleteAccount() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This permanently deletes your account on the server. This cannot be undone.")
            }
            .alert("Error", isPresented: errorBinding) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
    }

    // MARK: Sections

    private var profileSection: some View {
        Section {
            NavigationLink {
                EditProfileView()
            } label: {
                HStack(spacing: Theme.Spacing.md) {
                    if let id = appState.session?.publicId {
                        ProfileAvatar(publicId: id, fallback: id, size: 52)
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ownDisplayName)
                            .font(.headline)
                        Text(hasProfile ? "Edit your profile" : "Set up your name & photo")
                            .font(.caption)
                            .foregroundStyle(Theme.Palette.secondaryText)
                    }
                }
                .padding(.vertical, Theme.Spacing.xs)
            }
        } footer: {
            Text("Your profile is end-to-end encrypted and shared only with your mutual contacts.")
        }
    }

    private var ownProfile: DisplayProfile? {
        guard let id = appState.session?.publicId else { return nil }
        return appState.profileStore.profile(for: id)
    }

    private var hasProfile: Bool { (ownProfile?.displayName.isEmpty == false) }

    private var ownDisplayName: String {
        if let name = ownProfile?.displayName, !name.isEmpty { return name }
        return "Your profile"
    }

    private var identitySection: some View {
        Section {
            VStack(alignment: .leading, spacing: Theme.Spacing.md) {
                Text("Your address")
                    .font(.subheadline)
                    .foregroundStyle(Theme.Palette.secondaryText)
                HStack(alignment: .firstTextBaseline) {
                    Text(shareAddress)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                    Spacer()
                    Button { UIPasteboard.general.string = shareAddress } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    ShareLink(item: "Add me on Gotogo: \(shareAddress)") {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
                Text("Share this address so others can add you — it works across servers.")
                    .font(.caption)
                    .foregroundStyle(Theme.Palette.secondaryText)
                if appState.hasUsername, let id = appState.session?.publicId {
                    Text("Your random ID \(id)@\(appState.homeDomain) still works too.")
                        .font(.caption)
                        .foregroundStyle(Theme.Palette.secondaryText)
                }
            }
            .padding(.vertical, Theme.Spacing.xs)

            NavigationLink {
                UsernameEditorView()
            } label: {
                Label(appState.hasUsername ? "Change username" : "Choose a username",
                      systemImage: "at")
            }
        } header: {
            Text("Address")
        } footer: {
            Text("A username is optional — without one your address uses a random ID.")
        }
    }

    /// The address to share: the chosen `username@domain`, else `id@domain`.
    private var shareAddress: String {
        appState.myAddress ?? appState.session?.publicId ?? "—"
    }

    private var safetySection: some View {
        Section("Safety number") {
            HStack(alignment: .top) {
                Text(appState.identityFingerprint.isEmpty ? "—" : appState.identityFingerprint)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                Spacer()
                if !appState.identityFingerprint.isEmpty {
                    // Explicit, user-initiated copy of the safety number (a secret):
                    // routed through Clipboard.copySecret so it auto-expires + stays
                    // local-only. Nothing auto-copies it.
                    Button {
                        Clipboard.copySecret(appState.identityFingerprint)
                        safetyCopied = true
                        Task { try? await Task.sleep(nanoseconds: 2_000_000_000); safetyCopied = false }
                    } label: {
                        Image(systemName: safetyCopied ? "checkmark" : "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                }
            }
            Text("Compare this with a contact's to verify your end-to-end encrypted connection.")
                .font(.caption)
                .foregroundStyle(Theme.Palette.secondaryText)
        }
    }

    private var blockedSection: some View {
        Section("Blocked") {
            if appState.blockedIds.isEmpty {
                Text("You haven't blocked anyone.")
                    .font(.subheadline)
                    .foregroundStyle(Theme.Palette.secondaryText)
            } else {
                ForEach(blockedSorted, id: \.self) { id in
                    HStack {
                        Text(id)
                            .font(.body.monospaced())
                            .textSelection(.enabled)
                        Spacer()
                        if unblocking == id {
                            ProgressView()
                        } else {
                            Button("Unblock") { unblock(id) }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                        }
                    }
                }
            }
        }
    }

    private var blockedSorted: [String] { appState.blockedIds.sorted() }

    @State private var sealedWorking = false

    private var privacySection: some View {
        Section {
            Toggle(isOn: Binding(
                get: { appState.sealedSenderEnabled },
                set: { newValue in
                    sealedWorking = true
                    Task {
                        do { try await appState.setSealedSenderEnabled(newValue) }
                        catch { errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription }
                        sealedWorking = false
                    }
                }
            )) {
                HStack {
                    Label("Sealed sender", systemImage: "eye.slash")
                    if sealedWorking { Spacer(); ProgressView() }
                }
            }
            .disabled(sealedWorking)
        } header: {
            Text("Privacy")
        } footer: {
            Text(appState.sealedSenderEnabled
                 ? "Your contacts' servers don't learn it's you sending — your identity travels encrypted inside the message. Turn off to send normally."
                 : "Off: your messages carry your address to recipients' servers as usual.")
        }
    }

    private var realtimeSection: some View {
        Section("Connection") {
            HStack {
                Circle()
                    .fill(appState.isRealtimeConnected ? Theme.Palette.success : Color.gray)
                    .frame(width: 10, height: 10)
                Text(appState.isRealtimeConnected ? "Connected" : "Offline")
                Spacer()
                if let name = appState.session?.deviceName {
                    Text(name).font(.caption).foregroundStyle(Theme.Palette.secondaryText)
                }
            }
        }
    }

    private var deviceSection: some View {
        Section {
            NavigationLink {
                LinkDeviceView()
            } label: {
                Label("Link a device", systemImage: "laptopcomputer.and.iphone")
            }
            NavigationLink {
                CryptoDiagnosticsView()
            } label: {
                Label("Crypto diagnostics", systemImage: "checkmark.seal")
            }
            NavigationLink {
                MoveAccountView()
            } label: {
                Label("Move to another server", systemImage: "arrow.right.arrow.left.circle")
            }
        } header: {
            Text("Devices & security")
        } footer: {
            Text("Link another device to this account — each device keeps its own keys and becomes its own group member. Your messages, contacts and groups sync to it.")
        }
    }

    private var dangerSection: some View {
        Section {
            Button {
                showLogoutConfirm = true
            } label: {
                Label("Log out", systemImage: "rectangle.portrait.and.arrow.right")
            }
            .disabled(working)

            Button(role: .destructive) {
                showDeleteConfirm = true
            } label: {
                if working {
                    ProgressView()
                } else {
                    Label("Delete account", systemImage: "trash")
                }
            }
            .disabled(working)
        } footer: {
            Text("Logging out keeps your account on the server; you can recover it with your phrase.")
        }
    }

    // MARK: Actions

    private func logout() {
        do {
            try appState.auth.logout()
            appState.clearSession()
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    private func unblock(_ publicId: String) {
        unblocking = publicId
        Task {
            do {
                try await appState.unblock(publicId)
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            unblocking = nil
        }
    }

    private func deleteAccount() {
        working = true
        Task {
            do {
                try await appState.auth.deleteAccount()
                appState.clearSession()
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
