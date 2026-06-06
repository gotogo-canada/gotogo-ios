//
//  ContactsView.swift
//  Gotogo
//
//  Lists mutual contacts, surfaces pending incoming requests with an Accept
//  button, and offers an "Add by public ID" entry point. Tapping a mutual
//  contact opens the conversation.
//

import SwiftUI

struct ContactsView: View {
    @Environment(AppState.self) private var appState
    @State private var showAdd = false
    @State private var errorMessage: String?
    @State private var busyContact: String?

    var body: some View {
        NavigationStack {
            List {
                if !incoming.isEmpty {
                    Section("Requests") {
                        ForEach(incoming) { contact in
                            requestRow(contact)
                        }
                    }
                }

                Section("Contacts") {
                    if mutual.isEmpty {
                        Text("No contacts yet. Add someone by their public ID.")
                            .foregroundStyle(Theme.Palette.secondaryText)
                            .font(.subheadline)
                    } else {
                        ForEach(mutual) { contact in
                            NavigationLink {
                                ConversationView(peerPublicId: contact.publicId)
                            } label: {
                                contactRow(contact)
                            }
                        }
                    }
                }

                if !outgoing.isEmpty {
                    Section("Pending") {
                        ForEach(outgoing) { contact in
                            HStack {
                                contactRow(contact)
                                Spacer()
                                Text("Requested").font(.caption).foregroundStyle(Theme.Palette.secondaryText)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Contacts")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showAdd = true } label: { Image(systemName: "person.badge.plus") }
                }
            }
            .refreshable { await appState.refreshContacts() }
            .task { await appState.refreshContacts() }
            .sheet(isPresented: $showAdd) {
                AddContactView { await appState.refreshContacts() }
            }
            .alert("Error", isPresented: errorBinding) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
    }

    // MARK: Rows

    private func contactRow(_ contact: Contact) -> some View {
        HStack(spacing: Theme.Spacing.md) {
            ProfileAvatar(publicId: contact.publicId, fallback: contact.publicId, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                ProfileName(publicId: contact.publicId, font: .body)
                Text(contact.isMutual ? "Connected" : contact.direction.rawValue.capitalized)
                    .font(.caption)
                    .foregroundStyle(Theme.Palette.secondaryText)
            }
        }
    }

    private func requestRow(_ contact: Contact) -> some View {
        HStack {
            contactRow(contact)
            Spacer()
            if busyContact == contact.publicId {
                ProgressView()
            } else {
                Button("Accept") { accept(contact) }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.Palette.accent)
                    .controlSize(.small)
            }
        }
    }

    // MARK: Actions

    private func accept(_ contact: Contact) {
        busyContact = contact.publicId
        Task {
            do {
                try await appState.messaging.acceptContact(fromPublicId: contact.publicId)
                await appState.refreshContacts()
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            busyContact = nil
        }
    }

    // MARK: Derived

    private var mutual: [Contact] { appState.contacts.filter { $0.direction == .mutual } }
    private var incoming: [Contact] { appState.contacts.filter { $0.direction == .incoming } }
    private var outgoing: [Contact] { appState.contacts.filter { $0.direction == .outgoing } }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }
}
