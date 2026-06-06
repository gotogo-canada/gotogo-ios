//
//  NewGroupView.swift
//  Gotogo
//
//  The "New group" flow: pick a name and multi-select mutual contacts, then call
//  `GroupService.createGroup` (which mints a group key, seals the name, registers
//  the group, and bootstraps each member's sender key over the pairwise channel).
//

import SwiftUI

struct NewGroupView: View {
    /// Invoked after a successful create so the caller can refresh the list.
    let onCreated: () async -> Void

    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var selected: Set<String> = []
    @State private var creating = false
    @State private var errorMessage: String?

    private var mutualContacts: [Contact] {
        appState.contacts.filter { $0.direction == .mutual }
    }

    private var canCreate: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !selected.isEmpty && !creating
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") {
                    TextField("Group name", text: $name)
                }
                Section("Members") {
                    if mutualContacts.isEmpty {
                        Text("Add some contacts first to create a group.")
                            .font(.subheadline)
                            .foregroundStyle(Theme.Palette.secondaryText)
                    } else {
                        ForEach(mutualContacts) { contact in
                            memberRow(contact)
                        }
                    }
                }
            }
            .navigationTitle("New group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if creating {
                        ProgressView()
                    } else {
                        Button("Create") { create() }.disabled(!canCreate)
                    }
                }
            }
            .task { await appState.refreshContacts() }
            .alert("Couldn't create group", isPresented: errorBinding) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
    }

    private func memberRow(_ contact: Contact) -> some View {
        Button {
            if selected.contains(contact.publicId) { selected.remove(contact.publicId) }
            else { selected.insert(contact.publicId) }
        } label: {
            HStack(spacing: Theme.Spacing.md) {
                ProfileAvatar(publicId: contact.publicId, fallback: contact.publicId, size: 36)
                ProfileName(publicId: contact.publicId)
                Spacer()
                Image(systemName: selected.contains(contact.publicId) ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected.contains(contact.publicId) ? Theme.Palette.accent : Theme.Palette.secondaryText)
            }
        }
        .buttonStyle(.plain)
    }

    private func create() {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        creating = true
        Task {
            do {
                _ = try await appState.groupService.createGroup(name: trimmed,
                                                                memberPublicIds: Array(selected))
                await onCreated()
                dismiss()
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            creating = false
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }
}
