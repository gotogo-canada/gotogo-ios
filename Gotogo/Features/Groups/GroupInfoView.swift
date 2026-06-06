//
//  GroupInfoView.swift
//  Gotogo
//
//  The group-info screen: the member roster (with per-member name/avatar), admin
//  controls to add a mutual contact or remove a member (which ROTATES the sender
//  key so the removed member can't read future messages), and a "Leave group"
//  action. Reads the live roster from the cached `GroupState`.
//

import SwiftUI
import PhotosUI

struct GroupInfoView: View {
    let group: GroupInfo

    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var showAdd = false
    @State private var busy = false
    @State private var errorMessage: String?
    @State private var editName: String
    @State private var photoItem: PhotosPickerItem?
    @State private var pickedPhoto: Data?
    @State private var pickedPreview: UIImage?

    init(group: GroupInfo) {
        self.group = group
        _editName = State(initialValue: group.name)
    }

    /// Live name/photo from the cached group state (reflects admin edits + inbound
    /// `group_meta`), falling back to the passed-in snapshot.
    private var liveName: String { appState.groupService.state(group.groupId)?.name ?? group.name }
    private var livePhotoRef: MediaReference? { appState.groupService.state(group.groupId)?.photoRef }
    private var metaChanged: Bool {
        let trimmed = editName.trimmingCharacters(in: .whitespacesAndNewlines)
        return (!trimmed.isEmpty && trimmed != liveName) || pickedPhoto != nil
    }

    /// The live roster from the cached group state, falling back to the passed-in
    /// group's roster before the state has been synced in.
    private var members: [GroupMember] {
        appState.groupService.state(group.groupId)?.members ?? group.members
    }

    private var isAdmin: Bool {
        appState.groupService.state(group.groupId)?.myRole == .admin
    }

    private var myId: String? { appState.session?.publicId }

    /// Mutual contacts not already in the group (candidates to add).
    private var addableContacts: [Contact] {
        let current = Set(members.map(\.publicId))
        return appState.contacts.filter { $0.direction == .mutual && !current.contains($0.publicId) }
    }

    var body: some View {
        List {
            groupHeaderSection
            Section("Members") {
                ForEach(members) { member in
                    memberRow(member)
                }
            }
            Section {
                Button(role: .destructive) { leave() } label: {
                    Label(isAdmin ? "Delete group for everyone" : "Leave group",
                          systemImage: isAdmin ? "trash" : "rectangle.portrait.and.arrow.right")
                }
                .disabled(busy)
            } footer: {
                if isAdmin {
                    Text("You created this group, so leaving removes it for all members.")
                }
            }
        }
        .navigationTitle(liveName)
        .navigationBarTitleDisplayMode(.inline)
        .overlay {
            if busy {
                // The membership change is being ordered through the server commit
                // register (and may rebase if another member commits at the same time).
                VStack(spacing: Theme.Spacing.sm) {
                    ProgressView()
                    Text("Updating group…").font(.caption).foregroundStyle(Theme.Palette.secondaryText)
                }
                .padding(Theme.Spacing.lg)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
            }
        }
        .toolbar {
            if isAdmin {
                ToolbarItem(placement: .primaryAction) {
                    Button { showAdd = true } label: { Image(systemName: "person.badge.plus") }
                        .disabled(busy)
                }
            }
        }
        .task { await appState.refreshContacts() }
        .onChange(of: photoItem) { _, item in
            Task {
                guard let item, let data = try? await item.loadTransferable(type: Data.self) else { return }
                pickedPhoto = data
                pickedPreview = UIImage(data: data)
            }
        }
        .sheet(isPresented: $showAdd) { addSheet }
        .alert("Something went wrong", isPresented: errorBinding) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }

    /// The group's avatar + name. For the admin (owner) it's editable: pick a new
    /// photo and/or type a new name, then "Save changes" distributes it E2EE to every
    /// member via a `group_meta` control (they see it in real time).
    @ViewBuilder private var groupHeaderSection: some View {
        if isAdmin {
            Section("Group") {
                HStack(spacing: Theme.Spacing.md) {
                    GroupAvatar(name: liveName, photoRef: livePhotoRef, size: 56, override: pickedPreview)
                    PhotosPicker(selection: $photoItem, matching: .images, photoLibrary: .shared()) {
                        Label("Change photo", systemImage: "photo")
                    }
                    .disabled(busy)
                }
                TextField("Group name", text: $editName)
                    .textInputAutocapitalization(.words)
                Button("Save changes") { saveMeta() }
                    .disabled(busy || !metaChanged)
            }
        } else {
            Section {
                HStack(spacing: Theme.Spacing.md) {
                    GroupAvatar(name: liveName, photoRef: livePhotoRef, size: 56)
                    Text(liveName).font(.headline)
                }
            }
        }
    }

    private func memberRow(_ member: GroupMember) -> some View {
        HStack(spacing: Theme.Spacing.md) {
            ProfileAvatar(publicId: member.publicId, fallback: member.publicId, size: 36)
            VStack(alignment: .leading, spacing: 2) {
                ProfileName(publicId: member.publicId)
                if member.role == .admin {
                    Text("Admin").font(.caption).foregroundStyle(Theme.Palette.secondaryText)
                }
            }
            Spacer()
            if isAdmin, member.publicId != myId {
                Button(role: .destructive) { remove(member.publicId) } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .disabled(busy)
            }
        }
    }

    private var addSheet: some View {
        NavigationStack {
            List(addableContacts) { contact in
                Button { add(contact.publicId) } label: {
                    HStack(spacing: Theme.Spacing.md) {
                        ProfileAvatar(publicId: contact.publicId, fallback: contact.publicId, size: 36)
                        ProfileName(publicId: contact.publicId)
                    }
                }
                .buttonStyle(.plain)
            }
            .overlay { if addableContacts.isEmpty { Text("No contacts to add.").foregroundStyle(Theme.Palette.secondaryText) } }
            .navigationTitle("Add member")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { showAdd = false } } }
        }
    }

    // MARK: Actions

    private func add(_ publicId: String) {
        showAdd = false
        run { try await appState.groupService.addMember(groupId: group.groupId, publicId: publicId) }
    }

    private func remove(_ publicId: String) {
        run { try await appState.groupService.removeMember(groupId: group.groupId, publicId: publicId) }
    }

    private func leave() {
        run(after: { dismiss() }) {
            try await appState.groupService.leaveGroup(groupId: group.groupId)
            await appState.refreshGroups()
        }
    }

    /// Admin-only: distributes a new name and/or photo to every member (E2EE).
    private func saveMeta() {
        let name = editName.trimmingCharacters(in: .whitespacesAndNewlines)
        let photo = pickedPhoto   // capture by value before clearing the picked state
        run {
            try await appState.groupService.updateGroupMeta(
                groupId: group.groupId,
                name: name.isEmpty ? nil : name,
                photo: photo)
            await appState.refreshGroups()
        }
        pickedPhoto = nil
        pickedPreview = nil
    }

    /// Runs an async group action with a busy flag + error surface; `after` runs on
    /// success (on the main actor).
    private func run(after: @escaping () -> Void = {}, _ action: @escaping () async throws -> Void) {
        busy = true
        Task {
            do { try await action(); after() }
            catch { errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription }
            busy = false
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }
}
