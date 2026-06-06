//
//  GroupListView.swift
//  Gotogo
//
//  The Groups tab: lists the groups this account belongs to with their decrypted
//  names + member counts, a "New group" entry point, and navigation into each
//  group conversation. Pull to refresh re-fetches + decrypts the group list.
//

import SwiftUI

struct GroupListView: View {
    @Environment(AppState.self) private var appState
    @State private var showNew = false

    var body: some View {
        NavigationStack {
            Group {
                if appState.groups.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
            .navigationTitle("Groups")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showNew = true } label: { Image(systemName: "plus.circle") }
                }
            }
            .refreshable { await appState.refreshGroups() }
            .task { await appState.refreshGroups() }
            .sheet(isPresented: $showNew) {
                NewGroupView { await appState.refreshGroups() }
            }
        }
    }

    private var list: some View {
        List(appState.groups) { group in
            NavigationLink {
                GroupConversationView(group: group)
            } label: {
                GroupRow(group: group)
            }
            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                Button(role: .destructive) {
                    Task { await appState.clearGroupConversation(group.groupId) }
                } label: {
                    Label("Clear", systemImage: "trash")
                }
            }
        }
        .listStyle(.plain)
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No groups yet", systemImage: "person.3")
        } description: {
            Text("Create a group with your contacts to message everyone at once.")
        } actions: {
            Button("New group") { showNew = true }
                .buttonStyle(.borderedProminent)
                .tint(Theme.Palette.accent)
        }
    }
}

/// One row in the group list: a group glyph, the decrypted name, and the member count.
private struct GroupRow: View {
    let group: GroupInfo

    var body: some View {
        HStack(spacing: Theme.Spacing.md) {
            GroupAvatar(name: group.name, photoRef: group.photoRef, size: 48)
            VStack(alignment: .leading, spacing: 2) {
                Text(group.name).font(.body.weight(.semibold))
                Text("\(group.members.count) member\(group.members.count == 1 ? "" : "s")")
                    .font(.subheadline)
                    .foregroundStyle(Theme.Palette.secondaryText)
            }
            Spacer()
        }
        .padding(.vertical, Theme.Spacing.xs)
    }
}
