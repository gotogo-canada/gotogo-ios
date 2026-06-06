//
//  ChatListView.swift
//  Gotogo
//
//  The Chats tab: a list of conversations (mutual contacts + any peer with
//  message history). Tapping a row opens the conversation. Pull to refresh syncs.
//

import SwiftUI

struct ChatListView: View {
    @Environment(AppState.self) private var appState
    @State private var showAdd = false

    var body: some View {
        NavigationStack {
            Group {
                if rows.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
            .navigationTitle("Chats")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showAdd = true } label: { Image(systemName: "square.and.pencil") }
                }
            }
            .refreshable { await appState.syncNow() }
            .sheet(isPresented: $showAdd) {
                AddContactView { await appState.refreshContacts() }
            }
        }
    }

    private var list: some View {
        List(rows) { row in
            NavigationLink {
                ConversationView(peerPublicId: row.peerPublicId)
            } label: {
                ChatRow(row: row)
            }
            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                Button(role: .destructive) {
                    Task { await appState.deleteConversation(row.peerPublicId) }
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
        .listStyle(.plain)
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No chats yet", systemImage: "bubble.left.and.bubble.right")
        } description: {
            Text("Add a contact by their public ID to start a conversation.")
        } actions: {
            Button("Add contact") { showAdd = true }
                .buttonStyle(.borderedProminent)
                .tint(Theme.Palette.accent)
        }
    }

    private var rows: [ChatListRow] {
        ChatListBuilder.rows(conversations: appState.conversations,
                             mutualContacts: appState.contacts.filter { $0.direction == .mutual },
                             groupIds: Set(appState.groups.map(\.groupId)))
    }
}

/// One row in the chat list: avatar, peer name/id, last-message preview and time.
/// Shows the contact's decrypted display name + photo when known, else the id.
private struct ChatRow: View {
    let row: ChatListRow

    var body: some View {
        HStack(spacing: Theme.Spacing.md) {
            ProfileAvatar(publicId: row.peerPublicId, fallback: row.peerPublicId, size: 48)
            VStack(alignment: .leading, spacing: 2) {
                ProfileName(publicId: row.peerPublicId)
                Text(row.preview)
                    .font(.subheadline)
                    .foregroundStyle(Theme.Palette.secondaryText)
                    .lineLimit(1)
            }
            Spacer()
            if let timestamp = row.timestamp {
                Text(timestamp, style: .time)
                    .font(.caption)
                    .foregroundStyle(Theme.Palette.secondaryText)
            }
        }
        .padding(.vertical, Theme.Spacing.xs)
    }
}
