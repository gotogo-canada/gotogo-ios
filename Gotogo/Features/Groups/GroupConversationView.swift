//
//  GroupConversationView.swift
//  Gotogo
//
//  A group chat: per-sender bubbles (name + avatar for incoming, via the shared
//  ProfileStore), a photo/video + sticker + text composer wired to `GroupService`,
//  and a toolbar link to the group-info screen. Messages arrive via the app-wide
//  sync/realtime feed and reflect here when `AppState.conversations` changes.
//

import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

struct GroupConversationView: View {
    let group: GroupInfo

    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var model: GroupConversationViewModel?
    @State private var showStickers = false
    @State private var photoItem: PhotosPickerItem?

    var body: some View {
        Group {
            if let model {
                content(model)
            } else {
                ProgressView()
            }
        }
        .navigationTitle(appState.groupService.state(group.groupId)?.name ?? group.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                NavigationLink { GroupInfoView(group: group) } label: {
                    Image(systemName: "info.circle")
                }
            }
        }
        .task {
            let model = model ?? GroupConversationViewModel(groupId: group.groupId, groups: appState.groupService)
            self.model = model
            await model.sync()
        }
        .onChange(of: appState.conversations) { _, _ in model?.reload() }
        .onChange(of: appState.groups) { _, _ in
            // I was removed by the admin, or the creator dissolved the group → the
            // group is gone from local state, so leave the conversation immediately.
            if appState.groupService.state(group.groupId) == nil { dismiss() }
        }
    }

    private func content(_ model: GroupConversationViewModel) -> some View {
        VStack(spacing: 0) {
            messageList(model)
            composer(model)
        }
        .alert("Couldn't send", isPresented: errorBinding(model)) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
        .sheet(isPresented: $showStickers) {
            StickerPicker { id in Task { await model.sendSticker(id) } }
        }
    }

    private func messageList(_ model: GroupConversationViewModel) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: Theme.Spacing.sm) {
                    if model.messages.isEmpty { emptyState }
                    if model.hasOlder { loadEarlierButton(model) }
                    ForEach(model.windowed) { message in
                        GroupMessageRow(message: message, model: model).id(message.id)
                    }
                }
                .padding(.horizontal, Theme.Spacing.md)
                .padding(.vertical, Theme.Spacing.md)
            }
            .defaultScrollAnchor(.bottom)
            .onChange(of: model.messages) { _, _ in
                if let last = model.windowed.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
        }
    }

    /// Reveals one older page from the on-device cache (history is local-only).
    private func loadEarlierButton(_ model: GroupConversationViewModel) -> some View {
        Button { model.loadOlder() } label: {
            Label("Load earlier messages", systemImage: "arrow.up")
                .font(.footnote)
                .padding(.vertical, Theme.Spacing.xs)
        }
        .buttonStyle(.bordered)
        .padding(.bottom, Theme.Spacing.sm)
    }

    private func composer(_ model: GroupConversationViewModel) -> some View {
        HStack(spacing: Theme.Spacing.sm) {
            PhotosPicker(selection: $photoItem,
                         matching: .any(of: [.images, .videos]),
                         photoLibrary: .shared()) {
                Image(systemName: "plus.circle.fill").font(.system(size: 28))
                    .foregroundStyle(model.sending ? .gray : Theme.Palette.accent)
            }
            .disabled(model.sending)
            Button { showStickers = true } label: {
                Image(systemName: "face.smiling").font(.system(size: 26))
                    .foregroundStyle(model.sending ? .gray : Theme.Palette.accent)
            }
            .disabled(model.sending)
            TextField("Message", text: bindableDraft(model), axis: .vertical)
                .textFieldStyle(.plain)
                .padding(.horizontal, Theme.Spacing.md)
                .padding(.vertical, Theme.Spacing.sm)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
                .lineLimit(1...5)
            Button { Task { await model.send() } } label: {
                Image(systemName: "arrow.up.circle.fill").font(.system(size: 30))
                    .foregroundStyle(model.sending ? .gray : Theme.Palette.accent)
            }
            .disabled(model.sending)
        }
        .padding(Theme.Spacing.md)
        .background(.bar)
        .onChange(of: photoItem) { _, item in Task { await loadPickedItem(item, into: model) } }
    }

    /// Loads the picked item and routes it: a movie → `sendVideo` (size-gated at
    /// 25 MB in the group service), anything else → `sendImage`. Both encrypt before
    /// upload and MLS-fan-out the resulting `MediaReference` to every member.
    private func loadPickedItem(_ item: PhotosPickerItem?, into model: GroupConversationViewModel) async {
        guard let item else { return }
        photoItem = nil
        let isVideo = item.supportedContentTypes.contains { $0.conforms(to: .movie) }
        guard let data = try? await item.loadTransferable(type: Data.self) else { return }
        if isVideo { await model.sendVideo(data) } else { await model.sendImage(data) }
    }

    private var emptyState: some View {
        VStack(spacing: Theme.Spacing.sm) {
            Image(systemName: "lock.fill").font(.title).foregroundStyle(Theme.Palette.secondaryText)
            Text("Group messages are end-to-end encrypted with sender keys.")
                .font(.footnote).multilineTextAlignment(.center)
                .foregroundStyle(Theme.Palette.secondaryText)
        }
        .padding(.top, Theme.Spacing.xl)
    }

    private func bindableDraft(_ model: GroupConversationViewModel) -> Binding<String> {
        Binding(get: { model.draft }, set: { model.draft = $0 })
    }

    private func errorBinding(_ model: GroupConversationViewModel) -> Binding<Bool> {
        Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
    }
}

/// A single group message row: incoming messages show the sender's avatar + name
/// (via ProfileStore); outgoing align right. Dispatches image/video/voice to the
/// shared media bubbles, stickers to `StickerBubble`, everything else to a text bubble.
private struct GroupMessageRow: View {
    let message: ChatMessage
    let model: GroupConversationViewModel

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Spacing.sm) {
            if message.isMine {
                Spacer(minLength: 40)
                VStack(alignment: .trailing, spacing: 2) {
                    bubble.contextMenu { deleteActions }
                    timeLabel
                }
            } else {
                ProfileAvatar(publicId: message.senderPublicId ?? "?",
                              fallback: message.senderPublicId ?? "?", size: 30)
                VStack(alignment: .leading, spacing: 2) {
                    if let sender = message.senderPublicId {
                        ProfileName(publicId: sender, font: .caption)
                    }
                    bubble.contextMenu { deleteActions }
                    timeLabel
                }
                Spacer(minLength: 40)
            }
        }
    }

    /// The message send time (same `.time` style as the 1:1 bubble).
    private var timeLabel: some View {
        Text(message.createdAt, style: .time)
            .font(.caption2)
            .foregroundStyle(Theme.Palette.secondaryText)
    }

    /// Long-press actions: "delete for me" (local) always; "delete for everyone"
    /// (removed on every member) for my own messages.
    @ViewBuilder private var deleteActions: some View {
        Button(role: .destructive) {
            model.deleteForMe(message)
        } label: {
            Label("Delete for me", systemImage: "trash")
        }
        if message.isMine && message.clientId != nil {
            Button(role: .destructive) {
                Task { await model.deleteForEveryone(message) }
            } label: {
                Label("Delete for everyone", systemImage: "trash.slash")
            }
        }
    }

    @ViewBuilder private var bubble: some View {
        switch message.mediaKind {
        case "image" where message.media != nil:
            ImageMessageBubble(message: message, model: model)
                .padding(Theme.Spacing.xs)
                .background(bubbleColor)
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
        case "video" where message.media != nil:
            VideoMessageBubble(message: message, model: model)
                .padding(Theme.Spacing.xs)
                .background(bubbleColor)
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
        case "voice" where message.media != nil:
            VoiceMessageBubble(message: message, model: model)
                .padding(.horizontal, Theme.Spacing.md)
                .background(bubbleColor)
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
        case "sticker":
            StickerBubble(stickerId: message.stickerId)
        default:
            Text(message.body)
                .foregroundStyle(message.isMine ? Theme.Palette.outgoingText : Theme.Palette.incomingText)
                .padding(.horizontal, Theme.Spacing.md)
                .padding(.vertical, Theme.Spacing.sm)
                .background(bubbleColor)
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
        }
    }

    private var bubbleColor: Color {
        if !message.decrypted { return Color.orange.opacity(0.25) }
        return message.isMine ? Theme.Palette.outgoingBubble : Theme.Palette.incomingBubble
    }
}
