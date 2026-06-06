//
//  ConversationView.swift
//  Gotogo
//
//  A single chat: message bubbles (mine vs theirs) and a text composer. Sending
//  encrypts + posts; incoming arrive via the app-wide realtime/sync feed and are
//  reflected here when `AppState.conversations` changes.
//

import SwiftUI

struct ConversationView: View {
    let peerPublicId: String

    @Environment(AppState.self) private var appState
    @Environment(ScreenshotMonitor.self) private var screenshotMonitor
    @State private var model: ConversationViewModel?
    @State private var showReport = false
    @State private var showBlockConfirm = false
    @State private var safetyError: String?

    /// The peer's decrypted display name when known, else their public id.
    private var title: String {
        let name = appState.profileStore.profile(for: peerPublicId)?.displayName
        return (name?.isEmpty == false) ? name! : peerPublicId
    }

    private var isBlocked: Bool { appState.isBlocked(peerPublicId) }

    var body: some View {
        Group {
            if let model {
                content(model)
            } else {
                ProgressView()
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .sensitiveScreen(screenshotMonitor)
        .toolbar { safetyMenu }
        .task {
            // Create the view model once the environment is available, then sync.
            let model = model ?? ConversationViewModel(peerPublicId: peerPublicId,
                                                       messaging: appState.messaging)
            self.model = model
            await model.sync()
        }
        // Fetch the peer's decrypted profile so the title shows their name.
        .task(id: peerPublicId) { await appState.profileStore.load(peerPublicId) }
        // Keep the blocked state fresh so the menu shows Block vs Unblock correctly.
        .task { await appState.refreshBlocks() }
        // Reflect app-wide message updates (realtime/sync) into this view.
        .onChange(of: appState.conversations) { _, _ in model?.reload() }
        .sheet(isPresented: $showReport) {
            ReportUserView(peerPublicId: peerPublicId) {
                Task { await appState.refreshBlocks() }
            }
        }
        .confirmationDialog("Block this contact?",
                            isPresented: $showBlockConfirm,
                            titleVisibility: .visible) {
            Button("Block", role: .destructive) { performBlock() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Blocking stops messages in both directions. You can unblock later from this menu or in Me ▸ Blocked.")
        }
        .alert("Something went wrong", isPresented: safetyErrorBinding) {
            Button("OK") { safetyError = nil }
        } message: {
            Text(safetyError ?? "")
        }
    }

    /// The toolbar menu with Safety & verification + Block/Unblock + Report.
    @ToolbarContentBuilder private var safetyMenu: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            Menu {
                NavigationLink {
                    SafetyVerificationView(peerPublicId: peerPublicId)
                } label: {
                    Label("Safety & verification", systemImage: "checkmark.shield")
                }
                Divider()
                if isBlocked {
                    Button {
                        performUnblock()
                    } label: {
                        Label("Unblock", systemImage: "hand.raised.slash")
                    }
                } else {
                    Button(role: .destructive) {
                        showBlockConfirm = true
                    } label: {
                        Label("Block", systemImage: "hand.raised")
                    }
                }
                Button(role: .destructive) {
                    showReport = true
                } label: {
                    Label("Report", systemImage: "exclamationmark.bubble")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
        }
    }

    private func performBlock() {
        Task {
            do { try await appState.block(peerPublicId) }
            catch { safetyError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription }
        }
    }

    private func performUnblock() {
        Task {
            do { try await appState.unblock(peerPublicId) }
            catch { safetyError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription }
        }
    }

    private var safetyErrorBinding: Binding<Bool> {
        Binding(get: { safetyError != nil }, set: { if !$0 { safetyError = nil } })
    }

    private func content(_ model: ConversationViewModel) -> some View {
        VStack(spacing: 0) {
            messageList(model)
            ConversationComposer(model: model)
        }
        .alert("Couldn't send", isPresented: errorBinding(model)) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    private func messageList(_ model: ConversationViewModel) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: Theme.Spacing.xs) {
                    if model.messages.isEmpty {
                        emptyState
                    }
                    if model.hasOlder {
                        loadEarlierButton(model)
                    }
                    ForEach(model.windowed) { message in
                        MessageBubble(message: message, model: model).id(message.id)
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

    /// Reveals one older page from the on-device cache. With the bottom scroll
    /// anchor the list stays put (no jump) as older messages slot in above.
    private func loadEarlierButton(_ model: ConversationViewModel) -> some View {
        Button { model.loadOlder() } label: {
            Label("Load earlier messages", systemImage: "arrow.up")
                .font(.footnote)
                .padding(.vertical, Theme.Spacing.xs)
        }
        .buttonStyle(.bordered)
        .padding(.bottom, Theme.Spacing.sm)
    }

    private var emptyState: some View {
        VStack(spacing: Theme.Spacing.sm) {
            Image(systemName: "lock.fill").font(.title).foregroundStyle(Theme.Palette.secondaryText)
            Text("Messages are end-to-end encrypted.")
                .font(.footnote).foregroundStyle(Theme.Palette.secondaryText)
        }
        .padding(.top, Theme.Spacing.xl)
    }

    private func errorBinding(_ model: ConversationViewModel) -> Binding<Bool> {
        Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
    }
}

/// A single message bubble, aligned and colored by ownership. Dispatches to
/// image / voice content for media messages, falling back to a text bubble.
private struct MessageBubble: View {
    let message: ChatMessage
    let model: ConversationViewModel

    var body: some View {
        HStack {
            if message.isMine { Spacer(minLength: 40) }
            VStack(alignment: message.isMine ? .trailing : .leading, spacing: 2) {
                bubbleBody
                Text(message.createdAt, style: .time)
                    .font(.caption2)
                    .foregroundStyle(Theme.Palette.secondaryText)
            }
            .contextMenu { deleteActions }
            if !message.isMine { Spacer(minLength: 40) }
        }
    }

    /// Long-press actions: "delete for me" (local) always, plus "delete for
    /// everyone" for my own messages (removed on the peer + my other devices too).
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

    @ViewBuilder private var bubbleBody: some View {
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
            // Stickers render "naked" (no bubble) as a large tinted SF Symbol.
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
