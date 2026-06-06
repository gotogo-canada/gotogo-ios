//
//  MediaBubbles.swift
//  Gotogo
//
//  Bubble content for media messages: an image thumbnail (download + decrypt,
//  tap to view full size) and a voice note (download + decrypt, tap to play).
//  Each downloads through the conversation view model's MediaService, which
//  verifies the ciphertext hash and decrypts before any bytes are shown.
//

import SwiftUI
import AVKit

/// Anything that can fetch + decrypt a message's media blob for display. Both the
/// 1:1 `ConversationViewModel` and the `GroupConversationViewModel` conform, so the
/// media bubbles below render identically in direct and group chats.
@MainActor
protocol MediaLoading {
    /// Decrypted thumbnail bytes (falls back to the full blob), or nil on failure.
    func loadThumbnail(_ ref: MediaReference) async -> Data?
    /// Decrypted full media bytes (image/video/audio), or nil on failure.
    func loadFull(_ ref: MediaReference) async -> Data?
}

/// An image message: shows a decrypted thumbnail; tapping opens the full image.
struct ImageMessageBubble: View {
    let message: ChatMessage
    let model: any MediaLoading

    @State private var thumbnail: UIImage?
    @State private var loading = true
    @State private var showFull = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.xs) {
            thumbnailView
                .frame(width: 220, height: 220)
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
                .contentShape(Rectangle())
                .onTapGesture { if thumbnail != nil { showFull = true } }
            if !message.body.isEmpty {
                Text(message.body)
                    .font(.subheadline)
                    .foregroundStyle(message.isMine ? Theme.Palette.outgoingText : Theme.Palette.incomingText)
            }
        }
        .task(id: message.id) { await load() }
        .sheet(isPresented: $showFull) {
            if let ref = message.media { FullImageView(reference: ref, model: model) }
        }
    }

    @ViewBuilder private var thumbnailView: some View {
        if let thumbnail {
            Image(uiImage: thumbnail).resizable().scaledToFill()
        } else {
            ZStack {
                Color(.secondarySystemBackground)
                if loading { ProgressView() }
                else { Image(systemName: "photo").font(.largeTitle).foregroundStyle(Theme.Palette.secondaryText) }
            }
        }
    }

    private func load() async {
        guard thumbnail == nil, let ref = message.media else { loading = false; return }
        loading = true
        let data = await model.loadThumbnail(ref)
        if let data, let image = UIImage(data: data) { thumbnail = image }
        loading = false
    }
}

/// A voice message: a play/stop button that downloads + decrypts then plays.
struct VoiceMessageBubble: View {
    let message: ChatMessage
    let model: any MediaLoading

    @State private var player = VoiceNotePlayer()
    @State private var loading = false

    private var tint: Color { message.isMine ? Theme.Palette.outgoingText : Theme.Palette.accent }

    var body: some View {
        HStack(spacing: Theme.Spacing.sm) {
            Button(action: toggle) {
                if loading {
                    ProgressView().tint(tint)
                } else {
                    Image(systemName: player.isPlaying ? "stop.fill" : "play.fill")
                        .font(.title3)
                        .foregroundStyle(tint)
                }
            }
            .disabled(loading)
            Image(systemName: "waveform")
                .foregroundStyle(tint.opacity(0.8))
            Text(durationLabel)
                .font(.caption.monospacedDigit())
                .foregroundStyle(message.isMine ? Theme.Palette.outgoingText : Theme.Palette.secondaryText)
        }
        .padding(.vertical, Theme.Spacing.xs)
        .frame(minWidth: 120)
    }

    private var durationLabel: String {
        let secs = max(0, (message.durationMs ?? 0)) / 1000
        return String(format: "%d:%02d", secs / 60, secs % 60)
    }

    private func toggle() {
        if player.isPlaying { player.stop(); return }
        guard let ref = message.media else { return }
        loading = true
        Task {
            let data = await model.loadFull(ref)
            loading = false
            if let data { player.play(data) }
        }
    }
}

/// A video message: a placeholder (thumbnail if present) with a play glyph and the
/// file size; tapping downloads + decrypts to a temp file and plays it full screen.
struct VideoMessageBubble: View {
    let message: ChatMessage
    let model: any MediaLoading

    @State private var thumbnail: UIImage?
    @State private var showPlayer = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.xs) {
            ZStack {
                if let thumbnail {
                    Image(uiImage: thumbnail).resizable().scaledToFill()
                } else {
                    Color.black.opacity(0.85)
                }
                // Play glyph + size badge.
                Image(systemName: "play.circle.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(.white.opacity(0.95))
                    .shadow(radius: 4)
                if let label = sizeLabel {
                    Text(label)
                        .font(.caption2.weight(.semibold).monospacedDigit())
                        .foregroundStyle(.white)
                        .padding(.horizontal, Theme.Spacing.sm)
                        .padding(.vertical, 2)
                        .background(.black.opacity(0.55), in: Capsule())
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomTrailing)
                        .padding(Theme.Spacing.sm)
                }
            }
            .frame(width: 220, height: 220)
            .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
            .contentShape(Rectangle())
            .onTapGesture { showPlayer = true }

            if !message.body.isEmpty {
                Text(message.body)
                    .font(.subheadline)
                    .foregroundStyle(message.isMine ? Theme.Palette.outgoingText : Theme.Palette.incomingText)
            }
        }
        .task(id: message.id) { await loadThumbnail() }
        .sheet(isPresented: $showPlayer) {
            if let ref = message.media { FullVideoView(reference: ref, model: model) }
        }
    }

    /// Human-readable size of the original video, from the `MediaReference`.
    private var sizeLabel: String? {
        guard let bytes = message.media?.sizeBytes, bytes > 0 else { return nil }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private func loadThumbnail() async {
        guard thumbnail == nil, let ref = message.media, ref.thumbMediaId != nil else { return }
        if let data = await model.loadThumbnail(ref), let image = UIImage(data: data) {
            thumbnail = image
        }
    }
}

/// A full-screen player for a video attachment: downloads + decrypts the blob to a
/// temporary `.mp4` on open, then plays it with the system player. The temp file is
/// removed when the view goes away.
struct FullVideoView: View {
    let reference: MediaReference
    let model: any MediaLoading

    @Environment(\.dismiss) private var dismiss
    @State private var player: AVPlayer?
    @State private var tempURL: URL?
    @State private var failed = false

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                if let player {
                    VideoPlayer(player: player)
                        .ignoresSafeArea(edges: .bottom)
                } else if failed {
                    Label("Couldn't load video", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.white)
                } else {
                    ProgressView().tint(.white)
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
            .task { await prepare() }
            .onDisappear {
                player?.pause()
                if let tempURL { try? FileManager.default.removeItem(at: tempURL) }
            }
        }
    }

    private func prepare() async {
        guard player == nil, let data = await model.loadFull(reference) else { failed = true; return }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-video-\(UUID().uuidString).mp4")
        do {
            try data.write(to: url, options: .completeFileProtection)
            tempURL = url
            let p = AVPlayer(url: url)
            player = p
            p.play()
        } catch {
            failed = true
        }
    }
}

/// A full-size viewer for an image attachment, downloaded + decrypted on open.
struct FullImageView: View {
    let reference: MediaReference
    let model: any MediaLoading

    @Environment(\.dismiss) private var dismiss
    @State private var image: UIImage?

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                if let image {
                    Image(uiImage: image).resizable().scaledToFit()
                } else {
                    ProgressView().tint(.white)
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                if let data = await model.loadFull(reference) { image = UIImage(data: data) }
            }
        }
    }
}
