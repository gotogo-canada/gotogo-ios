//
//  ConversationComposer.swift
//  Gotogo
//
//  The chat input bar: a photo/video picker ("+"), a text field, and either a mic
//  button (records an m4a voice note) or a send button when there's text to
//  send. Picked images/videos / recorded audio are handed to the view model, which
//  encrypts them end to end before upload (videos are size-gated at 25 MB).
//

import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

struct ConversationComposer: View {
    @Bindable var model: ConversationViewModel

    @State private var photoItem: PhotosPickerItem?
    @State private var recorder = VoiceRecorder()
    @State private var micDenied = false
    @State private var showStickers = false

    private var hasText: Bool {
        !model.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        HStack(spacing: Theme.Spacing.sm) {
            photoButton
            stickerButton
            TextField("Message", text: $model.draft, axis: .vertical)
                .textFieldStyle(.plain)
                .padding(.horizontal, Theme.Spacing.md)
                .padding(.vertical, Theme.Spacing.sm)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.bubble, style: .continuous))
                .lineLimit(1...5)
            trailingButton
        }
        .padding(Theme.Spacing.md)
        .background(.bar)
        .onChange(of: photoItem) { _, item in Task { await loadPickedItem(item) } }
        .sheet(isPresented: $showStickers) {
            StickerPicker { id in Task { await model.sendSticker(id) } }
        }
        .alert("Microphone access needed", isPresented: $micDenied) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Enable microphone access in Settings to record voice messages.")
        }
    }

    // MARK: Buttons

    private var photoButton: some View {
        PhotosPicker(selection: $photoItem,
                     matching: .any(of: [.images, .videos]),
                     photoLibrary: .shared()) {
            Image(systemName: "plus.circle.fill")
                .font(.system(size: 28))
                .foregroundStyle(model.sending ? Color.gray : Theme.Palette.accent)
        }
        .disabled(model.sending)
    }

    private var stickerButton: some View {
        Button { showStickers = true } label: {
            Image(systemName: "face.smiling")
                .font(.system(size: 26))
                .foregroundStyle(model.sending ? Color.gray : Theme.Palette.accent)
        }
        .disabled(model.sending)
    }

    @ViewBuilder private var trailingButton: some View {
        if hasText {
            Button { Task { await model.send() } } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(model.sending ? Color.gray : Theme.Palette.accent)
            }
            .disabled(model.sending)
        } else {
            micButton
        }
    }

    private var micButton: some View {
        Button(action: toggleRecording) {
            Image(systemName: recorder.isRecording ? "stop.circle.fill" : "mic.circle.fill")
                .font(.system(size: 30))
                .foregroundStyle(recorder.isRecording ? Theme.Palette.destructive
                                 : (model.sending ? Color.gray : Theme.Palette.accent))
        }
        .disabled(model.sending)
    }

    // MARK: Actions

    /// Loads the picked item and routes it: a movie goes to `sendVideo` (size-gated
    /// at 25 MB inside the messaging service, which surfaces "Video too large" if
    /// over), anything else is treated as an image. Both paths encrypt before upload.
    private func loadPickedItem(_ item: PhotosPickerItem?) async {
        guard let item else { return }
        photoItem = nil
        let isVideo = item.supportedContentTypes.contains { $0.conforms(to: .movie) }
        guard let data = try? await item.loadTransferable(type: Data.self) else { return }
        if isVideo {
            await model.sendVideo(data)
        } else {
            await model.sendImage(data)
        }
    }

    private func toggleRecording() {
        if recorder.isRecording {
            guard let recording = recorder.stop() else { return }
            Task { await model.sendVoice(recording.data, durationMs: recording.durationMs) }
            return
        }
        Task {
            guard await recorder.requestPermission() else { micDenied = true; return }
            try? recorder.start()
        }
    }
}
