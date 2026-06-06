//
//  VoiceRecorder.swift
//  Gotogo
//
//  A tiny `AVAudioRecorder` wrapper for recording short voice notes as m4a
//  (AAC). Requests microphone permission, records to a temp file, and on stop
//  returns the encoded bytes + measured duration so the conversation can
//  encrypt and send them. UI-facing, `@MainActor @Observable`.
//

import Foundation
import AVFoundation
import Observation

/// Records a single voice note to a temporary m4a file and reports its duration.
@MainActor
@Observable
final class VoiceRecorder {

    /// True while a recording is in progress.
    private(set) var isRecording = false

    private var recorder: AVAudioRecorder?
    private var url: URL?
    private var startedAt: Date?

    /// The captured audio (bytes + duration in ms), or nil.
    struct Recording: Sendable {
        let data: Data
        let durationMs: Int
    }

    /// Requests microphone permission. Returns true if granted.
    func requestPermission() async -> Bool {
        await withCheckedContinuation { cont in
            AVAudioApplication.requestRecordPermission { granted in
                cont.resume(returning: granted)
            }
        }
    }

    /// Begins recording to a fresh temp file. Throws if the session/recorder
    /// can't be configured. No-op if already recording.
    func start() throws {
        guard !isRecording else { return }
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .default)
        try session.setActive(true)

        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("gotogo-voice-\(UUID().uuidString).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44_100,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.medium.rawValue,
        ]
        let rec = try AVAudioRecorder(url: file, settings: settings)
        rec.record()
        recorder = rec
        url = file
        startedAt = Date()
        isRecording = true
    }

    /// Stops recording and returns the encoded bytes + duration. Returns nil if
    /// nothing was recorded or the file can't be read.
    func stop() -> Recording? {
        guard isRecording, let rec = recorder, let file = url else { return nil }
        rec.stop()
        isRecording = false
        let durationMs = Int((startedAt.map { Date().timeIntervalSince($0) } ?? 0) * 1000)
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        defer { recorder = nil; url = nil; startedAt = nil }
        guard let data = try? Data(contentsOf: file) else { return nil }
        try? FileManager.default.removeItem(at: file)
        return Recording(data: data, durationMs: max(0, durationMs))
    }

    /// Cancels and discards an in-progress recording.
    func cancel() {
        recorder?.stop()
        if let file = url { try? FileManager.default.removeItem(at: file) }
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        isRecording = false
        recorder = nil
        url = nil
        startedAt = nil
    }
}
