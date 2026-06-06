//
//  VoiceNotePlayer.swift
//  Gotogo
//
//  Plays a single decrypted voice note from in-memory m4a bytes via
//  `AVAudioPlayer`. Tracks play/stop so the bubble can toggle its icon.
//  `@MainActor @Observable`.
//

import Foundation
import AVFoundation
import Observation

/// Plays decrypted voice-note audio held entirely in memory.
@MainActor
@Observable
final class VoiceNotePlayer: NSObject, AVAudioPlayerDelegate {

    /// True while audio is playing.
    private(set) var isPlaying = false

    private var player: AVAudioPlayer?

    /// Starts (or restarts) playback of the given m4a data. Returns false if the
    /// data can't be decoded into a player.
    @discardableResult
    func play(_ data: Data) -> Bool {
        stop()
        do {
            try AVAudioSession.sharedInstance().setCategory(.playback, mode: .default)
            try AVAudioSession.sharedInstance().setActive(true)
            let p = try AVAudioPlayer(data: data)
            p.delegate = self
            p.play()
            player = p
            isPlaying = true
            return true
        } catch {
            isPlaying = false
            return false
        }
    }

    /// Stops playback if any.
    func stop() {
        player?.stop()
        player = nil
        isPlaying = false
    }

    nonisolated func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        Task { @MainActor in self.isPlaying = false; self.player = nil }
    }
}
