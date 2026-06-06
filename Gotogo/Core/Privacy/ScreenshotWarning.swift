//
//  ScreenshotWarning.swift
//  Gotogo
//
//  Detects when the user takes a screenshot while a sensitive screen (the recovery
//  phrase, or a conversation) is on top, and surfaces a transient warning so they
//  know a private message may have been captured. iOS gives no way to *block* a
//  user screenshot, so this is an advisory: observe
//  `UIApplication.userDidTakeScreenshotNotification` and flash a banner.
//

import SwiftUI
import UIKit

/// A `.sensitiveScreen()` modifier registers/unregisters interest in screenshots
/// while it is on screen; when one is taken, the shared warning banner appears.
@MainActor
@Observable
final class ScreenshotMonitor {
    /// Whether a transient "screenshots can expose private messages" banner is up.
    private(set) var showWarning = false

    /// Number of currently-visible sensitive screens. We only warn when > 0 so a
    /// screenshot on a non-sensitive screen (e.g. the contact list) stays silent.
    private var sensitiveCount = 0
    // nonisolated so the (nonisolated) deinit can remove the observer; it is only
    // written once in init and read once in deinit, never concurrently.
    nonisolated(unsafe) private var observer: NSObjectProtocol?
    private var dismissTask: Task<Void, Never>?

    init() {
        observer = NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil, queue: .main) { [weak self] _ in
                // Hop to the main actor; the closure is delivered on the main queue.
                MainActor.assumeIsolated { self?.screenshotTaken() }
            }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    /// Marks that a sensitive screen appeared (call from `.onAppear`).
    func beginSensitive() { sensitiveCount += 1 }

    /// Marks that a sensitive screen disappeared (call from `.onDisappear`).
    func endSensitive() { sensitiveCount = max(0, sensitiveCount - 1) }

    private func screenshotTaken() {
        guard sensitiveCount > 0 else { return }
        showWarning = true
        dismissTask?.cancel()
        dismissTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            self?.showWarning = false
        }
    }
}

extension View {
    /// Marks this view as a sensitive screen: while it is visible, taking a
    /// screenshot surfaces the shared warning banner from `monitor`.
    func sensitiveScreen(_ monitor: ScreenshotMonitor) -> some View {
        self
            .onAppear { monitor.beginSensitive() }
            .onDisappear { monitor.endSensitive() }
    }
}
