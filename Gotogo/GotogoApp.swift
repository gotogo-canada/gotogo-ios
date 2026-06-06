//
//  GotogoApp.swift
//  Gotogo
//
//  App entry point. Owns the single `AppState` and injects it into the view
//  hierarchy, which routes between registration and the main tabbed app. Also owns
//  the `ScreenshotMonitor` (for the on-sensitive-screen screenshot warning) and
//  observes `scenePhase` so `AppRootView` can drop a privacy cover over the UI when
//  the app leaves the foreground (hiding chats from the app-switcher snapshot).
//

import SwiftUI

@main
struct GotogoApp: App {
    @State private var appState = AppState()
    @State private var screenshotMonitor = ScreenshotMonitor()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            AppRootView(scenePhase: scenePhase)
                .environment(appState)
                .environment(screenshotMonitor)
        }
    }
}
