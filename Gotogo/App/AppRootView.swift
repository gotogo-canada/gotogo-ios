//
//  AppRootView.swift
//  Gotogo
//
//  Top-level router: shows the registration flow when there is no session, and
//  the main tabbed app once registered. Also applies app-wide privacy: a branded
//  cover masks the UI whenever the scene is not active (so the app-switcher
//  snapshot reveals no chats), and a transient banner warns when a screenshot is
//  taken on a sensitive screen.
//

import SwiftUI

/// Routes between the not-registered (Register) and registered (MainTab) states.
struct AppRootView: View {
    /// The current scene phase, threaded down from `GotogoApp` so we can mask the
    /// UI when the app is inactive/backgrounded.
    let scenePhase: ScenePhase

    @Environment(AppState.self) private var appState
    @Environment(ScreenshotMonitor.self) private var screenshotMonitor

    var body: some View {
        ZStack {
            Group {
                if appState.isRegistered {
                    MainTabView()
                } else {
                    RegisterView()
                }
            }
            .animation(.default, value: appState.isRegistered)

            // App-switcher privacy: cover the whole UI the moment the scene leaves
            // the foreground, so the multitasking snapshot shows only the logo.
            if scenePhase != .active {
                PrivacyCoverView()
                    .transition(.opacity)
                    .zIndex(1)
            }
        }
        .animation(.easeInOut(duration: 0.15), value: scenePhase)
        .overlay(alignment: .top) { screenshotBanner }
    }

    /// A transient banner shown when a screenshot is taken on a sensitive screen.
    @ViewBuilder private var screenshotBanner: some View {
        if screenshotMonitor.showWarning {
            Label("Screenshots can expose private messages", systemImage: "exclamationmark.triangle.fill")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.white)
                .padding(.horizontal, Theme.Spacing.lg)
                .padding(.vertical, Theme.Spacing.md)
                .background(Theme.Palette.destructive, in: Capsule())
                .padding(.top, Theme.Spacing.sm)
                .shadow(radius: 6, y: 2)
                .transition(.move(edge: .top).combined(with: .opacity))
                .zIndex(2)
                .animation(.spring(duration: 0.3), value: screenshotMonitor.showWarning)
                .accessibilityAddTraits(.isStaticText)
        }
    }
}

/// The main app shell once registered: Chats, Contacts, and Me.
struct MainTabView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        TabView {
            ChatListView()
                .tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right.fill") }

            GroupListView()
                .tabItem { Label("Groups", systemImage: "person.3.fill") }

            ContactsView()
                .tabItem { Label("Contacts", systemImage: "person.2.fill") }

            MeView()
                .tabItem { Label("Me", systemImage: "person.crop.circle.fill") }
        }
        .tint(Theme.Palette.accent)
        .task {
            // Kick off an initial sync and open the realtime stream.
            await appState.startMessagingFeed()
        }
    }
}
