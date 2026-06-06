//
//  PrivacyCoverView.swift
//  Gotogo
//
//  The opaque cover shown over the whole UI whenever the scene leaves the
//  foreground (`.inactive` / `.background`). It is what the OS captures for the
//  multitasking / app-switcher snapshot, so that snapshot reveals only the app
//  logo on a solid background — never the chat list or an open conversation.
//

import SwiftUI

/// A full-screen branded cover (app logo on a solid background) used to mask the
/// UI in the app-switcher snapshot.
struct PrivacyCoverView: View {
    var body: some View {
        ZStack {
            Theme.Palette.accent.ignoresSafeArea()
            VStack(spacing: Theme.Spacing.md) {
                Image(systemName: "lock.circle.fill")
                    .font(.system(size: 72))
                    .foregroundStyle(.white)
                Text("Gotogo")
                    .font(.largeTitle.bold())
                    .foregroundStyle(.white)
            }
        }
        .transition(.opacity)
    }
}
