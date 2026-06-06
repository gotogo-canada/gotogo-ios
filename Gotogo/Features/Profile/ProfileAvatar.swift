//
//  ProfileAvatar.swift
//  Gotogo
//
//  A reusable circular avatar: shows a contact's decrypted profile photo when
//  available, otherwise the accent-tinted initials fallback used throughout the
//  app. Triggers a lazy profile fetch via the shared `ProfileStore` on appear, so
//  rows light up with real names/photos without each call site duplicating logic.
//

import SwiftUI

/// Circular avatar for a peer: profile photo if known, else initials of `fallback`.
struct ProfileAvatar: View {
    let publicId: String
    /// Text whose first two characters seed the initials fallback (usually the id).
    let fallback: String
    var size: CGFloat = 48

    @Environment(AppState.self) private var appState

    var body: some View {
        Group {
            if let image = appState.profileStore.profile(for: publicId)?.image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
            } else {
                Circle()
                    .fill(Theme.Palette.accent.opacity(0.15))
                    .overlay(
                        Text(String(fallback.prefix(2)).uppercased())
                            .font(.system(size: size * 0.36, weight: .semibold))
                            .foregroundStyle(Theme.Palette.accent)
                    )
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
        .task(id: publicId) { await appState.profileStore.load(publicId) }
    }
}

/// The display name for a peer (decrypted profile name) with a public-ID fallback.
/// When falling back, renders monospaced like the rest of the app's IDs.
struct ProfileName: View {
    let publicId: String
    var font: Font = .body

    @Environment(AppState.self) private var appState

    private var name: String? {
        let n = appState.profileStore.profile(for: publicId)?.displayName
        return (n?.isEmpty == false) ? n : nil
    }

    var body: some View {
        if let name {
            Text(name).font(font.weight(.semibold))
        } else {
            Text(publicId).font(font.monospaced().weight(.semibold))
        }
        // Avatar drives the fetch; this just reflects the store once loaded.
    }
}
