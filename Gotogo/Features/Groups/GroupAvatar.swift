//
//  GroupAvatar.swift
//  Gotogo
//
//  A group's avatar: its decrypted photo when the admin has set one (downloaded +
//  decrypted via the GroupService, the per-file key having ridden inside the E2EE
//  `group_meta` control), else the group's initials on a tinted circle. An optional
//  `override` image lets the edit screen preview a freshly picked photo before save.
//

import SwiftUI

struct GroupAvatar: View {
    let name: String
    let photoRef: MediaReference?
    var size: CGFloat = 40
    var override: UIImage? = nil

    @Environment(AppState.self) private var appState
    @State private var image: UIImage?

    var body: some View {
        ZStack {
            if let img = override ?? image {
                Image(uiImage: img).resizable().scaledToFill()
            } else {
                Circle().fill(Theme.Palette.accent.opacity(0.15))
                Image(systemName: "person.3.fill")
                    .font(.system(size: size * 0.42))
                    .foregroundStyle(Theme.Palette.accent)
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
        .accessibilityLabel(Text(name))
        .task(id: photoRef) { await load() }
    }

    private func load() async {
        guard override == nil else { return }
        guard let ref = photoRef else { image = nil; return }
        if let data = await appState.groupService.loadThumbnail(ref), let img = UIImage(data: data) {
            image = img
        }
    }
}
