//
//  StickerViews.swift
//  Gotogo
//
//  SwiftUI rendering for internal stickers: a large tinted SF Symbol for a sticker
//  message in the conversation, and a grid picker over `StickerCatalog.packs`.
//  Everything renders locally from the bundled catalog — no remote provider.
//

import SwiftUI

/// Resolves a `Color` from a sticker's hex tint (e.g. "FF375F"); falls back to
/// the accent color for an unknown / malformed value.
extension Color {
    init(stickerHex hex: String) {
        let cleaned = hex.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        guard cleaned.count == 6, let value = UInt32(cleaned, radix: 16) else {
            self = Theme.Palette.accent
            return
        }
        self.init(.sRGB,
                  red: Double((value >> 16) & 0xFF) / 255.0,
                  green: Double((value >> 8) & 0xFF) / 255.0,
                  blue: Double(value & 0xFF) / 255.0,
                  opacity: 1.0)
    }
}

/// A sticker message in the conversation: a large tinted SF Symbol, resolved from
/// the bundled catalog. Shows a neutral placeholder if the id is unknown.
struct StickerBubble: View {
    let stickerId: String?

    var body: some View {
        if let id = stickerId, let sticker = StickerCatalog.sticker(id: id) {
            Image(systemName: sticker.symbol)
                .font(.system(size: 72))
                .foregroundStyle(Color(stickerHex: sticker.tintHex))
                .padding(Theme.Spacing.xs)
        } else {
            Image(systemName: "questionmark.square.dashed")
                .font(.system(size: 72))
                .foregroundStyle(Theme.Palette.secondaryText)
                .padding(Theme.Spacing.xs)
        }
    }
}

/// A grid picker over every pack in `StickerCatalog`. Tapping a sticker invokes
/// `onPick` with its catalog id and dismisses the sheet.
struct StickerPicker: View {
    let onPick: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    private let columns = Array(repeating: GridItem(.flexible(), spacing: Theme.Spacing.md),
                                count: 4)

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: Theme.Spacing.lg) {
                    ForEach(StickerCatalog.packs) { pack in
                        packSection(pack)
                    }
                }
                .padding(Theme.Spacing.md)
            }
            .navigationTitle("Stickers")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func packSection(_ pack: StickerPack) -> some View {
        VStack(alignment: .leading, spacing: Theme.Spacing.sm) {
            Text(pack.name)
                .font(.headline)
                .foregroundStyle(Theme.Palette.secondaryText)
            LazyVGrid(columns: columns, spacing: Theme.Spacing.md) {
                ForEach(pack.stickers) { sticker in
                    Button {
                        onPick(sticker.id)
                        dismiss()
                    } label: {
                        Image(systemName: sticker.symbol)
                            .font(.system(size: 36))
                            .foregroundStyle(Color(stickerHex: sticker.tintHex))
                            .frame(maxWidth: .infinity, minHeight: 56)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(sticker.id)
                }
            }
        }
    }
}
