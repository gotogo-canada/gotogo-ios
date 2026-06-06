//
//  Theme.swift
//  Gotogo
//
//  A small Messenger-like design system: palette, spacing, corner radii and a
//  couple of reusable view modifiers so styles aren't copy-pasted across screens.
//

import SwiftUI

/// Centralized colors, spacing, and radii for the app's look and feel.
enum Theme {

    // MARK: Colors

    enum Palette {
        /// Brand accent / primary action color (Messenger-ish blue).
        static let accent = Color(red: 0.0, green: 0.48, blue: 1.0)
        /// Bubble color for outgoing messages.
        static let outgoingBubble = Color(red: 0.0, green: 0.48, blue: 1.0)
        /// Text color on outgoing bubbles.
        static let outgoingText = Color.white
        /// Bubble color for incoming messages (adapts to light/dark).
        static let incomingBubble = Color(.secondarySystemBackground)
        /// Text color on incoming bubbles.
        static let incomingText = Color.primary
        /// Subtle background for grouped surfaces.
        static let groupedBackground = Color(.systemGroupedBackground)
        /// Secondary/caption text.
        static let secondaryText = Color.secondary
        /// Destructive action color.
        static let destructive = Color.red
        /// Success / connected indicator.
        static let success = Color.green
    }

    // MARK: Spacing

    enum Spacing {
        static let xs: CGFloat = 4
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 16
        static let xl: CGFloat = 24
    }

    // MARK: Radii

    enum Radius {
        static let bubble: CGFloat = 18
        static let card: CGFloat = 12
        static let chip: CGFloat = 8
    }
}

// MARK: - Reusable modifiers

extension View {
    /// Styles a view as a primary call-to-action button.
    func primaryButtonStyle(enabled: Bool = true) -> some View {
        self
            .font(.headline)
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, Theme.Spacing.md)
            .background(enabled ? Theme.Palette.accent : Color.gray.opacity(0.4))
            .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
    }

    /// Wraps a view in a rounded card surface.
    func cardStyle() -> some View {
        self
            .padding(Theme.Spacing.lg)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
    }
}

/// A reusable monospaced "code chip" used to display the public ID prominently.
struct CodeChip: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(.title3, design: .monospaced).weight(.semibold))
            .padding(.horizontal, Theme.Spacing.md)
            .padding(.vertical, Theme.Spacing.sm)
            .background(Theme.Palette.accent.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.chip, style: .continuous))
            .foregroundStyle(Theme.Palette.accent)
            .textSelection(.enabled)
    }
}
