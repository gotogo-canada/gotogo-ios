//
//  Clipboard.swift
//  Gotogo
//
//  Centralizes copying SECRETS (recovery phrase, identity safety number) to the
//  pasteboard. Secrets are only ever placed on the clipboard from an explicit user
//  tap, and never allowed to linger: the item is marked `localOnly` (no Handoff /
//  Universal Clipboard to other devices) and given a short expiration so the OS
//  clears it automatically. Routing every secret-copy through here keeps that
//  policy in one place instead of scattered `UIPasteboard.general.string = …`.
//

import UIKit
import UniformTypeIdentifiers

/// Secret-aware pasteboard helper.
public enum Clipboard {

    /// How long a copied secret may live on the pasteboard before the OS clears it.
    public static let secretExpiry: TimeInterval = 90

    /// Copies a SECRET (recovery phrase, safety number) to the general pasteboard
    /// with an automatic expiration and `localOnly` set, so it never syncs to other
    /// devices via Universal Clipboard and is cleared after `secretExpiry` seconds.
    /// Call this ONLY in direct response to a user tap on a copy control.
    public static func copySecret(_ value: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: value]],
            options: [
                .expirationDate: Date().addingTimeInterval(secretExpiry),
                .localOnly: true,
            ])
    }
}
