//
//  StickerCatalog.swift
//  Gotogo
//
//  INTERNAL, bundle-signed sticker packs (plan section 6: "packs signés,
//  vérifiés, sans exécution de code distant"). Stickers are rendered locally
//  from SF Symbols — no third-party GIF/sticker provider is ever contacted, so
//  the user's identity/IP never leaks to Giphy/Tenor. A sticker message carries
//  only its pack id + sticker id (inside the E2EE payload); the receiver renders
//  it from this same bundled catalog.
//
import Foundation

/// One sticker: an SF Symbol name + a hex tint, rendered locally.
public struct Sticker: Codable, Sendable, Equatable, Identifiable {
    public var id: String          // stable id, e.g. "reactions/heart"
    public var symbol: String      // SF Symbol name
    public var tintHex: String     // e.g. "FF375F"
    public init(id: String, symbol: String, tintHex: String) {
        self.id = id; self.symbol = symbol; self.tintHex = tintHex
    }
}

/// A named pack of stickers.
public struct StickerPack: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var stickers: [Sticker]
    public init(id: String, name: String, stickers: [Sticker]) {
        self.id = id; self.name = name; self.stickers = stickers
    }
}

/// The built-in catalog. Adding a remote pack would require a signed manifest;
/// none is loaded at runtime — everything ships in the app bundle.
public enum StickerCatalog {

    public static let packs: [StickerPack] = [
        StickerPack(id: "reactions", name: "Reactions", stickers: [
            s("reactions/heart", "heart.fill", "FF375F"),
            s("reactions/thumbsup", "hand.thumbsup.fill", "0A84FF"),
            s("reactions/laugh", "face.smiling.fill", "FFD60A"),
            s("reactions/fire", "flame.fill", "FF9F0A"),
            s("reactions/party", "party.popper.fill", "BF5AF2"),
            s("reactions/clap", "hands.clap.fill", "FF9500"),
            s("reactions/cry", "drop.fill", "64D2FF"),
            s("reactions/star", "star.fill", "FFD60A"),
        ]),
        StickerPack(id: "secure", name: "Secure", stickers: [
            s("secure/lock", "lock.fill", "30D158"),
            s("secure/shield", "checkmark.shield.fill", "30D158"),
            s("secure/key", "key.fill", "FFD60A"),
            s("secure/quantum", "atom", "BF5AF2"),
            s("secure/sat", "antenna.radiowaves.left.and.right", "0A84FF"),
            s("secure/eyeslash", "eye.slash.fill", "8E8E93"),
        ]),
        StickerPack(id: "weather", name: "Weather", stickers: [
            s("weather/sun", "sun.max.fill", "FF9F0A"),
            s("weather/moon", "moon.stars.fill", "5E5CE6"),
            s("weather/rain", "cloud.rain.fill", "64D2FF"),
            s("weather/snow", "snowflake", "64D2FF"),
            s("weather/bolt", "bolt.fill", "FFD60A"),
        ]),
    ]

    /// Looks up a sticker by its catalog id (e.g. "reactions/heart").
    public static func sticker(id: String) -> Sticker? {
        for pack in packs {
            if let found = pack.stickers.first(where: { $0.id == id }) { return found }
        }
        return nil
    }

    private static func s(_ id: String, _ symbol: String, _ tint: String) -> Sticker {
        Sticker(id: id, symbol: symbol, tintHex: tint)
    }
}
