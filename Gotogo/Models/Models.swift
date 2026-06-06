//
//  Models.swift
//  Gotogo
//
//  App-level domain models: the persisted session, contacts, chat messages and
//  derived conversations. Pure Foundation so services/tests stay UI-free.
//

import Foundation

/// The authenticated session persisted to the Keychain after register/recover.
public struct Session: Codable, Sendable, Equatable {
    /// Short human-shareable id (e.g. "91JLGNSJ"). This is what users type to add each other.
    public var publicId: String
    /// Server account UUID.
    public var accountId: String
    /// This device's UUID; used as `toDeviceId` is the *peer's* device, but kept for self.
    public var deviceId: String
    /// Bearer token for `Authorization`.
    public var token: String
    /// Display name chosen for this device.
    public var deviceName: String

    public init(publicId: String, accountId: String, deviceId: String, token: String, deviceName: String) {
        self.publicId = publicId
        self.accountId = accountId
        self.deviceId = deviceId
        self.token = token
        self.deviceName = deviceName
    }
}

/// Direction of a contact relationship as reported by the server.
public enum ContactDirection: String, Codable, Sendable, Equatable {
    case mutual
    case outgoing
    case incoming
}

/// State of a contact relationship (server-defined string, kept opaque-ish).
public enum ContactState: String, Codable, Sendable, Equatable {
    case pending
    case accepted
    case blocked
    case unknown

    public init(from raw: String) {
        self = ContactState(rawValue: raw) ?? .unknown
    }
}

/// A contact entry derived from `GET /v1/contacts`.
public struct Contact: Codable, Sendable, Equatable, Identifiable {
    public var publicId: String
    public var state: ContactState
    public var direction: ContactDirection

    public var id: String { publicId }

    /// True once both sides accepted: messages can flow.
    public var isMutual: Bool { direction == .mutual }
    /// True for an incoming request awaiting our Accept.
    public var isIncomingRequest: Bool { direction == .incoming }

    public init(publicId: String, state: ContactState, direction: ContactDirection) {
        self.publicId = publicId
        self.state = state
        self.direction = direction
    }
}

/// A single chat message, after decryption (or as composed locally).
public struct ChatMessage: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    /// The public id of the other party in the conversation this belongs to.
    public var peerPublicId: String
    /// True if this device sent it.
    public var isMine: Bool
    /// Decrypted UTF-8 body for text, or the caption for an image (may be empty
    /// for a media-only message). A placeholder string if decryption failed.
    public var body: String
    public var createdAt: Date
    /// False when the ciphertext could not be opened.
    public var decrypted: Bool
    /// Attachment descriptor for image/voice messages (nil for plain text).
    /// Carries the per-file media key + ciphertext hash so the recipient can
    /// download and decrypt the opaque blob. Persisted in the conversation cache.
    public var media: MediaReference?
    /// `"image"`, `"video"`, `"voice"`, or `"sticker"` when this message is not
    /// plain text; nil for text.
    public var mediaKind: String?
    /// Voice-note duration in milliseconds, when known.
    public var durationMs: Int?
    /// Catalog sticker id (e.g. "reactions/heart") when `mediaKind == "sticker"`.
    /// Resolved for display via `StickerCatalog.sticker(id:)`.
    public var stickerId: String?
    /// For a GROUP message, the public id of the human who sent it (the
    /// conversation itself is keyed by the group id in `peerPublicId`). Nil for a
    /// 1:1 message or one I sent. Lets the group UI show per-sender name/avatar.
    public var senderPublicId: String?
    /// The SENDER's stable, cross-device message id (a UUID minted at send time,
    /// carried inside the E2EE payload). The same value lands on the sender's copy,
    /// the recipient's copy, and the sender's other devices, so "delete for
    /// everyone" can target one specific message everywhere. Nil for legacy or
    /// server-stamped messages that predate it.
    public var clientId: String?

    public init(id: String,
                peerPublicId: String,
                isMine: Bool,
                body: String,
                createdAt: Date,
                decrypted: Bool = true,
                media: MediaReference? = nil,
                mediaKind: String? = nil,
                durationMs: Int? = nil,
                stickerId: String? = nil,
                senderPublicId: String? = nil,
                clientId: String? = nil) {
        self.id = id
        self.peerPublicId = peerPublicId
        self.isMine = isMine
        self.body = body
        self.createdAt = createdAt
        self.decrypted = decrypted
        self.media = media
        self.mediaKind = mediaKind
        self.durationMs = durationMs
        self.stickerId = stickerId
        self.senderPublicId = senderPublicId
        self.clientId = clientId
    }
}

/// A conversation thread with one peer: its messages plus a convenience preview.
public struct Conversation: Codable, Sendable, Equatable, Identifiable {
    public var peerPublicId: String
    public var messages: [ChatMessage]

    public var id: String { peerPublicId }

    /// Most recent message, if any.
    public var lastMessage: ChatMessage? {
        messages.max { $0.createdAt < $1.createdAt }
    }

    public init(peerPublicId: String, messages: [ChatMessage] = []) {
        self.peerPublicId = peerPublicId
        self.messages = messages
    }
}

/// Encrypted-at-rest vault payload sealed during registration and restored on recover.
public struct VaultPayload: Codable, Sendable, Equatable {
    public var identity: IdentityKeyMaterial
    public var store: PreKeyStore

    public init(identity: IdentityKeyMaterial, store: PreKeyStore) {
        self.identity = identity
        self.store = store
    }
}
