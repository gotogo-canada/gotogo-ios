//
//  MediaReference.swift
//  Gotogo
//
//  The descriptor for an encrypted media attachment, carried INSIDE the E2EE
//  message body. It holds the per-file media key + ciphertext hash so the
//  recipient can download the opaque blob from object storage and decrypt it.
//  The server only ever sees the ciphertext + object id, never this descriptor.
//
import Foundation

/// Describes one encrypted media attachment (image, voice, video).
public struct MediaReference: Codable, Sendable, Equatable {
    public var mediaId: String
    public var key: Data        // MediaCrypto file key (32 bytes)
    public var sha256: Data     // SHA-256 of the ciphertext blob (integrity)
    public var sizeBytes: Int
    public var contentType: String
    public var width: Int?
    public var height: Int?
    /// Optional encrypted thumbnail (for images/video).
    public var thumbMediaId: String?
    public var thumbKey: Data?
    public var thumbSha256: Data?

    public init(mediaId: String, key: Data, sha256: Data, sizeBytes: Int, contentType: String,
                width: Int? = nil, height: Int? = nil,
                thumbMediaId: String? = nil, thumbKey: Data? = nil, thumbSha256: Data? = nil) {
        self.mediaId = mediaId
        self.key = key
        self.sha256 = sha256
        self.sizeBytes = sizeBytes
        self.contentType = contentType
        self.width = width
        self.height = height
        self.thumbMediaId = thumbMediaId
        self.thumbKey = thumbKey
        self.thumbSha256 = thumbSha256
    }
}
