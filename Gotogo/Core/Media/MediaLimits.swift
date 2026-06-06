//
//  MediaLimits.swift
//  Gotogo
//
//  Size/format limits for outbound media attachments. Centralized so the composer
//  (which gates before upload) and the messaging service (which gates before
//  sealing) agree on the same numbers. Foundation only.
//

import Foundation

/// Hard limits applied to media before it is encrypted/uploaded.
public enum MediaLimits {
    /// Maximum allowed size, in bytes, for a video attachment (25 MB). A video over
    /// this is rejected with a user-facing error and never uploaded.
    public static let maxVideoBytes = 25 * 1024 * 1024
}
