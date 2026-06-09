//
//  SealedSenderSettings.swift
//  Gotogo
//
//  Persists the user's sealed-sender preference. Sealed sender (V2-C) hides the
//  sender's identity from the recipient's server. It's on by default (best
//  privacy), but the user can turn it off — which both stops publishing their
//  access key (so they receive normally) and stops sending sealed.
//

import Foundation

public final class SealedSenderSettings: @unchecked Sendable {

    private let defaults: UserDefaults
    private let key = "gotogo.sealedSender.enabled.v1"

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        // Default ON when never set.
        if defaults.object(forKey: key) == nil {
            defaults.set(true, forKey: key)
        }
    }

    public var enabled: Bool {
        get { defaults.bool(forKey: key) }
        set { defaults.set(newValue, forKey: key) }
    }
}
