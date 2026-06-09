import Foundation

/// Client-side helpers for sealed (sender-anonymous) messaging (V2-C).
///
/// A sealed message carries no sender at the server, so the server cannot enforce
/// blocking or mutual-contact rules (the access key is the only gate). The client
/// therefore enforces blocking AFTER decrypting the in-ciphertext sender: if the
/// recovered sender is locally blocked, the message is dropped.
public enum SealedSender {
    /// Whether to drop a decrypted sealed message because its sender (recovered
    /// from the ciphertext) is on the local blocklist. Comparison is case-folded.
    public static func shouldDrop(senderAddress: String, blocked: Set<String>) -> Bool {
        let folded = Set(blocked.map { $0.lowercased() })
        return folded.contains(senderAddress.lowercased())
    }
}
