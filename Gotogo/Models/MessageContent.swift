//
//  MessageContent.swift
//  Gotogo
//
//  The content layer that lives INSIDE the E2EE plaintext. Instead of
//  ratchet-encrypting raw UTF-8 text, the app JSON-encodes a `MessageContent`
//  and encrypts THAT, so text and media share the same secure channel. The
//  server only ever sees the ratchet ciphertext; the `MediaReference` (and the
//  per-file media key it carries) never leaves the encrypted plaintext.
//

import Foundation

/// The decrypted payload of a message: a small tagged union over text + media,
/// plus the group-messaging control/transport types that ride the pairwise
/// Double-Ratchet channel (so they are pairwise-E2EE and fan out per device).
///
/// 1:1 content: `"text"` carries `text`; `"image"` carries `media` (+ optional
/// `text` caption); `"video"` carries `media` (+ optional `text` caption);
/// `"voice"` carries `media` and `durationMs`; `"sticker"` carries `stickerId`.
///
/// Group control (Signal Sender Keys, carried over the pairwise channel):
/// `"group_setup"` carries `groupId` + `groupKey` + `name` + `senderKey`
/// (bootstraps a member with the group key/name and the sender's Sender Key);
/// `"group_msg"` carries `groupId` + `groupMessage` (a Sender-Key-encrypted group
/// message whose plaintext is itself a JSON `MessageContent` text/sticker/image);
/// `"group_rekey"` carries `groupId` (asks recipients to rotate + redistribute
/// their Sender Key on a membership change).
public struct MessageContent: Codable, Sendable, Equatable {
    /// `"text"`, `"image"`, `"video"`, `"voice"`, `"sticker"`, or one of the group
    /// control types `"group_setup"` / `"group_msg"` / `"group_rekey"`.
    public var type: String
    /// Body text for a text message, or the caption for an image/video.
    public var text: String?
    /// Encrypted-media descriptor for `"image"` / `"video"` / `"voice"`.
    public var media: MediaReference?
    /// Voice-note duration in milliseconds, for `"voice"`.
    public var durationMs: Int?
    /// Catalog sticker id (e.g. "reactions/heart") for a `"sticker"` message.
    /// Carried inside the E2EE payload; the receiver renders it from the bundled
    /// `StickerCatalog` (no remote sticker provider is ever contacted).
    public var stickerId: String?

    // MARK: Group control fields (present only on the `"group_*"` types)

    /// The backend group id this control/transport message targets.
    public var groupId: String?
    /// The random 32-byte group key (seals the group name). Present on `"group_setup"`.
    public var groupKey: Data?
    /// The plaintext group name. Present on `"group_setup"`.
    public var name: String?
    /// The sender's Sender-Key distribution (chain key + iteration + signing pub
    /// key). Present on `"group_setup"`; the receiver stores it as that sender's
    /// `SenderKeyState` to decrypt their future `"group_msg"`s.
    public var senderKey: SenderKeyDistribution?
    /// A Sender-Key-encrypted group message. Present on `"group_msg"`; its
    /// plaintext is a JSON-encoded inner `MessageContent` (text/sticker/image).
    public var groupMessage: GroupMessage?
    /// The group's member roster (public ids) at send time. Carried on
    /// `"group_setup"` so a freshly bootstrapped member learns EVERY other member
    /// it must distribute its own Sender Key to — this is what makes the N²
    /// convergence reach members it only hears about transitively.
    public var members: [String]?

    /// Self-device sync marker. When a send is mirrored to the SENDER's own other
    /// devices, the mirrored copy carries the SAME inner content but with `syncPeer`
    /// set to the RECIPIENT's public id. On ingest, a message arriving from my own
    /// account is appended to `conversation(with: syncPeer)` as `isMine == true`,
    /// keeping every device's history consistent. Nil on ordinary peer messages.
    public var syncPeer: String?

    /// On a SEALED (sender-anonymous) message the sender's address travels here,
    /// inside the E2EE content, because the recipient's server stores no sender
    /// (V2-C). The recipient routes the conversation by this and applies
    /// client-side blocking against it.
    public var sealedSender: String?

    // MARK: MLS group control fields (RFC 9420; the live group transport)

    /// An MLS Welcome that admits me to a group. Present on `"group_mls_welcome"`;
    /// carried alongside `groupKey` + `name` + `members` (pairwise-E2EE) so a new
    /// member joins the MLS group and learns its name/roster in one message.
    public var mlsWelcome: MLSWelcome?
    /// An MLS Commit advancing the group to the next epoch (membership change /
    /// re-key). Present on `"group_mls_commit"`, with `committerLeaf` identifying
    /// the committer so receivers can `process(_:from:)`.
    public var mlsCommit: MLSCommit?
    /// The committer's MLS leaf index, present on `"group_mls_commit"`.
    public var committerLeaf: UInt32?
    /// An MLS application message (a group chat payload encrypted under the current
    /// epoch). Present on `"group_mls_app"`; its plaintext is a JSON `MessageContent`.
    public var mlsApp: MLSApplicationMessage?
    /// The OPAQUE commit-ordering token this Welcome/Commit lands on — the value the
    /// next committer must present to the server CAS register as its `prevToken`.
    /// Present on `"group_mls_welcome"` (the head at the epoch I join) and
    /// `"group_mls_commit"` (the head after this commit). Carried so every member's
    /// local `commitToken` stays in lockstep with the server's order.
    public var commitToken: Data?
    /// The monotonic sequence number the server assigned this commit (or the epoch a
    /// Welcome joins at). Lets receivers apply commits strictly in order, buffering
    /// any that arrive ahead of their turn. Present on the MLS welcome/commit types.
    public var commitSeq: Int?
    /// My account's device ids that already hold a leaf in this group, carried ONLY
    /// on the copy of a Welcome/Commit fanned out to MY OWN other devices (never to
    /// other members — it would leak my device topology). It lets every device of my
    /// account converge its `myDeviceIds` set, so a freshly-joined device doesn't
    /// mistake an already-present sibling for "missing" and re-add it (a ghost leaf).
    public var ownDeviceIds: [String]?

    // MARK: Deletion / message identity

    /// The sender's stable, cross-device id for THIS message (a UUID). Set on every
    /// ordinary 1:1 message so all copies (peer + the sender's other devices) agree
    /// on one id, which `"delete_message"` can then target everywhere.
    public var clientId: String?
    /// On `"delete_message"`, the sender `clientId`(s) to remove on the recipient.
    public var deleteIds: [String]?

    public init(type: String,
                text: String? = nil,
                media: MediaReference? = nil,
                durationMs: Int? = nil,
                stickerId: String? = nil,
                groupId: String? = nil,
                groupKey: Data? = nil,
                name: String? = nil,
                senderKey: SenderKeyDistribution? = nil,
                groupMessage: GroupMessage? = nil,
                members: [String]? = nil,
                syncPeer: String? = nil,
                mlsWelcome: MLSWelcome? = nil,
                mlsCommit: MLSCommit? = nil,
                committerLeaf: UInt32? = nil,
                mlsApp: MLSApplicationMessage? = nil,
                commitToken: Data? = nil,
                commitSeq: Int? = nil,
                ownDeviceIds: [String]? = nil,
                clientId: String? = nil,
                deleteIds: [String]? = nil,
                sealedSender: String? = nil) {
        self.type = type
        self.text = text
        self.media = media
        self.durationMs = durationMs
        self.stickerId = stickerId
        self.groupId = groupId
        self.groupKey = groupKey
        self.name = name
        self.senderKey = senderKey
        self.groupMessage = groupMessage
        self.members = members
        self.syncPeer = syncPeer
        self.mlsWelcome = mlsWelcome
        self.mlsCommit = mlsCommit
        self.committerLeaf = committerLeaf
        self.mlsApp = mlsApp
        self.commitToken = commitToken
        self.commitSeq = commitSeq
        self.ownDeviceIds = ownDeviceIds
        self.clientId = clientId
        self.deleteIds = deleteIds
        self.sealedSender = sealedSender
    }

    // MARK: Convenience constructors

    public static func text(_ value: String) -> MessageContent {
        MessageContent(type: "text", text: value)
    }

    public static func image(_ ref: MediaReference, caption: String?) -> MessageContent {
        let trimmed = caption?.trimmingCharacters(in: .whitespacesAndNewlines)
        return MessageContent(type: "image",
                              text: (trimmed?.isEmpty == false) ? trimmed : nil,
                              media: ref)
    }

    public static func voice(_ ref: MediaReference, durationMs: Int) -> MessageContent {
        MessageContent(type: "voice", media: ref, durationMs: durationMs)
    }

    public static func video(_ ref: MediaReference, caption: String?) -> MessageContent {
        let trimmed = caption?.trimmingCharacters(in: .whitespacesAndNewlines)
        return MessageContent(type: "video",
                              text: (trimmed?.isEmpty == false) ? trimmed : nil,
                              media: ref)
    }

    public static func sticker(_ stickerId: String) -> MessageContent {
        MessageContent(type: "sticker", stickerId: stickerId)
    }

    /// An admin's change to a group's metadata (name and/or avatar), carried INSIDE
    /// a `group_mls_app` so it is E2EE to the group and the server never sees it.
    /// `text` is the new name; `media` is the new avatar reference (if any).
    public static func groupMeta(name: String?, photoRef: MediaReference?) -> MessageContent {
        MessageContent(type: "group_meta", text: name, media: photoRef)
    }

    /// Tells a member they were REMOVED from a group, so their app ejects them from
    /// the conversation immediately (they're already cryptographically locked out of
    /// future messages). Sent pairwise (the removed member is off the group channel).
    public static func groupRemoved(groupId: String) -> MessageContent {
        MessageContent(type: "group_removed", groupId: groupId)
    }

    /// Tells every member a group was DISSOLVED (its creator left), so all apps drop
    /// it. Sent pairwise to each member.
    public static func groupDissolved(groupId: String) -> MessageContent {
        MessageContent(type: "group_dissolved", groupId: groupId)
    }

    // MARK: Group control constructors (carried over the pairwise channel)

    /// Bootstraps a member: hands them the group key + name, the sender's
    /// Sender-Key distribution, and the full member roster (so they know everyone
    /// to distribute their own Sender Key back to).
    public static func groupSetup(groupId: String,
                                  groupKey: Data,
                                  name: String,
                                  senderKey: SenderKeyDistribution,
                                  members: [String]) -> MessageContent {
        MessageContent(type: "group_setup", groupId: groupId,
                       groupKey: groupKey, name: name, senderKey: senderKey, members: members)
    }

    /// A Sender-Key-encrypted group message for `groupId`. The inner
    /// `GroupMessage` decrypts (via the sender's stored `SenderKeyState`) to a
    /// JSON `MessageContent` carrying the actual text/sticker/image.
    public static func groupMsg(groupId: String, groupMessage: GroupMessage) -> MessageContent {
        MessageContent(type: "group_msg", groupId: groupId, groupMessage: groupMessage)
    }

    /// Asks recipients to rotate their Sender Key for `groupId` and redistribute
    /// it (sent to every member on a membership change).
    public static func groupRekey(groupId: String) -> MessageContent {
        MessageContent(type: "group_rekey", groupId: groupId)
    }

    // MARK: MLS group control constructors (the live group transport)

    /// Admits a member to an MLS group: the Welcome plus the group key + name +
    /// roster (all pairwise-E2EE) so the joiner derives the epoch and learns the
    /// group's display name and members in one message.
    public static func groupMLSWelcome(groupId: String,
                                       welcome: MLSWelcome,
                                       groupKey: Data,
                                       name: String,
                                       members: [String],
                                       commitToken: Data = Data(),
                                       commitSeq: Int = 0) -> MessageContent {
        MessageContent(type: "group_mls_welcome", groupId: groupId, groupKey: groupKey,
                       name: name, members: members, mlsWelcome: welcome,
                       commitToken: commitToken, commitSeq: commitSeq)
    }

    /// An MLS Commit for `groupId` (membership change / re-key); `committerLeaf`
    /// identifies the committer so receivers can `process(_:from:)`. `commitToken`
    /// + `commitSeq` are the server CAS register's head after this commit, so every
    /// member advances its local order in lockstep and applies commits in sequence.
    public static func groupMLSCommit(groupId: String,
                                      commit: MLSCommit,
                                      committerLeaf: UInt32,
                                      commitToken: Data,
                                      commitSeq: Int) -> MessageContent {
        MessageContent(type: "group_mls_commit", groupId: groupId,
                       mlsCommit: commit, committerLeaf: committerLeaf,
                       commitToken: commitToken, commitSeq: commitSeq)
    }

    /// An MLS application (group chat) message for `groupId`, encrypted under the
    /// current epoch. Its plaintext is a JSON `MessageContent` (text/sticker/image).
    public static func groupMLSApp(groupId: String, app: MLSApplicationMessage) -> MessageContent {
        MessageContent(type: "group_mls_app", groupId: groupId, mlsApp: app)
    }

    // MARK: Deletion control constructors (pairwise-E2EE; mirrored to own devices)

    /// "Delete for everyone": asks the recipient(s) to remove the message(s) with
    /// these SENDER `clientId`s. Mirrored to the sender's own devices too.
    public static func deleteMessages(_ clientIds: [String]) -> MessageContent {
        MessageContent(type: "delete_message", deleteIds: clientIds)
    }

    /// "Delete conversation": asks the peer to remove THIS sender's messages from
    /// the shared thread; when mirrored to the sender's own other devices it drops
    /// the whole local thread there.
    public static func deleteConversation() -> MessageContent {
        MessageContent(type: "delete_conversation")
    }

    /// "Profile updated": a tiny ping telling a contact that the sender re-published
    /// its private profile, so the recipient should re-fetch + re-decrypt it (the new
    /// grant + encrypted profile are already on the server). Carries no profile data
    /// itself — the actual name/photo stay end-to-end encrypted behind the grant.
    public static func profileUpdated() -> MessageContent {
        MessageContent(type: "profile_updated")
    }
}

/// A server-originated control event delivered with `contentType == "system"`,
/// whose message `ciphertext` is PLAINTEXT JSON (NOT a ratchet envelope). The only
/// recognized type today is `account_deleted`, which tells us a peer tore down
/// their account so we can purge their local traces. Unknown types are ignored.
public struct SystemEvent: Codable, Sendable, Equatable {
    /// e.g. `"account_deleted"`.
    public var type: String
    /// The affected account's public id (present on `account_deleted`).
    public var publicId: String?

    public init(type: String, publicId: String? = nil) {
        self.type = type
        self.publicId = publicId
    }
}
