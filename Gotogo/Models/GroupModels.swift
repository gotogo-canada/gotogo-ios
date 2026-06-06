//
//  GroupModels.swift
//  Gotogo
//
//  Domain + persisted-state models for group messaging with Signal Sender Keys.
//  A `Group` is the display model (id, decrypted name, members); a `GroupState`
//  is the per-group crypto state the client persists (the group key that seals
//  the name, MY OWN Sender Key, and the map of other members' received Sender
//  Keys). Pure Foundation so services/tests stay UI-free.
//

import Foundation

/// A member's role in a group, as reported by the backend.
public enum GroupRole: String, Codable, Sendable, Equatable {
    case admin
    case member
    case unknown

    public init(from raw: String) {
        self = GroupRole(rawValue: raw) ?? .unknown
    }
}

/// One member of a group: their public id and role.
public struct GroupMember: Codable, Sendable, Equatable, Identifiable {
    public var publicId: String
    public var role: GroupRole

    public var id: String { publicId }

    public init(publicId: String, role: GroupRole) {
        self.publicId = publicId
        self.role = role
    }
}

/// The display model for a group: its id, decrypted name (or a "Group" fallback
/// when the group key isn't known yet), and members. Built by `GroupService`
/// from the backend listing + the locally cached `GroupState`. (Named `GroupInfo`,
/// not `Group`, to avoid colliding with SwiftUI's `Group` container view.)
public struct GroupInfo: Codable, Sendable, Equatable, Identifiable {
    public var groupId: String
    public var name: String
    public var members: [GroupMember]
    public var createdAt: Date?
    /// Optional group avatar (encrypted-media reference), set by the admin.
    public var photoRef: MediaReference?

    public var id: String { groupId }

    public init(groupId: String, name: String, members: [GroupMember],
                createdAt: Date? = nil, photoRef: MediaReference? = nil) {
        self.groupId = groupId
        self.name = name
        self.members = members
        self.createdAt = createdAt
        self.photoRef = photoRef
    }
}

/// The per-group crypto state persisted locally (a `GroupStore` JSON cache, keyed
/// by group id; cleared on logout). Group messaging now runs on **MLS (RFC 9420 /
/// TreeKEM)** rather than Sender Keys, so the live ratchet is the MLS group itself.
/// Holds:
///   - `groupKey`: random 32 bytes that AES-GCM-seal the group name (kept for the
///     backend group-listing display; distributed inside the MLS Welcome control
///     message).
///   - `name`: the plaintext group name (cached for display).
///   - `mls`: MY OWN `MLSGroup` state (ratchet tree, epoch, epoch secrets, my leaf
///     + leaf/init private keys). Nil until I create or join (via Welcome) the group.
///   - `outgoingGeneration`: my next application-message generation counter within
///     the CURRENT epoch (reset to 0 on every epoch change). The MLS application
///     layer derives a unique key per (sender, generation), so this just advances.
///   - `members`: the last-known member roster (drives fan-out + the info screen).
///   - `leafOwners`: committer-side map of MLS leaf index → owner public id, so the
///     admin can translate "remove this member" into the right `Remove(leaf)`.
///   - `myRole`: this account's role (admin when it created the group).
public struct GroupState: Codable, Sendable, Equatable {
    public var groupId: String
    public var groupKey: Data
    public var name: String
    /// MY MLS group state (tree + epoch + secrets + my private keys). Nil until I
    /// create the group or join it from a Welcome.
    public var mls: MLSGroup?
    /// My next application-message generation in the current epoch (reset per epoch).
    public var outgoingGeneration: UInt32
    /// Last-known member roster.
    public var members: [GroupMember]
    /// Committer-side leaf → owner public id (so a Remove can find the member's leaf).
    public var leafOwners: [UInt32: String]
    /// The device ids of MY OWN account that already hold a leaf in this group (as
    /// far as this device knows). Used to retro-add a newly provisioned device of
    /// mine to existing groups without re-adding ones already present.
    public var myDeviceIds: Set<String>
    /// My role in this group.
    public var myRole: GroupRole
    /// The OPAQUE commit-ordering token for this group's CURRENT epoch — the value
    /// the next membership-changing Commit must present to the server CAS register
    /// as its `prevToken`. Empty = genesis (the head before any commit). Advanced in
    /// lockstep with the server every time a Commit is accepted or processed, so any
    /// member (not just an admin) can change membership and concurrent commits are
    /// serialized rather than forking the group.
    public var commitToken: Data
    /// The monotonic sequence number of this group's current epoch in the server's
    /// commit order (0 at genesis). Lets commits apply strictly in order.
    public var commitSeq: Int
    /// The group's optional avatar: an encrypted-media `MediaReference` (the per-file
    /// key rides inside the E2EE `group_meta` control). Set by the admin; nil = none.
    public var photoRef: MediaReference?

    public init(groupId: String,
                groupKey: Data,
                name: String,
                mls: MLSGroup? = nil,
                outgoingGeneration: UInt32 = 0,
                members: [GroupMember] = [],
                leafOwners: [UInt32: String] = [:],
                myDeviceIds: Set<String> = [],
                myRole: GroupRole = .member,
                commitToken: Data = Data(),
                commitSeq: Int = 0,
                photoRef: MediaReference? = nil) {
        self.groupId = groupId
        self.groupKey = groupKey
        self.name = name
        self.mls = mls
        self.outgoingGeneration = outgoingGeneration
        self.members = members
        self.leafOwners = leafOwners
        self.myDeviceIds = myDeviceIds
        self.myRole = myRole
        self.commitToken = commitToken
        self.commitSeq = commitSeq
        self.photoRef = photoRef
    }

    /// Backward-compatible decoder: the commit-ordering fields were added after the
    /// first group states were persisted, so an on-disk cache may lack them; decode
    /// them when present and fall back to the genesis head otherwise (Encodable and
    /// CodingKeys stay synthesized).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        groupId = try c.decode(String.self, forKey: .groupId)
        groupKey = try c.decode(Data.self, forKey: .groupKey)
        name = try c.decode(String.self, forKey: .name)
        mls = try c.decodeIfPresent(MLSGroup.self, forKey: .mls)
        outgoingGeneration = try c.decodeIfPresent(UInt32.self, forKey: .outgoingGeneration) ?? 0
        members = try c.decodeIfPresent([GroupMember].self, forKey: .members) ?? []
        leafOwners = try c.decodeIfPresent([UInt32: String].self, forKey: .leafOwners) ?? [:]
        myDeviceIds = try c.decodeIfPresent(Set<String>.self, forKey: .myDeviceIds) ?? []
        myRole = try c.decodeIfPresent(GroupRole.self, forKey: .myRole) ?? .member
        commitToken = try c.decodeIfPresent(Data.self, forKey: .commitToken) ?? Data()
        commitSeq = try c.decodeIfPresent(Int.self, forKey: .commitSeq) ?? 0
        photoRef = try c.decodeIfPresent(MediaReference.self, forKey: .photoRef)
    }

    /// The public ids of every member other than `me` (the fan-out audience for
    /// pairwise control + group messages).
    public func others(excluding me: String) -> [String] {
        members.map(\.publicId).filter { $0 != me }
    }
}
