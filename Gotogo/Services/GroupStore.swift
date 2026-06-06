//
//  GroupStore.swift
//  Gotogo
//
//  On-disk persistence for per-group crypto state (`GroupState`: the group key,
//  MY OWN Sender Key, and the map of other members' received Sender Keys), keyed
//  by group id. Mirrors the Double-Ratchet session cache: a JSON file derived
//  from a per-user cache URL so distinct test users keep distinct group files,
//  cleared on logout. Foundation only; guarded by a lock for cross-task safety.
//

import Foundation

/// JSON-backed store of `GroupState` keyed by group id. Thread-safe.
final class GroupStore: @unchecked Sendable {

    private let url: URL
    private let lock = NSLock()
    private var states: [String: GroupState] = [:]
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    /// Seals/opens the group-state file at rest (group key + MY Sender Key + others'
    /// received Sender Keys). Nil falls back to plaintext (test-only convenience).
    private let cipher: EncryptedFileStore?

    /// - Parameters:
    ///   - cacheURL: a per-user base path (the messaging cache URL); the group file
    ///     is derived from it so each user/test gets its own file.
    ///   - cipher: when supplied, the group-state file is AES-GCM ciphertext at rest
    ///     instead of plaintext JSON. Production wires this from the secret store.
    init(cacheURL: URL, cipher: EncryptedFileStore? = nil) {
        self.url = Self.groupsURL(forCacheURL: cacheURL)
        self.cipher = cipher
        load()
    }

    /// The persisted state for a group, if known.
    func state(_ groupId: String) -> GroupState? {
        lock.lock(); defer { lock.unlock() }
        return states[groupId]
    }

    /// Every persisted group state.
    func all() -> [GroupState] {
        lock.lock(); defer { lock.unlock() }
        return Array(states.values)
    }

    /// Inserts or replaces a group's state and persists the store.
    func save(_ state: GroupState) {
        lock.lock()
        states[state.groupId] = state
        let snapshot = states
        lock.unlock()
        persist(snapshot)
    }

    /// Atomically reads, mutates, and writes back a group's state under the lock,
    /// so concurrent control-message ingest + sends don't clobber each other.
    /// `mutate` receives an `inout` state (a fresh empty one if none exists yet,
    /// seeded with `groupId`) and returns the value to persist.
    @discardableResult
    func update(_ groupId: String, _ mutate: (inout GroupState) -> Void) -> GroupState {
        lock.lock()
        var state = states[groupId] ?? GroupState(groupId: groupId, groupKey: Data(), name: "Group")
        mutate(&state)
        states[groupId] = state
        let snapshot = states
        lock.unlock()
        persist(snapshot)
        return state
    }

    /// Removes a group's state (e.g. on leave/delete) and persists.
    func remove(_ groupId: String) {
        lock.lock()
        states[groupId] = nil
        let snapshot = states
        lock.unlock()
        persist(snapshot)
    }

    /// Drops all group state and deletes the file (used on logout).
    func clear() {
        lock.lock()
        states = [:]
        lock.unlock()
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - Persistence

    private func load() {
        let raw: Data?
        if let cipher { raw = cipher.read(url) } else { raw = try? Data(contentsOf: url) }
        guard let data = raw,
              let map = try? decoder.decode([String: GroupState].self, from: data) else { return }
        lock.lock()
        states = map
        lock.unlock()
    }

    private func persist(_ snapshot: [String: GroupState]) {
        guard let data = try? encoder.encode(snapshot) else { return }
        if let cipher { try? cipher.write(data, to: url) }
        else { try? data.write(to: url, options: .atomic) }
    }

    /// Derives the group-state file path from the conversation-cache path so
    /// distinct users (distinct cache URLs) keep distinct group files.
    static func groupsURL(forCacheURL cacheURL: URL) -> URL {
        let dir = cacheURL.deletingLastPathComponent()
        let base = cacheURL.deletingPathExtension().lastPathComponent
        return dir.appendingPathComponent("\(base)-groups.json")
    }
}
