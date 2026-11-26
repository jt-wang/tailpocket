import Darwin
import Foundation
import Security

/// Push keys by key id, readable by the code that opens notes. `TailPocketPushKeychain` is the iOS one.
public protocol TailPocketPushKeys: Sendable {
    func key(kid: String) -> Data?
    func saveKey(_ key: Data, kid: String) throws
    func deleteKey(kid: String) throws
}

/// The highest seq accepted per key id. `withLock` runs its body under a lock that every reader and writer of the
/// store takes, in every process; call `last` and `store` only inside it. `store` must be durable when it returns.
public protocol TailPocketPushSeqs: Sendable {
    func withLock<T>(_ body: () throws -> T) throws -> T
    func last(kid: String) throws -> UInt64
    func store(kid: String, seq: UInt64) throws
}

public struct TailPocketPushStoreError: Error, Equatable, Sendable {
    /// An OSStatus from the Keychain, or an errno from the file system.
    public let status: Int32
    public let what: String
}

/// Push keys, and the push generation per app, in the Keychain.
///
/// Items are `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so the Notification Service Extension can read
/// them while the phone is locked (not `WhenUnlocked`: every push would show the placeholder) and they never leave
/// the device. Give the app and its extension the same `accessGroup`: a Keychain Sharing group from both targets'
/// `keychain-access-groups` entitlement, with the team prefix ("ABCDE12345.io.jingtao.herdr.push"), or an App
/// Group identifier ("group.io.jingtao.herdr") that both targets have.
public struct TailPocketPushKeychain: TailPocketPushKeys {
    public let accessGroup: String?
    public let service: String

    /// `accessGroup` nil uses the target's default group, which the extension does not share: only for tests.
    public init(accessGroup: String?, service: String = "tailpocket.push") {
        self.accessGroup = accessGroup
        self.service = service
    }

    public func key(kid: String) -> Data? {
        guard let d = try? read("key." + kid), d.count == 32 else { return nil }
        return d
    }

    public func saveKey(_ key: Data, kid: String) throws {
        guard key.count == 32 else { throw TailPocketPushStoreError(status: -50, what: "a push key is 32 bytes") }
        try write("key." + kid, key)
    }

    public func deleteKey(kid: String) throws { try delete("key." + kid) }

    /// The phone's push generation for `app` (docs/PUSH.md §5); 1 before the first registration.
    public func generation(app: String) -> UInt64 {
        guard let d = try? read("generation." + app), let s = String(data: d, encoding: .utf8), let g = UInt64(s), g >= 1 else { return 1 }
        return g
    }

    public func saveGeneration(_ generation: UInt64, app: String) throws { try write("generation." + app, Data(String(generation).utf8)) }

    /// The App Attest key id this phone uses with the gateway for `app`, once Apple has attested it.
    public func attestKeyID(app: String) -> String? {
        guard let d = try? read("appattest." + app) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    public func saveAttestKeyID(_ keyID: String, app: String) throws { try write("appattest." + app, Data(keyID.utf8)) }

    public func deleteAttestKeyID(app: String) throws { try delete("appattest." + app) }

    func query(_ account: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    /// What a new item is added with.
    func addQuery(_ account: String, _ data: Data) -> [String: Any] {
        var q = query(account)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return q
    }

    private func read(_ account: String) throws -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw TailPocketPushStoreError(status: status, what: "keychain read") }
        return out as? Data
    }

    private func write(_ account: String, _ data: Data) throws {
        // Updating also sets the accessibility, in case an older item was added with another one.
        let update: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query(account) as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw TailPocketPushStoreError(status: status, what: "keychain update") }
        let added = SecItemAdd(addQuery(account, data) as CFDictionary, nil)
        guard added == errSecSuccess else { throw TailPocketPushStoreError(status: added, what: "keychain add") }
    }

    private func delete(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw TailPocketPushStoreError(status: status, what: "keychain delete") }
    }
}

/// The highest seq per key id in one JSON file in the App Group container, shared by the app and its extension.
///
/// `withLock` takes `flock` on a lock file next to it, which holds across processes (each push may start a new
/// extension process, and two can run at once) and across threads (each call opens its own descriptor). `store`
/// writes a temporary file, syncs it to storage (F_FULLFSYNC), renames it over the old one and syncs the directory,
/// so a crash leaves either the old value or the new one. A file that exists but does not parse makes every note
/// fail (show the placeholder) rather than start over from 0, which would let old notes be replayed.
public final class TailPocketPushSeqFile: TailPocketPushSeqs, @unchecked Sendable {
    public let url: URL
    private let lockPath: String

    public init(directory: URL, name: String = "tailpocket-push-seq.json") {
        url = directory.appendingPathComponent(name)
        lockPath = directory.appendingPathComponent(name + ".lock").path
    }

    /// The file in the container of App Group `appGroup` ("group.io.jingtao.herdr"), or nil when this target does
    /// not have the App Groups entitlement for it.
    public convenience init?(appGroup: String) {
        guard let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else { return nil }
        self.init(directory: dir)
    }

    public func withLock<T>(_ body: () throws -> T) throws -> T {
        let fd = Darwin.open(lockPath, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw TailPocketPushStoreError(status: errno, what: "open lock") }
        defer { Darwin.close(fd) } // closing releases the lock
        while flock(fd, LOCK_EX) != 0 {
            guard errno == EINTR else { throw TailPocketPushStoreError(status: errno, what: "flock") }
        }
        return try body()
    }

    public func last(kid: String) throws -> UInt64 { try readAll()[kid] ?? 0 }

    public func store(kid: String, seq: UInt64) throws {
        var all = try readAll()
        all[kid] = seq
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        try writeDurably(try encoder.encode(all))
    }

    private func readAll() throws -> [String: UInt64] {
        // Under the lock, so the file cannot appear or go between the check and the read.
        guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
        return try JSONDecoder().decode([String: UInt64].self, from: try Data(contentsOf: url))
    }

    private func writeDurably(_ data: Data) throws {
        let tmp = url.path + ".tmp"
        let fd = Darwin.open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw TailPocketPushStoreError(status: errno, what: "open") }
        #if os(iOS)
        // Readable after the first unlock, like the push keys (the App Group default, set in case it is not).
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: tmp)
        #endif
        var failure: Int32 = 0
        data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            var off = 0
            while off < buf.count {
                let n = Darwin.write(fd, buf.baseAddress! + off, buf.count - off)
                if n < 0 {
                    if errno == EINTR { continue }
                    failure = errno
                    return
                }
                off += n
            }
        }
        if failure == 0 && !Self.sync(fd) { failure = errno }
        Darwin.close(fd)
        guard failure == 0 else {
            unlink(tmp)
            throw TailPocketPushStoreError(status: failure, what: "write")
        }
        guard Darwin.rename(tmp, url.path) == 0 else {
            let e = errno
            unlink(tmp)
            throw TailPocketPushStoreError(status: e, what: "rename")
        }
        let dir = Darwin.open(url.deletingLastPathComponent().path, O_RDONLY | O_CLOEXEC)
        guard dir >= 0 else { throw TailPocketPushStoreError(status: errno, what: "open directory") }
        defer { Darwin.close(dir) }
        guard Self.sync(dir) else { throw TailPocketPushStoreError(status: errno, what: "sync directory") }
    }

    /// F_FULLFSYNC asks the drive to write its cache too; fsync is the fallback where that is not supported.
    private static func sync(_ fd: Int32) -> Bool { fcntl(fd, F_FULLFSYNC) == 0 || fsync(fd) == 0 }
}
