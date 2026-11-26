import CryptoKit
import Foundation
import UserNotifications
import XCTest
@testable import TailPocketPush

/// The opening side against connectpush/testdata/vectors.json, the seq file, and the receiver.
final class PushTests: XCTestCase {
    /// connectpush/testdata/vectors.json at the root of the checkout, five path components above this file.
    static let vectors: [String: Any] = {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 5 { root.deleteLastPathComponent() }
        let data = try! Data(contentsOf: root.appendingPathComponent("connectpush/testdata/vectors.json"))
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }()

    static func hex(_ s: String) -> Data {
        var d = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i ..< j], radix: 16)!)
            i = j
        }
        return d
    }

    /// The sealing side, test-only: docs/PUSH.md §2 with a given nonce and padded plaintext.
    static func sealPadded(key: Data, kid: String, app: String, nonce: Data, plaintext: Data) throws -> String {
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce),
                                   authenticating: TailPocketPushCrypto.aad(app: Data(app.utf8), kid: Data(kid.utf8)))
        var raw = Data([UInt8(kid.utf8.count)])
        raw.append(Data(kid.utf8))
        raw.append(nonce)
        raw.append(box.ciphertext)
        raw.append(box.tag)
        return TailPocketPushCrypto.base64URL(raw)
    }

    static func seal(_ note: TailPocketPushNote, key: Data = testKey, kid: String = "k1", app: String = "io.jingtao.herdr", tier: Int? = nil) throws -> String {
        let js = try JSONEncoder().encode(note)
        let t = tier ?? TailPocketPushCrypto.tiers.first { js.count + 2 <= $0 }!
        var pt = Data([UInt8(js.count >> 8), UInt8(js.count & 0xff)])
        pt.append(js)
        pt.append(Data(count: t - pt.count))
        return try sealPadded(key: key, kid: kid, app: app, nonce: Data((0 ..< 12).map { UInt8($0) }), plaintext: pt)
    }

    static let testKey = Data((1 ... 32).map { UInt8($0) })
    static let now: Int64 = 1_790_000_000

    func note(_ seq: UInt64, sent: Int64 = PushTests.now, body: String = "Agent finished") -> TailPocketPushNote {
        TailPocketPushNote(title: "Herdr", body: body, sent: sent, seq: seq)
    }

    func open(_ ct: String, last: UInt64 = 0, app: String = "io.jingtao.herdr", at: Int64 = PushTests.now) throws -> TailPocketPushOpened {
        try TailPocketPushCrypto.open(ct, app: app, now: Date(timeIntervalSince1970: TimeInterval(at)),
                                      key: { $0 == "k1" ? Self.testKey : nil }, last: { _ in last })
    }

    func code(_ body: () throws -> Any) -> String {
        do { _ = try body(); return "opened" } catch let e as TailPocketPushError { return e.rawValue } catch { return "other: \(error)" }
    }

    func testSealVectorsOpenAndAreReproduced() throws {
        let seals = Self.vectors["seal"] as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(seals.count, 3)
        for v in seals {
            let name = v["name"] as! String, kid = v["kid"] as! String, app = v["app"] as! String, ct = v["ct"] as! String
            let key = Self.hex(v["key_hex"] as! String)
            let note = v["note"] as! [String: Any]
            XCTAssertEqual(TailPocketPushCrypto.aad(app: Data(app.utf8), kid: Data(kid.utf8)), Self.hex(v["aad_hex"] as! String), name)
            XCTAssertEqual(try Self.sealPadded(key: key, kid: kid, app: app, nonce: Self.hex(v["nonce_hex"] as! String),
                                               plaintext: Self.hex(v["plaintext_hex"] as! String)), ct, name)
            XCTAssertEqual(ct.count, (v["ct_length"] as! NSNumber).intValue, name)
            let sent = (note["sent"] as! NSNumber).int64Value
            let opened = try TailPocketPushCrypto.open(ct, app: app, now: Date(timeIntervalSince1970: TimeInterval(sent)),
                                                       key: { $0 == kid ? key : nil }, last: { _ in 0 })
            XCTAssertEqual(opened.kid, kid, name)
            XCTAssertEqual(opened.note.seq, (note["seq"] as! NSNumber).uint64Value, name)
            XCTAssertEqual(opened.note.sent, sent, name)
            XCTAssertEqual(opened.note.title, note["title"] as? String ?? "", name)
            XCTAssertEqual(opened.note.body, note["body"] as? String ?? "", name)
            XCTAssertEqual(opened.note.url, note["url"] as? String ?? "", name)
            XCTAssertEqual(opened.note.thread, note["thread"] as? String ?? "", name)
        }
    }

    func testRejectVectorsFailWithTheirError() {
        let rejects = Self.vectors["reject"] as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(rejects.count, 10)
        for v in rejects {
            let kid = v["kid"] as! String
            let key = Self.hex(v["key_hex"] as! String)
            let now = (v["now"] as! NSNumber).doubleValue, last = (v["last"] as! NSNumber).uint64Value
            let got = code {
                try TailPocketPushCrypto.open(v["ct"] as! String, app: v["app"] as! String, now: Date(timeIntervalSince1970: now),
                                              key: { $0 == kid ? key : nil }, last: { _ in last })
            }
            XCTAssertEqual(got, v["error"] as! String, v["name"] as! String)
        }
    }

    func testEachCheckRefuses() throws {
        let ct3 = try Self.seal(note(3))
        XCTAssertEqual(try open(ct3, last: 2).note.seq, 3)
        XCTAssertEqual(code { try open(ct3, last: 3) }, "replay")
        XCTAssertEqual(code { try open(ct3, last: 4) }, "replay")
        let ct1 = try Self.seal(note(1))
        XCTAssertEqual(code { try open(ct1, app: "io.jingtao.boop") }, "auth")
        XCTAssertEqual(code { try open(try Self.seal(note(1), kid: "k2")) }, "unknown_key")
        XCTAssertEqual(code { try open(ct1, at: Self.now + 24 * 3600 + 1) }, "expired")
        XCTAssertEqual(code { try open(ct1, at: Self.now + 24 * 3600) }, "opened")
        XCTAssertEqual(code { try open(ct1, at: Self.now - 301) }, "future")
        XCTAssertEqual(code { try open(ct1, at: Self.now - 300) }, "opened")
        XCTAssertEqual(code { try open(String(repeating: "A", count: 3001)) }, "too_large")
        XCTAssertEqual(code { try open(ct1 + "=") }, "malformed")
        XCTAssertEqual(code { try open("+" + String(ct1.dropFirst())) }, "malformed")
        XCTAssertEqual(code { try open(ct1, app: "") }, "invalid-app")
        // A stray bit in the last character decodes to the same bytes with a lenient decoder; strict refuses it.
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let stray = alphabet[alphabet.firstIndex(of: ct1.last!)! ^ 1]
        XCTAssertEqual(code { try open(String(ct1.dropLast()) + String(stray)) }, "malformed")
        // Every single changed byte fails.
        let raw = TailPocketPushCrypto.decodeBase64URL(ct1)!
        for i in 0 ..< raw.count {
            var b = raw
            b[i] ^= 0x01
            XCTAssertNotEqual(code { try open(TailPocketPushCrypto.base64URL(b)) }, "opened", "byte \(i)")
        }
    }

    func testPaddingIsChecked() throws {
        let js = try JSONEncoder().encode(note(1))
        func padded(_ len: Int, _ fill: (inout Data) -> Void = { _ in }) -> Data {
            var pt = Data([UInt8(len >> 8), UInt8(len & 0xff)])
            pt.append(js)
            pt.append(Data(count: 256 - pt.count))
            fill(&pt)
            return pt
        }
        let nonce = Data(count: 12)
        func sealed(_ pt: Data) throws -> String { try Self.sealPadded(key: Self.testKey, kid: "k1", app: "io.jingtao.herdr", nonce: nonce, plaintext: pt) }
        XCTAssertEqual(code { try open(try sealed(padded(js.count))) }, "opened")
        XCTAssertEqual(code { try open(try sealed(padded(js.count) { $0[255] = 1 })) }, "malformed")
        XCTAssertEqual(code { try open(try sealed(padded(255))) }, "malformed")
        XCTAssertEqual(code { try open(try sealed(Data(count: 300))) }, "malformed")
        for (len, tier) in [(10, 256), (400, 1024), (1500, 2048)] {
            let ct = try Self.seal(note(1, body: String(repeating: "x", count: len)))
            XCTAssertEqual(ct.count, ((1 + 2 + 12 + tier + 16) * 4 + 2) / 3)
            XCTAssertEqual(try open(ct).note.body, String(repeating: "x", count: len))
        }
    }

    func testAttestBindingMatchesGo() {
        // The same vector as connectpush/attest_test.go.
        let hash = TailPocketPushAttest.clientDataHash(op: "register", app: "io.jingtao.herdr", platform: "apns", token: "ab01", generation: 7, challenge: "CHALLENGE")
        XCTAssertEqual(TailPocketPushCrypto.base64URL(hash), "sheS7aeIcwOE_y7yGLnYIxbFa7mWPSMvt3jDBZY0N4Q")
        XCTAssertEqual(String(decoding: TailPocketPushAttest.clientData(op: "revoke", app: "a", platform: "fcm", token: "t", generation: 12, challenge: "c"), as: UTF8.self),
                       "tailpocket push attest 1\nrevoke\na\nfcm\nt\n12\nc")
    }

    func testKeychainItemsAreReadableWhileLockedAndShared() {
        let q = TailPocketPushKeychain(accessGroup: "ABCDE12345.io.jingtao.herdr.push").addQuery("key.k1", Data(count: 32))
        XCTAssertEqual((q[kSecAttrAccessible as String] as! CFString) as String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertEqual(q[kSecAttrAccessGroup as String] as? String, "ABCDE12345.io.jingtao.herdr.push")
    }

    // MARK: - seq file and receiver

    func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tp-push-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    final class MemoryKeys: TailPocketPushKeys, @unchecked Sendable {
        let lock = NSLock()
        var keys: [String: Data] = [:]
        func key(kid: String) -> Data? { lock.withLock { keys[kid] } }
        func saveKey(_ key: Data, kid: String) throws { lock.withLock { keys[kid] = key } }
        func deleteKey(kid: String) throws { lock.withLock { keys[kid] = nil } }
    }

    func receiver(_ dir: URL, seqs: (any TailPocketPushSeqs)? = nil) -> TailPocketPushReceiver {
        let keys = MemoryKeys()
        keys.keys["k1"] = Self.testKey
        return TailPocketPushReceiver(app: "io.jingtao.herdr", keys: keys, seqs: seqs ?? TailPocketPushSeqFile(directory: dir),
                                      now: { Date(timeIntervalSince1970: TimeInterval(PushTests.now)) })
    }

    func testSeqFileKeepsTheHighestAndRefusesACorruptFile() throws {
        let dir = try tempDir()
        let file = TailPocketPushSeqFile(directory: dir)
        XCTAssertEqual(try file.withLock { try file.last(kid: "k1") }, 0)
        try file.withLock { try file.store(kid: "k1", seq: 3); try file.store(kid: "k2", seq: 9) }
        let again = TailPocketPushSeqFile(directory: dir)
        XCTAssertEqual(try again.withLock { try again.last(kid: "k1") }, 3)
        XCTAssertEqual(try again.withLock { try again.last(kid: "k2") }, 9)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.url.path + ".tmp"))
        try Data("not json".utf8).write(to: file.url)
        XCTAssertThrowsError(try file.withLock { try file.last(kid: "k1") })
        XCTAssertEqual(code { try self.receiver(dir).open(try Self.seal(self.note(5))) }, "store-failed")
    }

    func testReceiverStoresSeqBeforeShowingAndRefusesReplays() throws {
        let dir = try tempDir()
        let r = receiver(dir)
        let ct5 = try Self.seal(note(5))
        XCTAssertEqual(try r.open(ct5).note.seq, 5)
        let file = TailPocketPushSeqFile(directory: dir)
        XCTAssertEqual(try file.withLock { try file.last(kid: "k1") }, 5)
        XCTAssertEqual(code { try r.open(ct5) }, "replay")
        XCTAssertEqual(code { try r.open(try Self.seal(self.note(4))) }, "replay")
        XCTAssertEqual(code { try r.open(userInfo: ["other": "x"]) }, "malformed")
        XCTAssertEqual(try r.open(userInfo: ["tp": try Self.seal(note(6))]).note.seq, 6)
    }

    /// A store whose writes fail, as a full disk would.
    final class FailingSeqs: TailPocketPushSeqs, @unchecked Sendable {
        var highest: UInt64 = 0
        func withLock<T>(_ body: () throws -> T) throws -> T { try body() }
        func last(kid: String) throws -> UInt64 { highest }
        func store(kid: String, seq: UInt64) throws { throw TailPocketPushStoreError(status: 28, what: "write") }
    }

    func testANoteWhoseSeqCannotBeSavedIsNotShown() throws {
        let seqs = FailingSeqs()
        let r = receiver(try tempDir(), seqs: seqs)
        XCTAssertEqual(code { try r.open(try Self.seal(self.note(7))) }, "store-failed")
        XCTAssertEqual(seqs.highest, 0)
    }

    func testOneOfManyConcurrentDeliveriesOpens() throws {
        let dir = try tempDir()
        let ct = try Self.seal(note(9))
        let opened = NSLock()
        var count = 0
        // Separate seq files on one directory: each takes its own flock, as separate extension processes do.
        DispatchQueue.concurrentPerform(iterations: 16) { _ in
            if (try? self.receiver(dir).open(ct)) != nil { opened.withLock { count += 1 } }
        }
        XCTAssertEqual(count, 1)
    }

    func testContentShowsTheNoteOrThePlaceholder() throws {
        let dir = try tempDir()
        let r = receiver(dir)
        func request(_ tp: String?) -> UNNotificationRequest {
            let c = UNMutableNotificationContent()
            c.title = "Herdr"
            c.body = "New activity"
            if let tp { c.userInfo = ["tp": tp] }
            return UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)
        }
        var n = note(1)
        n.thread = "session-1"
        let shown = r.content(for: request(try Self.seal(n)))
        XCTAssertEqual(shown.body, "Agent finished")
        XCTAssertEqual(shown.threadIdentifier, "session-1")
        XCTAssertNil(shown.userInfo["tp"])
        XCTAssertEqual((shown.userInfo["tailpocket"] as? [String: Any])?["seq"] as? NSNumber, 1)
        for bad in [try Self.seal(n), "junk", nil] {
            let p = r.content(for: request(bad))
            XCTAssertEqual(p.title, "Herdr")
            XCTAssertEqual(p.body, "New activity")
            XCTAssertNil(p.userInfo["tp"])
            XCTAssertNil(p.userInfo["tailpocket"])
        }
    }
}
