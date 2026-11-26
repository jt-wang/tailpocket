import CryptoKit
import Foundation

// TailPocketPush opens sealed push notes (docs/PUSH.md §2) in a Notification Service Extension, without the
// Go library: an extension has about 24 MB of memory. It only needs CryptoKit, Security and Foundation.

/// A push note once opened: what the computer sent. `sent` is unix seconds on the computer's clock.
public struct TailPocketPushNote: Codable, Equatable, Sendable {
    public var title: String
    public var body: String
    public var thread: String
    public var url: String
    public var kind: String
    public var sent: Int64
    public var seq: UInt64

    public init(title: String = "", body: String = "", thread: String = "", url: String = "", kind: String = "", sent: Int64, seq: UInt64) {
        self.title = title; self.body = body; self.thread = thread; self.url = url; self.kind = kind; self.sent = sent; self.seq = seq
    }

    enum CodingKeys: String, CodingKey { case title, body, thread, url, kind, sent, seq }

    // Missing fields are empty or 0, as the computer leaves empty ones out; unknown fields are ignored.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        title = try c.decodeIfPresent(String.self, forKey: .title) ?? ""
        body = try c.decodeIfPresent(String.self, forKey: .body) ?? ""
        thread = try c.decodeIfPresent(String.self, forKey: .thread) ?? ""
        url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
        kind = try c.decodeIfPresent(String.self, forKey: .kind) ?? ""
        sent = try c.decodeIfPresent(Int64.self, forKey: .sent) ?? 0
        seq = try c.decodeIfPresent(UInt64.self, forKey: .seq) ?? 0
    }
}

/// Why a note did not open. The raw values are the error names of connectpush/testdata/vectors.json, plus
/// "invalid-app" and "store-failed" (the new highest seq could not be saved, so the note is not shown).
public enum TailPocketPushError: String, Error, Sendable {
    case tooLarge = "too_large"
    case malformed
    case unknownKey = "unknown_key"
    case auth
    case expired
    case future
    case replay
    case invalidApp = "invalid-app"
    case storeFailed = "store-failed"
}

/// A note that opened, and the key id it was sealed under.
public struct TailPocketPushOpened: Equatable, Sendable {
    public let note: TailPocketPushNote
    public let kid: String
}

/// The sealed-note format of docs/PUSH.md §2, opening side.
public enum TailPocketPushCrypto {
    public static let label = "tailpocket push 1"
    public static let maxCiphertext = 3000
    public static let maxKid = 64
    public static let maxAge: TimeInterval = 24 * 3600
    public static let maxSkew: TimeInterval = 5 * 60
    public static let tiers = [256, 1024, 2048]
    static let nonceSize = 12
    static let tagSize = 16

    /// "tailpocket push 1" || 0x00 || app || 0x00 || kid.
    public static func aad(app: Data, kid: Data) -> Data {
        var d = Data(label.utf8)
        d.append(0)
        d.append(app)
        d.append(0)
        d.append(kid)
        return d
    }

    /// Opens `ct` sealed for `app` (the gateway app id, exactly as registered).
    ///
    /// `key` returns the 32-byte push key for a key id, or nil. `last` returns the highest seq already accepted for
    /// a key id (0 if none). Every check of PUSH.md §2 "Opening" must pass, in that order, or this throws
    /// `TailPocketPushError` and returns nothing of the note. The caller must then store the note's seq as the new
    /// highest for the kid, durably, before showing it, under the same lock as this call:
    /// `TailPocketPushReceiver` does both.
    public static func open(_ ct: String, app: String, now: Date, key: (String) -> Data?, last: (String) throws -> UInt64) throws -> TailPocketPushOpened {
        let appBytes = Data(app.utf8)
        guard !appBytes.isEmpty, appBytes.count <= 255, !appBytes.contains(0) else { throw TailPocketPushError.invalidApp }
        guard ct.utf8.count <= maxCiphertext else { throw TailPocketPushError.tooLarge }
        guard let raw = decodeBase64URL(ct), !raw.isEmpty else { throw TailPocketPushError.malformed }
        let bytes = [UInt8](raw)
        let k = Int(bytes[0])
        guard k >= 1, k <= maxKid, bytes.count >= 1 + k + nonceSize else { throw TailPocketPushError.malformed }
        let kidBytes = Data(bytes[1 ..< 1 + k])
        let sealed = Array(bytes[(1 + k + nonceSize)...])
        guard !kidBytes.contains(0), tiers.contains(sealed.count - tagSize) else { throw TailPocketPushError.malformed }
        guard let kid = String(data: kidBytes, encoding: .utf8) else { throw TailPocketPushError.malformed }
        guard let keyData = key(kid), keyData.count == 32 else { throw TailPocketPushError.unknownKey }

        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(bytes[(1 + k) ..< (1 + k + nonceSize)])),
                                        ciphertext: Data(sealed.prefix(sealed.count - tagSize)),
                                        tag: Data(sealed.suffix(tagSize)))
        } catch {
            throw TailPocketPushError.malformed
        }
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: SymmetricKey(data: keyData), authenticating: aad(app: appBytes, kid: kidBytes))
        } catch {
            throw TailPocketPushError.auth
        }
        guard let js = unpad([UInt8](plaintext)) else { throw TailPocketPushError.malformed }
        let note: TailPocketPushNote
        do { note = try JSONDecoder().decode(TailPocketPushNote.self, from: js) } catch { throw TailPocketPushError.malformed }

        // sent is the computer's clock and the phone's may be off: a backstop. seq is what stops a replay.
        let t = now.timeIntervalSince1970
        if Double(note.sent) < t - maxAge { throw TailPocketPushError.expired }
        if Double(note.sent) > t + maxSkew { throw TailPocketPushError.future }
        let highest: UInt64
        do { highest = try last(kid) } catch { throw TailPocketPushError.storeFailed }
        guard note.seq > highest else { throw TailPocketPushError.replay }
        return TailPocketPushOpened(note: note, kid: kid)
    }

    /// uint16_be(n) || json || zeros to a tier: the JSON, or nil for a bad length or a non-zero padding byte.
    static func unpad(_ pt: [UInt8]) -> Data? {
        guard tiers.contains(pt.count) else { return nil }
        let n = Int(pt[0]) << 8 | Int(pt[1])
        guard n <= pt.count - 2 else { return nil }
        guard pt[(2 + n)...].allSatisfy({ $0 == 0 }) else { return nil }
        return Data(pt[2 ..< (2 + n)])
    }

    /// base64url without padding: only A-Z a-z 0-9 - _, and no stray bits in the last character (as Go's Strict);
    /// nil for anything else.
    public static func decodeBase64URL(_ s: String) -> Data? {
        for c in s.utf8 {
            let ok = (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2D || c == 0x5F
            if !ok { return nil }
        }
        if s.utf8.count % 4 == 1 { return nil }
        var std = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        std += String(repeating: "=", count: (4 - std.utf8.count % 4) % 4)
        guard let d = Data(base64Encoded: std) else { return nil }
        return base64URL(d) == s ? d : nil
    }

    /// base64url without padding.
    public static func base64URL(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// The binding of attestation evidence to a register or revoke request (docs/PUSH.md §7).
public enum TailPocketPushAttest {
    public static let label = "tailpocket push attest 1"

    /// "tailpocket push attest 1\nop\napp\nplatform\ntoken\ngeneration\nchallenge", with op "register" or "revoke".
    public static func clientData(op: String, app: String, platform: String, token: String, generation: UInt64, challenge: String) -> Data {
        Data([label, op, app, platform, token, String(generation), challenge].joined(separator: "\n").utf8)
    }

    /// SHA-256 of `clientData`: App Attest's clientDataHash.
    public static func clientDataHash(op: String, app: String, platform: String, token: String, generation: UInt64, challenge: String) -> Data {
        Data(SHA256.hash(data: clientData(op: op, app: app, platform: platform, token: token, generation: generation, challenge: challenge)))
    }
}
