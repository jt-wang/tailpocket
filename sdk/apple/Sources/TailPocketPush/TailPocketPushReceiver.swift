import Foundation
import UserNotifications

/// Opens pushes in a Notification Service Extension (docs/PUSH.md §3):
///
/// ```swift
/// final class NotificationService: UNNotificationServiceExtension {
///     let receiver = TailPocketPushReceiver(app: "io.jingtao.herdr", appGroup: "group.io.jingtao.herdr",
///                                           keychainAccessGroup: "ABCDE12345.io.jingtao.herdr.push")
///     override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
///         contentHandler(receiver?.content(for: request) ?? TailPocketPushReceiver.placeholder(for: request))
///     }
/// }
/// ```
///
/// The seq check and store run under the seq store's lock, and the new seq is on disk before a note is returned.
/// Any failure gives the placeholder (the gateway's fixed text for the app) and never any of the note.
public final class TailPocketPushReceiver: @unchecked Sendable {
    public let app: String
    private let keys: any TailPocketPushKeys
    private let seqs: any TailPocketPushSeqs
    private let now: @Sendable () -> Date

    /// - Parameter app: the gateway app id, exactly as registered.
    public init(app: String, keys: any TailPocketPushKeys, seqs: any TailPocketPushSeqs, now: @escaping @Sendable () -> Date = { Date() }) {
        self.app = app
        self.keys = keys
        self.seqs = seqs
        self.now = now
    }

    /// Keys from the Keychain group `keychainAccessGroup` and seqs in App Group `appGroup`; nil when this target
    /// does not have the App Group.
    public convenience init?(app: String, appGroup: String, keychainAccessGroup: String) {
        guard let seqs = TailPocketPushSeqFile(appGroup: appGroup) else { return nil }
        self.init(app: app, keys: TailPocketPushKeychain(accessGroup: keychainAccessGroup), seqs: seqs)
    }

    /// Opens `ct` and stores its seq as the highest for its kid; throws `TailPocketPushError` on any failure.
    public func open(_ ct: String) throws -> TailPocketPushOpened {
        let keys = self.keys, seqs = self.seqs
        do {
            return try seqs.withLock { () throws -> TailPocketPushOpened in
                let opened = try TailPocketPushCrypto.open(ct, app: app, now: now(), key: { keys.key(kid: $0) }, last: { try seqs.last(kid: $0) })
                do { try seqs.store(kid: opened.kid, seq: opened.note.seq) } catch { throw TailPocketPushError.storeFailed }
                return opened
            }
        } catch let e as TailPocketPushError {
            throw e
        } catch {
            throw TailPocketPushError.storeFailed // the lock could not be taken
        }
    }

    /// Opens the "tp" field of a push's userInfo.
    public func open(userInfo: [AnyHashable: Any]) throws -> TailPocketPushOpened {
        guard let ct = userInfo["tp"] as? String else { throw TailPocketPushError.malformed }
        return try open(ct)
    }

    /// What the extension hands to its content handler: the note's title, body and thread when it opens, with
    /// `userInfo["tailpocket"] = {kid, seq, sent, url, kind, thread}` for the app; the placeholder otherwise. The
    /// sealed note ("tp") is removed either way.
    public func content(for request: UNNotificationRequest) -> UNNotificationContent {
        guard let ct = request.content.userInfo["tp"] as? String, let opened = try? open(ct) else { return Self.placeholder(for: request) }
        let content = Self.mutableCopy(request)
        let n = opened.note
        if !n.title.isEmpty { content.title = n.title }
        if !n.body.isEmpty { content.body = n.body }
        if !n.thread.isEmpty { content.threadIdentifier = n.thread }
        var info = content.userInfo
        info["tp"] = nil
        info["tailpocket"] = ["kid": opened.kid, "seq": NSNumber(value: n.seq), "sent": NSNumber(value: n.sent),
                              "url": n.url, "kind": n.kind, "thread": n.thread] as [String: Any]
        content.userInfo = info
        return content
    }

    /// The push as the gateway sent it (its fixed placeholder text) without the sealed note. Also what
    /// `serviceExtensionTimeWillExpire` should hand over.
    public static func placeholder(for request: UNNotificationRequest) -> UNNotificationContent {
        let content = mutableCopy(request)
        var info = content.userInfo
        info["tp"] = nil
        content.userInfo = info
        return content
    }

    private static func mutableCopy(_ request: UNNotificationRequest) -> UNMutableNotificationContent {
        (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
    }
}
