import CryptoKit
import DeviceCheck
import Foundation
import TailPocketMobile
import TailPocketPush

// The phone's side of push (docs/PUSH.md §1): register the APNs device token with a tailpocket-push gateway,
// give each paired computer its own push key with the handle, and revoke every handle when a computer is
// removed. Opening notes is in the TailPocketPush library, which the Notification Service Extension links
// without the Go framework.

/// A push handle from the gateway; register again before `expires` (unix seconds).
public struct TailPocketPushRegistration: Codable, Sendable, Equatable {
    public let handle: String
    public let expires: Int64
    public init(handle: String, expires: Int64) { self.handle = handle; self.expires = expires }
}

/// What a phone gives a computer so it can push to it. `key` is the 32-byte push key as base64url.
public struct TailPocketPushTarget: Codable, Sendable, Equatable {
    public let gateway: String
    public let app: String
    public let handle: String
    public let kid: String
    public let key: String
    public init(gateway: String, app: String, handle: String, kid: String, key: String) {
        self.gateway = gateway; self.app = app; self.handle = handle; self.kid = kid; self.key = key
    }
}

/// A new push key for one computer: `key` is 32 bytes base64url.
public struct TailPocketPushKey: Codable, Sendable, Equatable {
    public let kid: String
    public let key: String
}

extension TailPocket {
    /// A new push key and key id for one computer (`TailPocketPushPhone.give` makes and stores one for you).
    public static func pushNewKey() throws -> TailPocketPushKey { try decode(ConnectmobilePushNewKey()) }

    /// A challenge for attestation evidence from `gateway`, for `app`.
    public static func pushChallenge(gateway: String, app: String, timeout: TimeInterval = 30) async throws -> String {
        struct Challenge: Decodable { let challenge: String }
        let c: Challenge = try await blocking(cancel: {}) { ConnectmobilePushChallenge(gateway, app, Int(timeout * 1000)) }
        return c.challenge
    }

    /// Registers a device token ("apns": the token as lowercase hex; or "fcm") with `gateway` for `app` at
    /// `generation` (from 1, kept by the phone), with attestation `attest` JSON for a gateway that checks it.
    /// Errors: stale-generation (with `minGeneration`), attestation-required, attestation-failed,
    /// attest-key-unknown, rate-limited, invalid-arguments, unreachable, timeout, failed.
    public static func pushRegister(gateway: String, app: String, platform: String, token: String, generation: UInt64,
                                    attest: String? = nil, timeout: TimeInterval = 30) async throws -> TailPocketPushRegistration {
        let g = Int64(clamping: generation), a = attest ?? ""
        return try await blocking(cancel: {}) { ConnectmobilePushRegister(gateway, app, platform, token, g, a, Int(timeout * 1000)) }
    }

    /// Makes every handle for the token with a generation up to `generation` stop working; then register at
    /// generation + 1.
    public static func pushRevoke(gateway: String, app: String, platform: String, token: String, generation: UInt64,
                                  attest: String? = nil, timeout: TimeInterval = 30) async throws {
        let g = Int64(clamping: generation), a = attest ?? ""
        let _: Empty = try await blocking(cancel: {}) { ConnectmobilePushRevoke(gateway, app, platform, token, g, a, Int(timeout * 1000)) }
    }

    /// The APNs device token as the gateway takes it: lowercase hex.
    public static func pushToken(_ deviceToken: Data) -> String { deviceToken.map { String(format: "%02x", $0) }.joined() }
}

/// Makes attestation evidence for a gateway that checks it (docs/PUSH.md §7). `TailPocketAppAttest` is the iOS one.
public protocol TailPocketPushAttester: Sendable {
    /// The evidence JSON for a request whose binding is `clientData` (`TailPocketPushAttest.clientData`), with the
    /// gateway's `challenge` in it.
    func evidence(challenge: String, clientData: Data) async throws -> String
    /// The gateway does not know this phone's key (attest-key-unknown): the next evidence attests a new key.
    func reset() throws
}

/// App Attest evidence: the first time, a new key and its attestation; every later time, an assertion with it.
///
/// The key id is kept in the Keychain once Apple has attested it, so a lost reply does not make the phone attest
/// the same key twice (the gateway refuses that); a gateway that never stored the key answers attest-key-unknown
/// and `TailPocketPushPhone` calls `reset()` and tries once more with a new key. Needs the App Attest capability
/// (entitlement `com.apple.developer.devicecheck.appattest-environment`, "production" for TestFlight and the App
/// Store, "development" otherwise) and a device: the simulator and most Macs are not supported ("unsupported").
@available(iOS 14.0, macOS 11.0, *)
public final class TailPocketAppAttest: TailPocketPushAttester, @unchecked Sendable {
    private let keychain: TailPocketPushKeychain
    private let app: String

    /// - Parameter app: the gateway app id the key is for (one key per app id).
    public init(keychain: TailPocketPushKeychain, app: String) {
        self.keychain = keychain
        self.app = app
    }

    struct Evidence: Encodable {
        let challenge: String
        let key_id: String
        let attestation: String?
        let assertion: String?
    }

    public func evidence(challenge: String, clientData: Data) async throws -> String {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw TailPocketError(code: "unsupported") }
        let hash = Data(SHA256.hash(data: clientData))
        if let keyID = keychain.attestKeyID(app: app) {
            do {
                let assertion = try await service.generateAssertion(keyID, clientDataHash: hash)
                return try Self.json(Evidence(challenge: challenge, key_id: keyID, attestation: nil, assertion: assertion.base64EncodedString()))
            } catch let e as DCError where e.code == .invalidKey {
                try keychain.deleteAttestKeyID(app: app) // gone from this device (a restore): attest a new one
            }
        }
        let keyID = try await service.generateKey()
        let attestation = try await service.attestKey(keyID, clientDataHash: hash)
        try keychain.saveAttestKeyID(keyID, app: app)
        return try Self.json(Evidence(challenge: challenge, key_id: keyID, attestation: attestation.base64EncodedString(), assertion: nil))
    }

    public func reset() throws { try keychain.deleteAttestKeyID(app: app) }

    static func json(_ e: Evidence) throws -> String { String(decoding: try JSONEncoder().encode(e), as: UTF8.self) }
}

/// Register, give and revoke, with the generation and push keys kept in `keychain` (the Keychain group the
/// Notification Service Extension reads).
public final class TailPocketPushPhone: @unchecked Sendable {
    public let keychain: TailPocketPushKeychain
    private let attester: (any TailPocketPushAttester)?

    /// - Parameter attester: for an app whose gateway checks attestation (`TailPocketAppAttest`); nil for a
    ///   gateway in strict mode.
    public init(keychain: TailPocketPushKeychain, attester: (any TailPocketPushAttester)? = nil) {
        self.keychain = keychain
        self.attester = attester
    }

    /// Registers `token` (`TailPocket.pushToken(deviceToken)`) with `gateway` for `app` at the stored generation
    /// and returns the handle. A gateway that has seen a higher generation answers stale-generation: this moves
    /// to it and tries once more.
    public func register(gateway: String, app: String, token: String, platform: String = "apns", timeout: TimeInterval = 30) async throws -> TailPocketPushRegistration {
        var generation = keychain.generation(app: app)
        for attempt in 0 ..< 2 {
            do {
                let g = generation
                return try await attested("register", gateway: gateway, app: app, platform: platform, token: token, generation: g, timeout: timeout) { attest in
                    try await TailPocket.pushRegister(gateway: gateway, app: app, platform: platform, token: token, generation: g, attest: attest, timeout: timeout)
                }
            } catch let e as TailPocketError where e.code == "stale-generation" && attempt == 0 {
                guard let min = e.minGeneration, min > generation else { throw e }
                generation = min
                try keychain.saveGeneration(generation, app: app)
            }
        }
        throw TailPocketError(code: "failed")
    }

    /// Makes a push key for the computer of `connection`, stores it where the extension reads it, and gives it
    /// with `registration`'s handle. Returns the key id: keep it with the computer's link and pass it to `forget`
    /// (or `revoke`) when the computer is removed.
    public func give(_ connection: TailPocketConnection, gateway: String, app: String, registration: TailPocketPushRegistration,
                     timeout: TimeInterval = 30) async throws -> String {
        let k = try TailPocket.pushNewKey()
        guard let key = TailPocketPushCrypto.decodeBase64URL(k.key), key.count == 32 else { throw TailPocketError(code: "failed") }
        try keychain.saveKey(key, kid: k.kid)
        do {
            try await connection.givePush(TailPocketPushTarget(gateway: gateway, app: app, handle: registration.handle, kid: k.kid, key: k.key), timeout: timeout)
        } catch {
            try? keychain.deleteKey(kid: k.kid)
            throw error
        }
        return k.kid
    }

    /// After a computer is removed: makes every handle given so far stop working at the gateway (revoke at the
    /// current generation), deletes `kid`'s key, and registers again at generation + 1. Give the returned
    /// handle to the computers that stay, each with `give`.
    public func revoke(gateway: String, app: String, token: String, kid: String?, platform: String = "apns",
                       timeout: TimeInterval = 30) async throws -> TailPocketPushRegistration {
        let generation = keychain.generation(app: app)
        try await attested("revoke", gateway: gateway, app: app, platform: platform, token: token, generation: generation, timeout: timeout) { attest in
            try await TailPocket.pushRevoke(gateway: gateway, app: app, platform: platform, token: token, generation: generation, attest: attest, timeout: timeout)
        }
        try keychain.saveGeneration(generation + 1, app: app)
        if let kid { try forget(kid: kid) }
        return try await register(gateway: gateway, app: app, token: token, platform: platform, timeout: timeout)
    }

    /// Deletes a computer's push key: notes sealed with it no longer open.
    public func forget(kid: String) throws { try keychain.deleteKey(kid: kid) }

    /// Runs `call` with evidence for op (nil without an attester); a key the gateway does not know is replaced once.
    private func attested<T>(_ op: String, gateway: String, app: String, platform: String, token: String, generation: UInt64,
                             timeout: TimeInterval, _ call: (String?) async throws -> T) async throws -> T {
        guard let attester else { return try await call(nil) }
        for attempt in 0 ..< 2 {
            let challenge = try await TailPocket.pushChallenge(gateway: gateway, app: app, timeout: timeout)
            let data = TailPocketPushAttest.clientData(op: op, app: app, platform: platform, token: token, generation: generation, challenge: challenge)
            let evidence = try await attester.evidence(challenge: challenge, clientData: data)
            do {
                return try await call(evidence)
            } catch let e as TailPocketError where e.code == "attest-key-unknown" && attempt == 0 {
                try attester.reset()
            }
        }
        throw TailPocketError(code: "failed")
    }
}
