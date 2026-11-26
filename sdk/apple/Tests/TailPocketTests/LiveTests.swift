#if os(macOS)
import XCTest
@testable import TailPocket

/// Real helper, real Tailcat relays, an HTTP server on the "computer". Opt in with TAILPOCKET_LIVE=1 after
/// scripts/build-host.sh.
final class LiveTests: XCTestCase {
    var helper: Helper!
    var web: Process!
    var forwardTarget = ""

    override func setUp() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["TAILPOCKET_LIVE"] == "1", "set TAILPOCKET_LIVE=1")
        let port = try startWeb()
        forwardTarget = "127.0.0.1:\(port)"
        helper = try Helper(forward: forwardTarget)
    }

    override func tearDown() {
        helper?.stop()
        web?.terminate()
    }

    func startWeb() throws -> Int {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tailPocket-web-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try "hello from the computer\n".write(to: dir.appendingPathComponent("hello.txt"), atomically: true, encoding: .utf8)
        let port = Int.random(in: 20000...40000)
        web = Process()
        web.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        web.arguments = ["-m", "http.server", "\(port)", "--bind", "127.0.0.1", "--directory", dir.path]
        web.standardOutput = FileHandle.nullDevice
        web.standardError = FileHandle.nullDevice
        try web.run()
        // Wait until it serves the file: python3 can be slow to start on a cold CI runner, and until then
        // the computer's forward is refused and the phone sees the connection dropped (lastFailure none).
        // One deadline on the monotonic clock bounds the whole wait, each request included.
        let hello = URL(string: "http://127.0.0.1:\(port)/hello.txt")!
        let deadline = ProcessInfo.processInfo.systemUptime + 30
        while web.isRunning {
            let left = deadline - ProcessInfo.processInfo.systemUptime
            if left <= 0 { break }
            if Self.serves(hello, body: "hello from the computer\n", within: min(left, 2)) { return port }
            Thread.sleep(forTimeInterval: min(0.1, max(0, deadline - ProcessInfo.processInfo.systemUptime)))
        }
        throw TailPocketError(code: web.isRunning ? "test web server did not serve hello.txt in 30 s" : "test web server exited")
    }

    /// True when one GET answers 200 with exactly `body` within `seconds`, all of it.
    static func serves(_ url: URL, body: String, within seconds: TimeInterval) -> Bool {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = seconds
        config.timeoutIntervalForResource = seconds
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let done = DispatchSemaphore(value: 0)
        var ok = false
        let task = session.dataTask(with: url) { data, response, _ in
            ok = (response as? HTTPURLResponse)?.statusCode == 200 && data.map { String(decoding: $0, as: UTF8.self) } == body
            done.signal()
        }
        task.resume()
        if done.wait(timeout: .now() + seconds) == .timedOut {
            task.cancel()
            return false
        }
        return ok
    }

    func fetchHello(_ link: TailPocketHostLink) async throws -> String {
        let connection = try TailPocket.connect(link)
        defer { connection.close() }
        var lastError: Error?
        for _ in 0..<6 {
            do {
                var request = URLRequest(url: connection.baseURL.appendingPathComponent("hello.txt"))
                request.timeoutInterval = 20
                let (data, _) = try await URLSession.shared.data(for: request)
                return String(decoding: data, as: UTF8.self)
            } catch { lastError = error }
        }
        // The forward only drops the connection; lastFailure says why (code, reason, route; no secret).
        let why = (try? connection.lastFailure()).flatMap { $0 }.map { "\($0.code) \($0.reason) \($0.route) \($0.routes)" }
        XCTFail("no answer over the tunnel; lastFailure: \(why ?? "none")")
        throw lastError!
    }

    func testPairByQRAndFetchOverTheTunnel() async throws {
        let qr = try helper.pair(payload: "swift-token")
        let invite = try TailPocket.decodeInvite(qr)
        let key = TailPocket.newKey()
        let link = try await TailPocket.pair(invite, phoneKey: key, device: "swift phone")
        XCTAssertEqual(link.payload, "swift-token")
        let body = try await fetchHello(link)
        XCTAssertEqual(body, "hello from the computer\n")
    }

    /// Writes to the login keychain under a throwaway service and removes it again.
    func testKeychainStoreKeepsKeyAndLink() throws {
        let store = TailPocketKeychainStore(service: "tailPocket-test-\(UUID().uuidString)")
        defer { try? store.deleteLink(); try? store.deleteKey() }
        let key: String
        do { key = try store.phoneKey() } catch let error as TailPocketKeychainError where [-25308, -34018].contains(error.status) {
            // A locked keychain, or a process without keychain access (seen 2026-10-29 from a terminal session).
            throw XCTSkip("NOT TESTED HERE: keychain refused this process (\(error.status))")
        }
        XCTAssertNotNil(TailPocket.publicKey(for: key))
        XCTAssertEqual(try store.phoneKey(), key)
        XCTAssertNil(try store.link())
        let link = TailPocketHostLink(address: "fd7a:115c:a1e0::1", port: 48931, name: "Mac", payload: "p", key: "nodekey:x")
        try store.saveLink(link)
        XCTAssertEqual(try store.link(), link)
        try store.deleteLink()
        XCTAssertNil(try store.link())
    }

    func testBridgePairsAndConnects() async throws {
        let qr = try helper.pair(payload: "bridge-token")
        let bridge = TailPocketBridge(store: BridgeTests.MemoryStore(key: TailPocket.newKey()), emit: { _, _ in })
        let link = try await bridge.call("tailPocket.pair", ["invite": qr, "device": "swift bridge", "save": true]) as? [String: Any]
        XCTAssertEqual(link?["payload"] as? String, "bridge-token")
        let opened = try await bridge.call("tailPocket.connect", [:]) as? [String: Any]
        let base = try XCTUnwrap(opened?["baseUrl"] as? String)
        var body = ""
        for _ in 0..<6 where body.isEmpty {
            var request = URLRequest(url: URL(string: base + "/hello.txt")!)
            request.timeoutInterval = 20
            if let (data, _) = try? await URLSession.shared.data(for: request) { body = String(decoding: data, as: UTF8.self) }
        }
        let why = body.isEmpty ? try? await bridge.call("tailPocket.lastFailure", ["handle": opened?["handle"] as Any]) : nil
        XCTAssertEqual(body, "hello from the computer\n", "lastFailure: \(why.map { "\($0)" } ?? "none")")
        _ = try await bridge.call("tailPocket.disconnect", ["handle": opened?["handle"] as Any])
    }

    /// v0.3 over a local tailpocket-relay (scripts/build-host.sh builds it): pair from the v2 QR over the
    /// relay only; a phone paired over Tailcat syncs its key and then reaches the computer over the relay
    /// with no new QR; a revoke reaches the phone, encrypted, as "revoked".
    func testRelayPairSyncAndRevoke() async throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../..").standardized
        #if arch(arm64)
        let arch = "arm64"
        #else
        let arch = "amd64"
        #endif
        let relayPort = Int.random(in: 40001...50000)
        let relay = Process()
        relay.executableURL = root.appendingPathComponent("build/tailpocket-relay-darwin-\(arch)")
        relay.arguments = ["--listen", "127.0.0.1:\(relayPort)", "--public-host", "127.0.0.1"]
        relay.environment = ["TAILPOCKET_RELAY_TOKEN": "relay-token-for-the-swift-test"]
        relay.standardOutput = FileHandle.nullDevice
        relay.standardError = FileHandle.nullDevice
        try relay.run()
        defer { relay.terminate() }
        helper.stop()
        helper = try Helper(forward: forwardTarget, config: ["relays": [["url": "ws://127.0.0.1:\(relayPort)", "token": "relay-token-for-the-swift-test"]]])

        func fetch(_ c: TailPocketConnection) async throws -> String {
            var lastError: Error = TailPocketError(code: "unreachable")
            for _ in 0..<6 {
                do {
                    var request = URLRequest(url: c.baseURL.appendingPathComponent("hello.txt"))
                    request.timeoutInterval = 20
                    let (data, _) = try await URLSession.shared.data(for: request)
                    return String(decoding: data, as: UTF8.self)
                } catch { lastError = error; try await Task.sleep(nanoseconds: 500_000_000) }
            }
            throw lastError
        }

        // A new phone pairs from the v2 QR over the relay alone; both sides show the same emoji, and the
        // helper's user (Helper) confirms.
        let invite = try TailPocket.decodeInvite2(try helper.pair(payload: "relay-token", field: "qr2"))
        let relayOnly = TailPocketInvite2(v: invite.v, name: invite.name, exp: invite.exp, pk: invite.pk, psk: invite.psk,
                                          via: invite.via.filter { $0.t == "relay" })
        XCTAssertEqual(relayOnly.via.count, 1)
        var shown: [String] = []
        let paired = try await TailPocket.pair(relayOnly, phoneKey: TailPocket.newKey(), device: "swift relay phone") { shown = $0 }
        XCTAssertEqual(shown.count, 4)
        XCTAssertEqual(shown, helper.requestEmoji)
        XCTAssertEqual(paired.payload, "relay-token")
        XCTAssertNotNil(paired.hostKey)
        // Only the relay route: with the computer's lan route too, the session moves to the local network
        // (v0.3.1), and this part checks the relay.
        let overRelay = TailPocketHostLink(address: "", port: 0, name: paired.name, payload: paired.payload, key: paired.key,
                                           hostKey: paired.hostKey, via: paired.via?.filter { $0.t == "relay" })
        let c1 = try TailPocket.connect(overRelay)
        let body1 = try await fetch(c1)
        XCTAssertEqual(body1, "hello from the computer\n")
        let path1 = try await c1.path()
        XCTAssertEqual(path1.route, "relay")
        XCTAssertEqual(path1.relay, "127.0.0.1")
        c1.close()

        // A phone paired over Tailcat the old way syncs once, then uses the relay.
        // (A v0.3 computer already returns its key on a v1 pairing; a v0.2 link has neither field.)
        let fresh = try await TailPocket.pair(try TailPocket.decodeInvite(try helper.pair(payload: "old")), phoneKey: TailPocket.newKey(), device: "swift old phone")
        let old = TailPocketHostLink(address: fresh.address, port: fresh.port, name: fresh.name, payload: fresh.payload, key: fresh.key)
        let c2 = try TailPocket.connect(old)
        var synced: TailPocketHostLink?
        for _ in 0..<4 where synced == nil { synced = try? await c2.sync() }
        c2.close()
        let s = try XCTUnwrap(synced, "sync over Tailcat")
        XCTAssertNotNil(s.hostKey)
        XCTAssertEqual(s.via?.first?.t, "relay")
        let c3 = try TailPocket.connect(TailPocketHostLink(address: "", port: 0, name: s.name, payload: s.payload, key: s.key, hostKey: s.hostKey, via: s.via))
        let body3 = try await fetch(c3)
        XCTAssertEqual(body3, "hello from the computer\n")

        // Revoked over the relay: the phone learns it, encrypted.
        helper.send(["cmd": "revoke", "id": "r1", "phone": TailPocket.publicKey(for: s.key)!])
        _ = try helper.waitEvent("allowed")
        _ = try? await fetch(c3)
        do {
            _ = try await c3.path()
            XCTFail("path after revoke")
        } catch {
            XCTAssertEqual(error as? TailPocketError, TailPocketError(code: "revoked"))
        }
        c3.close()
    }

    func testPairOverSameWiFiWithNWBrowser() async throws {
        let qr = try helper.pair(payload: "")
        _ = qr
        let service = "_tailpocket-mac._tcp"
        helper.send(["cmd": "local", "id": helper.lastPairing, "service": service])
        var found: TailPocketNearbyHost?
        let deadline = Date().addingTimeInterval(20)
        for await hosts in TailPocketNearbyHosts.stream(service: service) {
            if let h = hosts.first(where: { $0.name == "swift host" }) { found = h; break }
            if Date() > deadline { break }
        }
        let host = try XCTUnwrap(found, "NWBrowser did not list the computer")
        let pending = try await TailPocketLocalPairing.begin(with: host, device: "swift wifi phone")
        let hostCode = try helper.waitEvent("localCode")
        XCTAssertEqual(hostCode["code"] as? String, pending.code)
        helper.send(["cmd": "confirm", "id": helper.lastPairing, "approve": true])
        let invite = try await pending.finish()
        let link = try await TailPocket.pair(invite, phoneKey: TailPocket.newKey(), device: "swift wifi phone")
        let body = try await fetchHello(link)
        XCTAssertEqual(body, "hello from the computer\n")
    }
}

/// Drives tailpocket-host over stdin/stdout. A background thread reads events and
/// acknowledges every save at once, as a real host app must.
final class Helper: @unchecked Sendable {
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    var lastPairing = ""
    /// The emoji of the last pairRequest, which this helper's "user" approves at once.
    var requestEmoji: [String]? { lock.lock(); defer { lock.unlock() }; return lastEmoji }
    private var lastEmoji: [String]?
    private var serial = 0
    private let lock = NSCondition()
    private var events: [[String: Any]] = []
    private var ended = false

    init(forward: String, config: [String: Any] = [:]) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../..").standardized
        #if arch(arm64)
        let arch = "arm64"
        #else
        let arch = "amd64"
        #endif
        process.executableURL = root.appendingPathComponent("sdk/node/bin/tailpocket-host-darwin-\(arch)")
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        Thread { [self] in readLoop() }.start()
        send(["v": 1, "name": "swift host", "forward": forward].merging(config) { _, new in new })
        _ = try waitEvent("ready")
    }

    private func readLoop() {
        var buffer = Data()
        while true {
            let chunk = output.fileHandleForReading.availableData
            if chunk.isEmpty { break }
            buffer.append(chunk)
            while let newline = buffer.firstIndex(of: 0x0a) {
                let line = buffer[buffer.startIndex..<newline]
                buffer.removeSubrange(buffer.startIndex...newline)
                guard let event = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
                if event["event"] as? String == "save" { send(["cmd": "saved", "id": event["id"]!, "ok": true]) }
                if event["event"] as? String == "pairRequest" {
                    lock.lock(); lastEmoji = event["emoji"] as? [String]; lock.unlock()
                    send(["cmd": "confirm", "id": event["id"]!, "approve": true])
                }
                lock.lock(); events.append(event); lock.broadcast(); lock.unlock()
            }
        }
        lock.lock(); ended = true; lock.broadcast(); lock.unlock()
    }

    func send(_ value: [String: Any]) {
        var data = try! JSONSerialization.data(withJSONObject: value)
        data.append(0x0a)
        input.fileHandleForWriting.write(data)
    }

    /// Opens a window and returns its "qr" (v1), or its "qr2" from an emoji window.
    func pair(payload: String, field: String = "qr") throws -> String {
        serial += 1
        lastPairing = "p\(serial)"
        send(["cmd": "pair", "id": lastPairing, "ttl": 180, "payload": payload, "emoji": field == "qr2"])
        return try waitEvent("pairing")[field] as! String
    }

    /// Waits for the next event of `kind` (earlier events of other kinds are dropped).
    func waitEvent(_ kind: String, timeout: TimeInterval = 120) throws -> [String: Any] {
        let deadline = Date().addingTimeInterval(timeout)
        lock.lock(); defer { lock.unlock() }
        while true {
            while !events.isEmpty {
                let event = events.removeFirst()
                if event["event"] as? String == kind { return event }
                if event["event"] as? String == "error" { throw TailPocketError(code: "helper: \(event["code"] ?? "")") }
            }
            if ended || !lock.wait(until: deadline) { throw TailPocketError(code: "helper: no \(kind)") }
        }
    }

    func stop() {
        try? input.fileHandleForWriting.close()
        process.waitUntilExit()
    }
}
#endif
