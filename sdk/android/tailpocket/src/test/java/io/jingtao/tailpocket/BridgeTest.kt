package io.jingtao.tailpocket

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

class BridgeTest {
    private class FakeNative : TailPocketNative {
        override fun newKey() = "privkey:new"
        override fun publicKey(key: String) = if (key.startsWith("privkey:")) "nodekey:" + key.removePrefix("privkey:") else ""
        override fun decodeInvite(text: String, prefix: String) =
            if (text.startsWith(prefix)) """{"v":1,"address":"tcA","port":48932,"key":"privkey:x","proof":"p","expiresAt":9,"name":"Mac"}""" else """{"error":"invalid-invite"}"""
        var pairedWith = ""
        override fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String {
            pairedWith = key
            return """{"address":"tcM","port":48931,"name":"Mac","payload":"t","key":"$key"}"""
        }
        override fun connect(link: String, derp: String) = """{"handle":4,"port":5555,"token":"TOK","base":"/_tailpocket/TOK"}"""
        var stopped = -1L
        override fun stop(handle: Long) { stopped = handle }
        override fun localPairStart(op: Long, address: String, label: String, device: String) = """{"code":"123456"}"""
        override fun localPairFinish(op: Long, timeoutMs: Long) = """{"v":1,"address":"tcB","port":48932,"key":"privkey:k","proof":"p","expiresAt":9}"""
        override fun cancel(op: Long) {}

        override fun decodeInvite2(text: String, prefix: String) = if (text.startsWith(prefix) || text.startsWith("tailpocket1:"))
            """{"v":2,"name":"Mac","exp":9,"via":[{"t":"relay","u":"wss://relay.example.com","r":"AAAAAAAAAAAAAAAAAAAAAA","m":"opaque"}]}""" else """{"error":"invalid-invite"}"""
        var paired2 = ""
        /** Pair as a v0.3.0-pre.4 computer: the emoji first, the link from pair2Finish. */
        var withEmoji = false
        override fun pair2(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String {
            paired2 = invite
            if (withEmoji) return """{"emoji":["🐶","🌙","🍕","🔑"]}"""
            return """{"name":"Mac","payload":"t","key":"$key","pk":"PK","via":[{"t":"relay","u":"wss://relay.example.com","r":"R"}]}"""
        }
        override fun pair2Finish(op: Long, timeoutMs: Long) = """{"name":"Mac","payload":"t","key":"privkey:stored","pk":"PK2"}"""
        var tailcatOnly: Boolean? = null
        override fun setTailcatOnly(on: Boolean) { tailcatOnly = on }
        var routes: String? = null
        override fun setRoutes(routes: String): String { this.routes = routes; return "" }
        override fun sync(handle: Long, timeoutMs: Long) = """{"address":"tcM","port":48931,"name":"Mac","key":"privkey:1","pk":"PK","via":[{"t":"relay","u":"wss://relay.example.com","r":"R"}]}"""
        override fun link(handle: Long) = sync(handle, 0)
        override fun path(handle: Long, timeoutMs: Long) = if (handle == 4L) """{"route":"relay","relay":"relay.example.com"}""" else """{"error":"revoked"}"""
        var failure = "{}"
        override fun lastFailure(handle: Long) = if (handle == 4L) failure else """{"error":"unknown-handle"}"""
    }

    private class MemoryStore : TailPocketLinkStore {
        val links = mutableMapOf<String, TailPocketHostLink>()
        override fun phoneKey() = "privkey:stored"
        override fun saveLink(link: TailPocketHostLink, slot: String) { links[slot] = link }
        override fun link(slot: String) = links[slot]
        override fun deleteLink(slot: String) { links.remove(slot) }
    }

    private class FakeNearby : TailPocketNearbySource {
        var onChange: ((List<String>) -> Unit)? = null
        override fun start(onChange: (List<String>) -> Unit) { this.onChange = onChange }
        override fun stop() { onChange = null }
        override suspend fun address(name: String) = if (name == "Mac") "192.168.1.2:4000" else throw TailPocketException("local-failed")
    }

    private val native = FakeNative()
    private val store = MemoryStore()
    private val nearby = FakeNearby()
    private val events = mutableListOf<Pair<String, Any?>>()
    private val scans = mutableListOf<List<String>>()
    private val bridge = TailPocketBridge(TailPocket.with(native), store, { nearby }, scanner = { scans += it; "tailpocket1:scanned" }, emit = { n, d -> events += n to d })

    private suspend fun call(name: String, args: Map<String, Any?> = emptyMap()) = bridge.call(name, args)

    @Test fun pairWithTextUsesTheStoredKeyAndSavesTheLink() = runTest {
        @Suppress("UNCHECKED_CAST")
        val link = call("tailPocket.pair", mapOf("invite" to "tailpocket1:x", "device" to "Pixel", "save" to true)) as Map<String, Any?>
        assertEquals("PK", link["pk"])
        assertEquals("privkey:stored", link["key"])
        assertEquals("PK", store.links["default"]?.hostKey)
        @Suppress("UNCHECKED_CAST")
        assertEquals("PK", (call("tailPocket.store.link") as Map<String, Any?>)["pk"])
    }

    // A v1 invite object pairs as its one tailcat route; sync on a stored link saves the result to its slot.
    @Test fun v1ObjectPairsAsTailcatAndSyncSaves() = runTest {
        call("tailPocket.pair", mapOf("invite" to mapOf("v" to 1, "address" to "tcA", "port" to 48932, "key" to "privkey:x", "proof" to "p", "expiresAt" to 9, "name" to "Mac"), "device" to "Pixel"))
        assertEquals(true, native.paired2.contains("\"t\":\"tailcat\""))
        store.links["default"] = TailPocketHostLink("tcM", 48931, "Mac", null, "privkey:1")
        @Suppress("UNCHECKED_CAST")
        val c = call("tailPocket.connect") as Map<String, Any?>
        call("tailPocket.sync", mapOf("handle" to c["handle"]))
        assertEquals("PK", store.links["default"]?.hostKey)
        @Suppress("UNCHECKED_CAST")
        assertEquals("relay", (call("tailPocket.path", mapOf("handle" to c["handle"])) as Map<String, Any?>)["route"])
        try { call("tailPocket.sync", mapOf("handle" to 99)); fail() } catch (e: TailPocketException) { assertEquals("unknown-handle", e.code) }
    }

    // The emoji reach JavaScript as an event while the pairing waits for the computer's answer.
    @Test fun pairEmitsTheEmojiThenReturnsTheLink() = runTest {
        native.withEmoji = true
        @Suppress("UNCHECKED_CAST")
        val link = call("tailPocket.pair", mapOf("invite" to "tailpocket2:x", "device" to "Pixel")) as Map<String, Any?>
        assertEquals("PK2", link["pk"])
        assertEquals(listOf("tailPocket.pair.emoji" to mapOf("emoji" to listOf("🐶", "🌙", "🍕", "🔑"))), events)
    }

    @Test fun setTailcatOnly() = runTest {
        call("tailPocket.setTailcatOnly", mapOf("on" to true))
        assertEquals(true, native.tailcatOnly)
        call("tailPocket.setTailcatOnly", mapOf("on" to false))
        assertEquals(false, native.tailcatOnly)
    }

    @Test fun setRoutes() = runTest {
        call("tailPocket.setRoutes", mapOf("routes" to listOf("relay")))
        assertEquals("relay", native.routes)
        call("tailPocket.setRoutes", mapOf("routes" to null))
        assertEquals("", native.routes)
    }

    // Audit v0.3.2, finding 3: only an explicit null means "every route". A call without `routes` (JavaScript's
    // undefined is dropped on the way), with a misspelt key or with something that is no list is refused.
    @Test fun setRoutesWithoutAListIsRefused() = runTest {
        call("tailPocket.setRoutes", mapOf("routes" to listOf("relay")))
        for (bad in listOf<Map<String, Any?>>(emptyMap(), mapOf("route" to listOf("lan")), mapOf("routes" to "lan"), mapOf("routes" to listOf("lan", 5)))) {
            try { call("tailPocket.setRoutes", bad); fail("accepted $bad") } catch (e: TailPocketException) { assertEquals("invalid-arguments", e.code) }
        }
        assertEquals("relay", native.routes)
    }

    @Test fun connectAndDisconnect() = runTest {
        @Suppress("UNCHECKED_CAST")
        val c = call("tailPocket.connect", mapOf("link" to mapOf("address" to "tcM", "port" to 48931, "name" to "Mac", "key" to "privkey:1"))) as Map<String, Any?>
        assertEquals("http://127.0.0.1:5555/_tailpocket/TOK", c["baseUrl"])
        assertEquals("TOK", c["token"])
        call("tailPocket.disconnect", mapOf("handle" to c["handle"]))
        assertEquals(4L, native.stopped)
    }

    // v0.3.4: tailPocket.lastFailure is the code, reason, route, routes and time of the last failed attempt (v0.3.5: reason and routes too), or null.
    @Test fun lastFailure() = runTest {
        @Suppress("UNCHECKED_CAST")
        val c = call("tailPocket.connect", mapOf("link" to mapOf("address" to "tcM", "port" to 48931, "name" to "Mac", "key" to "privkey:1"))) as Map<String, Any?>
        val h = mapOf("handle" to c["handle"])
        assertNull(call("tailPocket.lastFailure", h))
        // The Go library's own answer: every field reaches JavaScript, reason and routes included.
        native.failure = java.io.File("../../../connectmobile/testdata/lastfailure.json").readText().trim()
        assertEquals(mapOf("code" to "unreachable", "reason" to "no-answer", "route" to "relay",
            "routes" to listOf(mapOf("t" to "lan", "r" to "refused"), mapOf("t" to "relay", "r" to "no-answer")), "at" to 1795300000001L),
            call("tailPocket.lastFailure", h))
        // A failure without a reason (revoked) still gives JavaScript reason "" and routes [].
        native.failure = """{"code":"revoked","route":"lan","at":1795300000002}"""
        @Suppress("UNCHECKED_CAST")
        val revoked = call("tailPocket.lastFailure", h) as Map<String, Any?>
        assertEquals("" to emptyList<Any?>(), revoked["reason"] to revoked["routes"])
        native.failure = """{"code":"unreachable","at":1795300000001,"route":"relay"}"""
        @Suppress("UNCHECKED_CAST")
        assertEquals("unreachable", (call("tailPocket.lastFailure", h) as Map<String, Any?>)["code"])
        native.failure = "{}"
        assertNull(call("tailPocket.lastFailure", h))
        try { call("tailPocket.lastFailure", mapOf("handle" to 99)); fail() } catch (e: TailPocketException) { assertEquals("unknown-handle", e.code) }
    }

    @Test fun nearbyEmitsNamesAndLocalPairingUsesThem() = runTest {
        call("tailPocket.nearby.start", mapOf("service" to "_myapp._tcp"))
        nearby.onChange!!(listOf("Mac"))
        assertEquals("tailPocket.nearby" to mapOf("hosts" to listOf(mapOf("name" to "Mac"))), events.last())
        @Suppress("UNCHECKED_CAST")
        val begun = call("tailPocket.local.begin", mapOf("name" to "Mac", "device" to "Pixel")) as Map<String, Any?>
        assertEquals("123456", begun["code"])
        @Suppress("UNCHECKED_CAST")
        val invite = call("tailPocket.local.finish", mapOf("op" to begun["op"])) as Map<String, Any?>
        assertEquals("tcB", invite["address"])
        call("tailPocket.nearby.stop")
        assertNull(nearby.onChange)
    }

    // A v0.3 phone scans v1 and v2 invites: both defaults, or the app's two prefixes; one prefix alone stays one.
    @Test fun scanLooksForBothPrefixes() = runTest {
        call("tailPocket.scan")
        call("tailPocket.scan", mapOf("prefix" to "herdr1:", "prefix2" to "herdr2:"))
        call("tailPocket.scan", mapOf("prefix" to "herdr1:"))
        assertEquals(listOf(listOf("tailpocket1:", "tailpocket2:"), listOf("herdr1:", "herdr2:"), listOf("herdr1:")), scans)
        assertEquals("herdr2:abc", TailPocket.inviteText("see herdr2:abc", listOf("herdr1:", "herdr2:")))
        assertNull(TailPocket.inviteText("tailpocket2:abc", listOf("herdr1:", "herdr2:")))
    }

    @Test fun scanAndErrors() = runTest {
        assertEquals("tailpocket1:scanned", call("tailPocket.scan"))
        try { call("tailPocket.decodeInvite", mapOf("text" to "junk")); fail() } catch (e: TailPocketException) { assertEquals("invalid-invite", e.code) }
        try { call("tailPocket.nope"); fail() } catch (e: TailPocketException) { assertEquals("unknown-function", e.code) }
        try { call("tailPocket.pair", emptyMap()); fail() } catch (e: TailPocketException) { assertEquals("invalid-arguments", e.code) }
        assertEquals(TailPocketBridge.NAMES.sorted(), bridge.names.sorted())
    }
}
