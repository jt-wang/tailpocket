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
        override fun connect(link: String, derp: String) = """{"handle":4,"port":5555}"""
        var stopped = -1L
        override fun stop(handle: Long) { stopped = handle }
        override fun localPairStart(op: Long, address: String, label: String, device: String) = """{"code":"123456"}"""
        override fun localPairFinish(op: Long, timeoutMs: Long) = """{"v":1,"address":"tcB","port":48932,"key":"privkey:k","proof":"p","expiresAt":9}"""
        override fun cancel(op: Long) {}
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
    private val bridge = TailPocketBridge(TailPocket.with(native), store, { nearby }, scanner = { "tailpocket1:scanned" }, emit = { n, d -> events += n to d })

    private suspend fun call(name: String, args: Map<String, Any?> = emptyMap()) = bridge.call(name, args)

    @Test fun pairWithTextUsesTheStoredKeyAndSavesTheLink() = runTest {
        @Suppress("UNCHECKED_CAST")
        val link = call("tailPocket.pair", mapOf("invite" to "tailpocket1:x", "device" to "Pixel", "save" to true)) as Map<String, Any?>
        assertEquals("tcM", link["address"])
        assertEquals("privkey:stored", native.pairedWith)
        assertEquals("tcM", store.links["default"]?.address)
        @Suppress("UNCHECKED_CAST")
        assertEquals("tcM", (call("tailPocket.store.link") as Map<String, Any?>)["address"])
    }

    @Test fun connectAndDisconnect() = runTest {
        @Suppress("UNCHECKED_CAST")
        val c = call("tailPocket.connect", mapOf("link" to mapOf("address" to "tcM", "port" to 48931, "name" to "Mac", "key" to "privkey:1"))) as Map<String, Any?>
        assertEquals("http://127.0.0.1:5555", c["baseUrl"])
        call("tailPocket.disconnect", mapOf("handle" to c["handle"]))
        assertEquals(4L, native.stopped)
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

    @Test fun scanAndErrors() = runTest {
        assertEquals("tailpocket1:scanned", call("tailPocket.scan"))
        try { call("tailPocket.decodeInvite", mapOf("text" to "junk")); fail() } catch (e: TailPocketException) { assertEquals("invalid-invite", e.code) }
        try { call("tailPocket.nope"); fail() } catch (e: TailPocketException) { assertEquals("unknown-function", e.code) }
        try { call("tailPocket.pair", emptyMap()); fail() } catch (e: TailPocketException) { assertEquals("invalid-arguments", e.code) }
        assertEquals(TailPocketBridge.NAMES.sorted(), bridge.names.sorted())
    }
}
