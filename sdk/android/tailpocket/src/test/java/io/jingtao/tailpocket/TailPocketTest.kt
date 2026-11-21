package io.jingtao.tailpocket

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/** JVM tests with a fake native layer (the Go library is Android-only). */
class TailPocketTest {
    private class FakeNative(
        val pairResult: String = """{"error":"expired"}""",
        /** What pair2 returns first: a link, an error, or {"emoji":[…]} with [finishResult] from pair2Finish. */
        val pair2Result: String? = null,
        val finishResult: String = """{"error":"unauthorized"}""",
    ) : TailPocketNative {
        var cancelled = mutableListOf<Long>()
        override fun newKey() = "privkey:1"
        override fun publicKey(key: String) = if (key == "privkey:1") "nodekey:1" else ""
        override fun decodeInvite(text: String, prefix: String) =
            if (text.startsWith(prefix)) """{"v":1,"address":"tcA","port":48932,"key":"privkey:x","proof":"p","expiresAt":9,"name":"Mac"}""" else """{"error":"invalid-invite"}"""
        override fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long) = pairResult
        override fun connect(link: String, derp: String) = """{"handle":4,"port":5555,"token":"TOK","base":"/_tailpocket/TOK"}"""
        override fun stop(handle: Long) {}
        override fun localPairStart(op: Long, address: String, label: String, device: String) = """{"code":"123456"}"""
        override fun localPairFinish(op: Long, timeoutMs: Long) = """{"v":1,"address":"tcB","port":48932,"key":"k","proof":"p","expiresAt":9}"""
        override fun cancel(op: Long) { cancelled += op }

        override fun decodeInvite2(text: String, prefix: String) = if (text.startsWith(prefix) || text.startsWith("tailpocket1:"))
            """{"v":2,"name":"Mac","exp":9,"via":[{"t":"relay","u":"wss://relay.example.com","r":"AAAAAAAAAAAAAAAAAAAAAA","m":"opaque"}]}""" else """{"error":"invalid-invite"}"""
        var paired2 = ""
        var pair2Op = 0L
        override fun pair2(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String {
            paired2 = invite
            pair2Op = op
            return pair2Result ?: """{"name":"Mac","payload":"t","key":"$key","pk":"PK","via":[{"t":"relay","u":"wss://relay.example.com","r":"R"}]}"""
        }
        val finished = mutableListOf<Pair<Long, Long>>()
        override fun pair2Finish(op: Long, timeoutMs: Long): String { finished += op to timeoutMs; return finishResult }
        var tailcatOnly: Boolean? = null
        override fun setTailcatOnly(on: Boolean) { tailcatOnly = on }
        var routes: String? = null
        override fun setRoutes(routes: String): String {
            if (routes.split(",").any { it !in setOf("tailcat", "lan", "relay") } && routes != "") return """{"error":"invalid-routes"}"""
            this.routes = routes; return ""
        }
        override fun sync(handle: Long, timeoutMs: Long) = """{"address":"tcM","port":48931,"name":"Mac","key":"privkey:1","pk":"PK","via":[{"t":"relay","u":"wss://relay.example.com","r":"R"}]}"""
        override fun link(handle: Long) = sync(handle, 0)
        override fun path(handle: Long, timeoutMs: Long) = if (handle == 4L) """{"route":"relay","relay":"relay.example.com"}""" else """{"error":"revoked"}"""
    }

    @Test fun keys() {
        val tc = TailPocket.with(FakeNative())
        assertEquals("nodekey:1", tc.publicKey(tc.newKey()))
        assertNull(tc.publicKey("junk"))
    }

    @Test fun decodeInvite() {
        val tc = TailPocket.with(FakeNative())
        assertEquals("Mac", tc.decodeInvite("tailpocket1:abc").name)
        try { tc.decodeInvite("nope"); fail() } catch (e: TailPocketException) { assertEquals("invalid-invite", e.code) }
    }

    @Test fun pairErrorsBecomeCodes() = runTest {
        val tc = TailPocket.with(FakeNative())
        try { tc.pair(tc.decodeInvite("tailpocket1:x"), "privkey:1", "Pixel"); fail() } catch (e: TailPocketException) { assertEquals("expired", e.code) }
    }

    @Test fun pairReturnsTheLink() = runTest {
        val tc = TailPocket.with(FakeNative("""{"address":"tcM","port":48931,"name":"Mac","payload":"t","key":"privkey:1"}"""))
        val link = tc.pair(tc.decodeInvite("tailpocket1:x"), "privkey:1", "Pixel")
        assertEquals("t", link.payload)
        assertEquals(link, TailPocketHostLink.decode(link.encode()))
    }

    // A relay-only link has no Tailcat address and must not encode one; a v0.2 link reads with no key or routes.
    @Test fun v3LinkShapes() = runTest {
        val tc = TailPocket.with(FakeNative())
        val link = tc.pair(tc.decodeInvite2("tailpocket2:x"), "privkey:1", "Pixel") { fail("no emoji for a link at once") }
        assertEquals("", link.address)
        assertEquals("PK", link.hostKey)
        val text = link.encode()
        assertEquals(false, text.contains("\"address\""))
        assertEquals(true, text.contains("\"pk\":\"PK\""))
        assertEquals(link, TailPocketHostLink.decode(text))
        val old = TailPocketHostLink.decode("""{"address":"tcX","port":48931,"name":"Mac","key":"privkey:x"}""")
        assertNull(old.hostKey)
        assertNull(old.via)
        val c = tc.connect(old)
        assertEquals("PK", c.sync().hostKey)
        assertEquals("relay", c.path().route)
        c.close()
    }

    // v0.3.0-pre.4: the emoji first, then the computer's answer for the same operation.
    @Test fun pair2ShowsTheEmojiThenWaitsForTheComputer() = runTest {
        val native = FakeNative(pair2Result = """{"emoji":["🐶","🌙","🍕","🔑"]}""",
            finishResult = """{"name":"Mac","payload":"t","key":"privkey:1","pk":"PK"}""")
        val tc = TailPocket.with(native)
        val shown = mutableListOf<List<String>>()
        val link = tc.pair(tc.decodeInvite2("tailpocket2:x"), "privkey:1", "Pixel", timeoutMs = 30_000) { shown += it }
        assertEquals(listOf(listOf("🐶", "🌙", "🍕", "🔑")), shown)
        assertEquals("PK", link.hostKey)
        assertEquals(listOf(native.pair2Op to 90_000L), native.finished) // timeoutMs and the computer's user's minute
    }

    @Test fun pair2RefusedOnTheComputerIsUnauthorized() = runTest {
        val native = FakeNative(pair2Result = """{"emoji":["🐶","🌙","🍕","🔑"]}""")
        val tc = TailPocket.with(native)
        var shown = 0
        try { tc.pair(tc.decodeInvite2("tailpocket2:x"), "privkey:1", "Pixel") { shown++ }; fail() } catch (e: TailPocketException) { assertEquals("unauthorized", e.code) }
        assertEquals(1, shown)
        // An error before any emoji never calls back or waits.
        val early = FakeNative(pair2Result = """{"error":"unreachable"}""")
        try { TailPocket.with(early).pair(tc.decodeInvite2("tailpocket2:x"), "privkey:1", "Pixel") { fail() }; fail() } catch (e: TailPocketException) { assertEquals("unreachable", e.code) }
        assertEquals(emptyList<Pair<Long, Long>>(), early.finished)
    }

    @Test fun onEmojiFailingCancelsThePairing() = runTest {
        val native = FakeNative(pair2Result = """{"emoji":["🐶","🌙","🍕","🔑"]}""")
        val tc = TailPocket.with(native)
        try { tc.pair(tc.decodeInvite2("tailpocket2:x"), "privkey:1", "Pixel") { throw IllegalStateException("ui gone") }; fail() } catch (e: IllegalStateException) {}
        assertEquals(listOf(native.pair2Op), native.cancelled)
        assertEquals(emptyList<Pair<Long, Long>>(), native.finished)
    }

    @Test fun setTailcatOnlyReachesTheNativeLayer() {
        val native = FakeNative()
        TailPocket.with(native).setTailcatOnly(true)
        assertEquals(true, native.tailcatOnly)
    }

    @Test fun setRoutesReachesTheNativeLayer() {
        val native = FakeNative()
        val tc = TailPocket.with(native)
        tc.setRoutes(listOf("lan", "relay"))
        assertEquals("lan,relay", native.routes)
        tc.setRoutes(null)
        assertEquals("", native.routes)
        for (bad in listOf(emptyList(), listOf(""), listOf("lan,relay"), listOf("wifi"))) {
            try { tc.setRoutes(bad); fail("accepted $bad") } catch (e: TailPocketException) { assertEquals("invalid-routes", e.code) }
        }
    }

    @Test fun connectGivesALocalUrl() {
        val tc = TailPocket.with(FakeNative())
        val c = tc.connect(TailPocketHostLink("tcM", 48931, "Mac", null, "privkey:1"))
        assertEquals("http://127.0.0.1:5555/_tailpocket/TOK", c.baseUrl)
        assertEquals("TOK", c.token)
        c.close()
    }

    @Test fun localPairingTwoSteps() = runTest {
        val tc = TailPocket.with(FakeNative())
        val pending = tc.beginLocalPairing("192.168.1.2:4000", "Pixel")
        assertEquals("123456", pending.code)
        assertEquals("tcB", pending.finish().address)
    }

    @Test fun inviteTextFindsTheCode() {
        assertEquals("tailpocket1:abc", TailPocket.inviteText("  tailpocket1:abc\n"))
        assertEquals("tailpocket1:abc", TailPocket.inviteText("myapp://pair?c=tailpocket1:abc&x=1"))
        assertNull(TailPocket.inviteText("https://example.com"))
    }
}
