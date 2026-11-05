package io.jingtao.tailpocket

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/** JVM tests with a fake native layer (the Go library is Android-only). */
class TailPocketTest {
    private class FakeNative(val pairResult: String = """{"error":"expired"}""") : TailPocketNative {
        var cancelled = mutableListOf<Long>()
        override fun newKey() = "privkey:1"
        override fun publicKey(key: String) = if (key == "privkey:1") "nodekey:1" else ""
        override fun decodeInvite(text: String, prefix: String) =
            if (text.startsWith(prefix)) """{"v":1,"address":"tcA","port":48932,"key":"privkey:x","proof":"p","expiresAt":9,"name":"Mac"}""" else """{"error":"invalid-invite"}"""
        override fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long) = pairResult
        override fun connect(link: String, derp: String) = """{"handle":4,"port":5555}"""
        override fun stop(handle: Long) {}
        override fun localPairStart(op: Long, address: String, label: String, device: String) = """{"code":"123456"}"""
        override fun localPairFinish(op: Long, timeoutMs: Long) = """{"v":1,"address":"tcB","port":48932,"key":"k","proof":"p","expiresAt":9}"""
        override fun cancel(op: Long) { cancelled += op }
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

    @Test fun connectGivesALocalUrl() {
        val tc = TailPocket.with(FakeNative())
        val c = tc.connect(TailPocketHostLink("tcM", 48931, "Mac", null, "privkey:1"))
        assertEquals("http://127.0.0.1:5555", c.baseUrl)
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
