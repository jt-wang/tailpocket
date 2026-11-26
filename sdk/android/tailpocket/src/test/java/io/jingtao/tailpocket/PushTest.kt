package io.jingtao.tailpocket

import android.content.SharedPreferences
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** The push opening side against connectpush/testdata/vectors.json, and the phone's push flow over a fake native layer. */
class PushTest {
    private val vectors: JsonObject by lazy {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null && !File(dir, "connectpush/testdata/vectors.json").exists()) dir = dir.parentFile
        Json.parseToJsonElement(File(dir ?: error("connectpush/testdata/vectors.json not found above the working directory"), "connectpush/testdata/vectors.json").readText()).jsonObject
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content
    private fun JsonObject.l(k: String) = getValue(k).jsonPrimitive.long

    /** The sealing side, test-only: the format of docs/PUSH.md §2. */
    private fun seal(key: ByteArray, kid: String, app: String, nonce: ByteArray, note: TailPocketPushNote, tier: Int? = null): String {
        val js = json.encodeToString(TailPocketPushNote.serializer(), note).toByteArray()
        val t = tier ?: TailPocketPushCrypto.TIERS.first { js.size + 2 <= it }
        val pt = ByteArray(t).also { it[0] = (js.size shr 8).toByte(); it[1] = js.size.toByte(); js.copyInto(it, 2) }
        return sealPadded(key, kid, app, nonce, pt)
    }

    private fun sealPadded(key: ByteArray, kid: String, app: String, nonce: ByteArray, pt: ByteArray): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(TailPocketPushCrypto.aad(app.toByteArray(), kid.toByteArray()))
        }
        val raw = byteArrayOf(kid.length.toByte()) + kid.toByteArray() + nonce + c.doFinal(pt)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }

    @Test fun sealVectorsOpenAndAreReproduced() {
        val seals = vectors.getValue("seal").jsonArray.map { it.jsonObject }
        assertTrue(seals.size >= 3)
        for (v in seals) {
            val key = hex(v.s("key_hex"))
            val note = v.getValue("note").jsonObject
            assertArrayEquals(v.s("name"), hex(v.s("aad_hex")), TailPocketPushCrypto.aad(v.s("app").toByteArray(), v.s("kid").toByteArray()))
            assertEquals(v.s("name"), v.s("ct"), sealPadded(key, v.s("kid"), v.s("app"), hex(v.s("nonce_hex")), hex(v.s("plaintext_hex"))))
            val opened = TailPocketPushCrypto.open({ if (it == v.s("kid")) key else null }, v.s("app"), v.s("ct"), note.l("sent")) { 0 }
            assertEquals(v.s("kid"), opened.kid)
            assertEquals(note.l("seq"), opened.note.seq)
            assertEquals(note.l("sent"), opened.note.sent)
            assertEquals(note["title"]?.jsonPrimitive?.content ?: "", opened.note.title)
            assertEquals(note["body"]?.jsonPrimitive?.content ?: "", opened.note.body)
            assertEquals(note["url"]?.jsonPrimitive?.content ?: "", opened.note.url)
            assertEquals(v.l("ct_length").toInt(), v.s("ct").length)
        }
    }

    @Test fun rejectVectorsFailWithTheirError() {
        val rejects = vectors.getValue("reject").jsonArray.map { it.jsonObject }
        assertTrue(rejects.size >= 10)
        for (v in rejects) {
            val key = hex(v.s("key_hex"))
            try {
                TailPocketPushCrypto.open({ if (it == v.s("kid")) key else null }, v.s("app"), v.s("ct"), v.l("now")) { v.l("last") }
                fail("${v.s("name")} opened")
            } catch (e: TailPocketPushException) {
                assertEquals(v.s("name"), v.s("error"), e.code)
            }
        }
    }

    private val key = ByteArray(32) { (it + 1).toByte() }
    private val now = 1_790_000_000L
    private fun note(seq: Long, sent: Long = now, body: String = "Agent finished") = TailPocketPushNote(title = "Herdr", body = body, sent = sent, seq = seq)
    private fun ct(seq: Long, kid: String = "k1", app: String = "io.jingtao.herdr") = seal(key, kid, app, ByteArray(12) { seq.toByte() }, note(seq))
    private fun open(ct: String, last: Long = 0, app: String = "io.jingtao.herdr", at: Long = now) =
        TailPocketPushCrypto.open({ if (it == "k1") key else null }, app, ct, at) { last }

    private fun code(block: () -> Unit): String = try { block(); "opened" } catch (e: TailPocketPushException) { e.code }

    @Test fun eachCheckRefuses() {
        assertEquals(3L, open(ct(3), last = 2).note.seq)
        assertEquals("replay", code { open(ct(3), last = 3) })
        assertEquals("replay", code { open(ct(3), last = 4) })
        assertEquals("auth", code { open(ct(1), app = "io.jingtao.boop") })
        assertEquals("unknown_key", code { open(ct(1, kid = "k2")) })
        assertEquals("expired", code { open(ct(1), at = now + 24 * 3600 + 1) })
        assertEquals("opened", code { open(ct(1), at = now + 24 * 3600) })
        assertEquals("future", code { open(ct(1), at = now - 301) })
        assertEquals("opened", code { open(ct(1), at = now - 300) })
        assertEquals("too_large", code { open("A".repeat(3001)) })
        assertEquals("malformed", code { open(ct(1) + "=") })
        assertEquals("malformed", code { open(ct(1).replaceRange(5, 6, "+")) })
        assertEquals("invalid-app", code { open(ct(1), app = "") })
        // A stray bit in the last character decodes to the same bytes with a lenient decoder; strict refuses it.
        val c = ct(1)
        val last = c.last()
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val stray = alphabet[alphabet.indexOf(last) xor 1]
        assertEquals("malformed", code { open(c.dropLast(1) + stray) })
        // Every single changed byte fails.
        val raw = Base64.getUrlDecoder().decode(c)
        for (i in raw.indices) {
            val b = raw.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            assertTrue("byte $i", code { open(Base64.getUrlEncoder().withoutPadding().encodeToString(b)) } != "opened")
        }
    }

    @Test fun paddingIsChecked() {
        val js = json.encodeToString(TailPocketPushNote.serializer(), note(1)).toByteArray()
        fun padded(len: Int, fill: (ByteArray) -> Unit = {}) = ByteArray(256).also { it[0] = (len shr 8).toByte(); it[1] = len.toByte(); js.copyInto(it, 2); fill(it) }
        val nonce = ByteArray(12)
        assertEquals("opened", code { open(sealPadded(key, "k1", "io.jingtao.herdr", nonce, padded(js.size))) })
        assertEquals("malformed", code { open(sealPadded(key, "k1", "io.jingtao.herdr", nonce, padded(js.size) { it[255] = 1 })) })
        assertEquals("malformed", code { open(sealPadded(key, "k1", "io.jingtao.herdr", nonce, padded(255))) })
        assertEquals("malformed", code { open(sealPadded(key, "k1", "io.jingtao.herdr", nonce, ByteArray(300))) })
        // Each tier opens, and only those lengths.
        for ((len, tier) in listOf(10 to 256, 400 to 1024, 1500 to 2048)) {
            val c = seal(key, "k1", "io.jingtao.herdr", nonce, note(1, body = "x".repeat(len)))
            assertEquals(((1 + 2 + 12 + tier + 16) * 4 + 2) / 3, c.length)
            assertEquals("x".repeat(len), open(c).note.body)
        }
    }

    private class MemoryKeys : TailPocketPushKeys {
        val keys = ConcurrentHashMap<String, ByteArray>()
        override fun key(kid: String) = keys[kid]
        override fun saveKey(kid: String, key: ByteArray) { keys[kid] = key }
        override fun deleteKey(kid: String) { keys.remove(kid) }
    }

    private fun receiver(store: TailPocketKeystorePushStore, keys: TailPocketPushKeys) =
        TailPocketPushReceiver("io.jingtao.herdr", TailPocketPushPlaceholder("Herdr", "New activity"), keys, store) { now }

    /** SharedPreferences in memory. failCommits makes commit() fail, as a full disk would; readDelayMs slows reads. */
    private class MemoryPrefs : SharedPreferences {
        val map = HashMap<String, Any?>()
        @Volatile var failCommits = false
        @Volatile var commits = 0
        @Volatile var readDelayMs = 0L
        private fun <T> get(key: String?, def: T): T {
            @Suppress("UNCHECKED_CAST") val v = synchronized(map) { (map[key] ?: def) as T }
            if (readDelayMs > 0) Thread.sleep(readDelayMs)
            return v
        }
        override fun getAll(): MutableMap<String, *> = synchronized(map) { HashMap(map) }
        override fun getString(key: String?, defValue: String?): String? = get(key, defValue)
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = get(key, defValues)
        override fun getInt(key: String?, defValue: Int): Int = get(key, defValue)
        override fun getLong(key: String?, defValue: Long): Long = get(key, defValue)
        override fun getFloat(key: String?, defValue: Float): Float = get(key, defValue)
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = get(key, defValue)
        override fun contains(key: String?): Boolean = synchronized(map) { map.containsKey(key) }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            val ops = ArrayList<(HashMap<String, Any?>) -> Unit>()
            fun put(key: String?, value: Any?) = apply { ops += { m -> if (key != null) m[key] = value } }
            override fun putString(key: String?, value: String?) = put(key, value)
            override fun putStringSet(key: String?, values: MutableSet<String>?) = put(key, values)
            override fun putInt(key: String?, value: Int) = put(key, value)
            override fun putLong(key: String?, value: Long) = put(key, value)
            override fun putFloat(key: String?, value: Float) = put(key, value)
            override fun putBoolean(key: String?, value: Boolean) = put(key, value)
            override fun remove(key: String?) = apply { ops += { m -> m.remove(key) } }
            override fun clear() = apply { ops += { m -> m.clear() } }
            override fun commit(): Boolean {
                if (failCommits) return false
                synchronized(map) { ops.forEach { it(map) }; commits++ }
                return true
            }
            override fun apply() { commit() }
        }
    }

    private fun freshStore(): Pair<TailPocketKeystorePushStore, MemoryPrefs> {
        val prefs = MemoryPrefs()
        return TailPocketKeystorePushStore(prefs, "push-" + System.nanoTime()) to prefs
    }

    @Test fun receiverStoresSeqBeforeShowingAndRefusesReplays() {
        val (store, prefs) = freshStore()
        val keys = MemoryKeys().apply { keys["k1"] = key }
        val r = receiver(store, keys)
        val shown = r.receive(mapOf("tp" to ct(5)))
        assertEquals("Agent finished", shown.body)
        assertEquals(5L, shown.note?.seq)
        assertEquals(5L, store.last("k1"))
        val placeholder = TailPocketPushShown("Herdr", "New activity", null)
        assertEquals(placeholder, r.receive(mapOf("tp" to ct(5))))
        assertEquals(placeholder, r.receive(mapOf("tp" to ct(4))))
        assertEquals(placeholder, r.receive(mapOf("other" to "x")))
        assertEquals(placeholder, r.receive(mapOf("tp" to "junk")))
        assertEquals(6L, r.receive(mapOf("tp" to ct(6))).note?.seq)
        // A seq that cannot be saved is not shown, and the stored highest stays.
        prefs.failCommits = true
        assertEquals(placeholder, r.receive(mapOf("tp" to ct(7))))
        prefs.failCommits = false
        assertEquals(6L, store.last("k1"))
        assertEquals(7L, r.receive(mapOf("tp" to ct(7))).note?.seq)
    }

    @Test fun oneOfManyConcurrentDeliveriesOpens() {
        val name = "push-" + System.nanoTime()
        // Slow reads, so a missing lock lets several deliveries pass the same check.
        val prefs = MemoryPrefs().apply { readDelayMs = 20 }
        val keys = MemoryKeys().apply { keys["k1"] = key }
        val c = ct(9)
        val opened = AtomicInteger()
        val start = CountDownLatch(1)
        val threads = (1..16).map {
            // Separate stores with the same name share its lock, as an app and its service would.
            val r = receiver(TailPocketKeystorePushStore(prefs, name), keys)
            Thread { start.await(); if (r.receive(mapOf("tp" to c)).note != null) opened.incrementAndGet() }.apply { start() }
        }
        start.countDown()
        threads.forEach { it.join() }
        assertEquals(1, opened.get())
    }

    @Test fun storeKeepsGenerationAndSeq() {
        val (store, prefs) = freshStore()
        assertEquals(1L, store.generation("io.jingtao.herdr"))
        store.saveGeneration("io.jingtao.herdr", 4)
        assertEquals(4L, store.generation("io.jingtao.herdr"))
        assertEquals(1L, store.generation("io.jingtao.dsh"))
        assertEquals(0L, store.last("k1"))
        assertTrue(store.store("k1", 3))
        assertEquals(3L, store.last("k1"))
        val before = prefs.commits
        store.store("k1", 4)
        assertEquals(before + 1, prefs.commits)
    }

    @Test fun attestBindingMatchesGo() {
        // The same vector as connectpush/attest_test.go.
        assertEquals("sheS7aeIcwOE_y7yGLnYIxbFa7mWPSMvt3jDBZY0N4Q", TailPocketPushAttest.requestHash("register", "io.jingtao.herdr", "apns", "ab01", 7, "CHALLENGE"))
        assertEquals("sheS7aeIcwOE_y7yGLnYIxbFa7mWPSMvt3jDBZY0N4Q=", TailPocketPushAttest.classicNonce("register", "io.jingtao.herdr", "apns", "ab01", 7, "CHALLENGE"))
        assertEquals("tailpocket push attest 1\nrevoke\na\nfcm\nt\n12\nc", String(TailPocketPushAttest.clientData("revoke", "a", "fcm", "t", 12, "c")))
        assertEquals("""{"challenge":"c\"1","token":"t"}""", TailPocketPushAttest.integrityEvidence("c\"1", "t"))
    }

    /** The gateway and computer as the Go library would answer them. */
    private class PushNative : TailPocketNative {
        override fun newKey() = ""
        override fun publicKey(key: String) = ""
        override fun decodeInvite(text: String, prefix: String) = ""
        override fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long) = ""
        override fun connect(link: String, derp: String) = """{"handle":4,"port":5555,"token":"TOK","base":"/_tailpocket/TOK"}"""
        override fun stop(handle: Long) {}
        override fun localPairStart(op: Long, address: String, label: String, device: String) = ""
        override fun localPairFinish(op: Long, timeoutMs: Long) = ""
        override fun cancel(op: Long) {}
        override fun decodeInvite2(text: String, prefix: String) = ""
        override fun pair2(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long) = ""
        override fun pair2Finish(op: Long, timeoutMs: Long) = ""
        override fun setTailcatOnly(on: Boolean) {}
        override fun setRoutes(routes: String) = ""
        override fun lastFailure(handle: Long) = "{}"
        override fun sync(handle: Long, timeoutMs: Long) = ""
        override fun link(handle: Long) = ""
        override fun path(handle: Long, timeoutMs: Long) = ""

        var minGeneration = 1L
        val calls = mutableListOf<String>()
        var giveResult = "{}"
        override fun pushNewKey() = """{"kid":"KID${calls.size}","key":"${Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })}"}"""
        override fun pushChallenge(gateway: String, app: String, timeoutMs: Long) = """{"challenge":"CH"}"""
        override fun pushRegister(gateway: String, app: String, platform: String, token: String, generation: Long, attest: String, timeoutMs: Long): String {
            calls += "register $generation $attest"
            return if (generation < minGeneration) """{"error":"stale-generation","minGeneration":$minGeneration}""" else """{"handle":"H$generation","expires":99}"""
        }
        override fun pushRevoke(gateway: String, app: String, platform: String, token: String, generation: Long, attest: String, timeoutMs: Long): String {
            calls += "revoke $generation $attest"
            minGeneration = generation + 1
            return "{}"
        }
        override fun pushGive(handle: Long, target: String, timeoutMs: Long): String { calls += "give $target"; return giveResult }
        override fun pushClear(handle: Long, timeoutMs: Long): String { calls += "clear"; return "{}" }
    }

    private class MemoryPushStore : TailPocketPushStore {
        val keys = HashMap<String, ByteArray>()
        val generations = HashMap<String, Long>()
        override fun key(kid: String) = keys[kid]
        override fun saveKey(kid: String, key: ByteArray) { keys[kid] = key }
        override fun deleteKey(kid: String) { keys.remove(kid) }
        override fun generation(app: String) = generations[app] ?: 1
        override fun saveGeneration(app: String, generation: Long) { generations[app] = generation }
    }

    @Test fun phoneRegistersGivesAndRevokes() = runTest {
        val native = PushNative()
        val sdk = TailPocket.with(native)
        val store = MemoryPushStore()
        val phone = TailPocketPushPhone(sdk, store)
        val reg = phone.register("https://push.example.com", "io.jingtao.herdr", "TOKEN")
        assertEquals(TailPocketPushRegistration("H1", 99), reg)
        val conn = sdk.connect(TailPocketHostLink(name = "Mac", key = "k"))
        val kid = phone.give(conn, "https://push.example.com", "io.jingtao.herdr", reg)
        assertEquals(32, store.keys[kid]?.size)
        assertTrue(native.calls.last(), native.calls.last().startsWith("give ") && native.calls.last().contains("\"handle\":\"H1\"") && native.calls.last().contains("\"kid\":\"$kid\""))

        // Removing a computer: revoke at 1, register at 2, and the removed computer's key is gone.
        val reg2 = phone.revoke("https://push.example.com", "io.jingtao.herdr", "TOKEN", kid)
        assertEquals("H2", reg2.handle)
        assertNull(store.keys[kid])
        assertEquals(2L, store.generation("io.jingtao.herdr"))
        assertEquals(listOf("revoke 1 ", "register 2 "), native.calls.takeLast(2))

        // A refused give leaves no key behind.
        native.giveResult = """{"error":"push-refused","reason":"gateway-not-allowed"}"""
        try { phone.give(conn, "https://push.example.com", "io.jingtao.herdr", reg2); fail() } catch (e: TailPocketException) {
            assertEquals("push-refused", e.code)
            assertEquals("gateway-not-allowed", e.reason)
        }
        assertTrue(store.keys.isEmpty())
    }

    @Test fun phoneFollowsStaleGenerationOnce() = runTest {
        val native = PushNative().apply { minGeneration = 5 }
        val store = MemoryPushStore()
        val phone = TailPocketPushPhone(TailPocket.with(native), store)
        assertEquals("H5", phone.register("https://push.example.com", "a", "T").handle)
        assertEquals(5L, store.generation("a"))
        assertEquals(listOf("register 1 ", "register 5 "), native.calls)
    }

    @Test fun phoneBindsIntegrityToTheRequest() = runTest {
        val native = PushNative()
        val asked = mutableListOf<Pair<String, String>>()
        val phone = TailPocketPushPhone(TailPocket.with(native), MemoryPushStore()) { hash, nonce -> asked += hash to nonce; "ITOKEN" }
        phone.register("https://push.example.com", "io.jingtao.herdr", "TOKEN")
        val hash = TailPocketPushAttest.requestHash("register", "io.jingtao.herdr", "fcm", "TOKEN", 1, "CH")
        assertEquals(listOf(hash to "$hash="), asked)
        assertEquals("register 1 {\"challenge\":\"CH\",\"token\":\"ITOKEN\"}", native.calls.single())
    }

    @Test fun bridgeKeepsPushKeysNative() = runTest {
        val native = PushNative()
        val store = MemoryPushStore()
        val bridge = TailPocketBridge(TailPocket.with(native), object : TailPocketLinkStore {
            override fun phoneKey() = "privkey:1"
            override fun saveLink(link: TailPocketHostLink, slot: String) {}
            override fun link(slot: String): TailPocketHostLink? = TailPocketHostLink(name = "Mac", key = "k")
            override fun deleteLink(slot: String) {}
        }, { error("no nearby") }, pushStore = store)
        @Suppress("UNCHECKED_CAST")
        val reg = bridge.call("tailPocket.push.register", mapOf("gateway" to "https://push.example.com", "app" to "a", "token" to "T")) as Map<String, Any?>
        assertEquals("H1", reg["handle"])
        @Suppress("UNCHECKED_CAST")
        val c = bridge.call("tailPocket.connect", emptyMap()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val given = bridge.call("tailPocket.push.give", mapOf("handle" to c["handle"], "gateway" to "https://push.example.com", "app" to "a", "pushHandle" to "H1")) as Map<String, Any?>
        assertEquals(setOf("kid"), given.keys)
        val kid = given["kid"] as String
        assertTrue(store.keys.containsKey(kid))
        bridge.call("tailPocket.push.clear", mapOf("handle" to c["handle"], "kid" to kid))
        assertTrue(store.keys.isEmpty())
        assertEquals("clear", native.calls.last())
        val noPush = TailPocketBridge(TailPocket.with(native), object : TailPocketLinkStore {
            override fun phoneKey() = ""
            override fun saveLink(link: TailPocketHostLink, slot: String) {}
            override fun link(slot: String): TailPocketHostLink? = null
            override fun deleteLink(slot: String) {}
        }, { error("no nearby") })
        try { noPush.call("tailPocket.push.forget", mapOf("kid" to "x")); fail() } catch (e: TailPocketException) { assertEquals("unsupported", e.code) }
    }
}
