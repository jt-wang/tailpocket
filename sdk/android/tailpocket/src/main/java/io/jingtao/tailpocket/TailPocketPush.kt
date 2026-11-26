package io.jingtao.tailpocket

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// Push (docs/PUSH.md): opening sealed notes in FirebaseMessagingService, the push-key and seq stores it
// needs, Play Integrity evidence, and the phone's register / give / revoke flow. Opening uses only
// javax.crypto (AES/GCM, minSdk 26), not the Go library.

/** A push note once opened: what the computer sent. [sent] is unix seconds on the computer's clock. */
@Serializable
data class TailPocketPushNote(
    val title: String = "",
    val body: String = "",
    val thread: String = "",
    val url: String = "",
    val kind: String = "",
    val sent: Long = 0,
    val seq: Long = 0,
)

/**
 * A note that did not open. [code] is one of: too_large, malformed, unknown_key, auth, expired, future, replay
 * (the names of testdata/vectors.json), invalid-app, or store-failed (the new seq could not be saved).
 */
class TailPocketPushException(val code: String) : Exception(code)

/** What the phone gets when a note opens: the note and the key id it was sealed under. */
data class TailPocketPushOpened(val note: TailPocketPushNote, val kid: String)

/** The sealed-note format of docs/PUSH.md §2, opening side. */
object TailPocketPushCrypto {
    const val LABEL = "tailpocket push 1"
    const val MAX_CIPHERTEXT = 3000
    const val MAX_KID = 64
    const val MAX_AGE_SECONDS = 24 * 3600L
    const val MAX_SKEW_SECONDS = 5 * 60L
    val TIERS = listOf(256, 1024, 2048)
    private const val NONCE = 12
    private const val TAG = 16

    /** "tailpocket push 1" || 0x00 || app || 0x00 || kid. */
    fun aad(app: ByteArray, kid: ByteArray): ByteArray = LABEL.toByteArray() + 0 + app + 0 + kid

    /**
     * Opens [ct] sealed for [app]. [keys] gives the 32-byte push key for a key id (null if none); [last] the
     * highest seq already accepted for a key id (0 if none). Every check of PUSH.md §2 "Opening" must pass, or it
     * throws [TailPocketPushException] and returns nothing of the note. The caller stores the returned seq as the
     * new highest for the kid before showing the note, under the same lock as the call: [TailPocketPushReceiver]
     * does both.
     */
    fun open(keys: (kid: String) -> ByteArray?, app: String, ct: String, nowSeconds: Long, last: (kid: String) -> Long): TailPocketPushOpened {
        val appBytes = app.toByteArray(Charsets.UTF_8)
        if (appBytes.isEmpty() || appBytes.size > 255 || appBytes.contains(0)) throw TailPocketPushException("invalid-app")
        if (ct.length > MAX_CIPHERTEXT) throw TailPocketPushException("too_large")
        val raw = decodeStrict(ct) ?: throw TailPocketPushException("malformed")
        if (raw.isEmpty()) throw TailPocketPushException("malformed")
        val k = raw[0].toInt() and 0xff
        if (k == 0 || k > MAX_KID || raw.size < 1 + k + NONCE) throw TailPocketPushException("malformed")
        val kidBytes = raw.copyOfRange(1, 1 + k)
        val sealed = raw.size - 1 - k - NONCE
        if (kidBytes.contains(0) || (sealed - TAG) !in TIERS) throw TailPocketPushException("malformed")
        val kid = utf8(kidBytes) ?: throw TailPocketPushException("malformed")
        val key = keys(kid)?.takeIf { it.size == 32 } ?: throw TailPocketPushException("unknown_key")
        val pt = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG * 8, raw, 1 + k, NONCE))
                updateAAD(aad(appBytes, kidBytes))
                doFinal(raw, 1 + k + NONCE, sealed)
            }
        } catch (_: GeneralSecurityException) {
            throw TailPocketPushException("auth")
        }
        val js = unpad(pt) ?: throw TailPocketPushException("malformed")
        val note = try {
            json.decodeFromString(TailPocketPushNote.serializer(), utf8(js) ?: throw TailPocketPushException("malformed"))
        } catch (e: TailPocketPushException) {
            throw e
        } catch (_: Exception) {
            throw TailPocketPushException("malformed")
        }
        // sent is the computer's clock and the phone's may be off: a backstop. seq is what stops a replay.
        if (note.sent < nowSeconds - MAX_AGE_SECONDS) throw TailPocketPushException("expired")
        if (note.sent > nowSeconds + MAX_SKEW_SECONDS) throw TailPocketPushException("future")
        if (note.seq <= last(kid)) throw TailPocketPushException("replay")
        return TailPocketPushOpened(note, kid)
    }

    /** uint16_be(n) || json(n) || zeros to a tier: the JSON, or null for a bad length or a non-zero pad byte. */
    private fun unpad(pt: ByteArray): ByteArray? {
        if (pt.size !in TIERS) return null
        val n = ((pt[0].toInt() and 0xff) shl 8) or (pt[1].toInt() and 0xff)
        if (n > pt.size - 2) return null
        for (i in 2 + n until pt.size) if (pt[i] != 0.toByte()) return null
        return pt.copyOfRange(2, 2 + n)
    }

    /** base64url without padding, only A-Z a-z 0-9 - _, and no stray bits in the last character (as Go's Strict). */
    private fun decodeStrict(s: String): ByteArray? {
        if (s.any { !(it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_') }) return null
        val raw = try { Base64.getUrlDecoder().decode(s) } catch (_: IllegalArgumentException) { return null }
        return raw.takeIf { Base64.getUrlEncoder().withoutPadding().encodeToString(it) == s }
    }

    private fun utf8(b: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(b)).toString()
    } catch (_: CharacterCodingException) { null }
}

/** Push keys by key id, readable by the code that opens notes. [TailPocketKeystorePushStore] is the Android one. */
interface TailPocketPushKeys {
    fun key(kid: String): ByteArray?
    fun saveKey(kid: String, key: ByteArray)
    fun deleteKey(kid: String)
}

/**
 * The highest seq accepted per key id. [locked] runs its block under a lock that every reader and writer of
 * this store takes (other threads and, where the store supports it, other processes); [store] must be durable
 * when it returns true.
 */
interface TailPocketPushSeqs {
    fun <T> locked(block: () -> T): T
    fun last(kid: String): Long
    fun store(kid: String, seq: Long): Boolean
}

/** The fixed text a notification shows when a note does not open: the same as the gateway's placeholder for the app. */
data class TailPocketPushPlaceholder(val title: String, val body: String)

/** What to show for a push: the opened [note], or the placeholder text with [note] null. */
data class TailPocketPushShown(val title: String, val body: String, val note: TailPocketPushNote?, val kid: String? = null)

/**
 * Opens pushes in `FirebaseMessagingService.onMessageReceived`:
 *
 * ```
 * override fun onMessageReceived(message: RemoteMessage) {
 *     val shown = receiver.receive(message.data)
 *     // post a notification with shown.title / shown.body (and shown.note?.thread, url, kind when it opened)
 * }
 * ```
 *
 * The seq check and store happen under [seqs]'s lock, and the new seq is stored (commit()) before [receive]
 * returns the note. Any failure gives the placeholder and never any of the note.
 */
class TailPocketPushReceiver(
    /** The gateway app id, exactly as registered. */
    private val app: String,
    private val placeholder: TailPocketPushPlaceholder,
    private val keys: TailPocketPushKeys,
    private val seqs: TailPocketPushSeqs,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    /** For an FCM data message ([RemoteMessage.getData]): the note in "tp", or the placeholder. Never throws. */
    fun receive(data: Map<String, String>): TailPocketPushShown {
        val ct = data["tp"] ?: return shownPlaceholder()
        return try {
            val opened = open(ct)
            TailPocketPushShown(opened.note.title.ifEmpty { placeholder.title }, opened.note.body.ifEmpty { placeholder.body }, opened.note, opened.kid)
        } catch (_: Exception) {
            shownPlaceholder()
        }
    }

    /** Opens [ct] and stores its seq as the highest for its kid; throws [TailPocketPushException] on any failure. */
    fun open(ct: String): TailPocketPushOpened = seqs.locked {
        val opened = TailPocketPushCrypto.open({ keys.key(it) }, app, ct, nowSeconds()) { seqs.last(it) }
        if (!seqs.store(opened.kid, opened.note.seq)) throw TailPocketPushException("store-failed")
        opened
    }

    private fun shownPlaceholder() = TailPocketPushShown(placeholder.title, placeholder.body, null)
}

/** Binding of attestation evidence to a register or revoke request (docs/PUSH.md §7). */
object TailPocketPushAttest {
    const val LABEL = "tailpocket push attest 1"

    /** "tailpocket push attest 1\nop\napp\nplatform\ntoken\ngeneration\nchallenge", op "register" or "revoke". */
    fun clientData(op: String, app: String, platform: String, token: String, generation: Long, challenge: String): ByteArray =
        listOf(LABEL, op, app, platform, token, generation.toString(), challenge).joinToString("\n").toByteArray(Charsets.UTF_8)

    /** The Play Integrity request hash (standard request): base64url without padding of SHA-256 of [clientData]. */
    fun requestHash(op: String, app: String, platform: String, token: String, generation: Long, challenge: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(clientData(op, app, platform, token, generation, challenge)))

    /** The same hash as a classic request's nonce (URL-safe base64 with padding, as Play Integrity asks for). */
    fun classicNonce(op: String, app: String, platform: String, token: String, generation: Long, challenge: String): String =
        requestHash(op, app, platform, token, generation, challenge) + "="

    /** The evidence JSON the gateway takes for Play Integrity: {"challenge","token"}. */
    fun integrityEvidence(challenge: String, integrityToken: String): String =
        JsonObject(mapOf("challenge" to JsonPrimitive(challenge), "token" to JsonPrimitive(integrityToken))).toString()
}

/**
 * Gets a Play Integrity token bound to one request: a standard request passes [requestHash] to `setRequestHash`, a
 * classic request [classicNonce] to `setNonce`. [TailPocketPlayIntegrity] does either with Play's IntegrityManager.
 */
fun interface TailPocketIntegrityTokens {
    suspend fun token(requestHash: String, classicNonce: String): String
}

/** Where the phone keeps its push state: keys (for the receiver), and per app the generation and the handle. */
interface TailPocketPushStore : TailPocketPushKeys {
    /** The phone's generation for [app]; 1 before the first registration. */
    fun generation(app: String): Long
    fun saveGeneration(app: String, generation: Long)
}

/**
 * The phone's side of push (docs/PUSH.md §1): register the device token, give each computer its own push key
 * with the handle, and revoke every handle when a computer is removed.
 */
class TailPocketPushPhone(
    private val sdk: TailPocket,
    private val store: TailPocketPushStore,
    /** For an app whose gateway checks Play Integrity; null for a gateway in strict mode. */
    private val integrity: TailPocketIntegrityTokens? = null,
) {
    /**
     * Registers [token] ("fcm" platform) with [gateway] for [app] at the stored generation and returns the handle.
     * A gateway that has seen a higher generation answers stale-generation: this moves to it and tries once more.
     */
    suspend fun register(gateway: String, app: String, token: String, platform: String = "fcm", timeoutMs: Long = 30_000): TailPocketPushRegistration {
        var generation = store.generation(app)
        repeat(2) { attempt ->
            try {
                return sdk.pushRegister(gateway, app, platform, token, generation, evidence(gateway, "register", app, platform, token, generation, timeoutMs), timeoutMs)
            } catch (e: TailPocketException) {
                val min = e.minGeneration
                if (e.code != "stale-generation" || min == null || min <= generation || attempt == 1) throw e
                generation = min
                store.saveGeneration(app, generation)
            }
        }
        throw TailPocketException("failed")
    }

    /**
     * Makes a push key for the computer of [connection], stores it, and gives it with [registration]'s handle.
     * Returns the key id: keep it with the computer's link and pass it to [forget] when the computer is removed.
     */
    suspend fun give(connection: TailPocketConnection, gateway: String, app: String, registration: TailPocketPushRegistration, timeoutMs: Long = 30_000): String {
        val k = sdk.pushNewKey()
        val key = Base64.getUrlDecoder().decode(k.key)
        store.saveKey(k.kid, key)
        try {
            connection.givePush(TailPocketPushTarget(gateway, app, registration.handle, k.kid, k.key), timeoutMs)
        } catch (e: Exception) {
            store.deleteKey(k.kid)
            throw e
        }
        return k.kid
    }

    /**
     * After a computer is removed: makes every handle given so far stop working at the gateway (revoke at the
     * current generation), deletes [kid]'s key, and registers again at generation + 1. Give the returned handle
     * to the computers that stay, each with [give].
     */
    suspend fun revoke(gateway: String, app: String, token: String, kid: String?, platform: String = "fcm", timeoutMs: Long = 30_000): TailPocketPushRegistration {
        val generation = store.generation(app)
        sdk.pushRevoke(gateway, app, platform, token, generation, evidence(gateway, "revoke", app, platform, token, generation, timeoutMs), timeoutMs)
        store.saveGeneration(app, generation + 1)
        kid?.let { forget(it) }
        return register(gateway, app, token, platform, timeoutMs)
    }

    /** Deletes a computer's push key: notes sealed with it no longer open. */
    fun forget(kid: String) = store.deleteKey(kid)

    private suspend fun evidence(gateway: String, op: String, app: String, platform: String, token: String, generation: Long, timeoutMs: Long): String? {
        val integrity = integrity ?: return null
        val challenge = sdk.pushChallenge(gateway, app, timeoutMs)
        val tok = integrity.token(
            TailPocketPushAttest.requestHash(op, app, platform, token, generation, challenge),
            TailPocketPushAttest.classicNonce(op, app, platform, token, generation, challenge),
        )
        return TailPocketPushAttest.integrityEvidence(challenge, tok)
    }
}
