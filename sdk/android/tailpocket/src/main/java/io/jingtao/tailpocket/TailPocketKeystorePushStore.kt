package io.jingtao.tailpocket

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.withLock

/**
 * The phone's push state in private SharedPreferences (credential-encrypted storage, readable after the first
 * unlock): push keys wrapped with an AES key in the Android Keystore that needs no user authentication (so
 * `FirebaseMessagingService` can open notes while the phone is locked), the highest seq per key id, and the
 * generation per app.
 *
 * Every write is commit(), not apply(): a seq is on disk before the note is shown. The lock is per process,
 * because SharedPreferences does not see another process's writes: run the `FirebaseMessagingService` in the
 * app's own process (the default; no `android:process`).
 */
class TailPocketKeystorePushStore internal constructor(private val prefs: SharedPreferences, name: String) : TailPocketPushStore, TailPocketPushSeqs {
    constructor(context: Context, name: String = "tailpocket.push") : this(context.applicationContext.getSharedPreferences(name, Context.MODE_PRIVATE), name)

    private val alias = "$name.aes"
    private val lock = locks.getOrPut(name) { ReentrantLock() }

    override fun key(kid: String): ByteArray? = read("key.$kid")?.takeIf { it.size == 32 }

    override fun saveKey(kid: String, key: ByteArray) {
        require(key.size == 32) { "a push key is 32 bytes" }
        write("key.$kid", key)
    }

    // The seq stays: a kid is random and never comes back, and keeping it costs a few bytes.
    override fun deleteKey(kid: String) = check(prefs.edit().remove("key.$kid").commit()) { "could not save" }

    override fun generation(app: String): Long = prefs.getLong("generation.$app", 1L).coerceAtLeast(1L)

    override fun saveGeneration(app: String, generation: Long) =
        check(prefs.edit().putLong("generation.$app", generation).commit()) { "could not save" }

    override fun <T> locked(block: () -> T): T = lock.withLock(block)

    override fun last(kid: String): Long = prefs.getLong("seq.$kid", 0L)

    override fun store(kid: String, seq: Long): Boolean = prefs.edit().putLong("seq.$kid", seq).commit()

    private fun wrapKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        // No setUserAuthenticationRequired: the key must work while the phone is locked.
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build())
        }.generateKey()
    }

    private fun write(slot: String, value: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, wrapKey()) }
        val sealed = cipher.iv + cipher.doFinal(value)
        check(prefs.edit().putString(slot, Base64.getEncoder().encodeToString(sealed)).commit()) { "could not save" }
    }

    private fun read(slot: String): ByteArray? {
        val sealed = prefs.getString(slot, null)?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() } ?: return null
        if (sealed.size < 12 + 16) return null
        return runCatching {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, sealed, 0, 12)) }
            cipher.doFinal(sealed, 12, sealed.size - 12)
        }.getOrNull()
    }

    private companion object {
        val locks = ConcurrentHashMap<String, ReentrantLock>()
    }
}
