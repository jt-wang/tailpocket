package io.jingtao.tailpocket

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Play Integrity tokens for [TailPocketPushPhone], bound to each register or revoke request (docs/PUSH.md §7).
 *
 * The SDK only compiles against Play Integrity: an app that uses this class adds
 * `implementation("com.google.android.play:integrity:1.4.0")` itself (apps outside Google Play do not need it).
 * [standard] is Google's recommended request (the token provider is prepared once and reused; the request hash
 * carries the binding); [classic] puts the binding in the nonce. Either failing throws [TailPocketException]
 * "integrity-failed".
 */
class TailPocketPlayIntegrity private constructor(
    private val standardManager: StandardIntegrityManager?,
    private val classicManager: IntegrityManager?,
    private val cloudProjectNumber: Long?,
) : TailPocketIntegrityTokens {
    private val mutex = Mutex()
    private var provider: StandardIntegrityTokenProvider? = null

    override suspend fun token(requestHash: String, classicNonce: String): String = try {
        if (standardManager != null) standardToken(standardManager, requestHash) else classicToken(classicManager!!, classicNonce)
    } catch (e: TailPocketException) {
        throw e
    } catch (e: Exception) {
        throw TailPocketException("integrity-failed")
    }

    private suspend fun standardToken(manager: StandardIntegrityManager, requestHash: String): String {
        val request = StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()
        val first = prepared(manager, renew = false)
        return try {
            first.request(request).await().token()
        } catch (_: Exception) {
            // A provider stops working after a while (or after Play services update): prepare a new one, once.
            prepared(manager, renew = true).request(request).await().token()
        }
    }

    private suspend fun prepared(manager: StandardIntegrityManager, renew: Boolean): StandardIntegrityTokenProvider = mutex.withLock {
        if (!renew) provider?.let { return@withLock it }
        manager.prepareIntegrityToken(PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber!!).build()).await()
            .also { provider = it }
    }

    private suspend fun classicToken(manager: IntegrityManager, nonce: String): String {
        val builder = IntegrityTokenRequest.builder().setNonce(nonce)
        cloudProjectNumber?.let { builder.setCloudProjectNumber(it) }
        return manager.requestIntegrityToken(builder.build()).await().token()
    }

    companion object {
        /** Standard requests. [cloudProjectNumber] is the Google Cloud project linked in Play Console (App integrity). */
        fun standard(context: Context, cloudProjectNumber: Long) =
            TailPocketPlayIntegrity(IntegrityManagerFactory.createStandard(context.applicationContext), null, cloudProjectNumber)

        /** Classic requests; [cloudProjectNumber] is needed only for an app not distributed through Google Play. */
        fun classic(context: Context, cloudProjectNumber: Long? = null) =
            TailPocketPlayIntegrity(null, IntegrityManagerFactory.create(context.applicationContext), cloudProjectNumber)
    }
}

private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { c ->
    addOnSuccessListener { c.resume(it) }
    addOnFailureListener { c.resumeWithException(it) }
}
