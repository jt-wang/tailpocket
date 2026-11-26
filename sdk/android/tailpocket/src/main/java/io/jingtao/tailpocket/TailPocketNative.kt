package io.jingtao.tailpocket

import io.jingtao.tailpocket.connectmobile.Connectmobile

/** The string-only boundary to the Go library; see connectmobile/mobile.go for the contract. */
interface TailPocketNative {
    fun newKey(): String
    fun publicKey(key: String): String
    fun decodeInvite(text: String, prefix: String): String
    fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String
    fun connect(link: String, derp: String): String
    fun stop(handle: Long)
    fun localPairStart(op: Long, address: String, label: String, device: String): String
    fun localPairFinish(op: Long, timeoutMs: Long): String
    fun cancel(op: Long)
    // v0.3
    fun decodeInvite2(text: String, prefix: String): String
    fun pair2(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String
    // v0.3.0-pre.4: pair2 returns {"emoji":[…]} first; pair2Finish waits for the computer's answer.
    fun pair2Finish(op: Long, timeoutMs: Long): String
    fun setTailcatOnly(on: Boolean)
    // v0.3.2: comma-separated route types, "" for all; returns "" or {"error":"invalid-routes"}.
    fun setRoutes(routes: String): String
    fun sync(handle: Long, timeoutMs: Long): String
    fun link(handle: Long): String
    fun path(handle: Long, timeoutMs: Long): String
    // v0.3.4: why the handle's last connection attempt failed, {"code","reason","route","routes","at"} or {}.
    fun lastFailure(handle: Long): String
    // Push (connectmobile/push.go). The defaults keep other implementations of this interface compiling.
    fun pushNewKey(): String = UNSUPPORTED
    fun pushChallenge(gateway: String, app: String, timeoutMs: Long): String = UNSUPPORTED
    fun pushRegister(gateway: String, app: String, platform: String, token: String, generation: Long, attest: String, timeoutMs: Long): String = UNSUPPORTED
    fun pushRevoke(gateway: String, app: String, platform: String, token: String, generation: Long, attest: String, timeoutMs: Long): String = UNSUPPORTED
    fun pushGive(handle: Long, target: String, timeoutMs: Long): String = UNSUPPORTED
    fun pushClear(handle: Long, timeoutMs: Long): String = UNSUPPORTED
}

private const val UNSUPPORTED = """{"error":"unsupported"}"""

internal object GoNative : TailPocketNative {
    override fun newKey(): String = Connectmobile.newKey()
    override fun publicKey(key: String): String = Connectmobile.publicKey(key)
    override fun decodeInvite(text: String, prefix: String): String = Connectmobile.decodeInvite(text, prefix)
    override fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String =
        Connectmobile.pair(op, invite, key, device, derp, timeoutMs)
    override fun connect(link: String, derp: String): String = Connectmobile.connect(link, derp)
    override fun stop(handle: Long) = Connectmobile.stop(handle)
    override fun localPairStart(op: Long, address: String, label: String, device: String): String = Connectmobile.localPairStart(op, address, label, device)
    override fun localPairFinish(op: Long, timeoutMs: Long): String = Connectmobile.localPairFinish(op, timeoutMs)
    override fun cancel(op: Long) = Connectmobile.cancel(op)
    override fun decodeInvite2(text: String, prefix: String): String = Connectmobile.decodeInvite2(text, prefix)
    override fun pair2(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String =
        Connectmobile.pair2(op, invite, key, device, derp, timeoutMs)
    override fun pair2Finish(op: Long, timeoutMs: Long): String = Connectmobile.pair2Finish(op, timeoutMs)
    override fun setTailcatOnly(on: Boolean) = Connectmobile.setTailcatOnly(on)
    override fun setRoutes(routes: String): String = Connectmobile.setRoutes(routes)
    override fun sync(handle: Long, timeoutMs: Long): String = Connectmobile.sync(handle, timeoutMs)
    override fun link(handle: Long): String = Connectmobile.link(handle)
    override fun path(handle: Long, timeoutMs: Long): String = Connectmobile.path(handle, timeoutMs)
    override fun lastFailure(handle: Long): String = Connectmobile.lastFailure(handle)
    override fun pushNewKey(): String = Connectmobile.pushNewKey()
    override fun pushChallenge(gateway: String, app: String, timeoutMs: Long): String = Connectmobile.pushChallenge(gateway, app, timeoutMs)
    override fun pushRegister(gateway: String, app: String, platform: String, token: String, generation: Long, attest: String, timeoutMs: Long): String =
        Connectmobile.pushRegister(gateway, app, platform, token, generation, attest, timeoutMs)
    override fun pushRevoke(gateway: String, app: String, platform: String, token: String, generation: Long, attest: String, timeoutMs: Long): String =
        Connectmobile.pushRevoke(gateway, app, platform, token, generation, attest, timeoutMs)
    override fun pushGive(handle: Long, target: String, timeoutMs: Long): String = Connectmobile.pushGive(handle, target, timeoutMs)
    override fun pushClear(handle: Long, timeoutMs: Long): String = Connectmobile.pushClear(handle, timeoutMs)
}
