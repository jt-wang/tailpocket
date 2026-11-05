package io.jingtao.tailpocket.reactnative

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import com.facebook.react.uimanager.ViewManager
import io.jingtao.tailpocket.TailPocketBridge
import io.jingtao.tailpocket.TailPocketException
import io.jingtao.tailpocket.ui.TailPocketQrScanActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** `NativeModules.TailPocket`: every bridge function through one `call(name, args)`. */
class TailPocketModule(private val context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val bridge = TailPocketBridge.create(
        context,
        scanner = { prefix -> TailPocketQrScanActivity.scan(context.currentActivity ?: context, prefix) },
        emit = { event, data ->
            context.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java).emit(event, toJs(data))
        },
    )

    override fun getName() = "TailPocket"

    @ReactMethod
    fun call(name: String, args: ReadableMap?, promise: Promise) {
        scope.launch {
            try {
                promise.resolve(toJs(bridge.call(name, args?.toHashMap())))
            } catch (e: TailPocketException) {
                promise.reject(e.code, e.code, e)
            } catch (e: Exception) {
                promise.reject("failed", e.message, e)
            }
        }
    }

    // NativeEventEmitter calls these.
    @ReactMethod fun addListener(eventName: String) {}
    @ReactMethod fun removeListeners(count: Double) {}

    override fun invalidate() {
        bridge.close()
        scope.cancel()
        super.invalidate()
    }

    private fun toJs(value: Any?): Any? = when (value) {
        is Map<*, *> -> map(value)
        is List<*> -> array(value)
        is Number -> value.toDouble()
        else -> value
    }

    private fun map(value: Map<*, *>): WritableMap = Arguments.createMap().apply {
        for ((k, v) in value) {
            val key = k.toString()
            when (val js = toJs(v)) {
                null -> putNull(key)
                is String -> putString(key, js)
                is Double -> putDouble(key, js)
                is Boolean -> putBoolean(key, js)
                is WritableMap -> putMap(key, js)
                is WritableArray -> putArray(key, js)
                else -> putString(key, js.toString())
            }
        }
    }

    private fun array(value: List<*>): WritableArray = Arguments.createArray().apply {
        for (v in value) {
            when (val js = toJs(v)) {
                null -> pushNull()
                is String -> pushString(js)
                is Double -> pushDouble(js)
                is Boolean -> pushBoolean(js)
                is WritableMap -> pushMap(js)
                is WritableArray -> pushArray(js)
                else -> pushString(js.toString())
            }
        }
    }
}

class TailPocketPackage : ReactPackage {
    override fun createNativeModules(context: ReactApplicationContext): List<NativeModule> = listOf(TailPocketModule(context))
    override fun createViewManagers(context: ReactApplicationContext): List<ViewManager<*, *>> = emptyList()
}
