package io.jingtao.tailpocket.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.LocalLifecycleOwner
import io.jingtao.tailpocket.TailPocket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

private const val CAMERA_PERMISSION_BLOCKED = "camera_permission_blocked"
private const val MAX_AMBIGUOUS_CAMERA_DENIALS = 2

/**
 * A camera preview that reports the first QR code containing invite text, once. Asks for the camera
 * permission itself; frames are decoded on the device and never stored.
 */
@Composable
fun TailPocketQrScanner(onInvite: (String) -> Unit, modifier: Modifier = Modifier, prefix: String = TailPocket.DEFAULT_PREFIX) =
    TailPocketQrScanner(prefixes = listOf(prefix), onInvite = onInvite, modifier = modifier)

/** As above, for the first QR code with invite text for any of [prefixes], such as a v1 and a v2 prefix. */
@Composable
fun TailPocketQrScanner(prefixes: List<String>, onInvite: (String) -> Unit, modifier: Modifier = Modifier) =
    TailPocketQrScanner(prefixes, onInvite, modifier, onPairNearby = null)

/** Offers [onPairNearby] as an alternative when camera permission is denied, if supplied. */
@Composable
fun TailPocketQrScanner(
    prefixes: List<String>,
    onInvite: (String) -> Unit,
    modifier: Modifier = Modifier,
    onPairNearby: (() -> Unit)?,
) {
    val context = LocalContext.current
    val activity = LocalActivity.current
    val permission = Manifest.permission.CAMERA
    fun hasCameraPermission() = ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    fun canShowRationale() = activity?.let { ActivityCompat.shouldShowRequestPermissionRationale(it, permission) }

    val preferences = remember(context) {
        context.applicationContext.getSharedPreferences("io.jingtao.tailpocket.ui", Context.MODE_PRIVATE)
    }
    var granted by remember { mutableStateOf(hasCameraPermission()) }
    var requested by rememberSaveable { mutableStateOf(false) }
    var rationaleBeforeRequest by rememberSaveable { mutableStateOf<Boolean?>(null) }
    var ambiguousDenials by rememberSaveable { mutableStateOf(0) }
    var permanentlyDenied by rememberSaveable { mutableStateOf(preferences.getBoolean(CAMERA_PERMISSION_BLOCKED, false)) }
    fun updatePermanentDenial(blocked: Boolean) {
        permanentlyDenied = blocked
        if (preferences.getBoolean(CAMERA_PERMISSION_BLOCKED, false) != blocked) {
            preferences.edit {
                if (blocked) putBoolean(CAMERA_PERMISSION_BLOCKED, true) else remove(CAMERA_PERMISSION_BLOCKED)
            }
        }
    }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { allowed ->
        granted = allowed
        val rationaleAfter = canShowRationale()
        updatePermanentDenial(isCameraPermissionPermanentlyDenied(allowed, rationaleBeforeRequest, rationaleAfter))
        ambiguousDenials = countAmbiguousCameraDenials(ambiguousDenials, allowed, rationaleBeforeRequest, rationaleAfter)
    }
    fun requestCamera() {
        requested = true
        rationaleBeforeRequest = canShowRationale()
        ask.launch(permission)
    }
    fun openAppSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "package:${context.packageName}".toUri())
        if (activity == null) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        (activity ?: context).startActivity(intent)
    }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        granted = hasCameraPermission()
        if (granted) {
            updatePermanentDenial(false)
            ambiguousDenials = 0
        }
    }
    LaunchedEffect(Unit) {
        if (!granted && !requested && !shouldOpenCameraSettings(permanentlyDenied, canShowRationale())) requestCamera()
    }
    if (!granted) {
        Column(
            modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(stringResource(R.string.tailpocket_camera_permission_required), textAlign = TextAlign.Center)
            Button(onClick = {
                if (shouldOpenCameraSettings(permanentlyDenied, canShowRationale(), ambiguousDenials)) {
                    openAppSettings()
                } else {
                    requestCamera()
                }
            }) { Text(stringResource(R.string.tailpocket_camera_allow)) }
            OutlinedButton(onClick = ::openAppSettings) { Text(stringResource(R.string.tailpocket_camera_open_settings)) }
            onPairNearby?.let {
                TextButton(onClick = it) { Text(stringResource(R.string.tailpocket_camera_pair_nearby)) }
            }
        }
        return
    }
    val owner = LocalLifecycleOwner.current
    val view = remember { PreviewView(context) }
    DisposableEffect(owner) {
        val worker = Executors.newSingleThreadExecutor()
        val reported = AtomicBoolean(false)
        val decoder = QrDecoder()
        val future = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        future.addListener({
            val cameras = runCatching { future.get() }.getOrNull() ?: return@addListener
            provider = cameras
            val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
            val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
            analysis.setAnalyzer(worker) { image ->
                try {
                    val plane = image.planes.firstOrNull()
                    val text = plane?.let { decoder.decode(it.buffer, image.width, image.height, it.rowStride, it.pixelStride) }
                    val invite = text?.let { TailPocket.inviteText(it, prefixes) }
                    if (invite != null && reported.compareAndSet(false, true)) ContextCompat.getMainExecutor(context).execute { onInvite(invite) }
                } catch (_: Exception) {
                } finally { image.close() }
            }
            val selector = if (cameras.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) CameraSelector.DEFAULT_BACK_CAMERA else CameraSelector.DEFAULT_FRONT_CAMERA
            runCatching { cameras.unbindAll(); cameras.bindToLifecycle(owner, selector, preview, analysis) }
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            runCatching { provider?.unbindAll() }
            worker.shutdown()
        }
    }
    AndroidView(factory = { view }, modifier = modifier.fillMaxSize())
}

internal fun isCameraPermissionPermanentlyDenied(granted: Boolean, rationaleBefore: Boolean?, rationaleAfter: Boolean?): Boolean =
    !granted && rationaleBefore == true && rationaleAfter == false

internal fun countAmbiguousCameraDenials(previousCount: Int, granted: Boolean, rationaleBefore: Boolean?, rationaleAfter: Boolean?): Int =
    if (!granted && rationaleBefore == false && rationaleAfter == false) {
        minOf(previousCount + 1, MAX_AMBIGUOUS_CAMERA_DENIALS)
    } else {
        0
    }

internal fun shouldOpenCameraSettings(permanentlyDenied: Boolean, canShowRationale: Boolean?, ambiguousDenials: Int = 0): Boolean =
    canShowRationale == false && (permanentlyDenied || ambiguousDenials >= MAX_AMBIGUOUS_CAMERA_DENIALS)
