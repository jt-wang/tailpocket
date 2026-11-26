package io.jingtao.tailpocket.ui

import android.Manifest
import android.app.Application
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.core.app.ActivityOptionsCompat
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

// The scanner's camera-denied page: Allow asks again or opens Settings, Open Settings opens the app's
// settings page, Pair nearby calls back. The permission prompt is a fake registry that records each
// request and answers it.
@Config(sdk = [35])
@RunWith(RobolectricTestRunner::class)
class CameraDeniedScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val app = ApplicationProvider.getApplicationContext<Application>()
    private fun text(id: Int) = app.getString(id)
    private val deniedText get() = text(R.string.tailpocket_camera_permission_required)

    /** Records each camera request; answers it with [answer] (and grants or keeps denying the permission). */
    private inner class Prompt : ActivityResultRegistry() {
        val requests = mutableListOf<Any?>()
        var answer = false
        var beforeAnswer: () -> Unit = {}
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {
            requests += input
            if (answer) shadowOf(app).grantPermissions(Manifest.permission.CAMERA)
            beforeAnswer()
            dispatchResult(requestCode, answer)
        }
    }

    private val prompt = Prompt()
    private var nearby = 0

    @Before fun denyCamera() {
        shadowOf(app).denyPermissions(Manifest.permission.CAMERA)
        rationale(false)
        app.getSharedPreferences("io.jingtao.tailpocket.ui", Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun rationale(show: Boolean) =
        shadowOf(app.packageManager).setShouldShowRequestPermissionRationale(Manifest.permission.CAMERA, show)

    /** Whether the scanner is on screen: false, then true, takes it away and opens it anew (app data kept, its own state not). */
    private val mounted = androidx.compose.runtime.mutableStateOf(true)

    private fun show(withNearby: Boolean = true) = compose.setContent {
        CompositionLocalProvider(LocalActivityResultRegistryOwner provides object : ActivityResultRegistryOwner {
            override val activityResultRegistry = prompt
        }) {
            if (mounted.value) TailPocketQrScanner(prefixes = listOf("tailpocket1:"), onInvite = {}, onPairNearby = if (withNearby) ({ nearby++ }) else null)
        }
    }

    private fun startedActivity(): Intent? = shadowOf(compose.activity).nextStartedActivity

    private fun assertSettingsOpened() {
        val intent = startedActivity()
        assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, intent?.action)
        assertEquals("package:${app.packageName}", intent?.dataString)
    }

    @Test fun firstOpenAsksOnceThenShowsTheDeniedPage() {
        show()
        compose.waitForIdle()
        assertEquals(listOf(Manifest.permission.CAMERA), prompt.requests)
        compose.onNodeWithText(deniedText).assertExists()
        assertNull(startedActivity())
    }

    @Test fun allowAsksAgainThenOpensSettingsOnceAskingCannotWork() {
        show()
        compose.waitForIdle() // first request, denied: one ambiguous denial
        compose.onNodeWithText(text(R.string.tailpocket_camera_allow)).performClick()
        assertEquals(2, prompt.requests.size) // asked again, denied again: two
        assertNull(startedActivity())
        compose.onNodeWithText(text(R.string.tailpocket_camera_allow)).performClick()
        assertEquals(2, prompt.requests.size) // the system would no longer show a prompt
        assertSettingsOpened()
    }

    @Test fun allowWhenGrantedLeavesTheDeniedPage() {
        show()
        compose.waitForIdle()
        prompt.answer = true
        try {
            compose.onNodeWithText(text(R.string.tailpocket_camera_allow)).performClick()
            compose.waitForIdle()
            compose.onNodeWithText(deniedText).assertDoesNotExist()
            // The real scanner is up now and CameraX starts on its own threads. Wait for that to finish, or it
            // runs into the next test's launch (seen as lightZ Infinity there, 2 in 15 runs). A start that
            // finished by failing is fine (there is no camera here); a timeout or an interrupt fails the test.
            try {
                ProcessCameraProvider.getInstance(ApplicationProvider.getApplicationContext()).get(CAMERAX_WAIT_SECONDS, TimeUnit.SECONDS)
            } catch (_: ExecutionException) {
            }
        } finally {
            mounted.value = false
            compose.waitForIdle()
        }
    }

    @Test fun openSettingsOpensTheAppsSettingsWithoutAsking() {
        show()
        compose.waitForIdle()
        compose.onNodeWithText(text(R.string.tailpocket_camera_open_settings)).performClick()
        assertSettingsOpened()
        assertEquals(1, prompt.requests.size)
    }

    @Test fun pairNearbyCallsBackOnce() {
        show()
        compose.waitForIdle()
        compose.onNodeWithText(text(R.string.tailpocket_camera_pair_nearby)).performClick()
        assertEquals(1, nearby)
        assertNull(startedActivity())
        assertEquals(1, prompt.requests.size)
    }

    @Test fun pairNearbyIsOfferedOnlyWithACallback() {
        show(withNearby = false)
        compose.waitForIdle()
        compose.onNodeWithText(deniedText).assertExists()
        compose.onNodeWithText(text(R.string.tailpocket_camera_pair_nearby)).assertDoesNotExist()
    }

    // Denied with "Don't ask again" (a rationale before the prompt, none after): Allow goes to Settings,
    // also on the next open (the denial is remembered).
    @Test fun permanentDenialSendsAllowToSettings() {
        rationale(true)
        prompt.beforeAnswer = { rationale(false) }
        show()
        compose.waitForIdle()
        assertEquals(1, prompt.requests.size)
        compose.onNodeWithText(text(R.string.tailpocket_camera_allow)).performClick()
        assertEquals(1, prompt.requests.size)
        assertSettingsOpened()

        // The scanner closed and opened again: it neither asks by itself nor on Allow.
        compose.runOnIdle { mounted.value = false }
        compose.waitForIdle()
        compose.runOnIdle { mounted.value = true }
        compose.waitForIdle()
        compose.onNodeWithText(deniedText).assertExists()
        assertEquals(1, prompt.requests.size)
        compose.onNodeWithText(text(R.string.tailpocket_camera_allow)).performClick()
        assertEquals(1, prompt.requests.size)
        assertSettingsOpened()
    }
}

private const val CAMERAX_WAIT_SECONDS = 10L
