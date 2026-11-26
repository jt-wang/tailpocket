package io.jingtao.tailpocket.ui

import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

// SDK 36 sandboxes need Java 21; the build targets Java 17.
@Config(sdk = [35])
@RunWith(RobolectricTestRunner::class)
class PairingScreenRestoreTest {
    @get:Rule val compose = createComposeRule()

    @Test fun scannerSurvivesActivityRecreation() {
        val restoration = StateRestorationTester(compose)
        restoration.setContent { TailPocketPairingScreen(phoneKey = "phone-key", onPaired = {}) }
        val scannerText = ApplicationProvider.getApplicationContext<android.content.Context>()
            .getString(R.string.tailpocket_camera_permission_required)

        compose.onNodeWithText("Scan QR code").performClick()
        compose.onNodeWithText(scannerText).assertExists()

        restoration.emulateSavedInstanceStateRestore()

        compose.onNodeWithText(scannerText).assertExists()
        compose.onNodeWithText("Scan QR code").assertDoesNotExist()
    }
}
