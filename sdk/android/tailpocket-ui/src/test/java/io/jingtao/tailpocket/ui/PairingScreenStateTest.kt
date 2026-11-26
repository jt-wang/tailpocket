package io.jingtao.tailpocket.ui

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import io.jingtao.tailpocket.TailPocket
import io.jingtao.tailpocket.TailPocketHostLink
import io.jingtao.tailpocket.TailPocketNative
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

// The pairing screen's empty, busy and error states, told apart by what is shown and which buttons work.
@Config(sdk = [35])
@RunWith(RobolectricTestRunner::class)
class PairingScreenStateTest {
    @get:Rule val compose = createComposeRule()

    private val invite = "tailpocket1:sample"
    private val paired = mutableListOf<TailPocketHostLink>()

    /** decodeInvite accepts [invite]; pair waits for [release], then answers [answer]. */
    private class Native(var answer: String) : TailPocketNative {
        @Volatile var release = CountDownLatch(1)
        override fun decodeInvite(text: String, prefix: String) =
            if (text == "tailpocket1:sample") """{"v":1,"address":"tcAAAA","port":48932,"key":"k","proof":"p","expiresAt":4102444800,"name":"Studio Mac"}"""
            else """{"error":"invalid-invite"}"""
        override fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long): String {
            release.await(30, TimeUnit.SECONDS)
            return answer
        }
        override fun cancel(op: Long) {}
        override fun newKey() = error("unused")
        override fun publicKey(key: String) = error("unused")
        override fun connect(link: String, derp: String) = error("unused")
        override fun stop(handle: Long) = error("unused")
        override fun localPairStart(op: Long, address: String, label: String, device: String) = error("unused")
        override fun localPairFinish(op: Long, timeoutMs: Long) = error("unused")
        override fun decodeInvite2(text: String, prefix: String) = error("unused")
        override fun pair2(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long) = error("unused")
        override fun pair2Finish(op: Long, timeoutMs: Long) = error("unused")
        override fun setTailcatOnly(on: Boolean) = error("unused")
        override fun setRoutes(routes: String) = error("unused")
        override fun sync(handle: Long, timeoutMs: Long) = error("unused")
        override fun link(handle: Long) = error("unused")
        override fun path(handle: Long, timeoutMs: Long) = error("unused")
        override fun lastFailure(handle: Long) = error("unused")
    }

    private fun show(native: Native) = compose.setContent {
        TailPocketPairingScreen(phoneKey = "phone-key", onPaired = { paired += it }, sdk = TailPocket.with(native))
    }

    private fun assertIdle(error: String?) {
        compose.onNodeWithTag(TAG_BUSY).assertDoesNotExist()
        compose.onNodeWithTag(TAG_STATUS).assertDoesNotExist()
        if (error == null) compose.onNodeWithTag(TAG_ERROR).assertDoesNotExist()
        else compose.onNodeWithTag(TAG_ERROR).assertTextEquals(error)
        compose.onNodeWithText("Scan QR code").assertIsEnabled()
    }

    private fun paste(text: String) {
        compose.onNodeWithTag(TAG_PASTE).performTextInput(text)
        compose.onNodeWithTag(TAG_PAIR).performClick()
    }

    @Test fun emptyScreenOffersScanAndWaitsForAPastedCode() {
        show(Native(""))
        assertIdle(error = null)
        compose.onNodeWithTag(TAG_PAIR).assertIsNotEnabled()
    }

    @Test fun textWithoutACodeIsAnErrorAndCanBeRetried() {
        show(Native(""))
        paste("https://example.com")
        assertIdle(error = "That is not a pairing code.")
        compose.onNodeWithTag(TAG_PAIR).assertIsEnabled()
        assertEquals(emptyList<TailPocketHostLink>(), paired)
    }

    @Test fun pairingIsBusyThenReturnsTheLink() {
        val native = Native("""{"address":"tcLINK","port":48932,"name":"Studio Mac","key":"k"}""")
        show(native)
        paste(invite)
        compose.onNodeWithTag(TAG_STATUS).assertTextEquals("Pairing with Studio Mac…")
        compose.onNodeWithTag(TAG_BUSY).assertExists()
        compose.onNodeWithTag(TAG_ERROR).assertDoesNotExist()
        compose.onNodeWithTag(TAG_PAIR).assertIsNotEnabled()
        compose.onNodeWithText("Scan QR code").assertIsNotEnabled()

        native.release.countDown()
        compose.waitUntil(10_000) { paired.isNotEmpty() }
        compose.waitForIdle()
        assertEquals(listOf("Studio Mac"), paired.map { it.name })
        assertIdle(error = null)
    }

    @Test fun aRefusedPairingIsAnErrorNotBusyAndClearsOnRetry() {
        val native = Native("""{"error":"expired"}""")
        show(native)
        native.release.countDown()
        paste(invite)
        compose.waitUntil(10_000) { compose.onAllNodesWithTagCount(TAG_ERROR) == 1 }
        assertIdle(error = "This pairing code has expired. Show a new one on the computer.")
        assertEquals(emptyList<TailPocketHostLink>(), paired)

        // Retrying clears the old error while the new attempt runs.
        native.answer = """{"error":"taken"}"""
        native.release = CountDownLatch(1)
        compose.onNodeWithTag(TAG_PAIR).performClick()
        compose.onNodeWithTag(TAG_BUSY).assertExists()
        compose.onNodeWithTag(TAG_ERROR).assertDoesNotExist()
        native.release.countDown()
        compose.waitUntil(10_000) { runCatching { compose.onNodeWithTag(TAG_ERROR).assertTextEquals("Another phone already used this code.") }.isSuccess }
        assertIdle(error = "Another phone already used this code.")
    }
}

private fun androidx.compose.ui.test.junit4.ComposeContentTestRule.onAllNodesWithTagCount(tag: String) =
    onAllNodes(androidx.compose.ui.test.hasTestTag(tag)).fetchSemanticsNodes().size
