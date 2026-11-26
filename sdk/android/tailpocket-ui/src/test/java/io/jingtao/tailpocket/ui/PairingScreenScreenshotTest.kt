package io.jingtao.tailpocket.ui

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.unit.Density
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import io.jingtao.tailpocket.TailPocket
import io.jingtao.tailpocket.TailPocketNative
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO
import kotlin.math.abs
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Screenshot baselines of the pairing screen: light, dark with an error, a small screen, double-size text, and
 * the keyboard open over a pasted code. Each is drawn by Robolectric's native graphics and compared with
 * src/test/snapshots/<name>.png. TAILPOCKET_RECORD_SNAPSHOTS=1 writes the baselines instead; a mismatch writes
 * the actual image and a diff to build/snapshots/.
 *
 * Robolectric draws no keyboard, so the keyboard state gives the screen a 360 dp keyboard inset: what is
 * checked is how the screen lays itself out above it. The real keyboard is PairingScreenDeviceTest's.
 */
@Config(sdk = [35], qualifiers = "w360dp-h640dp-xhdpi")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
class PairingScreenScreenshotTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    /** Example data only: the screen never reaches the native library in these states. */
    private object NoNative : TailPocketNative {
        override fun decodeInvite(text: String, prefix: String) = error("unused")
        override fun pair(op: Long, invite: String, key: String, device: String, derp: String, timeoutMs: Long) = error("unused")
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

    private fun show(dark: Boolean = false, fontScale: Float = 1f) = compose.setContent {
        val density = LocalDensity.current
        CompositionLocalProvider(LocalDensity provides Density(density.density, fontScale)) {
            MaterialTheme(colorScheme = if (dark) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) {
                    TailPocketPairingScreen(phoneKey = "phone-key", onPaired = {}, device = "Example Phone", sdk = TailPocket.with(NoNative))
                }
            }
        }
    }

    @Test fun light() { show(); assertSnapshot("pairing-light") }

    // With an error, to see its colour on the dark theme.
    @Test fun dark() {
        show(dark = true)
        compose.onNodeWithTag(TAG_PASTE).performTextInput("not-a-code")
        compose.onNodeWithTag(TAG_PAIR).performClick()
        assertSnapshot("pairing-dark")
    }

    @Config(qualifiers = "w320dp-h568dp-xhdpi")
    @Test fun smallScreen() { show(); assertSnapshot("pairing-small") }

    @Test fun largeText() { show(fontScale = 2f); assertSnapshot("pairing-large-text") }

    // A small screen at double text size with the keyboard up (drawn grey), scrolled down to Pair: the field and
    // Pair must be above the keyboard.
    @Config(qualifiers = "w320dp-h568dp-xhdpi")
    @Test fun keyboardOpen() {
        show(fontScale = 2f)
        compose.onNodeWithTag(TAG_PASTE).performClick()
        compose.onNodeWithTag(TAG_PASTE).performTextInput("tailpocket1:EXAMPLE-INVITE")
        // The screen's own view: the window's decor would take the inset itself.
        val view = compose.activity.findViewById<android.view.ViewGroup>(android.R.id.content).getChildAt(0)
        keyboard = (360 * view.resources.displayMetrics.density).toInt()
        compose.runOnIdle {
            val insets = WindowInsetsCompat.Builder()
                .setInsets(WindowInsetsCompat.Type.ime(), Insets.of(0, 0, 0, keyboard))
                .setVisible(WindowInsetsCompat.Type.ime(), true)
                .build()
            ViewCompat.dispatchApplyWindowInsets(view, insets)
        }
        compose.onNodeWithTag(TAG_PAIR).performScrollTo()
        assertSnapshot("pairing-keyboard")
    }

    private var keyboard = 0

    private fun assertSnapshot(name: String) {
        // A still frame: the text cursor blinks with the clock.
        compose.waitForIdle()
        compose.mainClock.autoAdvance = false
        compose.mainClock.advanceTimeBy(100)
        val root = compose.activity.window.decorView
        val bitmap = Bitmap.createBitmap(root.width, root.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle {
            val canvas = Canvas(bitmap)
            root.draw(canvas)
            if (keyboard > 0) canvas.drawRect(0f, (root.height - keyboard).toFloat(), root.width.toFloat(), root.height.toFloat(), Paint().apply { color = Color.GRAY })
        }
        val pixels = IntArray(bitmap.width * bitmap.height).also { bitmap.getPixels(it, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height) }
        val actual = BufferedImage(bitmap.width, bitmap.height, BufferedImage.TYPE_INT_ARGB).apply { setRGB(0, 0, width, height, pixels, 0, width) }
        val baseline = File("src/test/snapshots/$name.png")
        if (System.getenv("TAILPOCKET_RECORD_SNAPSHOTS") == "1") {
            baseline.parentFile.mkdirs()
            ImageIO.write(actual, "png", baseline)
            return
        }
        if (!baseline.isFile) fail("no baseline $baseline: record it with TAILPOCKET_RECORD_SNAPSHOTS=1")
        val problem = compare(ImageIO.read(baseline), actual, File("build/snapshots/$name"))
        if (problem != null) fail("$name: $problem (actual and diff in build/snapshots/)")
    }

    companion object {
        /** A pixel differs when a channel is more than 16 off; up to 0.02% of the pixels may (anti-aliasing). */
        fun compare(expected: BufferedImage, actual: BufferedImage, out: File): String? {
            out.parentFile.mkdirs()
            if (expected.width != actual.width || expected.height != actual.height) {
                ImageIO.write(actual, "png", File("$out-actual.png"))
                return "size ${actual.width}x${actual.height}, baseline ${expected.width}x${expected.height}"
            }
            val diff = BufferedImage(actual.width, actual.height, BufferedImage.TYPE_INT_ARGB)
            var differing = 0
            for (y in 0 until actual.height) for (x in 0 until actual.width) {
                val a = expected.getRGB(x, y)
                val b = actual.getRGB(x, y)
                val off = (0..24 step 8).any { abs((a shr it and 0xff) - (b shr it and 0xff)) > 16 }
                if (off) differing++
                diff.setRGB(x, y, if (off) 0xffff0000.toInt() else (a and 0x00ffffff) or 0x30000000)
            }
            val allowed = actual.width * actual.height / 5000
            if (differing <= allowed) return null
            ImageIO.write(actual, "png", File("$out-actual.png"))
            ImageIO.write(diff, "png", File("$out-diff.png"))
            return "$differing pixels differ, at most $allowed allowed"
        }
    }
}
