package io.jingtao.tailpocket.ui

import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.unit.toSize
import androidx.compose.ui.layout.positionInWindow
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The pairing screen on a device (nightly, on an emulator): the pasted-code field and Pair stay above the
 * keyboard, and at a small size with normal and doubled font scale nothing is cut off, misaligned, off
 * the edge or spread apart.
 */
@RunWith(AndroidJUnit4::class)
class PairingScreenDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    // The screen under a 240 dp app header in an edge-to-edge window, with the real keyboard; at font scale 1
    // and 2. Sized for the nightly emulator (320x640 dp, keyboard top at 381 dp): 141 dp between header and
    // keyboard, so the field and Pair fit only by scrolling inside imePadding; without it Pair lands under the
    // keyboard. The old header, 55% of the height, left 29 dp there, less than the field itself (56 dp).
    @Test fun pasteFieldAndPairStayAboveTheKeyboard() = keyboard(fontScale = 1f)

    @Test fun pasteFieldAndPairStayAboveTheKeyboardLargeText() = keyboard(fontScale = 2f)

    private fun keyboard(fontScale: Float) {
        compose.activityRule.scenario.onActivity { it.enableEdgeToEdge() }
        compose.setContent {
            val d = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(d.density, fontScale)) {
                MaterialTheme {
                    Surface(Modifier.fillMaxSize()) {
                        Column {
                            Spacer(Modifier.height(240.dp))
                            TailPocketPairingScreen(phoneKey = "phone-key", onPaired = {}, modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            }
        }
        compose.onNodeWithTag(TAG_PASTE).performClick()
        val view = compose.activity.window.decorView
        compose.waitUntil(10_000) { imeBottom(view) > 0 }
        settle()
        compose.onNodeWithTag(TAG_PASTE).assertVisible(view, "the paste field at font scale $fontScale")
        compose.onNodeWithTag(TAG_PAIR).performScrollTo()
        settle()
        compose.onNodeWithTag(TAG_PAIR).assertVisible(view, "Pair at font scale $fontScale")

        // A wrong code sent from down here, twice: each time the error scrolls into view.
        compose.onNodeWithTag(TAG_PASTE).performTextInput("https://example.com")
        repeat(2) { attempt ->
            compose.onNodeWithTag(TAG_PAIR).performScrollTo().performClick()
            settle()
            compose.onNodeWithTag(TAG_ERROR).assertVisible(view, "the error after attempt ${attempt + 1} at font scale $fontScale")
        }
    }

    private fun settle() {
        compose.waitForIdle()
        Thread.sleep(600) // the keyboard's slide and the scroll
        compose.waitForIdle()
    }

    /** With the keyboard up: wholly shown (not clipped by a scrolling parent) and between the status bar and the keyboard. */
    private fun androidx.compose.ui.test.SemanticsNodeInteraction.assertVisible(view: android.view.View, what: String) {
        // The keyboard must still be up: with it gone, everything would fit and the check would prove nothing.
        val ime = imeBottom(view)
        assertTrue("$what: the keyboard is not showing", ime > 0)
        val insets = ViewCompat.getRootWindowInsets(view)
        val top = insets?.getInsets(WindowInsetsCompat.Type.statusBars())?.top ?: 0
        val bottom = view.height - ime
        val node = fetchSemanticsNode()
        val r = node.unclippedBounds()
        val shown = node.boundsInWindow // after every parent's clipping, such as the screen's own scroll area
        assertTrue("$what is at ${r.top}..${r.bottom} but shown at ${shown.top}..${shown.bottom}, visible $top..$bottom",
            shown.height >= r.height - 1 && shown.top >= top && shown.bottom <= bottom)
    }

    @Test fun smallScreenLayout() = smallScreen(fontScale = 1f)

    @Test fun smallScreenLayoutLargeText() = smallScreen(fontScale = 2f)

    private fun smallScreen(fontScale: Float) {
        compose.setContent {
            val d = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(d.density, fontScale)) {
                MaterialTheme {
                    Surface {
                        // iPhone SE / small Android phone width and height
                        Box(Modifier.size(320.dp, 568.dp)) {
                            TailPocketPairingScreen(phoneKey = "phone-key", onPaired = {}, service = "_tailpocket-test._tcp")
                        }
                    }
                }
            }
        }
        compose.waitForIdle()
        val root = compose.onRoot().fetchSemanticsNode().unclippedBounds()
        val width = with(compose.density) { 320.dp.toPx() }
        val nodes = compose.onRoot(useUnmergedTree = true).fetchSemanticsNode().descendants()
        val texts = nodes.filter { it.config.getOrNull(SemanticsProperties.Text) != null }
        assertTrue("no text found", texts.isNotEmpty())
        for (n in texts) {
            val layouts = mutableListOf<TextLayoutResult>()
            n.config.getOrNull(SemanticsActions.GetTextLayoutResult)?.action?.invoke(layouts)
            val name = n.config[SemanticsProperties.Text].joinToString()
            // Cut off: more lines than allowed, an ellipsis, or text taller than its box. (hasVisualOverflow
            // compares against the paragraph's full max width, so it reports short text too.)
            layouts.firstOrNull()?.let { t ->
                val cut = t.multiParagraph.didExceedMaxLines || (0 until t.lineCount).any(t::isLineEllipsized) ||
                    t.multiParagraph.height > t.size.height + 1
                assertTrue("\"$name\" is cut off at font scale $fontScale", !cut)
            }
            // Unclipped: a parent that clips would hide text that runs off the screen from boundsInRoot.
            val b = n.unclippedBounds()
            assertTrue("\"$name\" runs past the edge at font scale $fontScale (${b.left}..${b.right}, screen ${root.left}..${root.left + width})",
                b.left >= root.left - 1 && b.right <= root.left + width + 1)
        }
        // Scan, the paste field and Pair start at the same left edge.
        val lefts = listOf("Scan QR code", TAG_PASTE, TAG_PAIR).map { key ->
            val node = if (key == "Scan QR code") compose.onButton(key) else compose.onNodeWithTag(key)
            node.fetchSemanticsNode().boundsInRoot.left
        }
        assertEquals("left edges at font scale $fontScale: $lefts", 1, lefts.map { Math.round(it) }.distinct().size)
        // No gap between Scan, the field and Pair larger than the screen's 12 dp spacing plus rounding.
        val boxes = listOf(compose.onButton("Scan QR code"), compose.onNodeWithTag(TAG_PASTE), compose.onNodeWithTag(TAG_PAIR))
            .map { it.fetchSemanticsNode().boundsInRoot }
        val gap = with(compose.density) { 24.dp.toPx() }
        boxes.zipWithNext().forEach { (a, b) ->
            assertTrue("gap ${b.top - a.bottom}px between controls at font scale $fontScale", b.top - a.bottom in 0f..gap)
        }
    }

    private fun androidx.compose.ui.test.junit4.ComposeTestRule.onButton(text: String) =
        onNode(androidx.compose.ui.test.hasText(text) and androidx.compose.ui.test.hasClickAction())

    private fun imeBottom(view: android.view.View) =
        ViewCompat.getRootWindowInsets(view)?.getInsets(WindowInsetsCompat.Type.ime())?.bottom ?: 0
}

/** Where the node is laid out in the window, without its parents' clipping. */
private fun SemanticsNode.unclippedBounds(): Rect = layoutInfo.coordinates.let { Rect(it.positionInWindow(), it.size.toSize()) }

private fun SemanticsNode.descendants(): List<SemanticsNode> = children.flatMap { listOf(it) + it.descendants() }
