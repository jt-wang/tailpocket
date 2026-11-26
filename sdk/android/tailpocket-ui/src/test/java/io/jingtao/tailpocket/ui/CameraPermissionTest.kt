package io.jingtao.tailpocket.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CameraPermissionTest {
    @Test fun dismissedFirstPromptRetries() {
        assertFalse(opensSettingsAfterRequest(granted = false, rationaleBefore = false, rationaleAfter = false))
    }

    @Test fun firstDenialRetries() {
        assertFalse(opensSettingsAfterRequest(granted = false, rationaleBefore = false, rationaleAfter = true))
    }

    @Test fun secondDenialOpensSettings() {
        assertTrue(opensSettingsAfterRequest(granted = false, rationaleBefore = true, rationaleAfter = false))
    }

    @Test fun dismissedSecondPromptRetries() {
        assertFalse(opensSettingsAfterRequest(granted = false, rationaleBefore = true, rationaleAfter = true))
    }

    @Test fun grantDoesNotRecordPermanentDenial() {
        assertFalse(opensSettingsAfterRequest(granted = true, rationaleBefore = true, rationaleAfter = false))
    }

    @Test fun alreadyBlockedWithoutHistoryFallsBackAfterOneRetry() {
        val first = countAmbiguousCameraDenials(0, granted = false, rationaleBefore = false, rationaleAfter = false)
        assertFalse(shouldOpenCameraSettings(permanentlyDenied = false, canShowRationale = false, ambiguousDenials = first))
        val second = countAmbiguousCameraDenials(first, granted = false, rationaleBefore = false, rationaleAfter = false)
        assertTrue(shouldOpenCameraSettings(permanentlyDenied = false, canShowRationale = false, ambiguousDenials = second))
    }

    @Test fun aRecordedPermanentDenialOpensSettingsWithoutAnotherRequest() {
        assertTrue(shouldOpenCameraSettings(permanentlyDenied = true, canShowRationale = false))
    }

    @Test fun restoredRationaleOverridesARecordedPermanentDenial() {
        assertFalse(shouldOpenCameraSettings(permanentlyDenied = true, canShowRationale = true))
    }

    @Test fun unknownRationaleDoesNotOpenSettings() {
        assertFalse(shouldOpenCameraSettings(permanentlyDenied = true, canShowRationale = null))
    }

    private fun opensSettingsAfterRequest(granted: Boolean, rationaleBefore: Boolean, rationaleAfter: Boolean): Boolean =
        shouldOpenCameraSettings(
            isCameraPermissionPermanentlyDenied(granted, rationaleBefore, rationaleAfter),
            rationaleAfter,
            countAmbiguousCameraDenials(0, granted, rationaleBefore, rationaleAfter),
        )
}
