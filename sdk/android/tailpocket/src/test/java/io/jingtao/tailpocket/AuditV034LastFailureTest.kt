package io.jingtao.tailpocket

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Audit of v0.3.4, PoC C. The Go library answers LastFailure with {code, reason, route, routes, at}
 * (connectmobile/mobile.go; the line below is its output for a refused lan address with an unanswered relay).
 * docs/INTEGRATE.md tells every app to pick its message by `reason`. The Kotlin SDK decodes only code, at and
 * route, so on Android `reason` and `routes` never reach a Kotlin app, nor an NSH or React Native app through
 * the bridge: there `reason` is undefined and the app cannot tell "not running or reset" from "this network
 * blocks it".
 */
class AuditV034LastFailureTest {
    private val fromGo =
        """{"at":1795300000001,"code":"unreachable","reason":"no-answer","route":"relay","routes":[{"r":"refused","t":"lan"},{"r":"no-answer","t":"relay"}]}"""

    @Test fun reasonAndRoutesReachTheApp() {
        val decoded = json.decodeFromString(TailPocketDialFailure.serializer(), fromGo)
        assertEquals("unreachable", decoded.code)
        // What tailPocket.lastFailure hands to JavaScript on Android (Bridge.kt: toValue(serializer, it)).
        val toTheApp = json.encodeToString(TailPocketDialFailure.serializer(), decoded)
        assertTrue("the bridge answer has no reason: $toTheApp", toTheApp.contains("\"reason\":\"no-answer\""))
        assertTrue("the bridge answer has no routes: $toTheApp", toTheApp.contains("\"routes\""))
    }
}
