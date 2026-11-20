package com.islandcompanion.suite.core.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainBlocklistEngineTest {

    @Test
    fun parseHostsOrDomainList_parsesStandardHostsAndPlainDomains() {
        val sample = """
            # Comment line
            ! AdGuard comment
            127.0.0.1 localhost
            0.0.0.0 ads.example.com
            127.0.0.1 tracker.analytics.net # inline comment
            ::1 telemetry.vendor.org
            *.pixel.adnetwork.io
            ||metrics.app.dev^
            plain.bad.domain.com.
            not_a_domain
        """.trimIndent()

        val parsed = DomainBlocklistEngine.parseHostsOrDomainList(sample)

        assertEquals(
            setOf(
                "ads.example.com",
                "tracker.analytics.net",
                "telemetry.vendor.org",
                "pixel.adnetwork.io",
                "metrics.app.dev",
                "plain.bad.domain.com",
            ),
            parsed,
        )
    }

    @Test
    fun isBlocked_matchesExactAndSubdomainsWithoutFalsePositives() {
        val engine = DomainBlocklistEngine(listOf("tracker.com", "ADS.Example.org."))

        assertTrue(engine.isBlocked("tracker.com"))
        assertTrue(engine.isBlocked("TRACKER.COM."))
        assertTrue(engine.isBlocked("sub.tracker.com"))
        assertTrue(engine.isBlocked("a.b.c.tracker.com"))
        assertTrue(engine.isBlocked("ads.example.org"))
        assertTrue(engine.isBlocked("cdn.ads.example.org"))

        // Must NOT falsely block unrelated suffixes or parent domains
        assertFalse(engine.isBlocked("nottracker.com"))
        assertFalse(engine.isBlocked("example.org"))
        assertFalse(engine.isBlocked(null))
        assertFalse(engine.isBlocked(""))
    }

    @Test
    fun addAndRemoveDomain_updatesMatchingImmediately() {
        val engine = DomainBlocklistEngine()
        assertFalse(engine.isBlocked("telemetry.test.io"))

        engine.addDomain("Telemetry.Test.IO.")
        assertTrue(engine.isBlocked("sub.telemetry.test.io"))
        assertEquals(1, engine.size)

        engine.removeDomain("telemetry.test.io")
        assertFalse(engine.isBlocked("sub.telemetry.test.io"))
        assertEquals(0, engine.size)
    }
}
