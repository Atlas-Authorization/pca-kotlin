package net.atlasauth.pca.doctor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The native root-caveat probe: this library's own policy VM enforces a root `max_spend` outside the envelope and refuses an unknown root caveat type. */
class DoctorProbeTest {
    private val cap = linkedMapOf<String, Any?>("type" to "max_spend", "usd" to 100L)

    @Test fun aRootMaxSpendDeniesTheOverspendAndAllowsTheControl() {
        val over = Doctor.probeDecision(cap, 150.0)
        val under = Doctor.probeDecision(cap, 50.0)
        assertFalse(over.reasons.toString(), over.allowed)
        assertTrue(under.reasons.toString(), under.allowed)
    }

    @Test fun anUnknownRootCaveatTypeDenies() {
        assertFalse(Doctor.probeDecision(linkedMapOf<String, Any?>("type" to "pca-doctor-unknown-caveat"), 50.0).allowed)
    }

    @Test fun theDoctorPassesOnThisLibrary() {
        val r = Doctor.checkRootCaveats(linkedMapOf<String, Any?>(), Doctor.nativeLoader("0.5.0"))
        assertEquals(r.detail(), "pass", r.status())
    }
}
