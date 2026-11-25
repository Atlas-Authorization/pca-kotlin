package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** A freshness bound that is NaN must refuse, never pass: NaN compares false, so each check is the negation of its positive condition. */
class FailClosedClosenessTest {
    private val issued = Json.Num("1000")

    @Test fun aFreshNonceIsAccepted() {
        assertNull(Attestation.nonceAgeReason(issued, 1500.0, 0.0, 1000.0))
    }

    @Test fun aNaNClockSkewOrAgeBoundRefuses() {
        assertEquals("nonce issued in the future", Attestation.nonceAgeReason(issued, Double.NaN, 0.0, 1000.0))
        assertEquals("nonce issued in the future", Attestation.nonceAgeReason(issued, 1500.0, Double.NaN, 1000.0))
        assertEquals("attestation nonce expired (stale quote)", Attestation.nonceAgeReason(issued, 1500.0, 0.0, Double.NaN))
    }

    @Test fun aMissingOrNonNumericIssueTimeRefuses() {
        for (bad in listOf<Any?>(null, "x", true, Json.Num("NaN"))) {
            assertEquals("$bad", "server nonce issue time unknown (cannot establish freshness)", Attestation.nonceAgeReason(bad, 1500.0, 0.0, 1000.0))
        }
    }
}
