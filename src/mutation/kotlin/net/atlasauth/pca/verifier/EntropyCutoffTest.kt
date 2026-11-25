package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The adaptive-proportion cutoff is exact integer arithmetic (the old float recurrence underflowed for a large window and switched the test off). */
class EntropyCutoffTest {
    @Test fun theExactCutoffs() {
        assertEquals(1107.0, Entropy.proportionCutoff(1.0, 2000.0), 0.0)
        assertEquals(13.0, Entropy.proportionCutoff(8.0, 512.0), 0.0)
        assertEquals(410.0, Entropy.proportionCutoff(0.5, 512.0), 0.0)
    }

    @Test fun aDomainOutsideTheRuleIsRefusedNeverRounded() {
        val bad = listOf(Pair(1.1, 512.0), Pair(0.0, 512.0), Pair(0.0625, 512.0), Pair(64.125, 512.0), Pair(Double.NaN, 512.0), Pair(8.0, 1.0), Pair(8.0, 512.5), Pair(8.0, 65537.0), Pair(8.0, Double.NaN))
        for ((h, w) in bad) {
            try {
                Entropy.proportionCutoff(h, w)
                fail("h=$h w=$w must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue("h=$h w=$w", e.message!!.startsWith("proportionCutoff: "))
            }
        }
    }

    @Test fun aHealthTestWithAHThatIsNotAnEighthFails() {
        val bytes = ByteArray(1024) { (it * 7).toByte() }
        assertEquals("repetition-count", Entropy.healthTestBytes(bytes, 7.3, 512.0).test)
        assertFalse(Entropy.healthTestBytes(bytes, 7.3, 512.0).ok)
    }

    @Test fun theWindowClampsToTheBufferAndASingleByteWindowSkipsTheProportionTest() {
        val varied = ByteArray(600) { (it * 31 + it / 7).toByte() }
        assertTrue(Entropy.healthTestBytes(varied, 8.0, 100000.0).ok)
        assertTrue(Entropy.healthTestBytes(byteArrayOf(5), 8.0, 512.0).ok)
    }

    @Test fun aConstantBufferFailsTheProportionOrRepetitionTest() {
        assertFalse(Entropy.healthTestBytes(ByteArray(600) { 9 }, 8.0, 512.0).ok)
    }
}
