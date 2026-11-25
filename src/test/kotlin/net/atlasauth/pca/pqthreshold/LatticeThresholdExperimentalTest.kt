package net.atlasauth.pca.pqthreshold

import net.atlasauth.pca.pqthreshold.LatticeThresholdExperimental.ExperimentalOptIn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger

/** The experimental lattice-threshold toy: opt-in gate, the additive n-of-n sharing and its reconstruction, the design as data. */
class LatticeThresholdExperimentalTest {
    private val ok = ExperimentalOptIn(true)
    private val key = listOf(5L, 8380416L, 0L, 123456L).map { BigInteger.valueOf(it) }

    @Test fun everyRoutineNeedsTheExplicitOptIn() {
        for (opt in listOf(null, ExperimentalOptIn(false))) {
            try { LatticeThresholdExperimental.additiveShareLatticeKey(key, 3, opt); fail() } catch (e: IllegalStateException) { assertTrue(e.message!!.startsWith(LatticeThresholdExperimental.EXPERIMENTAL_BANNER)) }
            try { LatticeThresholdExperimental.reconstructLatticeKey(emptyList(), opt); fail() } catch (e: IllegalStateException) { assertTrue(e.message!!.endsWith("Pass { iUnderstandThisIsNotProduction: true } to proceed.")) }
        }
    }

    @Test fun theSharesSumToTheKeyAndAllOfThemAreNeeded() {
        var next = 1L
        val shares = LatticeThresholdExperimental.additiveShareLatticeKey(key, 4, ok, sampler = { q -> BigInteger.valueOf(next++ * 1000003L).mod(q) })
        assertEquals(listOf(1, 2, 3, 4), shares.map { it.index })
        assertEquals(key, LatticeThresholdExperimental.reconstructLatticeKey(shares, ok))
        assertTrue(LatticeThresholdExperimental.reconstructLatticeKey(shares.dropLast(1), ok) != key)
        // the default sampler also reconstructs
        val rnd = LatticeThresholdExperimental.additiveShareLatticeKey(key, 3, ok)
        assertEquals(key, LatticeThresholdExperimental.reconstructLatticeKey(rnd, ok))
        for (s in rnd) for (c in s.coeffs) assertTrue(c.signum() >= 0 && c < LatticeThresholdExperimental.TOY_DEFAULT_PARAMS.q)
    }

    @Test fun badArgumentsAreRefused() {
        for (n in listOf(0, 1025)) try { LatticeThresholdExperimental.additiveShareLatticeKey(key, n, ok); fail() } catch (e: IllegalArgumentException) { assertEquals("additiveShareLatticeKey: n must be an integer in [1, 1024]", e.message) }
        try { LatticeThresholdExperimental.additiveShareLatticeKey(key.take(3), 2, ok); fail() } catch (e: IllegalArgumentException) { assertEquals("additiveShareLatticeKey: key must have 4 coefficients", e.message) }
        val s = LatticeThresholdExperimental.additiveShareLatticeKey(key, 2, ok)
        try { LatticeThresholdExperimental.reconstructLatticeKey(listOf(s[0], s[0]), ok); fail() } catch (e: IllegalArgumentException) { assertEquals("reconstructLatticeKey: duplicate share index", e.message) }
        try { LatticeThresholdExperimental.reconstructLatticeKey(emptyList(), ok); fail() } catch (e: IllegalArgumentException) { assertEquals("reconstructLatticeKey: need at least one share", e.message) }
    }

    @Test fun theDesignIsDataThatSaysItIsNotProduction() {
        val d = LatticeThresholdExperimental.RACCOON_DESIGN
        assertEquals(false, d["productionReady"])
        assertEquals("research-prototype", d["status"])
        assertEquals(LatticeThresholdExperimental.EXPERIMENTAL_BANNER, d["banner"])
        assertEquals(5, (d["construction"] as List<*>).size)
        assertEquals(2, (d["parameterSets"] as List<*>).size)
    }
}
