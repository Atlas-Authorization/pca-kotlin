package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mutation kills for `Risk`: the sign of a clamped zero and a non-finite cost, leak rate or debit counting as none. */
class RiskEdgeKillTest {
    @Test fun aNegativeZeroIsNotClampedToPositiveZero() {
        assertEquals(java.lang.Double.doubleToRawLongBits(-0.0), java.lang.Double.doubleToRawLongBits(Risk.clamp01(-0.0)))
        assertEquals(java.lang.Double.doubleToRawLongBits(0.0), java.lang.Double.doubleToRawLongBits(Risk.clamp01(0.0)))
        assertEquals(0.0, Risk.clamp01(-0.1), 0.0)
        assertEquals(1.0, Risk.clamp01(1.1), 0.0)
        assertEquals(1.0, Risk.clamp01(1.0), 0.0)
    }

    @Test fun aNonFiniteRateCostOrDebitCountsAsNone() {
        val inf = Double.POSITIVE_INFINITY
        assertEquals(0.0, Risk.cost(0.5, inf), 0.0)
        assertEquals(0.0, Risk.cost(0.5, Double.NaN), 0.0)
        assertEquals(0.0, Risk.cost(0.5, -inf), 0.0)
        assertEquals(10.0, Risk.leak(Risk.Budget(10.0, 0.0), 10_000.0, inf).B, 0.0)
        assertEquals(10.0, Risk.leak(Risk.Budget(10.0, 0.0), 10_000.0, Double.NaN).B, 0.0)
        assertEquals(5.0, Risk.debit(Risk.Budget(5.0, 0.0), inf).B, 0.0)
        assertEquals(5.0, Risk.debit(Risk.Budget(5.0, 0.0), Double.NaN).B, 0.0)
        assertTrue(Risk.cost(0.5, 2.0) > 0.0)
    }
}
