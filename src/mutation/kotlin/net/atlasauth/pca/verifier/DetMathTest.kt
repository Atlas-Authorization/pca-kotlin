package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The deterministic logarithm, exponential and integer power: fixed values pin the bits, and the libm values bound the error to a few ulps. */
class DetMathTest {
    private val eps = Math.ulp(1.0)

    @Test fun lnPinnedValues() {
        assertEquals(0.0, DetMath.detLn(1.0), 0.0)
        assertEquals(4.605170185988092, DetMath.detLn(100.0), 0.0)
        assertEquals(-0.6931471805599453, DetMath.detLn(0.5), 0.0)
        assertEquals(Double.POSITIVE_INFINITY, DetMath.detLn(Double.POSITIVE_INFINITY), 0.0)
        for (bad in listOf(-1.0, Double.NaN, Double.NEGATIVE_INFINITY)) assertTrue("$bad", DetMath.detLn(bad).isNaN())
        for (x in listOf(0.3, 0.5, 0.9, 1.5, 3.0, 100.0, 1e-9, 1e300, 5e-324)) {
            val want = StrictMath.log(x)
            assertTrue("$x", Math.abs(DetMath.detLn(x) - want) <= 4 * eps * Math.abs(want))
        }
    }

    @Test fun log2OfAPowerOfTwoIsExact() {
        for (e in listOf(-1074, -1022, -10, -1, 0, 1, 3, 52, 1023)) assertEquals("$e", e.toDouble(), DetMath.detLog2(Math.scalb(1.0, e)), 0.0)
        assertTrue(DetMath.detLog2(-1.0).isNaN())
        assertTrue(DetMath.detLog2(Double.NaN).isNaN())
        for (z in listOf(0.0, -0.0)) {
            assertEquals(Double.NEGATIVE_INFINITY, DetMath.detLn(z), 0.0)
            assertEquals(Double.NEGATIVE_INFINITY, DetMath.detLog2(z), 0.0)
        }
        assertEquals(0.0, DetMath.detExp(Double.NEGATIVE_INFINITY), 0.0)
        assertEquals(Double.POSITIVE_INFINITY, DetMath.detLog2(Double.POSITIVE_INFINITY), 0.0)
        for (x in listOf(0.3, 0.5, 0.9, 1.5, 3.0, 100.0, 1e-9)) {
            val want = StrictMath.log(x) / StrictMath.log(2.0)
            assertTrue("$x", Math.abs(DetMath.detLog2(x) - want) <= 4 * eps * Math.max(1.0, Math.abs(want)))
        }
    }

    @Test fun expPinnedValuesAndRanges() {
        assertEquals(1.0, DetMath.detExp(0.0), 0.0)
        assertEquals(2.718281828459045, DetMath.detExp(1.0), 0.0)
        assertEquals(Double.POSITIVE_INFINITY, DetMath.detExp(710.0), 0.0)
        assertEquals(0.0, DetMath.detExp(-746.0), 0.0)
        assertTrue(DetMath.detExp(Double.NaN).isNaN())
        for (x in listOf(-700.0, -20.0, -1.5, -1e-9, 1e-9, 0.5, 2.0, 20.0, 700.0)) {
            val want = StrictMath.exp(x)
            assertTrue("$x", Math.abs(DetMath.detExp(x) - want) <= 4 * eps * want)
        }
    }

    @Test fun powIntMultipliesInSequence() {
        assertEquals(1024.0, DetMath.detPowInt(2.0, 10), 0.0)
        assertEquals(0.125, DetMath.detPowInt(0.5, 3), 0.0)
        assertEquals(1.0, DetMath.detPowInt(7.0, 0), 0.0)
    }
}
