package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/** The power curve is built from multiplications and square roots only (no pow), and a gamma that is not a multiple of 1/8 or exceeds 64 is refused. */
class BondPowerCurveTest {
    private fun policy(gamma: Any?): Map<String, Any?> =
        linkedMapOf("floor" to Json.Num("0"), "k" to Json.Num("1"), "curve" to linkedMapOf<String, Any?>("kind" to "power", "gamma" to gamma))

    @Test fun anIntegerGammaMultipliesTheExposureThatManyTimes() {
        assertEquals(40.0, BondSettlement.bondAmount(policy(Json.Num("1")), 40.0), 0.0)
        assertEquals(1600.0, BondSettlement.bondAmount(policy(Json.Num("2")), 40.0), 0.0)
        assertEquals(64000.0, BondSettlement.bondAmount(policy(Json.Num("3")), 40.0), 0.0)
    }

    @Test fun anEighthStepUsesTheNestedSquareRoots() {
        // e^(1 + 1/2) = e * sqrt(e); e^(1/4) = sqrt(sqrt(e)); e^(7/8) = sqrt(e) * sqrt(sqrt(e)) * sqrt(sqrt(sqrt(e)))
        assertEquals(16.0 * 4.0, BondSettlement.bondAmount(policy(Json.Num("1.5")), 16.0), 0.0)
        assertEquals(32.0, BondSettlement.bondAmount(policy(Json.Num("1.25")), 16.0), 0.0)
    }

    @Test fun aGammaThatIsNotAMultipleOfAnEighthOrExceeds64IsRefused() {
        for (g in listOf("1.1", "1.0625", "64.125", "65", "1e300")) {
            try {
                BondSettlement.bondAmount(policy(Json.Num(g)), 40.0)
                fail("gamma $g must be refused")
            } catch (e: IllegalStateException) {
                assertEquals(g, "bondAmount: power curve gamma must be a multiple of 1/8 and at most 64", e.message)
            }
        }
    }
}
