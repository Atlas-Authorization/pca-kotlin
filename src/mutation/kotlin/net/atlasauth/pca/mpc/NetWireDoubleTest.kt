package net.atlasauth.pca.mpc

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/** A double on the wire is the number JavaScript prints (a whole one without a fraction, negative zero as 0); a non-finite one is refused. */
class NetWireDoubleTest {
    @Test fun aWholeDoubleIsWrittenAsAnInteger() {
        assertEquals("[3,0,0,-7,1000000]", NetWire.stringify(listOf(3.0, 0.0, -0.0, -7.0, 1e6)))
        assertEquals("{\"q\":4}", NetWire.stringify(linkedMapOf<String, Any?>("q" to 4.0)))
    }

    @Test fun aNonFiniteDoubleIsRefused() {
        for (x in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            try { NetWire.stringify(listOf(x)); fail("$x") } catch (e: IllegalArgumentException) { /* refused */ }
        }
    }
}
