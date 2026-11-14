package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** A RIM Measurement index is a one-byte block index: 255 is the largest accepted, anything above is refused instead of saturating in Int (2^40 and 2^40 + 1 collided). */
class Kill14BRimIndexTest {
    private fun Kill05NvKit.verify(vararg indexes: String): Pair<AttestNvidiaCollateral.Rim?, String> {
        val payload = "<Payload>" + indexes.joinToString("") { res(it, listOf("aabbccdd")) } + "</Payload>"
        return AttestNvidiaCollateral.verifyRim(rim(payload = payload), RIM_PINS, NOW)
    }

    @Test fun theLargestByteIndexIsAccepted() = nv {
        val (r, why) = verify("255")
        assertEquals("", why)
        assertNotNull(r)
        assertNotNull(r!!.golden[255])
    }

    @Test fun anIndexAboveAByteIsMalformedNotSaturated() = nv {
        for (big in listOf("256", "1099511627776", "1099511627777", "2147483648", "4294967296")) {
            val (r, why) = verify(big)
            assertNull(big, r)
            assertEquals(big, "RIM: malformed Measurement resource", why)
        }
        val (r2, why2) = verify("1099511627776", "1099511627777")
        assertNull(r2)
        assertEquals("RIM: malformed Measurement resource", why2)
    }

    @Test fun twoEqualIndexesAreStillADuplicate() = nv {
        val (r, why) = verify("7", "7")
        assertNull(r)
        assertEquals("RIM: duplicate Measurement index 7", why)
    }
}
