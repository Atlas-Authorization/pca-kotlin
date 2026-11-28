package net.atlasauth.pca.mpc.lwe

import java.security.MessageDigest
import net.atlasauth.pca.mpc.Ot
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** The reference-named entry points reach the same adapter functions the corpus replays; the round trip needs liblweot (skipped without it). */
class EndemicLweApiTest {
    @Test fun sizesAndSessionId() {
        assertEquals(1184, PK_BYTES)
        assertEquals(1088, CT_BYTES)
        assertEquals(32, ENDEMIC_SECRET_BYTES)
        val rn = ByteArray(32) { it.toByte() }
        val want = MessageDigest.getInstance("SHA-256").digest("atlas-pca-mpc/endemic-lwe-ot-sid".toByteArray() + rn)
        assertArrayEquals(want, endemicSessionId(rn))
    }

    @Test fun randomOtRecoversExactlyTheChosenPads() {
        assumeTrue("liblweot not available", EndemicLweOt.available())
        val choices = intArrayOf(0, 1, 1, 0)
        val r = endemicLweBaseOtRandom(choices, Ot.otRandom(Ot.splitMix64(java.math.BigInteger.valueOf(11))))
        for (i in choices.indices) assertArrayEquals(r.senderPads[i][choices[i]], r.recvPads[i])
        assertEquals(choices.size, r.ciphertexts.size)
    }

    @Test fun chosenMessageOtDeliversTheChosenMessages() {
        assumeTrue("liblweot not available", EndemicLweOt.available())
        val m = Array(3) { i -> arrayOf(ByteArray(16) { (i + 1).toByte() }, ByteArray(16) { (i + 50).toByte() }) }
        val choices = intArrayOf(1, 0, 1)
        val r = endemicLweBaseOT(m, choices)
        for (i in choices.indices) assertArrayEquals(m[i][choices[i]], r.received()[i])
        assertTrue(endemicLweBaseOtFn !== null)
    }
}
