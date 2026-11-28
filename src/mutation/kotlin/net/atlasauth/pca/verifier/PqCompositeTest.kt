package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The LAMPS composite ML-DSA-65 + Ed25519 signature: representative layout, round trip, context binding, fail-closed verify. */
class PqCompositeTest {
    private val msg = "pca pq surface".toByteArray(Charsets.UTF_8)

    private fun seed(v: Int) = ByteArray(32) { v.toByte() }

    @Test fun sizeAndRepresentativeLayout() {
        assertEquals(3373, Pq.COMPOSITE_SIGNATURE_BYTES)
        val r = Pq.compositeRepresentative(msg, "ctx")
        assertEquals(32 + 30 + 1 + 3 + 64, r.size)
        val want = (Pq.COMPOSITE_PREFIX + Pq.COMPOSITE_LABEL).toByteArray(Charsets.US_ASCII) + byteArrayOf(3) + "ctx".toByteArray(Charsets.UTF_8) +
            java.security.MessageDigest.getInstance("SHA-512").digest(msg)
        assertArrayEquals(want, r)
        try {
            Pq.compositeRepresentative(msg, ByteArray(256))
            fail("a 256-byte context must be refused")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test fun compositeBindsBothHalvesAndTheContext() {
        val ed = Keys.edFromSeed(seed(6))
        val ml = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(6))
        val ctx = "ctx".toByteArray(Charsets.UTF_8)
        val sig = Pq.compositeSign(ed, ml, msg, ctx)
        assertEquals(Pq.COMPOSITE_SIGNATURE_BYTES, sig.size)
        assertTrue(Pq.compositeVerify(ed.pub, ml.pk, msg, sig, ctx))
        assertFalse(Pq.compositeVerify(ed.pub, ml.pk, msg, sig, null))
        assertFalse(Pq.compositeVerify(ed.pub, ml.pk, "other".toByteArray(), sig, ctx))
        assertFalse(Pq.compositeVerify(ed.pub, ml.pk, msg, sig.copyOf(sig.size - 1), ctx))
        val bad = sig.clone().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFalse(Pq.compositeVerify(ed.pub, ml.pk, msg, bad, ctx))
        val badMl = sig.clone().also { it[3000] = (it[3000].toInt() xor 1).toByte() }
        assertFalse(Pq.compositeVerify(ed.pub, ml.pk, msg, badMl, ctx))
        assertFalse(Pq.compositeVerify(ed.pub, ml.pk, msg, sig, ByteArray(256)))
        assertTrue(Pq.compositeVerify(ed.pub, ml.pk, msg, Pq.compositeSign(seed(6), ml, msg, ctx), ctx))
    }

    @Test fun compositeSignRefusesAWrongPrimitive() {
        val k = Keys.pqFromSeed(Pq.Prim.ML_DSA_87, seed(1))
        try {
            Pq.compositeSign(Keys.edFromSeed(seed(1)), k, msg)
            fail("an ML-DSA-87 key must be refused")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }
}
