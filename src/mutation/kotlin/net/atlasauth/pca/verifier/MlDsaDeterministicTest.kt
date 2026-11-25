package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** ML-DSA-65 signing is the deterministic FIPS 204 variant: the same key and message give the same bytes, on both signing entry points. */
class MlDsaDeterministicTest {
    @Test fun sameKeyAndMessageGiveTheSameSignature() {
        val key = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 5 })
        val msg = "deterministic".toByteArray(Charsets.UTF_8)
        val a = Pq.mlDsa65Sign(key.sk, msg)
        assertArrayEquals(a, Pq.mlDsa65Sign(key.sk, msg))
        assertArrayEquals(a, key.sign(msg)) // the suite signer is the same variant
        assertTrue(Pq.mlDsa65Verify(key.pk, msg, a))
        assertFalse(a.contentEquals(Pq.mlDsa65Sign(key.sk, "other".toByteArray(Charsets.UTF_8))))
        assertFalse(Pq.mlDsa65Verify(key.pk, "other".toByteArray(Charsets.UTF_8), a))
    }
}
