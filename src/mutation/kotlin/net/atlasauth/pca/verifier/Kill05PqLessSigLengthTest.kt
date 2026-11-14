package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Pq.sigFieldOk: a pure LESS suite judges `sig` by the LESS length rule (any length the parameter set produces, MIN..MAX in
 * 16-byte steps), not by the fixed maximum. A valid shorter LESS signature must pass the wire check; taking the fixed-length
 * branch (the `suite.pq != null` test forced false, or `getPq` removed) refuses it.
 */
class Kill05PqLessSigLengthTest {
    private fun sig(n: Int) = Pca.b64(ByteArray(n) { 7 })

    @Test fun aShorterLessSignaturePassesTheWireCheck() {
        assumeTrue("LESS suites resolve only with the native library", LessNative.available)
        val short = LessNative.SIGNATURE_MAX_BYTES - 16
        assertNull(Pq.validateShareSignatureWire(mapOf("alg" to "less-cat1", "sig" to sig(short))))
        assertNull(Pq.validateShareSignatureWire(mapOf("alg" to "less-cat1", "sig" to sig(LessNative.SIGNATURE_MIN_BYTES))))
        val pk = Pca.b64(ByteArray(LessNative.PUBLIC_KEY_BYTES))
        assertNull(Pq.validateSignatureWire(mapOf("alg" to "less-cat1", "sig" to sig(short), "pq_pk" to pk)))
        // off the 16-byte grid: refused by the same rule
        assertEquals(
            "'sig' is not canonical base64url (${LessNative.SIGNATURE_MAX_BYTES} bytes) for alg 'less-cat1'",
            Pq.validateShareSignatureWire(mapOf("alg" to "less-cat1", "sig" to sig(short + 1))),
        )
    }
}
