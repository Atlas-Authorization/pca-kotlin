package net.atlasauth.pca.verifier

import java.util.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The core's FN-DSA hook with a stub backend (the real libfndsa path is tested in pca-fndsa): suites resolve only while a backend is registered. */
class FnDsaRegistryTest {
    @After fun reset() = Pq.unregisterFnDsa()

    private fun b64u(n: Int) = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(n) { 3 })
    private val sizes = mapOf("fn-dsa-512" to (897 to 666), "fn-dsa-1024" to (1793 to 1280))

    @Test fun noBackendIsUnsupportedAndDenied() {
        for ((alg, sz) in sizes) {
            assertNull(Pq.resolveSigAlg(alg, true))
            assertEquals("unsupported_suite: $alg", Pq.refusal(alg))
            assertFalse(alg in Pq.supportedSuites())
            assertFalse(Pq.verifyLeafSuite(alg, true, null, b64u(sz.first), ByteArray(4), b64u(sz.second), null))
        }
    }

    @Test fun backendDispatchesWithLengthChecksFirst() {
        var calls = 0
        Pq.registerFnDsa { _, _, _, _ -> calls++; true }
        for ((alg, sz) in sizes) {
            val s = Pq.resolveSigAlg(alg, true)!!
            assertTrue(s.needsPqPk && !s.needsPqSig && !s.hasEd25519 && s.sigBytes == sz.second)
            assertTrue(alg in Pq.supportedSuites())
            assertNull(Pq.validateSignatureWire(mapOf("alg" to alg, "sig" to b64u(sz.second), "pq_pk" to b64u(sz.first))))
            assertEquals("'pq_sig' must be absent for alg '$alg'",
                Pq.validateSignatureWire(mapOf("alg" to alg, "sig" to b64u(sz.second), "pq_pk" to b64u(sz.first), "pq_sig" to b64u(sz.second))))
            assertTrue(Pq.verifyLeafSuite(alg, true, null, b64u(sz.first), ByteArray(4), b64u(sz.second), null))
            val before = calls
            assertFalse(Pq.verifyLeafSuite(alg, true, null, b64u(sz.first - 1), ByteArray(4), b64u(sz.second), null))
            assertFalse(Pq.verifyLeafSuite(alg, true, null, b64u(sz.first), ByteArray(4), b64u(sz.second - 1), null))
            assertEquals(before, calls)
        }
    }

    @Test fun throwingBackendDenies() {
        Pq.registerFnDsa { _, _, _, _ -> throw IllegalStateException("boom") }
        assertFalse(Pq.verifyLeafSuite("fn-dsa-512", true, null, b64u(897), ByteArray(4), b64u(666), null))
    }

    @Test fun hybridFnDsaStaysUnknown() {
        Pq.registerFnDsa { _, _, _, _ -> true }
        assertNull(Pq.resolveSigAlg("hybrid-ed25519-fn-dsa-512", true))
    }

    @Test fun verifyOnlyBackendDoesNotSign() {
        Pq.registerFnDsa { _, _, _, _ -> true }
        assertFalse(Pq.fnDsaCanSign())
        for (alg in sizes.keys) {
            val e = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { Keys.pqFromSeed(Pq.resolveSigAlg(alg, true)!!.pq!!, ByteArray(32)) }
            assertEquals("unsupported_suite: $alg", e.message)
        }
    }

    @Test fun scopedBackendRestoresThePreviousOne() {
        assertNull(Pq.resolveSigAlg("fn-dsa-512", true))
        Pq.withFnDsaBackend(Pq.FnDsaBackend { _, _, _, _ -> true }) { assertTrue("fn-dsa-512" in Pq.supportedSuites()) }
        assertNull(Pq.resolveSigAlg("fn-dsa-512", true))
    }
}
