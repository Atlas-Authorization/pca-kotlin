package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pq.Suite is a data class, so comparing one Suite with another built by the same constructor cannot see a constructor that
 * forgets to store a field (both sides forget alike). These read the stored `sigBytes` and `nested` of every suite the verifier
 * resolves and compare them with numbers that do not come from a Suite.
 */
class Kill11PqSuiteFieldsTest {
    @Test
    fun everyResolvedSuiteStoresItsSignatureLengthAndNestedFlag() {
        for (alg in Pq.supportedSuites()) {
            val s = Pq.resolveSigAlg(alg, true)!!
            val want = if (s.pq == null || s.hasEd25519) 64 else s.pq!!.sigBytes
            assertEquals(alg, want, s.sigBytes)
            assertEquals(alg, alg == "hybrid-nested-ed25519-ml-dsa-65", s.nested)
        }
    }

    // The suites of Pq.SUITES are built once, when the Pq object initialises, which can be before a mutant of the Suite constructor is
    // applied: only a Suite built by the test itself, after the mutation, can show a constructor that stores nothing.
    @Test
    fun aSuiteBuiltByTheTestStoresEveryFieldItWasGiven() {
        val s = Pq.Suite("x", 64, true, Pq.Prim.ML_DSA_65, true, false)
        assertEquals("x", s.alg)
        assertEquals(64, s.sigBytes)
        assertTrue(s.hasEd25519)
        assertEquals(Pq.Prim.ML_DSA_65, s.pq)
        assertTrue(s.needsPqPk)
        assertFalse(s.needsPqSig)
        assertFalse(s.nested)
        val n = Pq.Suite("y", 3309, false, null, false, true, nested = true)
        assertEquals(3309, n.sigBytes)
        assertFalse(n.hasEd25519)
        assertFalse(n.needsPqPk)
        assertTrue(n.needsPqSig)
        assertTrue(n.nested)
    }

    @Test
    fun theLengthsOfTheNamedSuites() {
        assertEquals(64, Pq.resolveSigAlg("ed25519", true)!!.sigBytes)
        assertEquals(3309, Pq.resolveSigAlg("ml-dsa-65", true)!!.sigBytes)
        assertEquals(4627, Pq.resolveSigAlg("ml-dsa-87", true)!!.sigBytes)
        assertEquals(64, Pq.resolveSigAlg("hybrid-ed25519-ml-dsa-65", true)!!.sigBytes)
        assertTrue(Pq.resolveSigAlg("hybrid-nested-ed25519-ml-dsa-65", true)!!.nested)
        assertFalse(Pq.resolveSigAlg("hybrid-ed25519-ml-dsa-65", true)!!.nested)
    }
}
