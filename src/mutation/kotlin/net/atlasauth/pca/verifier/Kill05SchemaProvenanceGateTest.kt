package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * k05 survivors in ProvenanceGate. Every inclusion-proof refusal is checked against a root the unguarded RFC 9162 walk
 * (below) DOES reach, so only the guard can refuse it: index / size range (incl. 2^53 - 1 and 2^53), a non-32-byte leaf or
 * proof entry, a proof longer than the tree, a null entry. Plus the lower-hex digest edges, the zero level of a refusal and the
 * fail-closed handler.
 */
class Kill05SchemaProvenanceGateTest {
    private val maxSafe = 9007199254740991L

    private fun node(l: ByteArray, r: ByteArray): ByteArray = Pca.sha(byteArrayOf(1), l, r)
    private fun leaf(i: Int): ByteArray = ProvenanceGate.rfc9162LeafHash(byteArrayOf(i.toByte()))
    private fun sib(i: Int, len: Int = 32): ByteArray = ByteArray(len) { (i * 31 + it).toByte() }
    private fun proof(k: Int): List<ByteArray> = List(k) { sib(it) }

    /** The verifier's walk with none of its guards. */
    private fun walk(leaf: ByteArray, index: Long, size: Long, proof: List<ByteArray>): ByteArray {
        var fn = index
        var sn = size - 1
        var r = leaf
        for (p in proof) {
            if (fn and 1L == 1L || fn == sn) {
                r = node(p, r)
                if (fn and 1L == 0L) while (fn and 1L == 0L && fn != 0L) { fn = fn shr 1; sn = sn shr 1 }
            } else {
                r = node(r, p)
            }
            fn = fn shr 1
            sn = sn shr 1
        }
        return r
    }

    /** Proof entries the walk consumes before sn reaches 0. */
    private fun need(index: Long, size: Long): Int {
        var fn = index
        var sn = size - 1
        var k = 0
        while (sn != 0L) {
            if ((fn and 1L == 1L || fn == sn) && fn and 1L == 0L) while (fn and 1L == 0L && fn != 0L) { fn = fn shr 1; sn = sn shr 1 }
            fn = fn shr 1
            sn = sn shr 1
            k++
        }
        return k
    }

    private fun v(leaf: ByteArray, index: Long, size: Long, proof: List<ByteArray>, root: ByteArray) =
        ProvenanceGate.verifyRfc9162Inclusion(leaf, index, size, proof, root)

    @Test fun validProofsUpToTheSafeIntegerLimit() {
        assertTrue(v(leaf(0), 0, 1, emptyList(), leaf(0)))
        for ((index, size) in listOf(0L to 1L, 0L to 2L, 1L to 2L, 2L to 3L, 5L to 8L, 6L to 7L, 4L to 6L, 0L to maxSafe, maxSafe - 1 to maxSafe, 12345L to maxSafe)) {
            val p = proof(need(index, size))
            val root = walk(leaf(1), index, size, p)
            assertTrue("$index/$size", v(leaf(1), index, size, p, root))
            val wrong = root.clone().also { it[0] = (it[0] + 1).toByte() }
            assertFalse("$index/$size", v(leaf(1), index, size, p, wrong))
        }
    }

    @Test fun rangeGuardsRefuseWhatTheWalkWouldAccept() {
        for ((index, size) in listOf(-1L to 4L, -2L to 8L, 4L to 4L, 5L to 4L, 0L to maxSafe + 1, maxSafe to maxSafe + 1, 3L to maxSafe + 1)) {
            val p = proof(need(index, size))
            assertFalse("$index/$size", v(leaf(1), index, size, p, walk(leaf(1), index, size, p)))
        }
    }

    @Test fun sizeGuardsRefuseWhatTheWalkWouldAccept() {
        for (len in listOf(0, 31, 33)) {
            val l = ByteArray(len) { 9 }
            val p = proof(1)
            assertFalse("leaf $len", v(l, 1, 2, p, walk(l, 1, 2, p)))
        }
        for (len in listOf(31, 33, 0)) {
            for (at in 0..1) {
                val p = proof(2).toMutableList().also { it[at] = sib(at, len) }
                assertFalse("entry $at of $len", v(leaf(1), 0, 4, p, walk(leaf(1), 0, 4, p)))
            }
        }
        assertFalse(v(leaf(1), 0, 1, emptyList(), leaf(1).copyOf(31)))
        assertFalse(v(leaf(1), 0, 1, emptyList(), leaf(1) + byteArrayOf(0)))
    }

    @Test fun aProofLongerThanTheTreeIsRefused() {
        for ((index, size) in listOf(0L to 4L, 3L to 4L, 0L to 1L, 2L to 3L)) {
            val p = proof(need(index, size) + 1)
            assertFalse("$index/$size", v(leaf(1), index, size, p, walk(leaf(1), index, size, p)))
        }
    }

    @Test fun aNullEntryIsFalseNotAnException() {
        @Suppress("UNCHECKED_CAST")
        val p = listOf<ByteArray?>(null) as List<ByteArray>
        assertFalse(v(leaf(1), 0, 2, p, leaf(1)))
    }

    private fun facts(digest: String, alg: String = "sha256"): Map<String, Any?> = linkedMapOf(
        "v" to 1L, "predicate_type" to ProvenanceGate.SLSA_PROVENANCE_V1, "build_type" to "b", "builder_id" to "bi",
        "subjects" to listOf(linkedMapOf<String, Any?>("alg" to alg, "digest" to digest)), "identity" to "id", "oidc_issuer" to "iss",
        "integrated_time" to 0L, "rekor_log_index" to 0L,
    )

    @Test fun lowerHexDigestEdges() {
        assertNull(ProvenanceGate.provenanceFactsError(facts("0123456789abcdef".repeat(4))))
        assertNull(ProvenanceGate.provenanceFactsError(facts("09af".repeat(32), "sha512")))
        for (c in listOf('/', ':', '`', 'g', 'A', 'F', '@', ' ')) {
            assertEquals("'$c'", "facts.subjects must be 1..64 {alg, digest}", ProvenanceGate.provenanceFactsError(facts("0".repeat(63) + c)))
            assertEquals("'$c' first", "facts.subjects must be 1..64 {alg, digest}", ProvenanceGate.provenanceFactsError(facts(c + "a".repeat(63))))
        }
        assertEquals("facts.subjects must be 1..64 {alg, digest}", ProvenanceGate.provenanceFactsError(facts("0".repeat(64), "sha512")))
    }

    /** A map whose every read throws. */
    private class Boom : AbstractMap<String, Any?>() {
        override val entries: Set<Map.Entry<String, Any?>> get() = throw IllegalStateException("boom")
        override fun get(key: String): Any? = throw IllegalStateException("boom")
    }

    @Test fun refusalsCarryLevelZeroAndTheHandlerFailsClosed() {
        for (input in listOf<Any?>("x", null, Boom(), mapOf("policy" to 1))) {
            val r = ProvenanceGate.provenanceGate(input)
            assertFalse(r.ok)
            assertEquals(0L, r.level)
            assertNull(r.claims)
        }
        assertEquals("malformed_facts", ProvenanceGate.provenanceGate(Boom()).code)
        assertEquals("malformed_facts", ProvenanceGate.provenanceGate("x").code)
        assertEquals("malformed_policy", ProvenanceGate.provenanceGate(mapOf("policy" to 1)).code)
    }
}
