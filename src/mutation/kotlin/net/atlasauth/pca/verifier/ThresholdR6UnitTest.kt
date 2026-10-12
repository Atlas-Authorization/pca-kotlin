package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.n
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round-6 threshold seams under the unit suite (so mutation testing sees them): the shared threshold_set / signer_set_hash /
 * malformed / depth primitives with their exact verdicts, plus the internal helpers (exactT, validatedRegistry,
 * signerSetHashB64u) whose individual guards are otherwise masked by the later checks of verifyShare.
 */
@Suppress("UNCHECKED_CAST")
class ThresholdR6UnitTest {
    private val prim: Map<String, Any?> get() = SnapshotTest.core["primitives"] as Map<String, Any?>
    private val impl = setOf("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")
    private fun tsEntry(name: String): Map<String, Any?> = (prim["threshold_set"] as List<Any?>).map { it as Map<String, Any?> }.first { it["name"] == name }

    @Test fun thresholdSetVectorsExact() {
        var ran = 0
        for (x in prim["threshold_set"] as List<Any?>) {
            val e = x as Map<String, Any?>
            val req = e["requires"] as? String
            if (req != null && req !in impl) continue
            val want = e["valid"] == true
            assertEquals(e["name"].toString(), want, Threshold.verifyShareEntry(e))
            val tm = Pca.decodeB64uStrict(e["threshold_message"], -1)
            val t = Threshold.exactT(e["t"])
            val role = e["role"] as? String; val set = e["signer_set"] as? List<Any?>; val share = e["share"] as? Map<String, Any?>
            if (tm != null && t != null && role != null && set != null && share != null)
                assertEquals(e["name"].toString(), want, Threshold.verifyShare(role, tm, set, t, share))
            ran++
        }
        assertTrue("ran $ran", ran >= 55)
    }

    @Test fun signerSetHashVectorsExact() {
        for (x in prim["signer_set_hash"] as List<Any?>) {
            val e = x as Map<String, Any?>
            assertEquals(e["name"].toString(), e["hash"], Threshold.signerSetHashB64u(e["signer_set"]))
        }
        assertNotNull(Threshold.signerSetHashB64u(l(m("role" to "agent", "publicKey" to "k"))))
        assertNull(Threshold.signerSetHashB64u(null))
        assertNull(Threshold.signerSetHashB64u(m("role" to "agent")))
        assertNull(Threshold.signerSetHashB64u(l("x")))
        assertNull(Threshold.signerSetHashB64u(l(m("role" to 1, "publicKey" to "k"))))
        assertNull(Threshold.signerSetHashB64u(l(m("role" to "agent", "publicKey" to 1))))
        assertNull(Threshold.signerSetHashB64u(l(m("publicKey" to "k"))))
        assertNull(Threshold.signerSetHashB64u(l(m("role" to "agent"))))
        assertNull(Threshold.signerSetHashB64u(l(m("role" to "\uD800", "publicKey" to "k"))))
        // only the FIRST bad member decides: a good member before a bad one is not enough
        assertNull(Threshold.signerSetHashB64u(l(m("role" to "agent", "publicKey" to "k"), m("role" to 1, "publicKey" to "k"))))
    }

    @Test fun malformedAndDepthVectorsDeny() {
        for (x in prim["malformed"] as List<Any?>) {
            val e = x as Map<String, Any?>
            if (e["api"] != "threshold_share") continue
            assertFalse(e["name"].toString(), Threshold.verifyShareEntry(e["input"]))
        }
        for (x in prim["depth"] as List<Any?>) {
            val d = x as Map<String, Any?>
            if (d["expand"] != null || d["api"] != "threshold_share") continue
            assertEquals(d["name"].toString(), d["valid"] == true, Threshold.verifyShareEntry(d["input"]))
        }
    }

    @Test fun exactT() {
        for (bad in listOf(null, true, false, "1", l(1), n("0"), n("4"), n("-1"), n("1.5"), n("x"), 0, 4L)) assertNull("$bad", Threshold.exactT(bad))
        assertEquals(1, Threshold.exactT(n("1")))
        assertEquals(2, Threshold.exactT(n("2.0")))
        assertEquals(3, Threshold.exactT(n("3")))
        assertEquals(1, Threshold.exactT(1))
        assertEquals(2, Threshold.exactT(2L))
        assertEquals(3, Threshold.exactT(3.0))
    }

    private fun b64(len: Int, fill: Int): String = Pca.b64(ByteArray(len) { fill.toByte() })

    @Test fun validatedRegistry() {
        val a = b64(32, 1); val g = b64(32, 2); val p = b64(32, 3); val pq = b64(1952, 7)
        val reg = Threshold.validatedRegistry(l(m("role" to "agent", "publicKey" to a, "pq_pk" to pq), m("role" to "guardian", "publicKey" to g),
            m("role" to "principal", "publicKey" to p), m("role" to "agent", "publicKey" to a, "pq_pk" to pq)))!!
        assertEquals(3, reg.size)
        assertEquals(Pair(a, pq), reg["agent"])
        assertEquals(Pair<String, String?>(g, null), reg["guardian"])
        val bad: List<List<Any?>> = listOf(
            l("x"),
            l(m("role" to "Agent", "publicKey" to a)),
            l(m("role" to 1, "publicKey" to a)),
            l(m("publicKey" to a)),
            l(m("role" to "agent", "publicKey" to 5)),
            l(m("role" to "agent")),
            l(m("role" to "agent", "publicKey" to b64(31, 1))),
            l(m("role" to "agent", "publicKey" to a, "pq_pk" to null)),
            l(m("role" to "agent", "publicKey" to a, "pq_pk" to 5)),
            l(m("role" to "agent", "publicKey" to a, "pq_pk" to "")),
            l(m("role" to "agent", "publicKey" to a, "pq_pk" to b64(100, 1))),
            l(m("role" to "agent", "publicKey" to a, "pq_pk" to "!!")),
            l(m("role" to "agent", "publicKey" to a), m("role" to "agent", "publicKey" to g)),
            l(m("role" to "agent", "publicKey" to a, "pq_pk" to pq), m("role" to "agent", "publicKey" to a)),
            l(m("role" to "agent", "publicKey" to a), m("role" to "guardian", "publicKey" to a)))
        for (s in bad) assertNull("$s", Threshold.validatedRegistry(s))
        for (len in listOf(1952, 2592, 32, 64, 897, 1793, 97484))
            assertNotNull("len $len", Threshold.validatedRegistry(l(m("role" to "agent", "publicKey" to a, "pq_pk" to b64(len, 9)))))
    }

    @Test fun verifyShareGuards() {
        val e = tsEntry("r6-pos-ed25519")
        val role = e["role"] as String
        val tm = Pca.decodeB64uStrict(e["threshold_message"], -1)!!
        val set = e["signer_set"] as List<Any?>
        val share = e["share"] as Map<String, Any?>
        assertTrue(Threshold.verifyShare(role, tm, set, 1, share))
        for (t in listOf(0, 2, 3, 4, -1, 256)) assertFalse("t=$t", Threshold.verifyShare(role, tm, set, t, share))
        assertFalse(Threshold.verifyShare(role, tm, set, 1, LinkedHashMap(share).also { it.remove("role") }))
        assertFalse(Threshold.verifyShare(role, tm, set, 1, LinkedHashMap(share).also { it["role"] = "guardian" }))
        assertFalse(Threshold.verifyShare("guardian", tm, set, 1, LinkedHashMap(share).also { it["role"] = "guardian" }))
        assertFalse(Threshold.verifyShare(role, tm, l("x"), 1, share))
        assertTrue(Threshold.verifyShareEntry(e))
        for (k in listOf("role", "t", "signer_set", "threshold_message", "share")) {
            assertFalse(k, Threshold.verifyShareEntry(LinkedHashMap(e).also { it[k] = 7 }))
            assertFalse(k, Threshold.verifyShareEntry(LinkedHashMap(e).also { it.remove(k) }))
        }
        assertFalse(Threshold.verifyShareEntry(l(e)))
        assertFalse(Threshold.verifyShareEntry(null))
    }
}
