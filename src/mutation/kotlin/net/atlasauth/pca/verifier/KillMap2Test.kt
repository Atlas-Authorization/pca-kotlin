package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Kotlin-side mutation kills for IntentMap.kt / IntentClassifier.kt that have no direct TS counterpart: the hashing
 * helpers' refusals (unknown leaf kind incl. a String.hashCode collision with every kind, salt length, empty leaf list),
 * u64be's high bytes, the Z0 primitive's own refusals (ε not a number, non-object input), normalization of the primitive
 * inputs (a non-canonical number spelling) and the fail-closed paths. Inputs come from test-data/killMap.json (TS oracle).
 */
class KillMap2Test {
    @Suppress("UNCHECKED_CAST")
    private fun case(name: String): Map<String, Any?> = KillMapTest.cases.first { it["name"] == name }

    @Suppress("UNCHECKED_CAST")
    private fun input(name: String): LinkedHashMap<String, Any?> = KillMapTest.args(case(name))[0] as LinkedHashMap<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun m(o: Any?, k: String): MutableMap<String, Any?> = (o as MutableMap<String, Any?>)[k] as MutableMap<String, Any?>

    private inline fun <reified T : Throwable> throws(msg: String?, f: () -> Unit) {
        try {
            f()
        } catch (e: Throwable) {
            assertEquals(e.toString(), T::class.java, e.javaClass)
            if (msg != null) assertEquals(msg, e.message)
            return
        }
        fail("no " + T::class.java.simpleName)
    }

    private val salt = ByteArray(32) { it.toByte() }

    @Test fun u64beAllBytes() {
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), IntentMap.u64be(0x0102030405060708L))
        assertArrayEquals(ByteArray(8) { -1 }, IntentMap.u64be(-1L))
        assertArrayEquals(byteArrayOf(-128, 0, 0, 0, 0, 0, 0, 1), IntentMap.u64be(Long.MIN_VALUE + 1))
    }

    @Test fun leafKindsAndTags() {
        val leaf = linkedMapOf<String, Any?>("a" to Json.Num("1"))
        val tags = mapOf("header" to IntentMap.MAP_TAG_HEADER, "cell" to IntentMap.MAP_TAG_CELL, "metrics" to IntentMap.MAP_TAG_METRICS, "learner" to IntentMap.MAP_TAG_LEARNER)
        for ((k, t) in tags) {
            assertEquals(t, IntentMap.tagOf(k))
            assertArrayEquals(k, Pca.sha(IntentJs.utf8(t), salt, IntentJs.canonBytes(leaf)), IntentMap.leafHash(k, salt, leaf))
        }
        // same String.hashCode as a known kind (a `when` on strings switches on the hash first, then compares)
        for ((k, twin) in listOf("header" to "iFader", "cell" to "dFll", "metrics" to "nFtrics", "learner" to "mFarner")) {
            assertEquals(k.hashCode(), twin.hashCode())
            throws<IllegalArgumentException>("unknown leaf kind") { IntentMap.leafHash(twin, salt, leaf) }
            throws<IllegalArgumentException>("unknown leaf kind") { IntentMap.tagOf(twin) }
        }
        throws<IllegalArgumentException>("unknown leaf kind") { IntentMap.tagOf("node") }
    }

    @Test fun saltAndEmptyTree() {
        for (s in listOf(null, ByteArray(0), ByteArray(31), ByteArray(33)))
            throws<IllegalArgumentException>("mapLeafHash: the salt is 32 bytes") { IntentMap.leafHash("cell", s, "x") }
        throws<IllegalArgumentException>("mapTree: empty") { IntentMap.commitLeaves(ArrayList<Any?>()) }
        throws<IllegalArgumentException>("unknown leaf kind") {
            IntentMap.commitLeaves(arrayListOf<Any?>(linkedMapOf("kind" to "dFll", "salt" to Pca.b64(salt), "leaf" to "x")))
        }
    }

    @Test fun metricFields() {
        assertEquals(listOf("residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm",
            "fidelity_est_ppm", "entropy_mbits", "questions", "conflicts"), IntentMap.METRIC_FIELDS)
    }

    @Test fun primitiveRefusals() {
        val ok = input("decide/ok")
        assertTrue(IntentMap.decidePrimitive(ok).ok)
        for (eps in listOf<Any?>("5", null, true, linkedMapOf<String, Any?>())) {
            val d = IntentMap.decidePrimitive(LinkedHashMap(ok).also { it["max_residual_risk_ppm"] = eps })
            assertEquals(eps.toString(), "max_residual_risk_ppm must be a number", d.reason)
            assertFalse(d.ok)
            assertEquals(0L, d.pPpm)
        }
        assertTrue(IntentMap.decidePrimitive(LinkedHashMap(ok).also { it["max_residual_risk_ppm"] = Json.Num("1200") }).ok)
        for (bad in listOf<Any?>(arrayListOf<Any?>(ok), "x", Json.Num("1")))
            assertEquals("map error (fail closed): ClassCastException", IntentMap.decidePrimitive(bad).reason)
        assertEquals("the params do not hash to action.params_digest", IntentMap.decidePrimitive(LinkedHashMap(ok).also { it.remove("action") }).reason)
    }

    @Test fun nonCanonicalNumberSpelling() {
        // `questions: 2` spelled 2e0: the primitive normalizes it (the leaf opens); the raw decision cannot hash the leaf
        // strictly, so the metrics leaf does not open (fail closed, never an exception)
        val raw = input("decide/ok")
        m(m(raw["disclosure"], "metrics"), "leaf")["questions"] = Json.Num("2e0")
        val d = IntentMap.decidePrimitive(raw)
        assertTrue(d.reason, d.ok)
        assertEquals(1200L, d.residualRiskPpm)
        val direct = IntentMap.decide(raw["map_commit"], raw["action"], true, raw["params"], raw["disclosure"], null)
        assertEquals("the metrics leaf does not open the map commitment", direct.reason)
        // the same for the header leaf
        val raw2 = input("decide/ok")
        m(m(raw2["disclosure"], "header"), "leaf")["cells"] = Json.Num("9.0")
        assertTrue(IntentMap.decidePrimitive(raw2).ok)
        assertEquals("the header leaf does not open the map commitment",
            IntentMap.decide(raw2["map_commit"], raw2["action"], true, raw2["params"], raw2["disclosure"], null).reason)
    }

    @Test fun classifierEntry() {
        for (bad in listOf<Any?>(arrayListOf<Any?>(), "x", Json.Num("1")))
            assertEquals("classes: evaluation error (fail closed): ClassCastException", IntentClassifier.decide(bad).reason)
        val ok = input("classify/ok")
        assertTrue(IntentClassifier.decide(ok).ok)
        // a verdict's `v: 1` spelled 1e0: normalized by the entry point, the verdict's reference is the committed one
        @Suppress("UNCHECKED_CAST")
        val vs = ok["verdicts"] as MutableList<Any?>
        @Suppress("UNCHECKED_CAST")
        (vs[0] as MutableMap<String, Any?>)["v"] = Json.Num("1e0")
        val r = IntentClassifier.decide(ok)
        assertTrue(r.reason, r.ok)
        assertEquals("classes: a committed verdict was not supplied (or is malformed)", IntentClassifier.decideNormalized(ok).reason)
    }
}
