package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.mm
import net.atlasauth.pca.verifier.IntentTestKit.ml
import net.atlasauth.pca.verifier.IntentTestKit.seed
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rule 19 (V15 committed map) mutation kills: leaf / node / commit hashing with per-kind tags and u64be size, the RFC 9162
 * tree shape and audit-path folding, the closed leaf and disclosure shapes, the cell of the action (cut cells, exact over
 * longer prefix over shorter prefix over other), the layout and position checks and the ε bound. The committed map is built
 * here with the leaf order of packages/pca/src/intent-map-commit.ts commitMap.
 */
class IntentMapKillTest {
    @Suppress("UNCHECKED_CAST")
    private fun <T> deep(o: T): T = IntentJs.normalize(Json.parseLenient(Json.canonicalize(o))) as T

    private val book = jm("verb", "air.book", "first", 2L, "cells", 9L, "dims", jl(
        jm("kind", "num", "path", "action.params.total", "lo", 0L, "hi", 100_000L, "cuts", jl(40_000L)),
        jm("kind", "cat", "path", "action.params.cabin", "values", jl(jm("kind", "exact", "value", "economy"), jm("kind", "exact", "value", "business"),
            jm("kind", "other", "value", IntentMap.MAP_OTHER)))))
    private val cancel = jm("verb", "air.cancel", "first", 11L, "cells", 1L, "dims", jl())
    private val metrics = jm("residual_risk_ppm", 1200L, "burden_ppm", 3L, "uncertainty_ppm", 4L, "disagreement_ppm", 0L,
        "mean_harm_ppm", 10L, "fidelity_est_ppm", 990_000L, "entropy_mbits", 12L, "questions", 2L, "conflicts", 0L)
    private val leaves: List<Pair<String, Any?>> = buildList {
        add("header" to book)
        add("header" to cancel)
        for (f in 0L until 9L) add("cell" to jm("verb", "air.book", "cell", jl(f / 3, f % 3), "p_ppm", 1000L + f, "in_grant", f / 3 < 2 && f % 3 == 0L))
        add("cell" to jm("verb", "air.cancel", "cell", jl(), "p_ppm", 0L, "in_grant", false))
        add("metrics" to metrics)
        add("learner" to jm("learner_digest", Pca.b64(seed("map/learner"))))
    }
    private val size = leaves.size
    private fun salt(i: Int) = seed("map/salt/$i")
    private fun hashes(): List<ByteArray> = leaves.mapIndexed { i, (k, l) -> IntentMap.leafHash(k, salt(i), deep(l)) }
    private fun split(n: Int): Int { var k = 1; while (k * 2 < n) k *= 2; return k }
    private fun root(hs: List<ByteArray>): ByteArray = if (hs.size == 1) hs[0] else split(hs.size).let { k -> IntentMap.nodeHash(root(hs.subList(0, k)), root(hs.subList(k, hs.size))) }
    private fun path(hs: List<ByteArray>, idx: Int, out: MutableList<Any?>) {
        if (hs.size == 1) return
        val k = split(hs.size)
        if (idx < k) { path(hs.subList(0, k), idx, out); out.add(Pca.b64(root(hs.subList(k, hs.size)))) }
        else { path(hs.subList(k, hs.size), idx - k, out); out.add(Pca.b64(root(hs.subList(0, k)))) }
    }
    private val commit = IntentMap.commitOf(size.toLong(), root(hashes()))
    private fun entry(i: Int): LinkedHashMap<String, Any?> = jm("index", i.toLong(), "salt", Pca.b64(salt(i)), "leaf", leaves[i].second, "path", ArrayList<Any?>().also { path(hashes(), i, it) })
    private fun disclosure(cellIndex: Int) = jm("size", size.toLong(), "header", entry(0), "cell", entry(cellIndex), "metrics", entry(size - 2))
    private fun params(total: Any?, cabin: String) = jm("total", total, "cabin", cabin)
    private fun decide(d: Map<String, Any?>, params: Map<String, Any?>, verb: String, eps: Double?): IntentMap.Decision {
        val action = jm("verb", verb, "resource", "r", "params_digest", Pca.paramsDigest(deep(params)))
        return IntentMap.decide(commit, deep(action), true, deep(params), deep(d), eps)
    }
    private fun ok(d: Map<String, Any?>) = decide(d, params(38_900L, "economy"), "air.book", null)

    @Test fun commitmentMatchesTheReferenceShape() {
        val ls = leaves.mapIndexed { i, (k, l) -> jm("kind", k, "salt", Pca.b64(salt(i)), "leaf", l) }
        assertEquals(commit, IntentMap.commitLeaves(ArrayList<Any?>(ls)))
        assertNotEquals(commit, IntentMap.commitOf(size + 1L, root(hashes())))
        assertFalse(IntentMap.leafHash("cell", salt(0), deep(book)).contentEquals(IntentMap.leafHash("header", salt(0), deep(book))))
        assertArrayEquals(byteArrayOf(0, 0, 0, 0, 0, 1, 0, 2), IntentMap.u64be(65_538L))
    }

    @Test fun grantedCellAndPolicyBound() {
        val d = ok(disclosure(2))
        assertTrue(d.reason, d.ok)
        assertEquals(listOf(0L, 0L), d.cell)
        assertEquals(1000L, d.pPpm)
        assertTrue(decide(disclosure(2), params(38_900L, "economy"), "air.book", 1200.0).ok)
        assertFalse(decide(disclosure(2), params(38_900L, "economy"), "air.book", 1199.0).ok)
        assertTrue(decide(disclosure(5), params(40_000L, "economy"), "air.book", null).ok)
        assertEquals("the action's cell is outside the committed grant", decide(disclosure(8), params(40_001L, "economy"), "air.book", null).reason)
        assertEquals("the action's cell is outside the committed grant", decide(disclosure(4), params(1L, "first"), "air.book", null).reason)
        val cancelD = jm("size", size.toLong(), "header", entry(1), "cell", entry(11), "metrics", entry(size - 2))
        assertEquals("the action's cell is outside the committed grant", decide(cancelD, jm(), "air.cancel", null).reason)
    }

    @Test fun valuesOutsideTheirDimension() {
        for (total in listOf<Any?>("38900", Json.Num("1.5"), 100_001L, -1L, null))
            assertEquals(total.toString(), "the action's value lies outside the committed map's dimension", decide(disclosure(2), params(total, "economy"), "air.book", null).reason)
        assertEquals("the action's value lies outside the committed map's dimension", decide(disclosure(2), jm("total", 38_900L), "air.book", null).reason)
        assertEquals("the action's value lies outside the committed map's dimension", decide(disclosure(2), jm("total", 38_900L, "cabin", 1L), "air.book", null).reason)
    }

    @Test fun prefixOrder() {
        val h = deep(jm("verb", "x", "first", 1L, "cells", 4L, "dims", jl(jm("kind", "cat", "path", "action.resource", "values", jl(
            jm("kind", "prefix", "value", "a/"), jm("kind", "prefix", "value", "a/b"), jm("kind", "exact", "value", "a/bc"), jm("kind", "other", "value", IntentMap.MAP_OTHER))))))
        assertNull(IntentMap.headerError(h))
        assertEquals(2L, IntentMap.cellOf(h, "a/bc", jm())!!.first[0])
        assertEquals(1L, IntentMap.cellOf(h, "a/bx", jm())!!.first[0])
        assertEquals(0L, IntentMap.cellOf(h, "a/x", jm())!!.first[0])
        assertEquals(3L, IntentMap.cellOf(h, "b", jm())!!.first[0])
        assertNull(IntentMap.cellOf(h, 7L, jm()))
    }

    @Test fun openingsAndLayout() {
        assertEquals("the cell leaf does not open the map commitment", ok(disclosure(2).also { mm(it["cell"])["salt"] = Pca.b64(seed("other")) }).reason)
        assertEquals("the cell leaf does not open the map commitment", ok(disclosure(2).also { ml(mm(it["cell"])["path"]).removeAt(0) }).reason)
        assertNotNull(ok(disclosure(2).also { it["size"] = size + 1L }).reason)
        assertFalse(ok(disclosure(2).also { it["cell"] = entry(0) }).ok)
        assertFalse(ok(disclosure(2).also { it["metrics"] = jm("index", size - 1L, "salt", Pca.b64(salt(size - 1)), "leaf", metrics, "path", jl()) }).ok)
        assertEquals("the disclosed cell is not the action's cell", ok(disclosure(3)).reason)
        assertEquals("the disclosed header is not the action's verb", decide(disclosure(2), params(38_900L, "economy"), "air.search", null).reason)
        assertEquals("the PCActn carries no map commitment", IntentMap.decide("abc", jm(), true, jm(), deep(disclosure(2)), null).reason)
        assertEquals("params must be an object", IntentMap.decide(commit, jm(), true, null, deep(disclosure(2)), null).reason)
    }

    @Test fun rootFromPathShape() {
        val hs = hashes()
        for (i in 0 until size) {
            val p = ArrayList<Any?>().also { path(hs, i, it) }.map { Pca.decodeB64uStrict(it, 32)!! }
            assertArrayEquals("index $i", root(hs), IntentMap.rootFromPath(i.toLong(), size.toLong(), hs[i], p))
            assertNull(IntentMap.rootFromPath(i.toLong(), size.toLong(), hs[i], p.subList(0, p.size - 1)))
        }
        assertNull(IntentMap.rootFromPath(size.toLong(), size.toLong(), hs[0], listOf()))
    }

    @Test fun closedShapes() {
        assertNull(IntentMap.disclosureError(deep(disclosure(2))))
        assertNotNull(IntentMap.disclosureError(deep(disclosure(2).also { it["extra"] = 1L })))
        for (s in listOf<Any?>(null, "15", 3L, (1L shl 24) + 1)) assertNotNull(s.toString(), IntentMap.disclosureError(deep(disclosure(2).also { it["size"] = s })))
        val mt = LinkedHashMap(metrics)
        assertNull(IntentMap.metricsError(deep(mt)))
        mt["log2_vs_mbits"] = 4500L
        assertNull(IntentMap.metricsError(deep(mt)))
        mt["log2_vs_mbits"] = null
        assertNotNull(IntentMap.metricsError(deep(mt)))
        assertNotNull(IntentMap.cellError(deep(jm("verb", "a", "cell", jl(), "p_ppm", 1_000_001L, "in_grant", true))))
        assertNotNull(IntentMap.cellError(deep(jm("verb", "a", "cell", jl(), "p_ppm", 0L, "in_grant", 1L))))
        assertNotNull(IntentMap.learnerError(deep(jm("learner_digest", "x"))))
        assertEquals("header.cells is not the product of the dimensions' cell counts", IntentMap.headerError(deep(book).also { mm(it)["cells"] = 8L }))
        assertNotNull(IntentMap.headerError(deep(book).also { mm(ml(it["dims"])[0])["path"] = "env.hour" }))
        assertNotNull(IntentMap.headerError(deep(book).also { ml(mm(ml(it["dims"])[1])["values"]).reverse() }))
    }

    @Test fun primitiveEntry() {
        val inp = jm("map_commit", commit, "action", jm("verb", "air.book", "resource", "r", "params_digest", Pca.paramsDigest(deep(params(38_900L, "economy")))),
            "params", params(38_900L, "economy"), "disclosure", disclosure(2))
        assertTrue(IntentMap.decidePrimitive(inp).ok)
        inp["max_residual_risk_ppm"] = 1199L
        assertFalse(IntentMap.decidePrimitive(inp).ok)
        inp.remove("max_residual_risk_ppm")
        inp.remove("params")
        assertFalse(IntentMap.decidePrimitive(inp).ok)
    }
}
