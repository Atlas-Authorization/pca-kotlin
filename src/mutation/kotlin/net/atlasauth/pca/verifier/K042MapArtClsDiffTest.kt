package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for IntentMap (rule 19), IntentClassifier (rule 18) and IntentArtifacts:
 * test-data/k042-mapartcls.json.gz from tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs. Every validator case asserts the
 * EXACT reason (or null), every decision the exact verdict. One wording difference, shared by every native verifier: TS names the
 * dimension path in "the action's <path> lies outside ..."; the natives say "the action's value lies outside ...".
 */
class K042MapArtClsDiffTest {
    companion object {
        const val OUTSIDE = "the action's value lies outside the committed map's dimension"
        @Suppress("UNCHECKED_CAST")
        val all: List<Map<String, Any?>> by lazy {
            GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-mapartcls.json.gz"))).use {
                IntentJs.normalize(Json.parseLenient(String(it.readAllBytes(), Charsets.UTF_8))) as List<Map<String, Any?>>
            }
        }
        fun of(fn: String): List<Map<String, Any?>> = all.filter { it["fn"] == fn }.also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        @Suppress("UNCHECKED_CAST") fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(bad: List<String>) = assertTrue("${bad.size} divergent case(s):\n" + bad.joinToString("\n"), bad.isEmpty())
    }

    private fun validators(fn: String, v: (Any?) -> String?) {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val want = c["out"] as String?
            val got = try { v(args(c)[0]) } catch (t: Throwable) { "THROWS $t" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad)
    }

    @Test fun headerLeaf() = validators("header") { IntentMap.headerError(it) }
    @Test fun cellLeaf() = validators("cell") { IntentMap.cellError(it) }
    @Test fun metricsLeaf() = validators("metrics") { IntentMap.metricsError(it) }
    @Test fun learnerLeaf() = validators("learner") { IntentMap.learnerError(it) }
    @Test fun disclosureShape() = validators("disclosure") { IntentMap.disclosureError(it) }
    @Test fun verdictWire() = validators("verdictwire") { IntentClassifier.validateVerdictWire(it) }
    @Test fun classifierPolicy() = validators("policy") { IntentClassifier.validatePolicy(it) }

    @Test fun numericCells() {
        val bad = ArrayList<String>()
        for (c in of("numcells")) {
            val got = IntentMap.numCells(IntentJs.obj(args(c)[0])).map { it.toList() }
            val want = (c["out"] as List<*>).map { r -> (r as List<*>).map { IntentJs.lng(it) } }
            if (got != want) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad)
    }

    @Test fun cellOfTheAction() {
        val bad = ArrayList<String>()
        for (c in of("cellof")) {
            val a = args(c); val want = c["out"]
            val got = try {
                val r = IntentMap.cellOf(IntentJs.obj(a[0]), a[1], if (a.size > 2) a[2] else null)
                if (r == null) "null" else "${r.first.toList()} ${r.second}"
            } catch (t: Throwable) { "THROWS $t" }
            val w = if (want == null) "null" else "${(IntentJs.get(want, "cell") as List<*>).map { IntentJs.lng(it) }} ${IntentJs.lng(IntentJs.get(want, "flat"))}"
            if (w != got) bad.add("${c["name"]}\n  want: $w\n  got:  $got")
        }
        report(bad)
    }

    @Test fun commitment() {
        val bad = ArrayList<String>()
        for (c in of("commit")) {
            val got = try { IntentMap.commitLeaves(args(c)[0]) } catch (t: Throwable) { "THROWS $t" }
            if (c["out"] != got) bad.add("${c["name"]}\n  want: ${c["out"]}\n  got:  $got")
        }
        report(bad)
    }

    private fun render(d: IntentMap.Decision) = "${d.ok}|${d.reason}|${d.cell}|${d.pPpm}|${d.residualRiskPpm}"
    private fun renderWant(o: Map<*, *>): String {
        if (o["ok"] == true) return "true|null|${(o["cell"] as List<*>).map { IntentJs.lng(it) }}|${IntentJs.lng(o["p_ppm"])}|${IntentJs.lng(o["residual_risk_ppm"])}"
        var r = o["reason"] as String
        if (r.startsWith("the action's ") && r.endsWith(" lies outside the committed map's dimension")) r = OUTSIDE
        return "false|$r|null|0|0"
    }

    @Test fun mapDecisions() {
        val bad = ArrayList<String>()
        for (c in of("decide")) {
            val want = renderWant(c["out"] as Map<*, *>)
            val got = try { render(IntentMap.decidePrimitive(args(c)[0])) } catch (t: Throwable) { "THROWS $t" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad)
    }

    @Test fun classifierDecisions() {
        val bad = ArrayList<String>()
        for (c in of("classify")) {
            val o = c["out"] as Map<*, *>
            val want = "${o["ok"]}|${o["reason"]}|${o["classes"]?.let { Json.canonicalize(it) }}"
            val got = try {
                val r = IntentClassifier.decide(args(c)[0])
                "${r.ok}|${r.reason}|${r.classes?.let { Json.canonicalize(it) }}"
            } catch (t: Throwable) { "THROWS $t" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad)
    }

    @Test fun classifierDecisionsNormalizedEntry() {
        for (c in of("classify")) {
            val inp = args(c)[0]
            if (inp !is Map<*, *>) continue
            val o = c["out"] as Map<*, *>
            val r = IntentClassifier.decideNormalized(IntentJs.obj(inp))
            assertEquals(c["name"] as String, o["reason"], r.reason)
            assertEquals(c["name"] as String, o["ok"], r.ok)
        }
    }

    @Test fun artifactSignature() {
        val a = args(of("sigfixture")[0])
        @Suppress("UNCHECKED_CAST") val v = IntentJs.obj(a[0]) as Map<String, Any?>
        val pk = a[1] as String; val other = a[2] as String
        val dom = IntentClassifier.INTENT_CLASSIFIER_DOMAIN
        assertTrue(IntentArtifacts.verifyArtifactSig(dom, v, pk, null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, v, other, null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom + "x", v, pk, null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, LinkedHashMap(v).also { it.remove("sig") }, pk, null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, LinkedHashMap(v).also { it["sig"] = Json.Num("5") }, pk, null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, v, null, null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, v, Json.Num("5"), null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, LinkedHashMap(v).also { it["label"] = "a\uD800" }, pk, null))
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, LinkedHashMap(v).also { it["v"] = Json.Num("1.0") }, pk, null))
    }

    @Test fun contentNormalization() {
        val c = of("classify").first { it["name"] == "classify/content-number" }
        val inp = IntentJs.obj(IntentJs.normalize(Json.parseLenient(Json.canonicalize(args(c)[0]))))
        (IntentJs.obj(IntentJs.obj(inp["action"])["params"]) as MutableMap<String, Any?>)["text"] = Json.Num("1.0")
        val r = IntentClassifier.decide(inp)
        assertTrue(r.reason, r.ok)
        assertEquals(mapOf("tone" to "calm"), r.classes)
        val inner = IntentClassifier.decideNormalized(inp)
        assertFalse(inner.ok)
        assertEquals("classes: evaluation error (fail closed): IllegalArgumentException", inner.reason)
        assertNull(inner.classes)
    }
}
