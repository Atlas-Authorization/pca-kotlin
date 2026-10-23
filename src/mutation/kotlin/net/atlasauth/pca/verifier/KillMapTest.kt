package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential mutation kills for rule 19 (IntentMap.kt) and rule 18 (IntentClassifier.kt) against the TS reference:
 * test-data/killMap.json is written by tools/pca-audit/kotlin-mutate/killMap-oracle-gen.mjs (packages/pca/src
 * intent-map-commit.ts / intent-classifier.ts on targeted inputs). Every shape check is pinned to the exact TS reason;
 * where the Kotlin wording is deliberately its own (the cell-of-ω refusal does not name the path, ε prints as an integer,
 * fail-closed errors name the exception class) the expected text is mapped to the Kotlin wording below.
 */
class KillMapTest {
    companion object {
        @Suppress("UNCHECKED_CAST")
        val cases: List<Map<String, Any?>> by lazy {
            Json.parseLenient(String(Files.readAllBytes(Path.of("test-data/killMap.json")), Charsets.UTF_8)) as List<Map<String, Any?>>
        }

        fun of(fn: String): List<Map<String, Any?>> = cases.filter { it["fn"] == fn }.also { require(it.isNotEmpty()) { fn } }

        @Suppress("UNCHECKED_CAST")
        fun args(c: Map<String, Any?>): List<Any?> = (IntentJs.normalize(c["args"]) as List<Any?>)

        private val OUTSIDE = Regex("^the action's .* lies outside the committed map's dimension$")
        private val EXCEEDS = Regex("^the committed residual risk (\\d+) ppm exceeds ε = (.*)$")

        /** The Kotlin wording of a TS decideMapDisclosure reason. */
        fun mapReason(ts: String): String {
            if (OUTSIDE.matches(ts)) return "the action's value lies outside the committed map's dimension"
            val m = EXCEEDS.matchEntire(ts)
            if (m != null) return "the committed residual risk ${m.groupValues[1]} ppm exceeds ε = ${m.groupValues[2].toDouble().toLong()}"
            return failClosed(ts)
        }

        /** TS fail-closed reasons carry the error message; Kotlin names the exception (strict canonicalization: IAE). */
        fun failClosed(ts: String): String {
            for (p in listOf("map error (fail closed): ", "classes: evaluation error (fail closed): "))
                if (ts.startsWith(p + "canonicalize: ")) return p + "IllegalArgumentException"
            return ts
        }
    }

    private fun shape(fn: String, f: (Any?) -> String?) {
        for (c in of(fn)) assertEquals(c["name"].toString(), c["out"], f(args(c)[0]))
    }

    @Test fun headerShapes() = shape("header") { IntentMap.headerError(it) }
    @Test fun cellShapes() = shape("cell") { IntentMap.cellError(it) }
    @Test fun metricsShapes() = shape("metrics") { IntentMap.metricsError(it) }
    @Test fun learnerShapes() = shape("learner") { IntentMap.learnerError(it) }
    @Test fun disclosureShapes() = shape("disclosure") { IntentMap.disclosureError(it) }

    @Test fun numericCells() {
        for (c in of("numcells")) {
            val cells = IntentMap.numCells(IntentJs.obj(args(c)[0]))
            for (r in cells) assertEquals(c["name"].toString(), 2, r.size)
            val got = cells.map { listOf(it[0], it[1]) }
            assertTrue(c["name"].toString(), IntentJs.jsonEquals(got, c["out"]))
        }
    }

    @Test fun cellOfOmega() {
        for (c in of("cellof")) {
            val a = args(c)
            val w = IntentMap.cellOf(IntentJs.obj(a[0]), a[1], if (a.size > 2) a[2] else null)
            val got: Any? = if (w == null) null else linkedMapOf("cell" to w.first.toList(), "flat" to w.second)
            assertTrue(c["name"].toString() + " got " + got, IntentJs.jsonEquals(got, c["out"]))
        }
    }

    @Test fun rootFromPath() {
        for (c in of("rootpath")) {
            val a = args(c)
            val path = (a[3] as List<*>).map { Pca.decodeB64uStrict(it, 32)!! }
            val r = IntentMap.rootFromPath(IntentJs.lng(a[0]), IntentJs.lng(a[1]), Pca.decodeB64uStrict(a[2], 32)!!, path)
            assertEquals(c["name"].toString(), c["out"], r?.let { Pca.b64(it) })
        }
    }

    @Test fun commitPrimitive() {
        for (c in of("commit")) assertEquals(c["name"].toString(), c["out"], IntentMap.commitLeaves(args(c)[0]))
    }

    @Test fun decisions() {
        for (c in of("decide")) {
            val d = IntentMap.decidePrimitive(args(c)[0])
            val want = IntentJs.obj(c["out"])
            val name = c["name"].toString()
            assertEquals(name + " " + d.reason, want["ok"], d.ok)
            if (d.ok) {
                assertTrue(name, IntentJs.jsonEquals(d.cell, want["cell"]))
                assertTrue(name, IntentJs.jsonEquals(d.pPpm, want["p_ppm"]))
                assertTrue(name, IntentJs.jsonEquals(d.residualRiskPpm, want["residual_risk_ppm"]))
                assertEquals(name, null, d.reason)
            } else {
                assertEquals(name, mapReason(want["reason"] as String), d.reason)
                assertEquals(name, null, d.cell)
                assertEquals(name, 0L, d.pPpm)
                assertEquals(name, 0L, d.residualRiskPpm)
            }
        }
    }

    @Test fun verdictWire() = shape("verdictwire") { IntentClassifier.validateVerdictWire(it) }
    @Test fun classifierPolicy() = shape("policy") { IntentClassifier.validatePolicy(it) }

    @Test fun classify() {
        for (c in of("classify")) {
            val r = IntentClassifier.decide(args(c)[0])
            val want = IntentJs.obj(c["out"])
            val name = c["name"].toString()
            assertEquals(name + " " + r.reason, want["ok"], r.ok)
            if (r.ok) {
                assertTrue(name + " " + r.classes, IntentJs.jsonEquals(r.classes, want["classes"]))
                assertEquals(name, null, r.reason)
            } else {
                assertEquals(name, failClosed(want["reason"] as String), r.reason)
                assertEquals(name, null, r.classes)
            }
        }
    }
}
