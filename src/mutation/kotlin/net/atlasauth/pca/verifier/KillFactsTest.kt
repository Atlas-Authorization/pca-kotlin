package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Differential mutation kills for rule 16 (OracleFacts.kt: facts, relational dimensions, offer sets) and rule 17 + the V14
 * read cell (ParamProvenance.kt: provenance, label receipts, flows, read purpose) against the TS reference:
 * test-data/killFacts.json is written by tools/pca-audit/kotlin-mutate/killFacts-oracle-gen.mjs (packages/pca/src
 * oracle-facts.ts, offer-set.ts, param-provenance.ts, label-receipts.ts on targeted inputs; reuses the Go W-B oracle cases).
 * Every validator and decision is pinned to the exact TS verdict AND reason; where the Kotlin wording is deliberately its
 * own (fail-closed errors name the exception class; a non-object input is a cast error) the expected text is mapped below.
 */
class KillFactsTest {
    companion object {
        @Suppress("UNCHECKED_CAST")
        val cases: List<Map<String, Any?>> by lazy {
            val top = Json.parseLenient(String(Files.readAllBytes(Path.of("test-data/killFacts.json")), Charsets.UTF_8)) as Map<String, Any?>
            top["cases"] as List<Map<String, Any?>>
        }

        fun of(kind: String, fn: String? = null): List<Map<String, Any?>> =
            cases.filter { it["kind"] == kind && (fn == null || it["fn"] == fn) }.also { require(it.isNotEmpty()) { "$kind/$fn" } }

        /**
         * Kotlin-specific reasons: the TS fail-closed text carries the JS error message, Kotlin the exception class; a
         * non-object input is a TS shape refusal but a Kotlin cast error (caught: the same fail-closed family).
         */
        val KOTLIN_REASON: Map<String, String> = mapOf(
            "world/k-input-array" to "facts: evaluation error (fail closed): ClassCastException",
            "world/k-input-null" to "facts: evaluation error (fail closed): NullPointerException",
            "prov/k-input-null" to "provenance: evaluation error (fail closed): NullPointerException",
            "prov/k-input-array" to "provenance: evaluation error (fail closed): ClassCastException",
        )
    }

    private fun n(o: Any?): Any? = IntentJs.normalize(o)

    private fun reasonOf(c: Map<String, Any?>): String? {
        KOTLIN_REASON[c["name"]]?.let { return it }
        val r = c["ts_reason"] as String
        return if (r.isEmpty()) null else r
    }

    private fun validator(fn: String, f: (Any?) -> String?) {
        val bad = ArrayList<String>()
        for (c in of("fn", fn)) {
            val got = f(n(c["arg"]))
            val want = reasonOf(c)
            if (got != want) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        if (bad.isNotEmpty()) fail(bad.joinToString("\n"))
    }

    @Test fun factWire() = validator("validateFactWire") { OracleFacts.validateFactWire(it) }
    @Test fun worldPolicy() = validator("validateWorldPolicy") { OracleFacts.validateWorldPolicy(it) }
    @Test fun offerPolicy() = validator("validateOfferPolicy") { OracleFacts.validateOfferPolicy(it) }
    @Test fun offerSetWire() = validator("validateOfferSetWire") { OracleFacts.validateOfferSetWire(it) }
    @Test fun labelsWire() = validator("validateLabelsWire") { ParamProvenance.validateLabelsWire(it) }
    @Test fun flowRules() = validator("validateFlowRules") { ParamProvenance.validateFlowRules(it) }
    @Test fun provenancePolicy() = validator("validateProvenancePolicy") { ParamProvenance.validateProvenancePolicy(it) }
    @Test fun provWire() = validator("validateProvWire") { ParamProvenance.validateProvWire(it) }

    @Test fun ratio() {
        for (c in of("ratio")) {
            val got = OracleFacts.ratioPpm(IntentJs.lng(c["a"]), IntentJs.lng(c["b"]))
            if (c["want_ok"] == true) assertEquals(c["name"].toString(), IntentJs.lng(c["want"]), got)
            else assertEquals(c["name"].toString(), null, got)
        }
    }

    @Test fun flowRule() {
        for (c in of("flowRule")) {
            val got = ParamProvenance.flowRuleFor(IntentJs.obj(n(c["rules"])), c["cls"] as String)
            assertEquals(c["name"].toString(), if (c["want_ok"] == true) c["want"] else null, got)
        }
    }

    @Test fun flowAllowed() {
        for (c in of("flowAllowed")) {
            val got = ParamProvenance.flowAllowed(IntentJs.obj(n(c["rules"])), c["cls"] as String, c["origin"] as String, c["aud"] as String)
            assertEquals(c["name"].toString(), c["want"], got)
        }
    }

    @Test fun worldActive() {
        for (c in of("worldActive")) {
            val i = n(c["input"]) as Map<*, *>
            assertEquals(c["name"].toString(), c["want"] ?: c["expect"], OracleFacts.intentWorldActive(i["committed"], i["policy"]))
        }
    }

    @Test fun worldDecisions() {
        val bad = ArrayList<String>()
        for (c in of("world")) {
            val r = OracleFacts.decideIntentWorld(n(c["input"]))
            val exp = c["expect"] as Map<*, *>
            val want = reasonOf(c)
            val okWant = exp["ok"] == true
            val sameOut = if (okWant) r.ok && r.reason == null && IntentJs.jsonEquals(r.world, n(exp["world"])) &&
                IntentJs.jsonEquals(r.singleSource, n(exp["single_source"])) && keyOrder(r.world!!, exp["world"] as Map<*, *>)
            else !r.ok && r.world == null && r.singleSource == null
            if (!sameOut || r.reason != want) bad.add("${c["name"]}: want ok=$okWant <$want> ${exp["world"]} got ok=${r.ok} <${r.reason}> ${r.world} ${r.singleSource}")
        }
        if (bad.isNotEmpty()) fail("${bad.size} mismatches\n" + bad.joinToString("\n"))
    }

    /** `env.world` keeps declaration order (worlds, relational, offers) like the TS null-prototype record. */
    private fun keyOrder(got: Map<String, Any?>, want: Map<*, *>): Boolean = got.keys.toList() == want.keys.toList()

    @Test fun provDecisions() {
        val bad = ArrayList<String>()
        for (c in of("prov")) {
            val r = ParamProvenance.decide(n(c["input"]))
            val exp = c["expect"] as Map<*, *>
            val want = reasonOf(c)
            var ok = r.outcome == exp["outcome"] && r.reason == want
            if (exp["outcome"] == "deny") ok = ok && r.friction == null && r.env.isEmpty()
            else {
                ok = ok && IntentJs.jsonEquals(r.labels, n(exp["labels"])) && IntentJs.jsonEquals(r.classes, n(exp["classes"])) &&
                    r.friction == exp["friction"] && IntentJs.jsonEquals(r.env, nest(r.labels))
            }
            if (!ok) bad.add("${c["name"]}: want ${exp["outcome"]} <$want> ${exp["labels"]} ${exp["classes"]} ${exp["friction"]} got ${r.outcome} <${r.reason}> ${r.labels} ${r.classes} ${r.friction} ${r.env}")
        }
        if (bad.isNotEmpty()) fail("${bad.size} mismatches\n" + bad.joinToString("\n"))
    }

    /** The expected `env`: every classified path nested (no overlaps reach a pass / question). */
    private fun nest(labels: Map<String, Any?>): Map<String, Any?> {
        val env = LinkedHashMap<String, Any?>()
        for ((p, v) in labels) assertTrue(p, IntentArtifacts.setNested(env, p, v))
        return env
    }

    @Test fun readPurpose() {
        for (c in of("read")) {
            val r = ParamProvenance.decideReadPurpose(n(c["input"]))
            val exp = c["expect"] as Map<*, *>
            assertEquals(c["name"].toString(), exp["outcome"], r.outcome)
            assertEquals(c["name"].toString(), exp["minimise"], r.minimise)
            assertEquals(c["name"].toString(), exp["uncovered"], r.uncovered)
        }
    }
}
