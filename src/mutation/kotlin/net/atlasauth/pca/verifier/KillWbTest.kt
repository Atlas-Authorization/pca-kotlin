package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Differential kills for IntentWB.kt (rules 16-18 unit, the W-B context shape rule, activity): every case of
 * test-data/killWb.json was decided by the TS reference (packages/pca/src/intent-env.ts `decideIntentWB` /
 * `intentWBActive`; generator tools/pca-audit/kotlin-mutate/killWb-oracle-gen.mjs) and this verifier must reproduce the
 * FULL result: outcome, the reported checks in order, the exact reason, and (when the unit does not deny) env.world /
 * env.prov / env.class, friction and single_source. On deny the Kotlin result carries no env, friction or single_source
 * (the verifier never reads them on deny; TS keeps the partial env in its result object, unread as well).
 */
class KillWbTest {
    companion object {
        @Suppress("UNCHECKED_CAST")
        val cases: List<Map<String, Any?>> by lazy {
            val j = Json.parseLenient(String(Files.readAllBytes(Path.of("test-data/killWb.json")), Charsets.UTF_8)) as Map<String, Any?>
            j["cases"] as List<Map<String, Any?>>
        }
        fun of(kind: String): List<Map<String, Any?>> = cases.filter { it["kind"] == kind }
        fun canon(v: Any?): String = Json.canonicalize(v)
    }

    @Suppress("UNCHECKED_CAST")
    private fun checkWb(c: Map<String, Any?>) {
        val name = c["name"] as String
        val exp = c["expect"] as Map<String, Any?>
        val r = IntentWB.decide(IntentJs.normalize(c["input"]) as Map<String, Any?>)
        assertEquals("$name outcome", exp["outcome"], r.outcome)
        assertEquals("$name check order", exp["check_order"], r.checks.keys.toList())
        assertEquals("$name checks", canon(exp["checks"]), canon(r.checks))
        assertEquals("$name reason", exp["reason"], r.reason)
        if (r.outcome == "deny") {
            assertNull("$name world on deny", r.world)
            assertNull("$name prov on deny", r.prov)
            assertNull("$name class on deny", r.cls)
            assertNull("$name friction on deny", r.friction)
            assertNull("$name single_source on deny", r.singleSource)
            return
        }
        val env = exp["env"] as Map<String, Any?>
        assertEquals("$name env.world", env["world"]?.let { canon(it) }, r.world?.let { canon(it) })
        assertEquals("$name env.prov", env["prov"]?.let { canon(it) }, r.prov?.let { canon(it) })
        assertEquals("$name env.class", env["class"]?.let { canon(it) }, r.cls?.let { canon(it) })
        assertEquals("$name friction", exp["friction"], r.friction)
        assertEquals("$name single_source", exp["single_source"], r.singleSource)
    }

    @Test fun unitDecisions() {
        val wb = of("wb").filter { !(it["name"] as String).startsWith("wb/ctx-") }
        assertEquals(true, wb.size > 40)
        for (c in wb) checkWb(c)
    }

    @Test fun contextShape() {
        val ctx = of("wb").filter { (it["name"] as String).startsWith("wb/ctx-") }
        assertEquals(true, ctx.size > 30)
        for (c in ctx) checkWb(c)
    }

    /** The internal contextError seam directly (null = well-formed), against the TS reason after its fixed prefix. */
    @Suppress("UNCHECKED_CAST")
    @Test fun contextErrorSeam() {
        for (c in of("wb").filter { (it["name"] as String).startsWith("wb/ctx-") }) {
            val exp = c["expect"] as Map<String, Any?>
            val want = (exp["reason"] as String?)?.removePrefix("facts: the W-B context is malformed: ")
            assertEquals(c["name"] as String, want, IntentWB.contextError(IntentJs.normalize(c["input"]) as Map<String, Any?>))
        }
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun activity() {
        val act = of("active")
        assertEquals(true, act.size > 15)
        for (c in act) {
            val e = c["expect"] as Map<String, Any?>
            assertArrayEquals(c["name"] as String, booleanArrayOf(e["facts"] == true, e["provenance"] == true, e["classes"] == true), IntentWB.active(c["input"]))
        }
    }

    /** A fresh Result is an admit with no checks and no env (the defaults the unit starts from). */
    @Test fun resultDefaults() {
        val r = IntentWB.Result()
        assertEquals("admit", r.outcome)
        assertEquals(0, r.checks.size)
        assertNull(r.world); assertNull(r.prov); assertNull(r.cls); assertNull(r.reason); assertNull(r.friction); assertNull(r.singleSource)
        val w = linkedMapOf<String, Any?>("a" to 1L)
        r.world = w; r.prov = w; r.cls = w; r.reason = "x"; r.friction = "tap"; r.singleSource = listOf("a")
        assertEquals(w, r.world); assertEquals(w, r.prov); assertEquals(w, r.cls)
        assertEquals("x", r.reason); assertEquals("tap", r.friction); assertEquals(listOf("a"), r.singleSource)
    }
}
