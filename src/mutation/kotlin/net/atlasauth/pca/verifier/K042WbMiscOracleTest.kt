package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential for IntentWB (the W-B unit, rules 16-18): every case of test-data/k042-wbmisc.json.gz (the TS reference
 * decideIntentWB, from tools/pca-audit/java-mutate/k042-wbmisc-oracle.mjs) compares the FULL result: outcome, checks in order, exact
 * reason, friction, world / prov / class env members and single_source (all cleared on deny).
 */
@Suppress("UNCHECKED_CAST")
class K042WbMiscOracleTest {
    companion object {
        /** The one deny-preserving divergence of the fail-closed evaluation-error text: the JVM reports the exception class. */
        val EVAL_ERROR_TEXT = mapOf("lift/cls/content-too-deep" to "classes: evaluation error (fail closed): IllegalArgumentException")
        val all: List<Map<String, Any?>> by lazy {
            GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-wbmisc.json.gz"))).use {
                (Json.parseLenient(String(it.readAllBytes(), Charsets.UTF_8)) as Map<String, Any?>)["cases"] as List<Map<String, Any?>>
            }
        }
        fun got(r: IntentWB.Result): Map<String, Any?> = linkedMapOf(
            "outcome" to r.outcome,
            "checks" to r.checks.entries.map { listOf(it.key, it.value) },
            "reason" to r.reason, "friction" to r.friction, "world" to r.world, "prov" to r.prov, "class" to r.cls,
            "single_source" to r.singleSource?.let { ArrayList<Any?>(it) },
        )
    }

    private fun run(vararg prefixes: String): Int {
        val bad = ArrayList<String>(); var n = 0
        for (c in all) {
            val name = c["name"] as String
            if (prefixes.none { name.startsWith(it) }) continue
            n++
            val input = IntentJs.obj(IntentJs.normalize(c["input"]))
            val r = try { IntentWB.decide(input) } catch (e: RuntimeException) { bad.add("$name: threw $e"); continue }
            var want = IntentJs.normalize(c["expect"]) as Map<String, Any?>
            if (EVAL_ERROR_TEXT.containsKey(name)) want = LinkedHashMap(want).also { it["reason"] = EVAL_ERROR_TEXT[name] }
            val w = Json.canonicalize(want); val have = Json.canonicalize(got(r))
            if (w != have) bad.add("$name\n   want $w\n   have $have")
        }
        assertEquals("${bad.size} mismatches:\n" + bad.take(30).joinToString("\n"), 0, bad.size)
        return n
    }

    @Test fun contextShape() = assertTrue(run("ctx/", "wb/ctx-") > 60)
    @Test fun goUnitCases() = assertTrue(run("wb/") >= 30)
    @Test fun liftedWorld() = assertTrue(run("lift/world/") > 100)
    @Test fun liftedProvenance() = assertTrue(run("lift/prov/") > 100)
    @Test fun liftedClassifiers() = assertTrue(run("lift/cls/") > 40)
    @Test fun droppedMembers() = assertTrue(run("drop-", "other-") > 150)
    @Test fun denyClearsEarlierEnv() = assertTrue(run("then-") >= 20)

    @Test fun everyCaseIsRun() {
        val total = listOf("ctx/", "wb/", "lift/world/", "lift/prov/", "lift/cls/", "drop-", "other-", "then-")
            .sumOf { p -> all.count { (it["name"] as String).startsWith(p) } }
        assertEquals(all.size, total)
    }
}
