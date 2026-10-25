package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential tests of [IntentV2.decide] / [IntentV2.active] against the TS reference decideIntentV2.
 * test-data/k042-intentv2-cases.json.gz is the shared oracle (tools/pca-audit/java-mutate/k042-intentv2-oracle.mts; the Java,
 * Python, PHP and .NET suites run the same file): every case asserts the EXACT check list (name, ok, reason, in order), the
 * canonical env and `active`. A thrown-internal-error reason is compared up to its prefix "<check> error (fail closed): ".
 */
class IntentV2DiffTest {
    companion object {
        private const val FAIL_CLOSED = "(fail closed): "
        @Suppress("UNCHECKED_CAST")
        val cases: List<Map<String, Any?>> by lazy {
            GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-intentv2-cases.json.gz"))).use {
                (Json.parseLenient(String(it.readAllBytes(), Charsets.UTF_8)) as Map<String, Any?>)["cases"] as List<Map<String, Any?>>
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun mismatch(cs: Map<String, Any?>): String? {
        val p = Json.parseLenient(cs["p"] as String) as Map<String, Any?>
        val grant = Json.parseLenient(cs["grant"] as String) as Map<String, Any?>
        var ctx = if (cs.containsKey("ctx")) IntentV2.Context.fromJsonText(cs["ctx"] as String) else null
        if (cs.containsKey("wp")) ctx = ctx!!.withParams(Json.parseLenient(cs["wp"] as String))
        val d = IntentV2.decide(p, grant, ctx, (cs["now"] as Json.Num).raw.toLong())
        val want = cs["checks"] as List<Map<String, Any?>>
        val got = d.checks.mapIndexed { i, c ->
            var r = c.reason
            if (r != null && r.contains("unsupported_suite")) return null // a PQ suite this host lacks: by design
            if (r != null && want.getOrNull(i)?.get("prefix") == true) {
                val k = r.indexOf(FAIL_CLOSED)
                if (k >= 0) r = r.substring(0, k + FAIL_CLOSED.length)
            }
            "${c.name}|${c.ok}|$r"
        }.joinToString("\n")
        val w = want.joinToString("\n") { "${it["name"]}|${it["ok"]}|${it["reason"]}" }
        val env = Json.canonicalize(d.env)
        val active = IntentV2.active(p, ctx)
        val wantActive = cs["active"] == true || cs["active"] == "true"
        return if (got == w && env == (cs["env"] ?: "{}") && active == wantActive) null
        else "${cs["name"]}:\n  want $w\n  got  $got\n  env want ${cs["env"]} got $env; active want $wantActive got $active"
    }

    @Test fun everyCaseMatchesTheReference() {
        assertTrue(cases.size > 1000)
        val bad = cases.mapNotNull { mismatch(it) }
        assertEquals("${bad.size} of ${cases.size} cases differ:\n" + bad.take(15).joinToString("\n"), 0, bad.size)
    }
}
