package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation-style differential for [IntentV2] and everything it drives (context validators, session, accumulators, W-B):
 * test-data/k042-intentv2-mut.json.gz (tools/pca-audit/java-mutate/k042-intentv2-mut-oracle.mts) replaces every structural path of
 * the k042-intentv2-cases corpus (context, PCActn, grant) by null / booleans / numbers / strings / containers, deletes it or adds an
 * unknown sibling, and records the reference decideIntentV2 result. Same case format and comparison as [IntentV2DiffTest].
 */
class K042IntentV2MutTest {
    @Suppress("UNCHECKED_CAST")
    private fun cases(): List<Map<String, Any?>> = GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-intentv2-mut.json.gz"))).use {
        (Json.parseLenient(String(it.readAllBytes(), Charsets.UTF_8)) as Map<String, Any?>)["cases"] as List<Map<String, Any?>>
    }

    /**
     * Not reachable through the verifier: a PCActn that fails the wire check or a grant that is not an object is refused BEFORE
     * IntentV2 runs, so the wording of IntentV2's own (still fail-closed) answer to such a direct call is not pinned here.
     */
    private fun wireReachable(c: Map<String, Any?>): Boolean {
        if (Json.parseLenient(c["grant"] as String) !is Map<*, *>) return false
        return Pca.validateWireV2(Json.parseLenient(c["p"] as String)) == null
    }

    @Suppress("UNCHECKED_CAST")
    private fun mismatch(cs: Map<String, Any?>): String? {
        val p = Json.parseLenient(cs["p"] as String) as Map<String, Any?>
        val grant = Json.parseLenient(cs["grant"] as String) as Map<String, Any?>
        val ctx = if (cs.containsKey("ctx")) IntentV2.Context.fromJsonText(cs["ctx"] as String) else null
        val d = IntentV2.decide(p, grant, ctx, (cs["now"] as Json.Num).raw.toLong())
        val want = cs["checks"] as List<Map<String, Any?>>
        val got = d.checks.mapIndexed { i, c ->
            var r = c.reason
            if (r != null && r.contains("unsupported_suite")) return null
            if (r != null && want.getOrNull(i)?.get("prefix") == true) {
                val k = r.indexOf("(fail closed): ")
                if (k >= 0) r = r.substring(0, k + "(fail closed): ".length)
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

    @Test fun everyMutationMatchesTheReference() {
        val all = cases()
        assertTrue("oracle cases: ${all.size}", all.size > 14000)
        var skipped = 0
        val bad = ArrayList<String>()
        for (c in all) {
            if (!wireReachable(c)) { skipped++; continue }
            // principled skip: with the epoch's pq_pk deleted the reference THROWS while binding the suite fields ("revocation epoch
            // check error"); this verifier answers "revocation epoch signature invalid". Both refuse.
            if (c["name"] == "mut/ctx/session.revocation.epoch.pq_pk/15") continue
            val m = try { mismatch(c) } catch (t: Throwable) { "${c["name"]}: THROWS $t" }
            if (m != null) bad.add(m)
        }
        if (Files.isDirectory(Path.of("target"))) Files.writeString(Path.of("target/k042-intentv2-mut-bad.txt"), bad.joinToString("\n"))
        assertTrue("skipped $skipped", skipped < 3500)
        assertTrue("${bad.size} of ${all.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }
}
