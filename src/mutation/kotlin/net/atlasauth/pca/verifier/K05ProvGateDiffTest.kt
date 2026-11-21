package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for build provenance as a K1 discharge (ProvenanceGate): test-data/k05-provgate.json.gz
 * from tools/pca-audit/k05-oracles/provgate-oracle.mts. Shape errors compare the exact reason, the gate the canonical JSON of
 * `{ok, level, claims}` / `{ok: false, code}`, inclusion proofs the verdict, the leaf hash the bytes, the caveat its canonical JSON.
 */
class K05ProvGateDiffTest {
    companion object {
        const val FILE = "k05-provgate.json.gz"

        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }

        @Suppress("UNCHECKED_CAST") fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(bad: List<String>) = assertTrue("${bad.size} divergent case(s):\n" + bad.take(60).joinToString("\n"), bad.isEmpty())
        fun canon(v: Any?): String = Json.canonicalize(v)
        fun ub(o: Any?): ByteArray = Base64.getUrlDecoder().decode(o as String)

        @Suppress("UNCHECKED_CAST") fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    }

    private fun check(fn: String, want: (Any?) -> String, got: (List<Any?>) -> String) {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val w = want(c["out"])
            val g = try { got(args(c)) } catch (t: Throwable) { "THROWS $t" }
            if (w != g) bad.add("${c["name"]}\n  want: $w\n  got:  $g")
        }
        report(bad)
    }

    @Test fun factsShape() = check("provenanceFactsError", { "$it" }) { "${ProvenanceGate.provenanceFactsError(it[0])}" }
    @Test fun policyShape() = check("provenancePolicyError", { "$it" }) { "${ProvenanceGate.provenancePolicyError(it[0])}" }

    @Test fun gate() = check("provenanceGate", { canon(it) }) {
        val r = ProvenanceGate.provenanceGate(it[0])
        canon(if (r.ok) linkedMapOf("ok" to true, "level" to r.level, "claims" to r.claims) else linkedMapOf("ok" to false, "code" to r.code))
    }

    @Test fun inclusion() = check("verifyRfc9162Inclusion", { "$it" }) {
        "${ProvenanceGate.verifyRfc9162Inclusion(ub(it[0]), IntentJs.lng(it[1]), IntentJs.lng(it[2]), (it[3] as List<*>).map { p -> ub(p) }, ub(it[4]))}"
    }

    @Test fun leafHash() = check("rfc9162LeafHash", { mp(it)["\$bytes"] as String }) { Pca.b64(ProvenanceGate.rfc9162LeafHash(ub(it[0]))) }

    @Test fun caveat() = check("provenanceCaveat", { canon(it) }) {
        val o = mp(it[0])
        canon(
            ProvenanceGate.provenanceCaveat(
                ProvenanceGate.CaveatOptions(
                    issuer = o["issuer"] as String,
                    minLevel = IntentJs.lng(o["min_level"]),
                    id = o["id"] as String?,
                    sourceRepo = o["source_repo"] as String?,
                    builderIds = (o["builder_ids"] as List<*>?)?.map { x -> x as String },
                    oidcIssuer = o["oidc_issuer"] as String?,
                    requireRuntime = o["require_runtime"] as Boolean?,
                    bind = o["bind"] as String?,
                    ttlMs = o["ttl_ms"]?.let { x -> IntentJs.lng(x) },
                ),
            ),
        )
    }
}
