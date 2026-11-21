package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for the action-kit registry layer (evolution records, registry signatures, re-approvals,
 * the grant pin, signed packs + shards, the rollback tracker, rule 22, pack proofs): test-data/k05-actionregistry.json.gz from
 * tools/pca-audit/k05-oracles/actionregistry-oracle.mts. Results compare as lenient canonical JSON. A reference throw requires a
 * throw, with the same ActionKitError code when the reference names one. A case carrying `textPrefix` (an engine- or
 * canonicalizer-specific message tail) requires the same decision with a message that STARTS WITH the prefix.
 */
@Suppress("UNCHECKED_CAST")
class K05ActionRegistryDiffTest {
    companion object {
        const val FILE = "k05-actionregistry.json.gz"
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(bad: List<String>) = assertTrue("${bad.size} divergent case(s):\n" + bad.joinToString("\n"), bad.isEmpty())
        fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")
        fun canon(o: Any?): String = Json.canonicalize(o)

        /** The tracker's pinned keys (the reference's ALLKEYS: ed25519, ml-dsa-65, hybrid) as the `p1` verifyPack case passes them. */
        val ALLKEYS: Any? by lazy { args(of("verifyPack").first { it["name"] == "verifyPack/p1" })[1] }
    }

    /** True when the native outcome ([got] or the throw [err]) matches the case. */
    private fun agrees(c: Map<String, Any?>, got: Any?, err: Throwable?): Boolean {
        val want = c["out"]
        val prefix = c["textPrefix"] as String?
        if (want is Map<*, *> && want.containsKey("\$throws")) {
            if (err == null) return false
            val code = want["code"] as String?
            if (code != null && (err as? ActionKitError)?.code != code) return false
            return prefix == null || (err.message ?: "").startsWith(prefix)
        }
        if (err != null) return false
        if (prefix == null) return canon(want) == canon(got)
        if (want is String) return got is String && got.startsWith(prefix)
        if (want is Map<*, *> && got is Map<*, *>) {
            val r = got["reason"]
            return r is String && r.startsWith(prefix) &&
                canon(LinkedHashMap(map(want)).also { it.remove("reason") }) == canon(LinkedHashMap(map(got)).also { it.remove("reason") })
        }
        return false
    }

    private fun diff(fn: String, skip: (Map<String, Any?>) -> Boolean = { false }, f: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        var ran = 0
        for (c in of(fn)) {
            if (skip(c)) continue
            ran++
            var got: Any? = null
            var err: Throwable? = null
            try { got = f(args(c)) } catch (t: Throwable) { err = t }
            if (!agrees(c, got, err)) {
                val g = if (err != null) "THROWS ${(err as? ActionKitError)?.code ?: ""} $err" else canon(got)
                bad.add("${c["name"]}\n  want: ${canon(c["out"])}${c["textPrefix"]?.let { " (prefix '$it')" } ?: ""}\n  got:  $g")
            }
        }
        assertTrue("$fn: every case skipped", ran > 0)
        report(bad)
    }

    @Test fun compareVersions() = diff("compareVersions") { ActionsRegistry.compareVersions(it[0] as String, it[1] as String) }

    @Test fun packDefs() = diff("packDefs") { a -> ActionsRegistry.packDefs(map(a[0]), a[1] as Map<String, Any?>?).map { it["verb"] } }

    @Test fun evolutionRecordError() = diff("evolutionRecordError") { ActionsRegistry.evolutionRecordError(it[0], it[1] as Boolean) }

    @Test fun evolutionDiffDigest() = diff("evolutionDiffDigest") { ActionsRegistry.evolutionDiffDigest(map(it[0])) }

    @Test fun verifyRegistrySig() = diff("verifyRegistrySig") { ActionsRegistry.verifyRegistrySig(it[0] as String, it[1], map(it[2]), it[3]) }

    @Test fun verifyEvolutionRecord() = diff("verifyEvolutionRecord") { ActionsRegistry.verifyEvolutionRecord(it[0], it[1]) }

    @Test fun reapprovalValid() = diff("reapprovalValid") { ActionsRegistry.reapprovalValid(it[0], it[1], it[2], it[3], it[4]) }

    @Test fun actionPinError() = diff("actionPinError") { ActionsRegistry.actionPinError(it[0]) }

    @Test fun decidePin() = diff("decidePin") { ActionsRegistry.decidePin(map(it[0])) }

    @Test fun packShapeError() = diff("packShapeError") { ActionsRegistry.packShapeError(it[0], it[1] as Boolean) }

    @Test fun verifyPack() = diff("verifyPack") { a ->
        val r = ActionsRegistry.verifyPack(a[0], a[1], a[2] as Map<String, Any?>?)
        if (r["ok"] == true) linkedMapOf<String, Any?>("ok" to true, "digest" to r["digest"], "verbs" to (r["defs"] as List<Map<String, Any?>>).map { it["verb"] })
        else r
    }

    // tracker results compare ok/status/code, and the reason only for bad_pack (other reasons are each port's wording)
    @Test fun packTracker() {
        fun trim(x: Any?): Any? {
            val m = LinkedHashMap(map(x))
            if (m["code"] != "bad_pack") m.remove("reason")
            return m
        }
        val bad = ArrayList<String>()
        for (c in of("packTracker")) {
            val t = ActionsRegistry.PackTracker(ALLKEYS)
            val got = (args(c)[0] as List<Any?>).map { s -> val st = s as List<Any?>; trim(t.accept(st[0], st[1] as Map<String, Any?>?)) }
            val want = (c["out"] as List<Any?>).map { trim(it) }
            if (canon(want) != canon(got)) bad.add("${c["name"]}\n  want: ${canon(want)}\n  got:  ${canon(got)}")
        }
        report(bad)
    }

    // the native signature is typed (verb: String, grant: Map, context: List); every untypable reference case answers "deny".
    // A floors member of -0 is compared like any other case: the reference refuses it per the strict JSON profile, as the native does.
    @Test fun rule22Decide() = diff("rule22Decide", {
        val a = args(it)
        a[1] !is String || a.getOrNull(2) !is Map<*, *> || a[3] !is List<*>
    }) {
        ActionsRegistry.rule22Decide(it[0], it[1] as String, map(it[2]), it[3] as List<*>)
    }

    @Test fun verifyPackProof() = diff("verifyPackProof") { ActionsRegistry.verifyPackProof(it[0], it[1], it[2]) }
}
