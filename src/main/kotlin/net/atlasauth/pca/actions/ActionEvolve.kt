package net.atlasauth.pca.actions

import java.util.TreeMap
import java.util.TreeSet
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.ActionsRegistry
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * The signed per-definition changes between two versions of a pack (an evolution record per changed verb). A grant that pinned a
 * definition digest follows a record chain only through steps the registry signed as `equal` or `narrow`; everything else
 * needs the principal. Signing supports every suite the core signer does.
 */
object ActionEvolve {
    const val EVOLUTION_RECORD_KIND = "pca-evolution-record"
    private const val EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\u0000"

    private fun byVerb(defs: List<*>): TreeMap<String, Map<String, Any?>> {
        val m = TreeMap<String, Map<String, Any?>>()
        for (d in defs) {
            val v = J.get(d, "verb") as String
            if (m.containsKey(v)) throw ActionKitError("duplicate_def", "verb '$v' appears twice")
            m[v] = J.m(d)
        }
        return m
    }

    /** The unsigned records that take `prev` to `next` (sorted by verb). A verb rename is `removed` + `added`. */
    fun evolutionRecords(
        ns: String,
        prev: List<*>,
        next: List<*>,
        reg: Map<String, Map<String, Any?>>?,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): MutableList<Any?> {
        val registry = reg ?: Actions.CORE_REGISTRY
        val a = byVerb(prev)
        val b = byVerb(next)
        val verbs = TreeSet<String>(a.keys)
        verbs.addAll(b.keys)
        val out = ArrayList<Any?>()
        for (verb in verbs) {
            val o = a[verb]
            val n = b[verb]
            val r = J.obj("v", J.n(1), "kind", EVOLUTION_RECORD_KIND, "ns", ns, "verb", verb)
            if (o == null) { r["from"] = null; r["to"] = Actions.defDigest(n!!); r["class"] = "added"; r["reasons"] = ArrayList<Any?>() }
            else if (n == null) { r["from"] = Actions.defDigest(o); r["to"] = null; r["class"] = "removed"; r["reasons"] = ArrayList<Any?>() }
            else {
                val from = Actions.defDigest(o)
                val to = Actions.defDigest(n)
                if (from == to) continue
                val d = ActionDiff.diffDefs(o, n, registry, attestationVerified)
                r["from"] = from; r["to"] = to; r["class"] = d["class"]; r["reasons"] = d["reasons"]
            }
            out.add(r)
        }
        return out
    }

    /** Sign the records as the registry with an Ed25519 seed (`kid` names the pinned key entry). */
    fun signEvolution(records: List<*>, kid: String, secret: ByteArray): MutableList<Any?> =
        signEvolution(records, kid, Keys.ed25519(Keys.edFromSeed(secret)))

    /** Sign the records as the registry under any signature suite the core supports (Ed25519, hybrids, pure PQ). */
    fun signEvolution(records: List<*>, kid: String, key: Keys.SuiteKey): MutableList<Any?> {
        val out = ArrayList<Any?>()
        for (r in records) {
            val bad = ActionsRegistry.evolutionRecordError(r, false)
            if (bad != null) throw IllegalArgumentException("signEvolutionRecord: $bad")
            val dom = EVOLUTION_DOMAIN.toByteArray(Charsets.UTF_8)
            val body = Json.canonicalizeStrict(r).toByteArray(Charsets.UTF_8)
            val msg = dom + body
            val parts = key.sign(msg)
            val sig = J.obj("alg", key.alg, "kid", kid, "value", parts.first)
            if (parts.second != null) sig["pq_value"] = parts.second
            val s = LinkedHashMap(J.m(r))
            s["sig"] = sig
            out.add(s)
        }
        return out
    }

    private fun key(r: Map<String, Any?>): String =
        "${r["verb"]}|${J.jsStr(r["from"])}|${J.jsStr(r["to"])}|${r["class"]}|${ActionsRegistry.evolutionDiffDigest(r)}"

    /**
     * Does `records` EXACTLY describe the change from `prev` to `next`? Every record verifies under the pinned registry keys and names
     * `ns`; none is missing and none is extra; the class of each is the one the diff computes. Null = consistent, else the reason.
     */
    fun evolutionError(
        ns: String,
        prev: List<*>,
        next: List<*>,
        records: List<*>,
        keys: List<*>,
        reg: Map<String, Map<String, Any?>>?,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): String? {
        try {
            for (r in records) {
                val v = ActionsRegistry.verifyEvolutionRecord(r, keys)
                if (v != null) return "evolution record: $v"
                if (ns != J.get(r, "ns")) return "evolution record names namespace '${J.jsStr(J.get(r, "ns"))}', not '$ns'"
            }
            val want = ArrayList<String>()
            val have = ArrayList<String>()
            for (r in evolutionRecords(ns, prev, next, reg, attestationVerified)) want.add(key(J.m(r)))
            for (r in records) { val u = LinkedHashMap(J.m(r)); u.remove("sig"); have.add(key(u)) }
            want.sort()
            have.sort()
            if (want.size != have.size) return "evolution has ${have.size} records, the change needs ${want.size}"
            for (i in want.indices) if (want[i] != have[i]) return "evolution records do not match the computed change (a missing, extra or mis-classified record)"
            return null
        } catch (e: RuntimeException) {
            return "evolution error: ${e.message}"
        }
    }
}
