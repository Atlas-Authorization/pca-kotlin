package net.atlasauth.pca.actions

import java.util.TreeMap
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.ActionsRegistry
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * Building, chaining and signing action packs, and verifying an upgrade between two versions. The verify side of a single pack
 * ([ActionsRegistry.verifyPack], `packDigest`, `shardDigest`, `packShapeError`, `packDefs`) is in the core.
 */
object ActionPacks {
    const val PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\u0000"
    const val PACK_SHARD_KIND = "pca-action-pack-shard"

    /** Largest shard the builder writes by default. */
    const val DEFAULT_SHARD_DEFS = 512

    /** Most defs an inline pack carries. */
    const val MAX_PACK_DEFS = 4096

    /** Sign `body` under `domain` as the registry: `{alg, kid, value[, pq_value]}`. */
    fun signRegistryDoc(domain: String, body: Any?, kid: String, key: Keys.SuiteKey): MutableMap<String, Any?> {
        val dom = Json.utf8(domain)
        val bd = Json.canonicalizeStrict(body).toByteArray(Charsets.UTF_8)
        val parts = key.sign(dom + bd)
        val sig = J.obj("alg", key.alg, "kid", kid, "value", parts.first)
        if (parts.second != null) sig["pq_value"] = parts.second
        return sig
    }

    private fun byVerb(a: Any?, b: Any?): Int = (J.get(a, "verb") as String).compareTo(J.get(b, "verb") as String)

    /**
     * Shard names are the resource family (the first segment of `resource.type`) of the defs, split in order into chunks of `max`
     * (null = [DEFAULT_SHARD_DEFS]). Returns a list of `{name, defs}`.
     */
    fun shardDefs(defs: List<*>, max: Any?): MutableList<Any?> {
        val m: Double = if (max == null) DEFAULT_SHARD_DEFS.toDouble() else (if (J.isInt(max)) J.num(max)!! else Double.NaN)
        if (m.isNaN() || m < 1) throw ActionKitError("bad_shard_size", "the shard size must be a positive integer")
        val mx = Math.min(m, Int.MAX_VALUE.toDouble()).toInt()
        val fam = TreeMap<String, MutableList<Any?>>()
        for (d in defs) {
            val t = J.get(J.get(d, "resource"), "type") as String
            val dot = t.indexOf('.')
            fam.getOrPut(if (dot < 0) t else t.substring(0, dot)) { ArrayList<Any?>() }.add(d)
        }
        val out = ArrayList<Any?>()
        for ((family, l) in fam) {
            var n = 1
            var i = 0
            while (i < l.size) {
                out.add(J.obj("name", if (l.size > mx) "$family-$n" else family, "defs", ArrayList<Any?>(l.subList(i, Math.min(i.toLong() + mx, l.size.toLong()).toInt()))))
                i += mx
                n++
            }
        }
        return out
    }

    private fun sortedUniqueDefsError(defs: List<Any?>): String? {
        for (i in defs.indices) {
            val e = Actions.validateDef(defs[i])
            if (e != null) return "def $i: $e"
            if (i > 0 && byVerb(defs[i - 1], defs[i]) >= 0) return "defs must be sorted by verb and unique (at '${J.get(defs[i], "verb")}')"
        }
        return null
    }

    /**
     * Build, chain and sign a pack. `a` holds `ns, version, stability, defs, source, kid` and optionally `prev: {pack, shards?}`
     * and `shard: true | {max?}`; `shardUri` names a shard's location (null = `shards/<name>.json`). Returns `{pack, shards}`.
     * Throws ActionKitError on any inconsistency.
     */
    @Suppress("UNCHECKED_CAST")
    fun buildPack(
        a: Map<String, Any?>,
        key: Keys.SuiteKey,
        reg: Map<String, Map<String, Any?>>?,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
        shardUri: ((String) -> String)?,
    ): MutableMap<String, Any?> {
        val r = reg ?: Actions.CORE_REGISTRY
        val defs = ArrayList<Any?>(J.a(a["defs"]))
        defs.sortWith { x, y -> byVerb(x, y) }
        val de = sortedUniqueDefsError(defs)
        if (de != null) throw ActionKitError("bad_pack", de)
        if (defs.isEmpty()) throw ActionKitError("empty_pack", "a pack has at least one def")
        val prev: Map<String, Any?>? = if (a["prev"] is Map<*, *>) J.m(a["prev"]) else null
        var prevDefs: List<Any?> = ArrayList()
        if (prev != null) {
            val pp = J.m(prev["pack"])
            prevDefs = ActionsRegistry.packDefs(pp, if (prev["shards"] is Map<*, *>) J.m(prev["shards"]) else null)
            if (pp["ns"] != a["ns"]) throw ActionKitError("bad_chain", "the previous pack is of another namespace")
            if (ActionsRegistry.compareVersions(a["version"] as String, pp["version"] as String) <= 0) throw ActionKitError("bad_chain", "the version must increase")
        }
        val records = ActionEvolve.evolutionRecords(a["ns"] as String, prevDefs, defs, r, attestationVerified)
        val evolution = ActionEvolve.signEvolution(records, a["kid"] as String, key)
        val digests = ArrayList<String>()
        for (d in defs) digests.add(Actions.defDigest(J.m(d)))
        val root = Actions.packRoot(digests)
        val wantShards = if (a.containsKey("shard") && a["shard"] != false) true else defs.size > MAX_PACK_DEFS
        val shards = LinkedHashMap<String, Any?>()
        var body: Any? = defs
        if (wantShards) {
            val opts: Any? = if (a["shard"] is Map<*, *>) a["shard"] else LinkedHashMap<String, Any?>()
            val refs = ArrayList<Any?>()
            for (s0 in shardDefs(defs, J.get(opts, "max"))) {
                val s = J.m(s0)
                val name = s["name"] as String
                val doc = J.obj("v", J.n(1), "kind", PACK_SHARD_KIND, "ns", a["ns"], "version", a["version"], "name", name, "defs", s["defs"])
                shards[name] = doc
                refs.add(J.obj("name", name, "digest", ActionsRegistry.shardDigest(doc), "uri", if (shardUri != null) shardUri(name) else "shards/$name.json"))
            }
            body = J.obj("shards", refs)
        }
        val unsigned = J.obj(
            "v", J.n(1), "kind", "pca-action-pack", "ns", a["ns"], "version", a["version"], "stability", a["stability"],
            "traits_digest", Actions.traitsDigest(r), "roles_digest", Actions.tablesDigest(), "rules_digest", ActionsRegistry.rulesDigest(),
            "root", root, "defs", body, "source", a["source"], "prev", if (prev != null) ActionsRegistry.packDigest(J.get(prev, "pack")) else null, "evolution", evolution,
        )
        val pe = ActionsRegistry.packShapeError(unsigned, false)
        if (pe != null) throw ActionKitError("bad_pack", pe)
        val pack = LinkedHashMap<String, Any?>(unsigned)
        pack["sig"] = signRegistryDoc(PACK_SIG_DOMAIN, unsigned, a["kid"] as String, key)
        return J.obj("pack", pack, "shards", shards)
    }

    /**
     * Verify `next` as the successor of `prev`: both verify, same namespace, `next.prev` is `prev`'s digest, the version
     * increases, and the signed evolution is EXACTLY the computed change. Returns `{ok}` or `{ok:false, reason}`. Shard maps may be null.
     * The vocabulary is the core trait registry (shortcut: a custom registry is not supported for verification here).
     */
    fun verifyUpgrade(
        prev: Map<String, Any?>,
        next: Map<String, Any?>,
        keys: Any?,
        prevShards: Map<String, Any?>?,
        shards: Map<String, Any?>?,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): MutableMap<String, Any?> {
        val a = ActionsRegistry.verifyPack(prev, keys, prevShards)
        if (a["ok"] != true) return J.obj("ok", false, "reason", "previous pack: ${a["reason"]}")
        val b = ActionsRegistry.verifyPack(next, keys, shards)
        if (b["ok"] != true) return J.obj("ok", false, "reason", "pack: ${b["reason"]}")
        if (next["ns"] != prev["ns"]) return J.obj("ok", false, "reason", "the packs are of different namespaces")
        if (a["digest"] != next["prev"]) return J.obj("ok", false, "reason", "chain gap: prev does not name the previous pack")
        if (ActionsRegistry.compareVersions(next["version"] as String, prev["version"] as String) <= 0) return J.obj("ok", false, "reason", "the version does not increase")
        val ee = ActionEvolve.evolutionError(next["ns"] as String, J.a(a["defs"]), J.a(b["defs"]), J.a(next["evolution"]), J.a(keys), Actions.CORE_REGISTRY, attestationVerified)
        return if (ee == null) J.obj("ok", true) else J.obj("ok", false, "reason", ee)
    }
}
