package net.atlasauth.pca.policyci

import net.atlasauth.pca.verifier.Authorize

/**
 * Input detection and normalization. `lintPolicy` accepts a bare predicate/caveat set, a compiled policy, a signed envelope or a minted
 * grant; they all reduce to one effective authority: `{predicates, caveats, riskPolicy?, kind}`.
 */
object Normalize {
    /** The caveat type that carries the signed envelope payload inside a grant. */
    internal const val ENVELOPE_CAVEAT_TYPE = "envelope"

    /** A minted grant / delegation hop: has the content-addressed, signed shape of a capability. */
    fun isCapability(x: Any?): Boolean {
        if (!PcJs.isRecord(x)) return false
        return PcJs.get(x, "id") is String && PcJs.get(x, "issuer") is String && PcJs.get(x, "holder") is String &&
            PcJs.get(x, "body_digest") is String && PcJs.get(x, "sig") is String && PcJs.get(x, "caveats") is List<*>
    }

    /** A signed policy envelope (the root intent grant payload). */
    fun isEnvelope(x: Any?): Boolean {
        if (!PcJs.isRecord(x)) return false
        return PcJs.get(x, "goal_commit") is String && PcJs.get(x, "predicates") is List<*> && PcJs.get(x, "caveats") is List<*> &&
            PcJs.isRecord(PcJs.get(x, "agent_binding")) && PcJs.isRecord(PcJs.get(x, "risk_policy"))
    }

    private fun isCompiledPolicy(x: Any?): Boolean =
        PcJs.isRecord(x) && PcJs.get(x, "predicates") is List<*> && PcJs.get(x, "caveats") is List<*> && PcJs.isRecord(PcJs.get(x, "riskPolicy")) && PcJs.get(x, "actions") is List<*>

    private fun isBarePolicy(x: Any?): Boolean = PcJs.isRecord(x) && PcJs.get(x, "predicates") is List<*>

    /** Drop the envelope-carrying caveat; keep the runtime gate caveats (and any appended attenuation). */
    private fun runtimeCaveats(caveats: List<*>): List<Any?> {
        val out = ArrayList<Any?>()
        for (c in caveats) if (PcJs.isObject(c) && ENVELOPE_CAVEAT_TYPE != PcJs.get(c, "type")) out.add(c)
        return out
    }

    private fun ok(policy: Map<String, Any?>): Map<String, Any?> = PcJs.obj("ok", true, "policy", policy)
    private fun fail(reason: String): Map<String, Any?> = PcJs.obj("ok", false, "reason", reason)

    private fun policy(predicates: Any?, caveats: Any?, riskPolicy: Any?, hasRisk: Boolean, kind: String): Map<String, Any?> {
        val p = LinkedHashMap<String, Any?>()
        p["predicates"] = predicates
        p["caveats"] = caveats
        if (hasRisk) p["riskPolicy"] = riskPolicy
        p["kind"] = kind
        return p
    }

    /**
     * Reduce a grant to its effective authority: its predicates and baseline gate caveats live inside its first envelope caveat, and
     * delegation appends further gate caveats to the grant's own caveats, so the effective gates are both lists together.
     */
    fun fromGrant(grant: Any?): Map<String, Any?> {
        val env = Authorize.readEnvelope(grant) ?: return fail("grant has no readable `envelope` caveat (malformed or unsigned payload)")
        val gc = PcJs.get(grant, "caveats")
        val caveats = ArrayList<Any?>(env["caveats"] as List<*>)
        caveats.addAll(runtimeCaveats(if (gc is List<*>) gc else emptyList<Any?>()))
        return ok(policy(env["predicates"], caveats, env["risk_policy"], true, "grant"))
    }

    /** Normalize any single-policy input to its effective authority: `{ok:true, policy}` or `{ok:false, reason}`. */
    fun normalizePolicyInput(input: Any?): Map<String, Any?> {
        if (isCapability(input)) return fromGrant(input)
        if (isEnvelope(input)) return ok(policy(PcJs.get(input, "predicates"), PcJs.get(input, "caveats"), PcJs.get(input, "risk_policy"), true, "envelope"))
        if (isCompiledPolicy(input)) return ok(policy(PcJs.get(input, "predicates"), PcJs.get(input, "caveats"), PcJs.get(input, "riskPolicy"), true, "compiled"))
        if (isBarePolicy(input)) {
            val c = PcJs.get(input, "caveats")
            return ok(policy(PcJs.get(input, "predicates"), if (c is List<*>) c else ArrayList<Any?>(), null, false, "bare"))
        }
        return fail("unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })")
    }

    /**
     * Normalize a delegation chain (root to leaf) to one effective policy per hop: `{ok:true, hops}` or `{ok:false, reason}`. A chain of
     * grants shares the root envelope's predicates and each hop's gates are the envelope's caveats plus that hop's appended ones; a chain
     * of already-effective policies is taken as it is.
     */
    fun normalizeChain(chain: List<*>): Map<String, Any?> {
        if (chain.isEmpty()) return fail("empty chain")
        var allCaps = true
        for (c in chain) if (!isCapability(c)) { allCaps = false; break }
        if (allCaps) {
            val env = Authorize.readEnvelope(chain[0]) ?: return fail("root grant has no readable `envelope` caveat")
            val hops = ArrayList<Any?>()
            for (cap in chain) {
                val cc = PcJs.get(cap, "caveats")
                val caveats = ArrayList<Any?>(env["caveats"] as List<*>)
                caveats.addAll(runtimeCaveats(if (cc is List<*>) cc else emptyList<Any?>()))
                hops.add(policy(env["predicates"], caveats, env["risk_policy"], true, "chain-hop"))
            }
            return PcJs.obj("ok", true, "hops", hops)
        }
        val hops = ArrayList<Any?>()
        for (i in chain.indices) {
            val r = normalizePolicyInput(chain[i])
            if (r["ok"] != true) return fail("hop $i: " + PcJs.str(r["reason"]))
            @Suppress("UNCHECKED_CAST")
            val p = LinkedHashMap(r["policy"] as Map<String, Any?>)
            p["kind"] = "chain-hop"
            hops.add(p)
        }
        return PcJs.obj("ok", true, "hops", hops)
    }
}
