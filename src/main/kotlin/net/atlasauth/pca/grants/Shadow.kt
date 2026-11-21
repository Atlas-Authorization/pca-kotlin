package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Bundle as BundleVerify

/**
 * Shadow policy rollout. An enforced bundle revision may list candidate bundles in `shadow`; [runShadow] computes the enforced decision
 * first and returns it untouched, recording what each candidate would have said. Every divergence becomes a verifier-signed diff;
 * [promotionGate] must pass before [promoteShadow] builds the next revision's body. Nothing here decides an action: it is analysis and
 * rollout tooling that runs beside the verifier.
 */
object Shadow {
    const val SHADOW_DIFF_DOMAIN = "atlas-pca/shadow-diff/v1\u0000"
    const val WIDENING_EXPLANATION_DOMAIN = "atlas-pca/shadow-widening-explanation/v1\u0000"
    const val PROMOTION_APPROVAL_DOMAIN = "atlas-pca/shadow-promotion-approval/v1\u0000"

    private fun rank(k: Any?): Int = when (k) { "deny" -> 0; "escalate" -> 1; "allow" -> 2; else -> -1 }

    private fun isKind(k: Any?): Boolean = rank(k) >= 0

    /** A candidate bundle: its digest and its pure decision function. */
    class Candidate(val digest: String, val decide: (Any?) -> String?)

    /** What one candidate said. [decision] is a decision kind or `error`. [widening]: the candidate would have been MORE permissive. */
    class Outcome internal constructor(val digest: String, val decision: String, val diverged: Boolean, val widening: Boolean) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["digest"] = digest
            m["decision"] = decision
            m["diverged"] = diverged
            m["widening"] = widening
            return m
        }
    }

    /** The enforced decision and what each candidate would have said. */
    class Run internal constructor(val decision: String?, val shadow: List<Outcome>)

    @JvmStatic
    fun runShadow(input: Any?, enforced: (Any?) -> String?, candidates: List<Candidate>): Run {
        val decision = enforced(input)
        val out = ArrayList<Outcome>()
        for (c in candidates) {
            try {
                val d = c.decide(deepCopy(input)) // the candidate gets a copy: it cannot mutate the enforced input
                if (!isKind(d)) out.add(Outcome(c.digest, "error", false, false))
                else out.add(Outcome(c.digest, d!!, d != decision, rank(d) > rank(decision)))
            } catch (e: RuntimeException) {
                out.add(Outcome(c.digest, "error", false, false))
            }
        }
        return Run(decision, out)
    }

    private fun deepCopy(v: Any?): Any? {
        val m = K3Sig.map(v)
        if (m != null) {
            val o = LinkedHashMap<String, Any?>()
            for ((k, x) in m) o[k] = deepCopy(x)
            return o
        }
        val l = K3Sig.list(v)
        if (l != null) {
            val o = ArrayList<Any?>()
            for (x in l) o.add(deepCopy(x))
            return o
        }
        return v
    }

    /** The `shadow` member of a decision record, from the outcomes. */
    @JvmStatic
    fun shadowRecordField(o: List<Outcome>): List<Any?> {
        val out = ArrayList<Any?>()
        for (x in o) {
            val m = LinkedHashMap<String, Any?>()
            m["digest"] = x.digest
            m["decision"] = x.decision
            m["diverged"] = x.diverged
            out.add(m)
        }
        return out
    }

    private fun pick(o: Map<String, Any?>, vararg keys: String): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in keys) b[k] = o[k]
        return b
    }

    private fun diffBody(d: Map<String, Any?>) = pick(d, "v", "shadow_digest", "enforced_digest", "action_digest", "enforced", "shadow", "widening", "at", "signer")

    private fun isOne(v: Any?): Boolean = Json.isSafeInt(v) && Json.asLong(v) == 1L

    /** A well formed shadow diff signed by its signer (`signer` null = any signer). Never throws. */
    @JvmStatic
    fun verifyShadowDiff(dObj: Any?, signer: String?): Boolean {
        try {
            val d = K3Sig.map(dObj)
            if (d == null || !isOne(d["v"]) || !K3Sig.isStr(d["shadow_digest"], 128) || !K3Sig.isStr(d["enforced_digest"], 128) ||
                !K3Sig.isStr(d["action_digest"], 128) || !isKind(d["enforced"]) || !isKind(d["shadow"]) || d["widening"] !is Boolean ||
                !K3Sig.isSafeInt(d["at"]) || !K3Sig.isStr(d["signer"], 128)
            ) return false
            if (d["enforced"] == d["shadow"] || (d["widening"] as Boolean) != (rank(d["shadow"]) > rank(d["enforced"]))) return false
            if (signer != null && signer != d["signer"]) return false
            val rest = K3Sig.without(d, "sig")
            return GrantSigning.verifyBody(SHADOW_DIFF_DOMAIN, diffBody(rest), rest["signer"] as String, d["sig"])
        } catch (e: RuntimeException) {
            return false
        }
    }

    /** Per-candidate counters. */
    class Stats {
        var total = 0L
        var diverged = 0L
        var widened = 0L
        var tightened = 0L
        var errors = 0L

        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["total"] = total
            m["diverged"] = diverged
            m["widened"] = widened
            m["tightened"] = tightened
            m["errors"] = errors
            return m
        }
    }

    /** Collects the signed diffs and counters per candidate. In memory: persist `diffs()` to the decision log for the audit trail. */
    class ShadowLog(private val secret: Keys.EdKey) {
        private val stat = HashMap<String, Stats>()
        private val list = HashMap<String, ArrayList<Map<String, Any?>>>()

        fun signer(): String = GrantSigning.signerOf(secret)

        /** Count one observation; sign and keep a diff when the candidate diverged. Returns the diff or null. */
        @Synchronized
        fun observe(enforcedDigest: String, actionDigest: String, enforced: String?, outcome: Outcome, at: Long): Map<String, Any?>? {
            val s = stat.getOrPut(outcome.digest) { Stats() }
            s.total++
            if (outcome.decision == "error") { s.errors++; return null }
            if (!outcome.diverged) return null
            s.diverged++
            if (outcome.widening) s.widened++ else s.tightened++
            val base = LinkedHashMap<String, Any?>()
            base["v"] = 1L
            base["shadow_digest"] = outcome.digest
            base["enforced_digest"] = enforcedDigest
            base["action_digest"] = actionDigest
            base["enforced"] = enforced
            base["shadow"] = outcome.decision
            base["widening"] = outcome.widening
            base["at"] = at
            base["signer"] = signer()
            val diff = LinkedHashMap<String, Any?>(base)
            diff["sig"] = GrantSigning.signBody(SHADOW_DIFF_DOMAIN, diffBody(base), secret)
            list.getOrPut(outcome.digest) { ArrayList() }.add(diff)
            return diff
        }

        @Synchronized
        fun stats(digest: String): Stats {
            val s = stat[digest]
            val c = Stats()
            if (s != null) { c.total = s.total; c.diverged = s.diverged; c.widened = s.widened; c.tightened = s.tightened; c.errors = s.errors }
            return c
        }

        @Synchronized
        fun diffs(digest: String): List<Map<String, Any?>> = ArrayList(list[digest] ?: ArrayList())
    }

    private fun expBody(e: Map<String, Any?>) = pick(e, "v", "shadow_digest", "action_digest", "reason_digest", "principal")

    /** A principal states that this widening is intended; [e] = `{shadow_digest, action_digest, reason_digest}`. */
    @JvmStatic
    fun signWideningExplanation(secret: Keys.EdKey, e: Map<String, Any?>): Map<String, Any?> {
        val base = LinkedHashMap<String, Any?>()
        base["v"] = 1L
        base.putAll(e)
        base["principal"] = GrantSigning.signerOf(secret)
        base["sig"] = GrantSigning.signBody(WIDENING_EXPLANATION_DOMAIN, expBody(base), secret)
        return base
    }

    private fun verifyExplanation(eo: Any?): Boolean {
        val e = K3Sig.map(eo)
        if (e == null || !isOne(e["v"]) || !K3Sig.isStr(e["shadow_digest"], 128) || !K3Sig.isStr(e["action_digest"], 128) ||
            !K3Sig.isStr(e["reason_digest"], 128) || !K3Sig.isStr(e["principal"], 128)
        ) return false
        return GrantSigning.verifyBody(WIDENING_EXPLANATION_DOMAIN, expBody(e), e["principal"] as String, e["sig"])
    }

    private fun apBody(a: Map<String, Any?>) = pick(a, "v", "shadow_digest", "enforced_digest", "at", "principal")

    /** [a] = `{shadow_digest, enforced_digest, at}`. */
    @JvmStatic
    fun signPromotionApproval(secret: Keys.EdKey, a: Map<String, Any?>): Map<String, Any?> {
        val base = LinkedHashMap<String, Any?>()
        base["v"] = 1L
        base.putAll(a)
        base["principal"] = GrantSigning.signerOf(secret)
        base["sig"] = GrantSigning.signBody(PROMOTION_APPROVAL_DOMAIN, apBody(base), secret)
        return base
    }

    private fun verifyApproval(ao: Any?): Boolean {
        val a = K3Sig.map(ao)
        if (a == null || !isOne(a["v"]) || !K3Sig.isStr(a["shadow_digest"], 128) || !K3Sig.isStr(a["enforced_digest"], 128) ||
            !K3Sig.isSafeInt(a["at"]) || !K3Sig.isStr(a["principal"], 128)
        ) return false
        return GrantSigning.verifyBody(PROMOTION_APPROVAL_DOMAIN, apBody(a), a["principal"] as String, a["sig"])
    }

    private fun no(code: String, reason: String, unexplained: List<String>? = null): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["ok"] = false
        r["code"] = code
        r["reason"] = reason
        if (unexplained != null) r["unexplained"] = ArrayList<Any?>(unexplained)
        return r
    }

    private val SURFACES = listOf("narrower", "equal", "wider", "unknown")

    /**
     * May the candidate be promoted? [o] = `{shadow_digest, enforced_digest, minSamples, principals, explanations?, surface, approval?}`.
     * Returns `{ok:true, samples, widenings, surface}` or `{ok:false, code, reason, unexplained?}`. Fails closed on any evaluation error.
     */
    @JvmStatic
    fun promotionGate(log: ShadowLog, o: Map<String, Any?>): Map<String, Any?> {
        try {
            val ms = o["minSamples"]
            if (!K3Sig.isStr(o["shadow_digest"], 128) || !K3Sig.isStr(o["enforced_digest"], 128) || !K3Sig.isSafeInt(ms) || Json.asLong(ms) < 1 ||
                o["principals"] !is List<*> || o["surface"] !is String || o["surface"] !in SURFACES
            ) return no("bad_input", "bad gate options")
            val shadow = o["shadow_digest"] as String
            val enforced = o["enforced_digest"] as String
            val principals = K3Sig.list(o["principals"])!!
            val s = log.stats(shadow)
            if (s.total < Json.asLong(ms)) return no("too_few_samples", "${s.total} observation(s), need ${Json.asLong(ms)}")
            if (s.errors > 0) return no("shadow_errors", "${s.errors} observation(s) where the candidate failed")
            val diffs = log.diffs(shadow)
            for (d in diffs) {
                if (!(verifyShadowDiff(d, log.signer()) && shadow == d["shadow_digest"] && enforced == d["enforced_digest"])) {
                    return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing")
                }
            }
            if (diffs.size.toLong() != s.diverged) return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing")
            val explained = LinkedHashSet<Any?>()
            val ex = o["explanations"]
            // a string iterates its characters (none is an explanation); any other non-iterable throws in the reference
            if (ex != null && ex !is List<*> && ex !is String) return no("bad_input", "evaluation error (fail closed)")
            if (ex is List<*>) {
                for (e in ex) if (verifyExplanation(e) && K3Sig.map(e)!!["principal"] in principals && shadow == K3Sig.map(e)!!["shadow_digest"]) explained.add(K3Sig.map(e)!!["action_digest"])
            }
            val un = LinkedHashSet<String>()
            var widenings = 0L
            for (d in diffs) {
                if (d["widening"] == true) {
                    widenings++
                    if (d["action_digest"] !in explained) un.add(d["action_digest"] as String)
                }
            }
            if (un.isNotEmpty()) {
                val sorted = un.sorted()
                return no("unexplained_widening", "${sorted.size} widening(s) without a principal's explanation", sorted)
            }
            val surface = o["surface"] as String
            if (surface == "wider" || surface == "unknown") {
                val a = o["approval"]
                if (!verifyApproval(a) || K3Sig.map(a)!!["principal"] !in principals || shadow != K3Sig.map(a)!!["shadow_digest"] || enforced != K3Sig.map(a)!!["enforced_digest"]) {
                    return no("advisory_wider", "the analyzer reports the candidate " + (if (surface == "wider") "wider" else "not provably narrower") + " on the declared surfaces: a principal-signed approval is required")
                }
            }
            val ok = LinkedHashMap<String, Any?>()
            ok["ok"] = true
            ok["samples"] = s.total
            ok["widenings"] = widenings
            ok["surface"] = surface
            return ok
        } catch (e: RuntimeException) {
            return no("bad_input", "evaluation error (fail closed)")
        }
    }

    /**
     * The body of the bundle revision that makes the candidate the enforced policy: the candidate's content at revision + 1 chained to the
     * enforced revision with the shadow list cleared. Needs a passing gate and the candidate listed in the enforced revision's shadow.
     */
    @JvmStatic
    fun promoteShadow(enforced: Map<String, Any?>, candidate: Map<String, Any?>, gate: Map<String, Any?>, now: Any?): Map<String, Any?> {
        val digest = BundleVerify.digest(candidate)
        require(gate["ok"] == true) { "promoteShadow: the gate did not pass (${gate["code"]})" }
        val sh = K3Sig.list(enforced["shadow"])
        require(sh != null && digest in sh) { "promoteShadow: the candidate is not listed in the enforced revision's shadow" }
        require(K3Sig.isSafeInt(now)) { "promoteShadow: bad time" }
        require(Json.isSafeInt(enforced["revision"])) { "promoteShadow: bad revision" }
        val out = LinkedHashMap<String, Any?>(candidate)
        out.remove("sigs")
        out.remove("shadow")
        out.remove("prev")
        out["revision"] = Json.asLong(enforced["revision"]) + 1
        out["prev"] = BundleVerify.digest(enforced)
        out["issued_at"] = Json.asLong(now)
        return out
    }
}
