package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.BigInteger

/**
 * PCA 0.4.1 policy-layer caveat helpers, mirroring `policyCaveats` (packages/pca/src/policy-vm.ts) and the caveat evaluator
 * (`envelopeCaveatEvaluator` in predicates.ts + `max_spend` in agent-native.ts).
 *
 * The core verifier ([Pca.verifyPcactn], the nine checks) treats caveats as opaque and does NOT evaluate them. A resource
 * server that enforces a grant's caveats calls `Caveats.evaluateCaveats(Caveats.policyCaveats(grant, chain), ctx)` with its
 * own action parameters. [policyCaveats] includes the caveats placed directly on the ROOT grant (outside the `envelope`
 * caveat): before 0.4.1 the reference policy layer signed those but never evaluated them.
 *
 * The context is a map with snake_case keys, exactly the `context` of the `primitives.caveat_eval` vectors: `now` (epoch
 * ms), `delegation_depth`, `blast_radius`, `reversibility_class`, `recent_action_times` (all optional) and `action`
 * (`{verb, resource, reversibility_class, params}`). An absent optional field leaves the caveat that needs it unsatisfied.
 * A well-formed `intent_session` caveat (Intent Layer v2) is satisfied (it constrains nothing per action), a malformed one is not.
 * Unknown caveat types (and `note`, `envelope`, `resource_prefix`, `predicates`, `tool_schema`) are unsatisfied: fail closed.
 */
object Caveats {
    /** The verdict of [evaluateCaveats]: `ok` iff every caveat is satisfied; `failed` = the unsatisfied types, in order. */
    data class Result(val ok: Boolean, val failed: List<String>)

    private val REVERSIBILITY_ORDER = listOf("reversible", "rate_limited", "irreversible")

    /**
     * The ROOT grant's caveats the policy layer evaluates: `grant.caveats` without its FIRST `envelope` caveat (order kept;
     * a second envelope stays and is unsatisfied). A non-list `caveats` is returned as is (and refused by
     * [evaluateCaveats]); a non-object grant yields null. The input is never mutated.
     */
    fun rootCaveats(grant: Any?): Any? {
        if (grant !is Map<*, *>) return null
        val cs = grant["caveats"]
        if (cs !is List<*>) return cs
        val out = ArrayList<Any?>(cs)
        val i = out.indexOfFirst { it is Map<*, *> && it["type"] == "envelope" }
        if (i >= 0) out.removeAt(i)
        return out
    }

    /**
     * Every caveat the policy layer evaluates for an action under `grant` delegated along `chain` (root first): [rootCaveats]
     * of the grant, then the caveats the hops appended (`leaf.caveats` beyond the grant's, leaf = the last chain element).
     * Nothing is appended when the chain is absent, empty or not a list, or when either caveat list is not a list.
     */
    fun policyCaveats(grant: Any?, chain: Any?): Any? {
        val root = rootCaveats(grant)
        if (root !is List<*>) return root
        val out = ArrayList<Any?>(root)
        if (chain is List<*> && chain.isNotEmpty()) {
            val leaf = chain[chain.size - 1]
            val gcs = (grant as Map<*, *>)["caveats"]
            val lcs = (leaf as? Map<*, *>)?.get("caveats")
            if (lcs is List<*> && gcs is List<*>) for (k in gcs.size until lcs.size) out.add(lcs[k])
        }
        return out
    }

    /** Evaluate every caveat against `ctx`. Total: never throws; a non-list => `ok=false, failed=["<malformed caveats>"]`. */
    fun evaluateCaveats(caveats: Any?, ctx: Any?): Result {
        if (caveats !is List<*>) return Result(false, listOf("<malformed caveats>"))
        val failed = ArrayList<String>()
        for (cv in caveats) {
            val ok = try { satisfied(cv, ctx) } catch (e: RuntimeException) { false }
            if (!ok) failed.add(((cv as? Map<*, *>)?.get("type") as? String) ?: "<malformed>")
        }
        return Result(failed.isEmpty(), failed)
    }

    /** One caveat against `ctx`; false (unsatisfied) for anything malformed or unknown. */
    fun satisfied(caveat: Any?, ctx: Any?): Boolean {
        if (caveat !is Map<*, *> || ctx !is Map<*, *>) return false
        val type = caveat["type"]
        if (type == "max_spend") return maxSpend(caveat, ctx)
        val now = fin(ctx["now"]) ?: return false
        return when (type) {
            "expires" -> fin(caveat["at"])?.let { now < it } ?: false
            "not_before" -> fin(caveat["at"])?.let { now >= it } ?: false
            "rate" -> {
                val max = fin(caveat["max"])
                val per = fin(caveat["per_secs"])
                val times = ctx["recent_action_times"]
                if (max == null || per == null || per <= 0 || times !is List<*>) false
                else {
                    val lo = now - per * 1000
                    times.count { t -> fin(t)?.let { it > lo && it <= now } ?: false } < max
                }
            }
            "max_blast_radius" -> {
                val max = fin(caveat["max"])
                val br = fin(ctx["blast_radius"])
                max != null && br != null && br <= max
            }
            "reversibility_max" -> {
                val lim = caveat["class"]
                val cur = ctx["reversibility_class"]
                if (lim !is String || cur !is String) false
                else {
                    val li = REVERSIBILITY_ORDER.indexOf(lim)
                    val ci = REVERSIBILITY_ORDER.indexOf(cur)
                    li >= 0 && ci >= 0 && ci <= li
                }
            }
            "delegation_depth" -> {
                val max = fin(caveat["max"])
                val d = fin(ctx["delegation_depth"])
                max != null && d != null && d <= max
            }
            "budget_alloc" -> fin(caveat["limit"])?.let { it >= 0 } ?: false
            // Intent Layer v2 session binding (rule 13): no per-action constraint; satisfied iff well-formed.
            "intent_session" -> IntentSession.caveatError(caveat) == null
            else -> false
        }
    }

    /**
     * `max_spend {usd}`: `usd` a finite number >= 0; `ctx.action.params` an object with an own finite `amount` >= 0 and
     * `amount <= usd`; an own `currency`, when present, exactly "usd" or "USD". Does not need `now`.
     */
    private fun maxSpend(cv: Map<*, *>, ctx: Map<*, *>): Boolean {
        val lim = fin(cv["usd"])
        if (lim == null || lim < 0) return false
        val params = (ctx["action"] as? Map<*, *>)?.get("params") as? Map<*, *> ?: return false
        if (!params.containsKey("amount")) return false
        val amount = fin(params["amount"])
        if (amount == null || amount < 0) return false
        if (params.containsKey("currency")) {
            val cur = params["currency"]
            if (cur != "usd" && cur != "USD") return false
        }
        return amount <= lim
    }

    /** A finite JSON number as a double (JavaScript semantics: an overflowing literal is not finite), else null. */
    private fun fin(o: Any?): Double? {
        val d: Double = when (o) {
            is Json.Num -> o.raw.toDoubleOrNull() ?: return null
            is Double, is Float, is Int, is Long, is Short, is Byte, is BigDecimal, is BigInteger -> (o as Number).toDouble()
            else -> return null
        }
        return if (d.isFinite()) d else null
    }
}
