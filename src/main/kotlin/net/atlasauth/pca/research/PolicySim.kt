package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.Caveats
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Predicates
import net.atlasauth.pca.verifier.Risk
import net.atlasauth.pca.verifier.StoreJs

/**
 * Policy simulation and linting: before a principal enables a grant, replay a batch of historical or hypothetical actions against the
 * compiled policy (which auto-admit, which force a human step-up, which are denied) and run static lints for the classic mistakes. Pure,
 * offline, and mutating nothing: it composes the compiled policy's predicates and caveats with the trust-budget algebra. A planning tool:
 * the resource server's verifier remains the authority at run time.
 */
@Suppress("UNCHECKED_CAST")
object PolicySim {
    private val REVERSIBILITY_ORDER = listOf("reversible", "rate_limited", "irreversible")

    private fun n(d: Double): Json.Num = StoreJs.num(d)
    private fun nz(x: Double): Double = if (!x.isNaN() && !x.isInfinite() && x > 0) x else 0.0
    private fun clamp01(x: Double): Double = Math.max(0.0, Math.min(1.0, x))
    private fun num(o: Any?): Double = IntentJs.num(o) ?: Double.NaN
    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun cost(r: Double, kappa: Double): Double = nz(kappa) * clamp01(if (r.isNaN() || r.isInfinite()) 1.0 else r)

    private fun truthy(v: Any?): Boolean = when (v) {
        null -> false
        is Boolean -> v
        is String -> v.isNotEmpty()
        else -> IntentJs.num(v)?.let { !(it == 0.0 || it.isNaN()) } ?: true
    }

    /** `Number(params[field])` for a parsed JSON value; an absent member is NaN. */
    private fun jsNumber(params: Map<String, Any?>?, field: String): Double {
        if (params == null || !params.containsKey(field)) return Double.NaN
        val v = params[field]
        return when {
            v == null -> 0.0
            v is Boolean -> if (v) 1.0 else 0.0
            IntentJs.num(v) != null -> IntentJs.num(v)!!
            v is String || v is List<*> -> jsToNumber(Js.str(v))
            else -> Double.NaN
        }
    }

    private val HEX = Regex("0[xX][0-9a-fA-F]+")
    private val OCT = Regex("0[oO][0-7]+")
    private val BIN = Regex("0[bB][01]+")
    private val DEC = Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")

    /** JavaScript `Number(string)`: trimmed, empty is 0, hex/octal/binary prefixes, decimal and Infinity; anything else NaN. */
    private fun jsToNumber(s: String): Double {
        val t = s.trim()
        if (t.isEmpty()) return 0.0
        return try {
            when {
                HEX.matches(t) -> java.lang.Long.parseLong(t.substring(2), 16).toDouble()
                OCT.matches(t) -> java.lang.Long.parseLong(t.substring(2), 8).toDouble()
                BIN.matches(t) -> java.lang.Long.parseLong(t.substring(2), 2).toDouble()
                t == "Infinity" || t == "+Infinity" -> Double.POSITIVE_INFINITY
                t == "-Infinity" -> Double.NEGATIVE_INFINITY
                !DEC.matches(t) -> Double.NaN
                else -> t.toDouble()
            }
        } catch (e: NumberFormatException) {
            Double.NaN
        }
    }

    private fun riskOf(policy: Facade.CompiledPolicy, catalog: Catalog, verb: String?, params: Map<String, Any?>?): Double {
        val spec = if (verb == null) null else catalog.get(verb)
        val kappa = num(policy.riskPolicy["kappa"])
        if (policy.budgetModel == "dollars" && spec != null && spec.amountField != null) {
            val amt = jsNumber(params, spec.amountField)
            if (!amt.isNaN() && !amt.isInfinite() && kappa > 0) return clamp01(amt / kappa)
        }
        return clamp01(spec?.blastRadius ?: 0.8)
    }

    private fun simResult(action: Map<String, Any?>, outcome: String, t: Int?, r: Double, reason: String?, budgetAfter: Double): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["action"] = action
        m["outcome"] = outcome
        if (t != null) m["t"] = StoreJs.num(t.toLong())
        m["r"] = n(r)
        if (reason != null) m["reason"] = reason
        m["budgetAfter"] = n(budgetAfter)
        return m
    }

    private class Timed(val a: Map<String, Any?>, val at: Double)

    /**
     * Replay actions in time order against the policy, threading the trust budget as the server would (leak between actions; debit kappa*r on
     * every metered admit; step-up when the budget cannot cover a machine-band action). An action with no usable time is reported as denied,
     * not skipped or guessed. [catalog] may be null (the built-in one); [start] is the clock the budget starts at and the base of untimed
     * actions' order (`start + index`).
     */
    @JvmStatic
    @JvmOverloads
    fun simulate(policy: Facade.CompiledPolicy, actions: List<Map<String, Any?>>, catalog: Catalog? = null, start: Double = 0.0): Map<String, Any?> {
        val cat = catalog ?: Catalog.DEFAULT
        val timed = ArrayList<Timed>()
        for ((i, a) in actions.withIndex()) {
            val at = a["at"]
            timed.add(Timed(a, if (at != null) (if (IntentJs.isFinite(at)) num(at) else Double.NaN) else start + i))
        }
        val results = ArrayList<Map<String, Any?>>()
        val rp = policy.riskPolicy
        val bMax = num(rp["bMax"])
        val lambda = num(rp["lambda"])
        val kappa = num(rp["kappa"])
        val theta1 = num(rp["theta1"])
        val theta2 = num(rp["theta2"])
        val rpol = Risk.Policy(LinkedHashMap(), theta1, theta2, 0.0, 0.0, 0.0, 0.0)
        var budgetB = bMax
        var asOf = start
        val ordered = timed.filter { !it.at.isNaN() && !it.at.isInfinite() }.sortedWith { x, y -> val d = x.at - y.at; if (d == 0.0) 0 else if (d < 0) -1 else 1 }
        for (x in timed) if (x.at.isNaN() || x.at.isInfinite()) results.add(simResult(x.a, "deny", null, 1.0, "action has no finite time", budgetB))

        val recent = ArrayList<Double>()
        var peakRisk = 0.0
        var autonomousRisk = 0.0
        for (x in ordered) {
            val a = x.a
            val at = x.at
            val verb = a["verb"] as String?
            val spec = if (verb == null) null else cat.get(verb)
            val params = map(a["params"])
            val act = linkedMapOf<String, Any?>(
                "verb" to a["verb"], "resource" to a["resource"], "params" to (params ?: LinkedHashMap<String, Any?>()),
                "reversibility_class" to (spec?.reversibility ?: "irreversible"),
            )
            val ctx = linkedMapOf<String, Any?>("action" to act)
            val r = riskOf(policy, cat, verb, params)
            peakRisk = Math.max(peakRisk, r)

            val denial = Predicates.denialReason(policy.predicates, ctx)
            var cav: Caveats.Result? = null
            if (denial == null) {
                val cctx = linkedMapOf<String, Any?>(
                    "now" to n(at), "blast_radius" to n(spec?.blastRadius ?: 1.0), "reversibility_class" to (spec?.reversibility ?: "irreversible"),
                    "recent_action_times" to ArrayList<Any?>(recent.map { n(it) }),
                )
                cav = Caveats.evaluateCaveats(policy.caveats, cctx)
            }
            // leak: B falls by lambda per second since the last update (idempotent at the same instant)
            val dt = Math.max(0.0, at - asOf)
            budgetB = Math.max(0.0, budgetB - nz(lambda) * (dt / 1000))
            asOf = Math.max(at, asOf)

            if (denial != null) { results.add(simResult(a, "deny", null, r, denial, budgetB)); continue }
            if (!cav!!.ok) { results.add(simResult(a, "deny", null, r, "caveat(s) failed: " + cav.failed.joinToString(", "), budgetB)); continue }
            val t = Risk.requiredThreshold(r, rpol, false).t
            val c = cost(r, kappa)
            var admit = false
            val tOut: Int
            if (t < 3 && !(budgetB >= c)) tOut = 3
            else if (t == 1) { admit = true; tOut = 1 }
            else tOut = if (t == 2) 2 else 3
            if (admit) {
                budgetB -= c
                autonomousRisk += r
                recent.add(at)
                results.add(simResult(a, "auto", 1, r, null, budgetB))
            } else {
                // t=2 (guardian auto-cosign) and t=3 (human) both surface as a step-up in the planning view
                results.add(simResult(a, "step_up", tOut, r, "requires tier $tOut", budgetB))
            }
        }
        var auto = 0L
        var stepUp = 0L
        var deny = 0L
        for (m in results) when (m["outcome"]) { "auto" -> auto++; "step_up" -> stepUp++; else -> deny++ }
        return linkedMapOf(
            "results" to ArrayList<Any?>(results), "auto" to StoreJs.num(auto), "stepUp" to StoreJs.num(stepUp), "deny" to StoreJs.num(deny),
            "endBudget" to n(budgetB), "peakRisk" to n(peakRisk), "autonomousRisk" to n(autonomousRisk),
        )
    }

    // ---- linting ----

    private fun sev(cls: String): Int = REVERSIBILITY_ORDER.indexOf(cls)

    private fun lint(level: String, code: String, message: String): Map<String, Any?> = linkedMapOf("level" to level, "code" to code, "message" to message)

    private val INDEX_KEY = Regex("0|[1-9][0-9]{0,9}")

    /** `Object.keys` order: array-index keys ascending, then insertion order. */
    private fun keysOf(m: Map<String, Any?>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) (if (INDEX_KEY.matches(k) && k.toLong() < 4294967295L) idx else rest).add(k)
        idx.sortBy { it.toLong() }
        return idx + rest
    }

    /**
     * Static lints over a compiled policy: `error` = almost certainly a mistake (a limit that matches no granted action), `warn` = a real risk
     * worth a second look, `info` = a notable but intentional property. [catalog] may be null.
     */
    @JvmStatic
    @JvmOverloads
    fun lintPolicy(policy: Facade.CompiledPolicy, catalog: Catalog? = null): List<Any?> {
        val cat = catalog ?: Catalog.DEFAULT
        val lints = ArrayList<Any?>()
        val granted = HashSet<String>()
        for (s in policy.actions) { granted.add(s.verb); granted.add(s.action); granted.addAll(s.aliases) }
        for (key in keysOf(policy.inputLimits)) if (!granted.contains(key)) lints.add(lint("error", "limit-unmatched", "limit for '$key' matches no granted action"))

        for (spec in policy.actions) {
            var pred: Map<String, Any?>? = null
            for (p in policy.predicates) {
                val pm = map(p)
                if (pm != null && spec.verb == pm["verb"]) { pred = pm; break }
            }
            val broad = pred == null || !truthy(pred["resource"]) || pred["resource"] == "*"
            if (!spec.amountField.isNullOrEmpty() && !policy.limits.containsKey(spec.verb)) {
                lints.add(lint("warn", "money-unbounded", "money action '${spec.verb}' has no per-call limit — spend is bounded only by the trust budget"))
            }
            if (broad && sev(spec.reversibility) >= sev("rate_limited")) {
                lints.add(lint("warn", "broad-resource", "'${spec.verb}' (${spec.reversibility}) matches ANY resource — consider a resource prefix"))
            }
            if (cat.get(spec.verb) == null) {
                lints.add(lint("info", "uncatalogued", "'${spec.verb}' is not in the catalog — treated conservatively (irreversible, high blast radius)"))
            }
        }

        val theta2 = num(policy.riskPolicy["theta2"])
        val bMax = num(policy.riskPolicy["bMax"])
        val kappa = num(policy.riskPolicy["kappa"])
        if (theta2 >= 1) {
            val hasIrrev = policy.actions.any { sev(it.reversibility) >= sev("irreversible") }
            lints.add(
                lint(
                    if (hasIrrev) "warn" else "info", "no-step-up-band",
                    "theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted" + (if (hasIrrev) " — including irreversible actions" else ""),
                ),
            )
        }
        if (kappa > 0 && bMax / kappa > 100) {
            lints.add(lint("warn", "large-autonomy", "autonomous bound is ${AttestUtil.jsNumString(Math.floor(bMax / kappa + 0.5))}× a max-risk action between human co-signs"))
        }
        return lints
    }
}
