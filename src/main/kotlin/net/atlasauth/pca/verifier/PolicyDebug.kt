package net.atlasauth.pca.verifier

import net.atlasauth.pca.explain.ExplainJs

/**
 * Replayable policy debugger (policy-debug.ts). The decision core is pure and total, so a "why" is a re-run, not a log: [explainRisk]
 * decomposes the risk functional into its six weighted terms, [explainDecision] explains a [Decide.decide] input (risk, threshold, budget
 * trajectory), [applyDelta] / [counterfactual] re-run the core under hypothetical single edits and report which one flips the outcome or
 * moves the threshold, [auditPCActn] adds the verifier's per-check table. Inputs and results are JSON trees (maps and lists).
 *
 * Shortcut: a budget that is not a trust budget (`B` and `tau` numbers) makes [explainDecision] throw; the reference would then compute NaN
 * fields. [Decide.decide] denies such an input, so it is the only place the two differ.
 */
@Suppress("UNCHECKED_CAST")
object PolicyDebug {
    private val TERMS = Risk.INPUT_KEYS
    private val INVERTED = listOf(false, true, false, false, true, false)

    private fun n(d: Double): Json.Num = StoreJs.num(d)

    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")

    private fun mapOrEmpty(o: Any?): Map<String, Any?> = if (o is Map<*, *>) o as Map<String, Any?> else LinkedHashMap()

    private fun dbl(o: Any?): Double = Risk.fin(o) ?: Double.NaN

    private fun nz(x: Double): Double = if (!x.isNaN() && !x.isInfinite() && x > 0) x else 0.0

    private fun wt(x: Double): Double = if (!x.isNaN() && !x.isInfinite() && x > 0) x else 0.0

    private fun budgetOf(o: Any?): Risk.Budget? {
        val m = o as? Map<*, *> ?: return null
        val b = Risk.fin(m["B"]) ?: return null
        val tau = Risk.fin(m["tau"]) ?: return null
        return Risk.Budget(b, tau, Risk.fin(m["asOf"]) ?: tau)
    }

    /** `r = max(score, rFloor)` with the six terms in the reference's fixed order; `rFloor` null / not finite reads as 0. */
    fun explainRisk(inputsO: Any?, weightsO: Any?, rFloorIn: Any?): Map<String, Any?> {
        val inputs = map(inputsO)
        val weights = map(weightsO)
        val rFloor = Risk.fin(rFloorIn) ?: 0.0
        val terms = ArrayList<Any?>()
        var rawSum = 0.0
        for (i in TERMS.indices) {
            val raw = Risk.fin(inputs[TERMS[i]])
            val input = if (raw == null) Risk.WORST.getValue(TERMS[i]) else Risk.clamp01(raw)
            val effective = if (INVERTED[i]) 1 - input else input
            val weight = wt(dbl(weights[Risk.WEIGHT_KEYS[i]]))
            val contribution = weight * effective
            terms.add(
                Issue.obj(
                    "term" to TERMS[i], "weight" to n(weight), "input" to n(input), "effective" to n(effective), "contribution" to n(contribution),
                    "inverted" to INVERTED[i],
                ),
            )
            rawSum += contribution
        }
        val rScore = Risk.clamp01(rawSum)
        val r = Math.max(rScore, Risk.clamp01(rFloor))
        return Issue.obj(
            "inputs" to inputs, "weights" to weights, "terms" to terms, "rawSum" to n(rawSum), "rScore" to n(rScore),
            "rFloor" to n(Risk.clamp01(rFloor)), "r" to n(r),
        )
    }

    private fun safetyBound(pol: Map<String, Any?>): Double {
        val kappa = dbl(pol["kappa"])
        return if (kappa > 0) Math.max(0.0, dbl(pol["bMax"])) / kappa else 0.0
    }

    private fun budgetMap(b: Risk.Budget): Map<String, Any?> = Issue.obj("B" to n(b.B), "tau" to n(b.tau), "asOf" to n(b.asOf ?: b.tau))

    /** Explains one decision input (the [Decide.decide] input); the decision itself is under `decision`. */
    fun explainDecision(input: Map<String, Any?>): Map<String, Any?> {
        val decision = Decide.decide(input)
        val env = Authorize.readEnvelope(input["grant"])
        val pol = if (env != null && env["risk_policy"] is Map<*, *>) IntentJs.obj(env["risk_policy"]) else Issue.defaultRiskPolicy()
        val dr = dbl(decision["r"])
        val risk: Map<String, Any?>
        val leaked: Any?
        if (env != null) {
            val b = budgetOf(input["budget"]) ?: throw IllegalArgumentException("budget is not a trust budget")
            val now = dbl(input["now"])
            val lk = Risk.leak(b, now, dbl(pol["lambda"]))
            leaked = budgetMap(lk)
            val inputs = LinkedHashMap<String, Any?>()
            for (k in TERMS) inputs[k] = n(Risk.WORST.getValue(k))
            val rk = mapOrEmpty(input["risk"])
            for (k in TERMS) { val v = Risk.fin(rk[k]); if (v != null) inputs[k] = n(v) }
            val nodeId = input["nodeId"]
            val planO = input["plan"]
            if (planO is List<*> && !rk.containsKey("semanticDistance")) {
                val goal = if (input["goalNodeId"] != null) input["goalNodeId"] else if (planO.isEmpty()) null else mapOrEmpty(planO[planO.size - 1])["id"]
                inputs["semanticDistance"] = n(if (nodeId is String && goal is String) Risk.planGeodesic(planO, nodeId, goal) else 1.0)
            }
            if (!rk.containsKey("age")) {
                val horizon = Risk.fin(input["ageHorizonMs"])
                inputs["age"] = n(Risk.ageSinceTouch(lk, now, horizon ?: (if (input.containsKey("ageHorizonMs")) Double.NaN else 3_600_000.0)))
            }
            val rf = Risk.fin(input["rFloor"])
            risk = explainRisk(inputs, pol["weights"], n(if (rf == null) 0.0 else Math.min(1.0, Math.max(0.0, rf))))
        } else {
            // fail-closed denial (no envelope): the decision is r = 1; keep the shape coherent
            leaked = input["budget"]
            val inputs = LinkedHashMap<String, Any?>()
            val zero = LinkedHashMap<String, Any?>()
            for (i in TERMS.indices) { inputs[TERMS[i]] = n(Risk.WORST.getValue(TERMS[i])); zero[Risk.WEIGHT_KEYS[i]] = StoreJs.num(0L) }
            risk = Issue.obj("inputs" to inputs, "weights" to zero, "terms" to ArrayList<Any?>(), "rawSum" to n(dr), "rScore" to n(dr), "rFloor" to StoreJs.num(0L), "r" to n(dr))
        }
        val thr = decision["requiredThreshold"]
        val budget = Issue.obj(
            "before" to input["budget"], "leaked" to leaked, "after" to decision["budget"],
            "cost" to n(Risk.cost(dr, dbl(pol["kappa"]))), "safetyBound" to n(safetyBound(pol)),
        )
        return Issue.obj(
            "decision" to decision, "risk" to risk, "requiredThreshold" to thr, "t" to mapOrEmpty(thr)["t"],
            "autoAllow" to decision["admit"], "needStepUp" to decision["needStepUp"], "releaseGuardianShare" to decision["releaseGuardianShare"],
            "budget" to budget, "reasons" to decision["reasons"], "envelopeValid" to (env != null),
        )
    }

    private fun merged(base: Any?, over: Any?): Map<String, Any?> {
        val out = LinkedHashMap(mapOrEmpty(base))
        out.putAll(mapOrEmpty(over))
        return out
    }

    /**
     * The hypothetical decision input a delta `{label?, risk?, budget?, rFloor?, now?, caveatContext?, humanCosign?}` denotes; `humanCosign`
     * recharges the budget (full when `{full: true}`) before deciding. Does not mutate [input].
     */
    fun applyDelta(input: Map<String, Any?>, d: Map<String, Any?>): Map<String, Any?> {
        val now = if (d["now"] != null) d["now"] else input["now"]
        var budget: Map<String, Any?> = merged(input["budget"], d["budget"])
        if (ZkJs.truthy(d["humanCosign"])) {
            val env = Authorize.readEnvelope(input["grant"])
            val pol = if (env != null && env["risk_policy"] is Map<*, *>) IntentJs.obj(env["risk_policy"]) else Issue.defaultRiskPolicy()
            val hc = d["humanCosign"]
            val full = hc is Map<*, *> && hc["full"] == true
            val nb = LinkedHashMap<String, Any?>()
            nb["B"] = n(if (full) nz(dbl(pol["bMax"])) else Math.min(nz(dbl(pol["bMax"])), dbl(budget["B"]) + nz(dbl(pol["rho"]))))
            nb["tau"] = now
            nb["asOf"] = now
            budget = nb
        }
        val next = LinkedHashMap(input)
        if (now != null || input.containsKey("now")) next["now"] = now
        next["budget"] = budget
        next["risk"] = merged(input["risk"], d["risk"])
        next["caveatContext"] = merged(input["caveatContext"], d["caveatContext"])
        if (d.containsKey("rFloor")) next["rFloor"] = d["rFloor"]
        return next
    }

    private fun describe(d: Map<String, Any?>): String {
        if (ZkJs.truthy(d["label"])) return IntentRevocation.jsText(d["label"], true)
        val parts = ArrayList<String>()
        val hc = d["humanCosign"]
        if (ZkJs.truthy(hc)) parts.add(if (hc is Map<*, *> && ZkJs.truthy(hc["full"])) "human re-confirms goal (B←Bmax)" else "human co-signs (B+ρ)")
        if (d["risk"] is Map<*, *>) for ((k, v) in IntentJs.obj(d["risk"])) parts.add("$k=" + IntentRevocation.jsText(v, true))
        if (d["budget"] is Map<*, *>) for ((k, v) in IntentJs.obj(d["budget"])) parts.add("budget.$k=" + IntentRevocation.jsText(v, true))
        if (d.containsKey("rFloor")) parts.add("caution=" + IntentRevocation.jsText(d["rFloor"], true))
        if (d.containsKey("now")) parts.add("now=" + IntentRevocation.jsText(d["now"], true))
        if (d["caveatContext"] is Map<*, *>) for ((k, v) in IntentJs.obj(d["caveatContext"])) parts.add("ctx.$k=" + ExplainJs.stringify(v))
        return if (parts.isEmpty()) "no-op" else parts.joinToString(", ")
    }

    /** Re-runs the decision under each delta: `{baseline, outcomes, flipping, thresholdChanging}` (the labels that flip allow, that move t). */
    fun counterfactual(input: Map<String, Any?>, deltas: List<Any?>): Map<String, Any?> {
        val baseline = explainDecision(input)
        val bt = dbl(baseline["t"])
        val br = dbl((baseline["risk"] as Map<String, Any?>)["r"])
        val outcomes = ArrayList<Any?>()
        val flipping = ArrayList<Any?>()
        val changing = ArrayList<Any?>()
        for (o in deltas) {
            val d = map(o)
            val ex = explainDecision(applyDelta(input, d))
            val t = dbl(ex["t"])
            val dir = if (t > bt) "raised" else if (t < bt) "lowered" else "same"
            val label = describe(d)
            val flips = ex["autoAllow"] != baseline["autoAllow"]
            outcomes.add(
                Issue.obj(
                    "label" to label, "delta" to d, "explanation" to ex, "flipsAllow" to flips, "allow" to ex["autoAllow"],
                    "thresholdDirection" to dir, "changesThreshold" to (dir != "same"), "t" to ex["t"],
                    "rDelta" to n(dbl((ex["risk"] as Map<String, Any?>)["r"]) - br),
                ),
            )
            if (flips) flipping.add(label)
            if (dir != "same") changing.add(label)
        }
        return Issue.obj("baseline" to baseline, "outcomes" to outcomes, "flipping" to flipping, "thresholdChanging" to changing)
    }

    /** The verifier's per-check table for the PCActn plus the decomposition of the decision for the same action: `{verify, explanation}`. */
    fun auditPCActn(pcactn: Any?, input: Map<String, Any?>, opts: PcaCore.Options): Map<String, Any?> {
        val r = PcaCore.verify(pcactn, opts)
        val v = LinkedHashMap<String, Any?>()
        v["allow"] = r.allow
        v["checks"] = LinkedHashMap<String, Any?>(r.checks)
        if (r.reason != null) v["reason"] = r.reason
        if (r.assurance != null) v["assurance"] = r.assurance
        return Issue.obj("verify" to v, "explanation" to explainDecision(input))
    }
}
