package net.atlasauth.pca.verifier

import net.atlasauth.pca.research.PolicySim

/**
 * Policy sizing (budget-forecast.ts): how large a trust budget lets an agent act autonomously for a number of actions, and the
 * autonomy bound of a risk policy.
 */
@Suppress("UNCHECKED_CAST")
object BudgetForecast {
    /**
     * Forecast a plan `[{verb, resource, params?, at?}]` against a compiled policy: how the trust budget drains step by step, the index of the
     * first action forced to a step-up (`firstStepUpAt`, absent when none is), the risk the machine-only actions add up to, and how many
     * co-signs the whole plan needs. Composes [PolicySim.simulate]. [start] is the clock the budget starts at (null = 0); [catalog] null is the
     * built-in one, and a verb unknown to the catalog given fails closed.
     */
    @JvmOverloads
    fun forecast(policy: Facade.CompiledPolicy, plan: List<Map<String, Any?>>, start: Double? = null, catalog: Catalog? = null): Map<String, Any?> {
        val rep = PolicySim.simulate(policy, plan, catalog, start ?: 0.0)
        val steps = ArrayList<Any?>()
        var first = -1
        for (o in rep["results"] as List<Any?>) {
            val r = o as Map<String, Any?>
            val action = r["action"] as Map<String, Any?>
            val step = LinkedHashMap<String, Any?>()
            if (action.containsKey("verb")) step["verb"] = action["verb"]
            if (action.containsKey("resource")) step["resource"] = action["resource"]
            step["outcome"] = r["outcome"]
            step["r"] = r["r"]
            step["budgetAfter"] = r["budgetAfter"]
            if (first < 0 && r["outcome"] == "step_up") first = steps.size
            steps.add(step)
        }
        val out = LinkedHashMap<String, Any?>()
        out["steps"] = steps
        if (first >= 0) out["firstStepUpAt"] = StoreJs.num(first.toLong())
        out["autonomousRisk"] = rep["autonomousRisk"]
        out["forcesCosign"] = (IntentJs.num(rep["stepUp"]) ?: 0.0) > 0
        out["cosignsNeeded"] = rep["stepUp"]
        out["endBudget"] = rep["endBudget"]
        return out
    }

    /**
     * The smallest trust budget `bMax = n * r * kappa` that lets an agent run `targetActions` actions of per-action risk `perActionRisk`
     * (clamped to [1e-6, 1]) before a human co-sign is needed: `{kappa, bMax, autonomousBound, rationale}`. `kappa` defaults to 1.
     * Throws IllegalArgumentException on a kappa that is not a positive finite number or a non-finite count or risk.
     */
    @JvmOverloads
    fun recommendPolicy(targetActions: Double, perActionRisk: Double, kappa: Double? = null): Map<String, Any?> {
        val k = kappa ?: 1.0
        require(!k.isNaN() && !k.isInfinite() && k > 0) { "recommendPolicy: kappa must be a positive finite number" }
        require(!targetActions.isNaN() && !targetActions.isInfinite() && !perActionRisk.isNaN() && !perActionRisk.isInfinite()) {
            "recommendPolicy: targetActions and perActionRisk must be finite numbers"
        }
        val r = Math.max(1e-6, Math.min(1.0, perActionRisk))
        val n = Math.max(0.0, targetActions)
        val bMax = n * r * k
        return linkedMapOf(
            "kappa" to StoreJs.num(k), "bMax" to StoreJs.num(bMax), "autonomousBound" to StoreJs.num(bMax / k),
            "rationale" to "Σr ≤ bMax/κ = ${Reputation.toFixed(bMax / k, 3)} ≥ ${AttestUtil.jsNumString(n)}×${Reputation.toFixed(r, 3)} actions before a human co-sign",
        )
    }

    /** The autonomy bound of a risk policy `{bMax, kappa}`: the total risk an agent can accrue between human co-signs, `max(0, bMax) / kappa` (0 when kappa is not above zero). */
    fun autonomyBoundOf(policy: Map<String, Any?>): Double {
        val kappa = IntentJs.num(policy["kappa"]) ?: Double.NaN
        return if (kappa > 0) Math.max(0.0, IntentJs.num(policy["bMax"]) ?: Double.NaN) / kappa else 0.0
    }
}
