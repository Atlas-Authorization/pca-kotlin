package net.atlasauth.pca.verifier

/**
 * Maps the results of the frontier checks (semantic threshold, progress, objective risk) onto the one three-valued model signal the
 * decision lattice reads (`ok`, `escalate`, `deny`), and tightens risk inputs: the objective path can raise friction, never lower it
 * (frontier-signals.ts). Anything malformed is `deny`.
 */
object FrontierSignals {
    private val PROGRESS_ESCALATE = setOf("exploration-exhausted", "budget-exceeded")

    /** `ok` when the semantic threshold held, `escalate` when it did not (ask a human), `deny` for a missing or malformed result. */
    fun semanticSignal(result: Any?): String {
        val ok = (result as? Map<*, *>)?.get("ok") as? Boolean ?: return "deny"
        return if (ok) "ok" else "escalate"
    }

    /** `ok` for a verified step; a failure whose reason is `exploration-exhausted` or `budget-exceeded` escalates; every other failure is `deny`. */
    fun progressSignal(result: Any?): String {
        val r = result as? Map<*, *>
        val ok = r?.get("ok") as? Boolean ?: return "deny"
        if (ok) return "ok"
        return if (r["reason"] is String && r["reason"] in PROGRESS_ESCALATE) "escalate" else "deny"
    }

    /** An objective risk resolution: mode `none` or `objective` is `ok`; a `mismatch` is `ok` only under the grant's `heuristic` fallback; anything else is `deny`. */
    fun objectiveSignal(res: Any?): String {
        val r = res as? Map<*, *> ?: return "deny"
        return when (r["mode"]) {
            "none", "objective" -> "ok"
            "mismatch" -> if (r["onMismatch"] == "heuristic") "ok" else "deny"
            else -> "deny"
        }
    }

    /**
     * The safer of a baseline and an objective set of risk inputs `{reversibility, blastRadius, semanticDistance}`: the lower
     * reversibility, the higher blast radius, the objective semantic distance (1 when it is not a finite number). A non-finite
     * reversibility or blast radius on either side gives the worst case (reversibility 0, blast radius 1).
     */
    fun tightenRiskInputs(baseline: Map<String, Any?>, objective: Map<String, Any?>): Map<String, Any?> {
        val fin = IntentJs::isFinite
        val ok = fin(baseline["reversibility"]) && fin(objective["reversibility"]) && fin(baseline["blastRadius"]) && fin(objective["blastRadius"])
        val rev = if (ok) Math.min(IntentJs.num(baseline["reversibility"])!!, IntentJs.num(objective["reversibility"])!!) else 0.0
        val blast = if (ok) Math.max(IntentJs.num(baseline["blastRadius"])!!, IntentJs.num(objective["blastRadius"])!!) else 1.0
        return linkedMapOf(
            "reversibility" to StoreJs.num(rev), "blastRadius" to StoreJs.num(blast),
            "semanticDistance" to (if (fin(objective["semanticDistance"])) objective["semanticDistance"] else StoreJs.num(1L)),
        )
    }
}
