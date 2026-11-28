package net.atlasauth.pca.verifier

/**
 * The multi-agent budget algebra over trust budgets given as JSON objects `{B, tau, asOf?}` (the typed form is [Risk]): allocating a
 * sub-agent's budget out of its parent's, consolidated debits (a sub-agent's spend also debits every ancestor, so a swarm can never
 * collectively spend more than a node's allocation) and the full re-confirmation recharge. A refusal changes nothing and names the
 * reason. A budget keeps the members it came with.
 */
object RiskBudgets {
    private fun nz(x: Double): Double = if (!x.isNaN() && !x.isInfinite() && x > 0) x else 0.0

    private fun num(o: Any?): Double = IntentJs.num(o) ?: Double.NaN

    private fun no(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    private fun debit(b: Map<String, Any?>, x: Double): Map<String, Any?> = LinkedHashMap(b).also { it["B"] = StoreJs.num(Math.max(0.0, num(b["B"]) - x)) }

    /** Allocate a sub-agent budget `B_sub = alloc`, guarded by `0 <= alloc <= parent.B`: `{ok: true, sub}` or `{ok: false, reason}`. */
    fun subBudget(parent: Map<String, Any?>, alloc: Double): Map<String, Any?> {
        if (alloc.isNaN() || alloc.isInfinite() || alloc < 0) return no("allocation must be finite and >= 0")
        if (!(num(parent["B"]).isFinite() && alloc <= num(parent["B"]))) return no("allocation exceeds parent remaining budget")
        val sub = linkedMapOf<String, Any?>("B" to StoreJs.num(alloc))
        if (parent.containsKey("tau")) sub["tau"] = parent["tau"]
        (parent["asOf"] ?: parent["tau"])?.let { sub["asOf"] = it }
        return linkedMapOf("ok" to true, "sub" to sub)
    }

    /** A sub-agent's debit also debits the parent; fails with no state change if either cannot cover `c`: `{ok: true, parent, sub}` or `{ok: false, reason}`. */
    fun debitConsolidated(parent: Map<String, Any?>, sub: Map<String, Any?>, c: Double): Map<String, Any?> {
        val x = nz(c)
        if (!(num(sub["B"]).isFinite() && num(sub["B"]) >= x)) return no("sub-agent budget insufficient")
        if (!(num(parent["B"]).isFinite() && num(parent["B"]) >= x)) return no("parent budget insufficient")
        return linkedMapOf("ok" to true, "parent" to debit(parent, x), "sub" to debit(sub, x))
    }

    /**
     * [debitConsolidated] along a root-to-leaf budget path: every node must cover `c`; if any cannot, nothing is debited and the first
     * offender is named. `{ok: true, nodes}` or `{ok: false, reason}`. Throws IllegalArgumentException when a node is not an object.
     */
    @Suppress("UNCHECKED_CAST")
    fun debitConsolidatedPath(path: List<Any?>, c: Double): Map<String, Any?> {
        val x = nz(c)
        val nodes = path.map { it as? Map<String, Any?> ?: throw IllegalArgumentException("debitConsolidatedPath: a budget node is not an object") }
        for ((i, node) in nodes.withIndex()) {
            if (!(num(node["B"]).isFinite() && num(node["B"]) >= x)) {
                return no("budget node at depth $i insufficient (need ${AttestUtil.jsNumString(x)}, have ${IntentRevocation.jsText(node["B"], node.containsKey("B"))})")
            }
        }
        return linkedMapOf("ok" to true, "nodes" to nodes.map { debit(it, x) })
    }

    /** Full goal re-confirmation: `{B: bMax, tau: now, asOf: now}`. */
    fun rechargeFull(bMax: Double, now: Double): Map<String, Any?> = linkedMapOf("B" to StoreJs.num(nz(bMax)), "tau" to StoreJs.num(now), "asOf" to StoreJs.num(now))
}
