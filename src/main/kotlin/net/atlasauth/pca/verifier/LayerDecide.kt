package net.atlasauth.pca.verifier

/**
 * Layered intent, the verifier side (Intent Layer v2 sections 2.4, 3.5; check `layers`; T18). Layers are predicate sets evaluated by the
 * ONE predicate evaluator with the action context of the admitting root. The effective grant is G^org n G^site n G^std n
 * (G^task_0 u D_1 u ... u D_k) minus vetoed cells, and DENY ANYWHERE WINS: an action outside a ceiling is denied with `ceiling` and is
 * NEVER a question. An ABSENT layer is the whole space (no constraint); a layer PRESENT with null or any value that is not
 * `{predicates: [...]}` is MALFORMED and fails closed. Every function here is total.
 */
object LayerDecide {
    @JvmField val LAYER_CEILINGS: List<String> = listOf("org", "site", "std")

    private fun isPlain(o: Any?): Boolean = o is Map<*, *>

    private fun closedTo(o: Map<*, *>, allowed: List<String>): Boolean = o.keys.all { it in allowed }

    /** A well-formed layer: a map with exactly one member, `predicates`, a list. */
    @JvmStatic
    fun isLayerPolicy(l: Any?): Boolean = l is Map<*, *> && closedTo(l, listOf("predicates")) && l.containsKey("predicates") && l["predicates"] is List<*>

    private fun layerAdmits(l: Any?, ctx: Map<String, Any?>?): Boolean = Predicates.evaluatePredicates((l as Map<*, *>)["predicates"], ctx)

    /** `pass`, or the first failing ceiling and why. */
    class CeilingResult internal constructor(val pass: Boolean, val layer: String? = null, val reason: String? = null)

    /**
     * The `layers` check: the action must be inside G^org, then G^site, then G^std (absent = the whole space). The first ceiling that
     * denies is named. `layers` must be a map with no member other than `org`, `site`, `std` (an unknown member fails, reported as `org`).
     */
    @JvmStatic
    fun decideLayerCeilings(layers: Any?, ctx: Map<String, Any?>?): CeilingResult {
        if (isPlain(layers) && !closedTo(layers as Map<*, *>, LAYER_CEILINGS)) return CeilingResult(false, "org", "layers: unknown member (the layers object is {org?, site?, std?})")
        return ceilingsOf(layers, ctx)
    }

    private fun ceilingsOf(layers: Any?, ctx: Map<String, Any?>?): CeilingResult = try {
        if (layers !is Map<*, *>) CeilingResult(false, "org", "layers: the layers member is malformed (not an object)")
        else {
            var out = CeilingResult(true)
            for (k in LAYER_CEILINGS) {
                if (!layers.containsKey(k)) continue
                val layer = layers[k]
                if (!isLayerPolicy(layer)) { out = CeilingResult(false, k, "layers: the $k ceiling is malformed (null or not {predicates: [...]})"); break }
                if (!layerAdmits(layer, ctx)) { out = CeilingResult(false, k, "layers: the action is outside the $k ceiling (a ceiling is never a question)"); break }
            }
            out
        }
    } catch (e: RuntimeException) {
        CeilingResult(false, "org", "layers: evaluation error (fail closed): " + (e.message ?: "error"))
    }

    /** `decision` is `admit` (with [by]: 0 for G^task_0, k for D_k), `ceiling` (with [layer]), `intent_denied` or `intent_required`. */
    class LayerDecision internal constructor(val decision: String, val by: Int? = null, val layer: String? = null)

    /**
     * The full layer decision for one action, in order: outside G^org, G^site, then G^std gives `ceiling`; inside a denied region (a veto)
     * gives `intent_denied`; inside G^task_0 or some delta gives `admit`; otherwise `intent_required` (an uncertain cell: the lazy
     * question). A grant member other than org / site / std / task / denied, a `denied` that is present but not a list, a `task` that is
     * not a list (it is required) or any entry that is not `{predicates: [...]}` is malformed: `intent_denied` (fail closed).
     */
    @JvmStatic
    fun decideLayers(g: Any?, ctx: Map<String, Any?>?): LayerDecision = try {
        if (isPlain(g) && !closedTo(g as Map<*, *>, LAYER_CEILINGS + listOf("task", "denied"))) LayerDecision("intent_denied")
        else {
            val c = ceilingsOf(g, ctx)
            if (!c.pass) LayerDecision("ceiling", layer = c.layer)
            else {
                val m = g as Map<*, *>
                val denied = if (m.containsKey("denied")) m["denied"] else emptyList<Any?>()
                val task = m["task"]
                if (denied !is List<*> || !denied.all { isLayerPolicy(it) } || task !is List<*> || !task.all { isLayerPolicy(it) }) LayerDecision("intent_denied")
                else if (denied.any { layerAdmits(it, ctx) }) LayerDecision("intent_denied")
                else {
                    val i = task.indexOfFirst { layerAdmits(it, ctx) }
                    if (i >= 0) LayerDecision("admit", by = i) else LayerDecision("intent_required")
                }
            }
        }
    } catch (e: RuntimeException) {
        LayerDecision("intent_denied")
    }
}
