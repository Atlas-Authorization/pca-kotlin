package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentLayers.CeilingAdmitters
import net.atlasauth.pca.intent.IntentOmega.Outcome

/**
 * The layered lattice over a task learner: deny anywhere wins (a cell outside a ceiling is denied with reason ceiling and is never a question),
 * the effective grant, the uncertain cells (the only cells ever asked about), the wallet-side decision for a concrete outcome, and an organisation layer
 * that is itself a learned map.
 */
object IntentLattice {
    private fun lm(): MutableMap<String, Any?> = LinkedHashMap()

    private fun verbOf(l: IntentLearner, verb: String): IntentOmega.VerbSpace? = l.omega.verbs.firstOrNull { it.verb == verb }

    /** {effective, uncertain, ceiling}: cell keys {verb, cell} (ceiling ones with their layer) of the learner's cells under the ceilings. */
    @JvmStatic
    fun latticeView(task: IntentLearner, ceilings: CeilingAdmitters): Map<String, Any?> {
        val effective = ArrayList<Any?>()
        val uncertain = ArrayList<Any?>()
        val ceiling = ArrayList<Any?>()
        for (c in task.cells()) {
            val vs = verbOf(task, c.verb)!!
            val layer = IntentLayers.ceilingOf(ceilings, vs, IntentOmega.cellRep(vs, c.cell))
            val key = lm()
            key["verb"] = c.verb
            key["cell"] = c.cell.map { it.toDouble() }.toMutableList()
            if (layer != null) {
                key["layer"] = layer
                ceiling.add(key)
                continue
            }
            if (c.vetoed) continue
            if (c.inGrant) effective.add(key)
            else if (c.p > 1e-12 && c.p < task.tau - 1e-12) uncertain.add(key)
        }
        val out = lm()
        out["effective"] = effective
        out["uncertain"] = uncertain
        out["ceiling"] = ceiling
        return out
    }

    /** The wallet-side decision for a concrete outcome against a task learner: {decision, layer?, by?}. */
    @JvmStatic
    fun decideOutcomeLayers(task: IntentLearner, ceilings: CeilingAdmitters, o: Outcome): Map<String, Any?> {
        val r = lm()
        val vs = verbOf(task, o.verb)
        if (vs == null) { r["decision"] = "intent_denied"; return r }
        val layer = IntentLayers.ceilingOf(ceilings, vs, o)
        if (layer != null) { r["decision"] = "ceiling"; r["layer"] = layer; return r }
        if (task.isVetoed(o) || task.acceptance(o) <= 1e-12) { r["decision"] = "intent_denied"; return r }
        if (task.admitsOutcome(o)) { r["decision"] = "admit"; r["by"] = 0.0; return r }
        r["decision"] = "intent_required"
        return r
    }

    /** An org layer that is itself a learned map over a shared space: the joint grant of the approvers' maps under the org's rule. Returns {map, policy}. */
    @JvmStatic
    fun orgLayerFromMaps(maps: List<Any?>, rule: Map<String, Any?>): Map<String, Any?> {
        val map = IntentMultiAgg.aggregateIntentMaps(maps, rule, null)
        val r = lm()
        r["map"] = map
        r["policy"] = map["grant"]
        return r
    }
}
