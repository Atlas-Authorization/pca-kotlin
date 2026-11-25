package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions

/**
 * The facts the default provenance gate reads, derived from signed action defs. "Unconfirmed means maximally dangerous": a def without a
 * valid signed confirmation reports no effects and the top trait set, and its `provenance_min` relaxations are ignored.
 */
object ActionProvenance {
    /** The gate facts of one def under a trait registry: `{effects, traits, params?}`. */
    fun provenanceInfoOf(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, attestationVerified: ((Map<String, Any?>) -> Boolean)?): MutableMap<String, Any?> {
        val traits = ActionEffective.traitsOf(d, reg, attestationVerified)
        if (!ActionEffective.isConfirmed(d, attestationVerified)) return J.obj("effects", ArrayList<Any?>(), "traits", J.objs(traits))
        val n = Actions.normalize(d)
        val params = LinkedHashMap<String, Any?>()
        for ((k, v) in J.m(n["params"])) if (J.get(v, "provenance_min") != null) params[k] = J.get(v, "provenance_min")
        val out = J.obj("effects", ArrayList<Any?>(J.a(n["effects"])), "traits", J.objs(traits))
        if (params.isNotEmpty()) out["params"] = params
        return out
    }

    /**
     * The `provenance.actions` resolver: the facts of the def whose verb (or alias) is the operation's verb; null for an unknown verb
     * (the gate then treats the action as sensitive). Two defs claiming one name throw at build time.
     */
    fun provenanceActions(defs: List<*>, reg: Map<String, Map<String, Any?>>, attestationVerified: ((Map<String, Any?>) -> Boolean)?): (String) -> Map<String, Any?>? {
        val byVerb = LinkedHashMap<String, Map<String, Any?>>()
        for (dO in defs) {
            val d = J.m(dO)
            val n = Actions.normalize(d)
            val info = provenanceInfoOf(d, reg, attestationVerified)
            val names = ArrayList<Any?>()
            names.add(n["verb"])
            names.addAll(J.a(n["aliases"]))
            for (v in names) {
                if (byVerb.containsKey(v as String)) throw IllegalStateException("provenanceActions: two definitions claim the verb '$v'")
                byVerb[v] = info
            }
        }
        return { v -> byVerb[v] }
    }
}
