package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.ActionKitError

/**
 * The facade's view of an action def: the spec rows a facade compiles permissions and limits from (reversibility class, blast preset,
 * the amount parameter), DERIVED from the effective profile of the def instead of written by hand.
 */
object ActionFacade {
    /**
     * One def to one facade row. Reversibility and blast are the EFFECTIVE values (declared joined with the floor of the trait closure).
     * `reviewed` prices the def as REVIEWED (its declared + implied traits), not as unconfirmed (only for the release-attested catalog).
     */
    fun specOfDef(d: Map<String, Any?>, reg: Map<String, Map<String, Any?>>, reviewed: Boolean, attestationVerified: ((Map<String, Any?>) -> Boolean)?): MutableMap<String, Any?> {
        val full = ActionEffective.effective(d, reg, attestationVerified)
        val e = if (reviewed) J.m(full["hint"]) else full
        val verb = d["verb"] as String
        val dot = verb.indexOf('.')
        val connector = if (dot < 0) verb else verb.substring(0, dot)
        val action = if (dot < 0) "" else verb.substring(dot + 1)
        val amountField: String? = try { ActionDerive.paramByRole(d, "money.amount") } catch (x: ActionKitError) { null }
        val eff = J.m(e["eff"])
        val out = J.obj("connector", connector, "action", action, "verb", verb, "reversibility", eff["rev"], "blastRadius", J.num(eff["blast_ppm"])!! / 1_000_000)
        if (amountField != null) out["amountField"] = amountField
        out["description"] = if (d["description"] != null) d["description"] else d["title"]
        if (d["aliases"] is List<*> && J.a(d["aliases"]).isNotEmpty()) {
            val sorted = ArrayList<String>()
            for (a in J.a(d["aliases"])) sorted.add(a as String)
            sorted.sort()
            out["aliases"] = J.objs(sorted)
        }
        out["traits"] = e["closure"]
        return out
    }

    /** The facade rows of a pack, in the pack's own order. */
    fun facadeSpecs(defs: List<*>, reg: Map<String, Map<String, Any?>>, reviewed: Boolean, attestationVerified: ((Map<String, Any?>) -> Boolean)?): List<Any?> {
        val out = ArrayList<Any?>()
        for (d in defs) out.add(specOfDef(J.m(d), reg, reviewed, attestationVerified))
        return out
    }
}
