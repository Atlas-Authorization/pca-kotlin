package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Approval
import net.atlasauth.pca.verifier.Pca

/**
 * The undo-window engine over action definitions. Reversibility counts only when it is CONFIRMED: the definition carries a valid signed review by a
 * pinned reviewer key, its effective class (declared joined with every trait floor, and for value-dependent reversibility the class of THESE params) is
 * `reversible`, and it names a compensating action that is itself confirmed and can be derived before the effect runs. The compensating call is
 * derived, never authored by the agent. Anything it cannot decide is "not undoable" (a null plan).
 */
@Suppress("UNCHECKED_CAST")
class ActionUndoEngine(defs: List<*>, private val verified: ((Map<String, Any?>) -> Boolean)?, reg: Map<String, Map<String, Any?>>?) {
    private val byVerb = HashMap<String, Map<String, Any?>>()
    private val reg: Map<String, Map<String, Any?>> = reg ?: Actions.CORE_REGISTRY

    init {
        for (d in defs) { val v = J.get(d, "verb") as String; if (!byVerb.containsKey(v)) byVerb[v] = J.m(d) }
    }

    private fun confirmed(d: Map<String, Any?>): Boolean = try { ActionEffective.isConfirmed(d, verified) } catch (e: RuntimeException) { false }

    /** The plan `{def_digest, compensation: {verb, params, def_digest, target_param?}, render, render_digest}` for an operation `{verb, params?}`, or null. */
    fun plan(op: Map<String, Any?>): Map<String, Any?>? {
        try {
            val d = byVerb[op["verb"] as String]
            val p0 = op["params"]
            val params: Map<String, Any?> = if (p0 is Map<*, *>) J.m(p0) else LinkedHashMap()
            if (d == null || !confirmed(d) || readOnly(d["effects"]) || d["compensates"] == null) return null
            val eff = J.m(J.get(ActionEffective.effective(d, reg, verified), "eff"))
            if ("reversible" != eff["rev"] || "reversible" != ActionUndo.reversibilityFor(d, params)) return null
            val c = byVerb[d["compensates"] as String]
            if (c == null || !confirmed(c)) return null
            val s = ActionUndo.compensationShape(d, c)
            if (s["ok"] != true) return null
            val shape = J.m(s["shape"])
            val cparams = LinkedHashMap<String, Any?>()
            val nc = J.m(Actions.normalize(c)["params"])
            for (k0 in J.a(shape["copied"])) {
                val k = k0 as String
                if (params.containsKey(k)) cparams[k] = deepCopy(params[k])
                else if (J.get(nc[k], "required") == true) return null // the call left out what the undo needs
            }
            // an action that cannot be shown completely is never put to a human, so it gets no window either
            val render = Approval.render(d, params, confirmed(d))
            val comp = J.obj("verb", c["verb"], "params", cparams, "def_digest", Actions.defDigest(c))
            if (shape["target"] != null) comp["target_param"] = shape["target"]
            return J.obj("def_digest", Actions.defDigest(d), "compensation", comp, "render", render, "render_digest", Approval.renderDigest(render))
        } catch (e: RuntimeException) {
            return null
        }
    }

    companion object {
        /** The engine over pinned reviewer keys (`pins` null: nothing is confirmed). */
        @JvmStatic
        fun undoEngine(defs: List<*>, pins: Any?, reg: Map<String, Map<String, Any?>>?): ActionUndoEngine {
            val r = reg ?: Actions.CORE_REGISTRY
            return ActionUndoEngine(defs, if (pins == null) null else attestationVerifier(pins, r), r)
        }

        private fun readOnly(effects: Any?): Boolean {
            if (effects !is List<*> || effects.isEmpty()) return false
            for (e in effects) if (e != "read") return false
            return true
        }

        private fun deepCopy(v: Any?): Any? {
            if (v is Map<*, *>) {
                val out = LinkedHashMap<String, Any?>()
                for ((k, x) in v) out[k as String] = deepCopy(x)
                return out
            }
            if (v is List<*>) {
                val out = ArrayList<Any?>()
                for (x in v) out.add(deepCopy(x))
                return out
            }
            return v
        }

        /**
         * The attestation check a pinned-reviewer engine uses: the def is `confirmed`, carries a well-formed attestation over exactly its digest and
         * declared traits, against an accepted trait registry, signed by a key pinned with the reviewer role inside its validity. Never throws.
         */
        @JvmStatic
        fun attestationVerifier(pins: Any?, reg: Map<String, Map<String, Any?>>): (Map<String, Any?>) -> Boolean = { d ->
            try { attested(d, pins, reg) } catch (e: RuntimeException) { false }
        }

        private fun attested(def: Map<String, Any?>, pins: Any?, reg: Map<String, Map<String, Any?>>): Boolean {
            if (ActionConfirmation.reviewerPinsError(pins) != null) return false
            val review = def["review"]
            if ("confirmed" != J.get(review, "state")) return false
            val a = J.get(review, "attestation")
            if (a !is Map<*, *>) return false
            val am = J.m(a)
            if (am["sig"] !is String || am["facts_digest"] !is String) return false
            if (am["final_traits"] !is List<*> || am["dismissed"] !is List<*> || !J.isInt(am["ts"]) || am["reviewer_kid"] !is String) return false
            for (t in J.a(am["final_traits"])) if (t !is String) return false
            for (x in J.a(am["dismissed"])) if (x !is Map<*, *> || J.get(x, "trait") !is String || J.get(x, "reason") !is String) return false
            if (Actions.defDigest(def) != am["def_digest"]) return false
            val accepted = HashSet<Any?>()
            accepted.add(Actions.traitsDigest(reg))
            val extra = J.get(pins, "traits_digests")
            if (extra is List<*>) accepted.addAll(extra)
            if (!accepted.contains(am["traits_digest"])) return false
            val dt = def["traits"]
            if (J.stringify(J.objs(J.sortUniq(am["final_traits"]))) != J.stringify(J.objs(J.sortUniq(if (dt is List<*>) dt else emptyList<Any?>())))) return false
            val fin = HashSet<Any?>(J.a(am["final_traits"]))
            for (x in J.a(am["dismissed"])) if (fin.contains(J.get(x, "trait")) || ActionConfirmation.blankReason(J.get(x, "reason") as String)) return false
            var key: Map<String, Any?>? = null
            for (k in J.a(J.get(pins, "keys"))) if (am["reviewer_kid"] == J.get(k, "kid")) { key = J.m(k); break }
            if (key == null || !J.a(key["roles"]).contains("reviewer")) return false
            val ts = J.num(am["ts"])!!
            if ((key.containsKey("not_before") && ts < J.num(key["not_before"])!!) || (key.containsKey("not_after") && ts > J.num(key["not_after"])!!)) return false
            val body = LinkedHashMap(am)
            body.remove("sig")
            val pk = Pca.decodeB64uStrict(key["pk"], 32)
            val sg = Pca.decodeB64uStrict(am["sig"], 64)
            return pk != null && sg != null && Pca.verifyB64u(key["pk"] as String, ActionConfirmation.reviewMessage(body), am["sig"] as String)
        }
    }
}
