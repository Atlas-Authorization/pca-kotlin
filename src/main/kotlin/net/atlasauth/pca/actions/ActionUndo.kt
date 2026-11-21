package net.atlasauth.pca.actions

import java.util.TreeMap
import net.atlasauth.pca.verifier.Actions

/**
 * The structural half of the undo-window engine over action definitions: the class of a reversibility declaration for concrete params,
 * whether any value of it is reversible, and whether a compensating action can undo another without the agent's help (derived, never
 * authored by the agent). The confirmation-gated engine itself sits on top of these.
 */
@Suppress("UNCHECKED_CAST")
object ActionUndo {
    /** The class of a reversibility declaration for concrete params (an unmapped or absent value takes `default`, else irreversible). */
    fun reversibilityFor(d: Map<String, Any?>, params: Map<String, Any?>): String {
        val r = Actions.normalize(d)["reversibility"]
        if (r is String) return r
        val v = params[J.get(r, "by") as String]
        val k = if (v is String) v else if (v is Boolean || J.isInt(v)) J.jsStr(v) else null
        val map = J.m(J.get(r, "map"))
        if (k != null && map.containsKey(k)) return map[k] as String
        val dflt = J.get(r, "default")
        return if (dflt != null) dflt as String else "irreversible"
    }

    /** True when some value of the declaration is `reversible` (a fixed class, a map value or the default). */
    fun mayBeReversible(d: Map<String, Any?>): Boolean {
        val r = d["reversibility"] ?: return false
        if (r is String) return "reversible" == r
        return J.m(J.get(r, "map")).containsValue("reversible") || "reversible" == J.get(r, "default")
    }

    private fun sameType(a: Any?, b: Map<String, Any?>): Boolean =
        a != null && J.get(a, "type") == b["type"] && J.get(a, "items") == b["items"]

    private fun isReadOnly(effects: Any?): Boolean {
        if (effects !is List<*> || effects.isEmpty()) return false
        for (e in effects) if (e != "read") return false
        return true
    }

    /** Can `comp` undo `orig`? `{ok: true, shape: {copied, target?}}` or `{ok: false, reason}`. */
    fun compensationShape(orig: Map<String, Any?>, comp: Map<String, Any?>): Map<String, Any?> {
        if (isReadOnly(comp["effects"])) return J.obj("ok", false, "reason", "the compensating action ${comp["verb"]} only reads")
        val ct = J.get(comp["resource"], "type") as String
        val ot = J.get(orig["resource"], "type") as String
        if (ct != ot) return J.obj("ok", false, "reason", "the compensating action ${comp["verb"]} acts on $ct, not $ot")
        val nc = Actions.normalize(comp)
        val copied = ArrayList<Any?>()
        var target: String? = null
        val idemO = nc["idempotency"]
        val idem = if ("key_param" == J.get(idemO, "mode")) J.get(idemO, "param") as String? else null
        val origParams = J.m(orig["params"])
        for ((name, pv) in TreeMap(J.m(nc["params"]))) {
            val p = J.m(pv)
            if (name == idem) continue
            if (sameType(origParams[name], p)) { copied.add(name); continue }
            if (p["required"] != true) continue
            if (("id.$ct") == p["role"] && target == null) { target = name; continue }
            return J.obj("ok", false, "reason", "the compensating action ${comp["verb"]} needs '$name', which neither the original call nor its result supplies")
        }
        val shape = J.obj("copied", copied)
        if (target != null) shape["target"] = target
        return J.obj("ok", true, "shape", shape)
    }
}
