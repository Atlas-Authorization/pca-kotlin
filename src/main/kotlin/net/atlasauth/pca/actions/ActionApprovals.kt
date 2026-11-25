package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Approval
import net.atlasauth.pca.verifier.Pca

/**
 * The approval-render helpers over action defs. The canonical render itself is [Approval.render]; these bind it to an executed
 * PCActn, to the approver client's check, and to the pinned definitions a step-up renderer is derived from.
 */
@Suppress("UNCHECKED_CAST")
object ActionApprovals {
    /** The canonical approval render of a def for params (`confirmed`: the def carries a valid signed confirmation). */
    fun renderApproval(def: Map<String, Any?>, params: Any?, confirmed: Boolean): Map<String, Any?> = Approval.render(def, params, confirmed)

    /** H(R) for an executed action: refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb. */
    fun renderDigestForAction(def: Map<String, Any?>, params: Map<String, Any?>, pcactn: Map<String, Any?>, confirmed: Boolean): String {
        val action = pcactn["action"]
        if (def["verb"] != J.get(action, "verb")) throw ActionKitError("render_verb_mismatch", "the PCActn is for '${J.get(action, "verb")}', the definition for '${def["verb"]}'")
        val pd = J.get(action, "params_digest")
        if (pd !is String || pd != Pca.paramsDigest(params)) throw ActionKitError("render_params_mismatch", "the supplied params are not the params the PCActn signed")
        return Approval.renderDigest(renderApproval(def, params, confirmed))
    }

    /** The approver client's check before it signs: re-render from the pinned def and the displayed params, and require the digest the request carries. */
    fun approverRenderCheck(def: Map<String, Any?>, params: Map<String, Any?>, requestedRenderDigest: String?, confirmed: Boolean): String {
        val d = Approval.renderDigest(renderApproval(def, params, confirmed))
        if (d != requestedRenderDigest) throw ActionKitError("render_mismatch", "the approval request commits to a render this definition and these params do not produce")
        return d
    }

    private fun truthy(v: Any?): Boolean {
        if (v == null || v == false || v == "") return false
        val d = J.num(v)
        return d == null || !(d == 0.0 || d.isNaN())
    }

    /** Single-tap (one-gesture) approval is allowed only for a confirmed definition. */
    fun singleTapAllowed(render: Map<String, Any?>): Boolean = !truthy(render["unreviewed"])

    /**
     * The step-up renderer derived from the PINNED definitions: the def is found by verb (or alias, first definition wins); a verb with no pinned
     * definition throws, which makes the review a deny.
     */
    fun renderFromDefs(defs: List<*>, verb: String, params: Map<String, Any?>?, confirmed: Boolean): Map<String, Any?> {
        val byVerb = LinkedHashMap<String, Any?>()
        for (d in defs) {
            byVerb[J.get(d, "verb") as String] = d
            val al = J.get(d, "aliases")
            if (al is List<*>) for (a in al) if (!byVerb.containsKey(a as String)) byVerb[a] = d
        }
        val d = byVerb[verb] ?: throw ActionKitError("render_unknown_verb", "no pinned action definition for '$verb'")
        return renderApproval(J.m(d), params ?: LinkedHashMap<String, Any?>(), confirmed)
    }
}
