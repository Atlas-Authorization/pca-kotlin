package net.atlasauth.pca.policybridge

import net.atlasauth.pca.verifier.Predicates

/**
 * Import external authorization policy into PCA: each translator compiles a policy source into PCA envelope predicates plus a report
 * of what was and was not translated; everything unmodeled fails closed (default deny). A result is the JSON map
 * `{predicates, denies, caveats, report: {source, translated, skipped, errors}}`.
 *
 * - [Cedar.cedarToPca]: Cedar permit/forbid policies
 * - [Rego.regoToPca]: OPA/Rego allow-rule subset
 * - [OpenFga.openfgaToPca]: OpenFGA / Zanzibar ReBAC model and tuples
 * - [Cel]: strict CEL conditions (Google IAM Conditions, Kubernetes admission policy, SpiceDB caveats)
 *
 * The emitted predicates plug into an envelope's predicates; `denies` (Cedar forbid) is applied by [decide] (deny-overrides-permit) on
 * top of the core evaluator.
 */
object PolicyBridge {
    internal fun newReport(source: String): MutableMap<String, Any?> {
        val report = LinkedHashMap<String, Any?>()
        report["source"] = source
        report["translated"] = ArrayList<Any?>()
        report["skipped"] = ArrayList<Any?>()
        report["errors"] = ArrayList<Any?>()
        return report
    }

    @Suppress("UNCHECKED_CAST")
    internal fun list(report: Map<String, Any?>, key: String): MutableList<Any?> = report[key].let { if (it is MutableList<*>) it as MutableList<Any?> else ArrayList(it as List<Any?>) }

    internal fun result(predicates: List<Any?>, denies: List<Any?>, report: Map<String, Any?>): MutableMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["predicates"] = predicates
        r["denies"] = denies
        r["caveats"] = ArrayList<Any?>()
        r["report"] = report
        return r
    }

    /**
     * Decide one action under a translation with deny-overrides-permit (Cedar's combining rule) on the core evaluator: any matching deny
     * denies; otherwise the permit predicates decide. Fails closed on an incomplete translation (a result whose report carries errors).
     * Returns `{allowed, matched?, reason?}`.
     */
    fun decide(result: Map<String, Any?>, ctx: Map<String, Any?>): Map<String, Any?> {
        val report = result["report"]
        if (report is Map<*, *> && report["errors"] is List<*> && (report["errors"] as List<*>).isNotEmpty()) {
            return PbJs.obj("allowed", false, "reason", "translation incomplete (fail closed)")
        }
        val denies = result["denies"]
        if (denies is List<*> && denies.isNotEmpty() && Predicates.evaluatePredicates(denies, ctx)) {
            return PbJs.obj("allowed", false, "matched", firstMatch(denies, ctx), "reason", "forbidden by deny policy")
        }
        val permits = result["predicates"]
        if (Predicates.evaluatePredicates(permits, ctx)) return PbJs.obj("allowed", true, "matched", firstMatch(permits as List<*>, ctx))
        return PbJs.obj("allowed", false, "reason", Predicates.denialReason(permits, ctx))
    }

    /** The first predicate of an allowing list that matches. */
    private fun firstMatch(predicates: List<*>, ctx: Map<String, Any?>): Any? {
        for (p in predicates) if (Predicates.predicateMatches(p, ctx)) return p
        return null
    }
}
