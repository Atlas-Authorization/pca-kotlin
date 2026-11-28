package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * The pure parts of runtime intent conformance: the judge input and the PCActn action shape for an outcome, the content
 * addresses of the conformance attestation, the calibration set and the just-in-time consent request, the consent prompt, and
 * the monotone risk fold. The route decision lives in [IntentRouting].
 */
object IntentRuntime {
    const val IC_ATT_DOMAIN = "atlas-pca/intent-ic-att/v1"

    /** Deep copy with every Double spelled as the JSON number JavaScript would print (hashed trees carry Json.Num). */
    internal fun jsonNums(v: Any?): Any? = when (v) {
        is Double -> Json.Num(AttestUtil.jsNumString(v))
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = jsonNums(x) }
        is List<*> -> v.mapTo(ArrayList()) { jsonNums(it) }
        else -> v
    }

    /** The PCActn action shape for an outcome (params digest by the canonical rule). */
    fun pcactnActionOf(vs: VerbSpace, o: Outcome): MutableMap<String, Any?> {
        val a = IntentPolicy.outcomeToAction(vs, o)
        val out = LinkedHashMap<String, Any?>()
        out["verb"] = a["verb"]
        out["resource"] = a["resource"]
        out["params_digest"] = Pca.paramsDigest(if (a["params"] == null) LinkedHashMap<String, Any?>() else jsonNums(a["params"]))
        out["reversibility_class"] = vs.reversibility
        return out
    }

    /** The digest every verdict must bind to. */
    fun actionDigest(action: Any?): String = Pca.hashCanonical(action)

    /** Digest of a verdict (strict canonical over the full verdict). */
    fun verdictDigest(verdict: Any?): String = Pca.hashCanonical(verdict)

    /** What every judge sees; [p] is the map's acceptance of the outcome; [ctx]: intentRef, mapDigest, statementText, slots, goalCommitment. */
    fun judgeInputOf(vs: VerbSpace, o: Outcome, p: Double, ctx: Map<String, Any?>): MutableMap<String, Any?> {
        val out = LinkedHashMap(ctx)
        out["renderedAction"] = IntentRender.renderAction(vs, o.values)
        out["p"] = p
        out["reversibility"] = vs.reversibility
        out["actionDigest"] = actionDigest(pcactnActionOf(vs, o))
        return out
    }

    /** Digest of a calibration set ({alpha, samples: [{score, faithful}]}). */
    fun calibrationDigest(c: Map<String, Any?>): String {
        val samples = IntentOmega.arr(c["samples"]).map { s -> linkedMapOf<String, Any?>("score" to IntentOmega.obj(s)["score"], "faithful" to IntentOmega.obj(s)["faithful"]) }
        return Pca.hashCanonical(linkedMapOf<String, Any?>("d" to "atlas-pca/intent-calibration/v1", "alpha" to c["alpha"], "samples" to samples))
    }

    /** Content address of an IC-Att (the value a PCActn carries as `ic_att_digest`). */
    fun icAttDigest(att: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to IC_ATT_DOMAIN, "a" to att))

    /** The risk contribution of an aggregate judge score: 1 - score clamped to [0, 1] (1 when not finite). */
    fun semanticRiskContribution(aggregateScore: Double): Double {
        if (aggregateScore.isNaN() || aggregateScore.isInfinite()) return 1.0
        val r = 1 - aggregateScore
        return if (r < 0) 0.0 else if (r > 1) 1.0 else r
    }

    /** The monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r. */
    fun foldSemanticRisk(r: Double, att: Map<String, Any?>): Double =
        Math.max(r, semanticRiskContribution(IntentOmega.dbl(att["aggregate_score_ppm"]) / 1_000_000))

    /** The consent prompt for an action; [p] is the map's acceptance of the outcome. */
    fun jitConsentRequest(vs: VerbSpace, o: Outcome, p: Double, intentRef: String?, mapDigest: String?): MutableMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["v"] = Json.Num("1")
        out["kind"] = "pca-intent-jit"
        out["intent_ref"] = intentRef
        out["map_digest"] = mapDigest
        out["verb"] = o.verb
        out["values"] = jsonNums(LinkedHashMap(o.values))
        out["reversibility"] = vs.reversibility
        out["p_ppm"] = Json.Num(Math.round(p * 1_000_000).toString())
        out["text"] = IntentRender.renderAction(vs, o.values) + " This cannot be undone. Approve?"
        return out
    }

    fun jitConsentDigest(request: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to "atlas-pca/intent-jit/v1", "r" to request))
}
