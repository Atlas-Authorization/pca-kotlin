package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.IntentJs

/**
 * Runtime conformance: how an action the grant admits is routed (deny / allow / optimistic / jit-consent) from the map's posterior, the
 * judge-panel hook and its intent-conformance attestation (IC-Att), re-verification of an IC-Att, and recording a just-in-time consent
 * decision as a runtime observation.
 */
object IntentRouting {
    private fun lm(): MutableMap<String, Any?> = LinkedHashMap()

    /** Routing options; every field optional (null = default): theta2 (0.5), hMax (the space's harm maximum), bondPolicy. */
    class RouteOptions {
        @JvmField var theta2: Double? = null
        @JvmField var hMax: Double? = null
        @JvmField var bondPolicy: IntentBond.BondPolicy? = null

        companion object {
            @JvmStatic
            fun fromJson(o: Any?): RouteOptions {
                val r = RouteOptions()
                if (o == null) return r
                val m = IntentOmega.obj(o)
                r.theta2 = IntentLearner.numOrNull(m["theta2"])
                r.hMax = IntentLearner.numOrNull(m["hMax"])
                if (m["bondPolicy"] != null) r.bondPolicy = IntentBond.BondPolicy.fromJson(m["bondPolicy"])
                return r
            }
        }
    }

    private fun verbOf(l: IntentLearner, verb: String): VerbSpace? = l.omega.verbs.firstOrNull { it.verb == verb }

    /** The routing decision {route, p, inGrant, vetoed, reversibility, harm, risk, judges, bond?, reason}. */
    @JvmStatic
    fun routeAction(l: IntentLearner, o: Outcome, opts: RouteOptions): Map<String, Any?> {
        val vs = verbOf(l, o.verb)
        val r = lm()
        if (vs == null || IntentOmega.cellOf(vs, o) == null) {
            r["route"] = "deny"; r["p"] = 0.0; r["inGrant"] = false; r["vetoed"] = false
            r["reversibility"] = if (vs == null) "unknown" else vs.reversibility
            r["harm"] = 0.0; r["risk"] = 1.0; r["judges"] = false
            r["reason"] = "outside the Intent Map's outcome space"
            return r
        }
        val p = l.acceptance(o)
        val inGrant = l.admitsOutcome(o)
        val vetoed = l.isVetoed(o)
        val harm = IntentOmega.harmOf(vs, o, l.harm)
        val hMax = opts.hMax ?: IntentOmega.harmMax(l.omega, l.harm)
        val risk = Math.min(1.0, Math.max(0.0, ((1 - p) * harm) / (if (hMax > 0) hMax else 1.0)))
        val theta2 = opts.theta2 ?: 0.5
        r["p"] = p; r["inGrant"] = inGrant; r["vetoed"] = vetoed; r["reversibility"] = vs.reversibility; r["harm"] = harm; r["risk"] = risk
        if (!inGrant) {
            r["route"] = "deny"; r["judges"] = false
            r["reason"] = if (vetoed) "the cell was vetoed by a runtime divergence" else "outside the conservative grant (p_n < τ)"
            return r
        }
        val judges = vs.reversibility == "irreversible" || p < 1 - 1e-12 || risk >= theta2
        if (vs.reversibility == "irreversible") {
            r["route"] = "jit-consent"; r["judges"] = judges
            r["reason"] = "irreversible: just-in-time consent on the rendered action"
            return r
        }
        if (judges) {
            r["route"] = "optimistic"; r["judges"] = true
            r["bond"] = IntentBond.bondAmount(opts.bondPolicy ?: IntentBond.DEFAULT_BOND_POLICY, harm)
            r["reason"] = if (p < 1 - 1e-12) "unconfirmed region (p_n < 1): bonded claim + judges" else "risk ≥ θ₂: bonded claim + judges"
            return r
        }
        r["route"] = "allow"; r["judges"] = false
        r["reason"] = "confirmed region, reversible, low risk"
        return r
    }

    /** The judge input for an outcome: ctx = {intentRef, mapDigest, statementText, slots, goalCommitment}. */
    @JvmStatic
    fun judgeInputOf(l: IntentLearner, o: Outcome, ctx: Map<String, Any?>): Map<String, Any?> {
        val vs = verbOf(l, o.verb) ?: throw IllegalArgumentException("judgeInputOf: no verb ${o.verb} in Omega")
        return IntentRuntime.judgeInputOf(vs, o, l.acceptance(o), ctx)
    }

    /** The consent prompt for an action. */
    @JvmStatic
    fun jitConsentRequest(l: IntentLearner, o: Outcome, intentRef: String?, mapDigest: String?): Map<String, Any?> {
        val vs = verbOf(l, o.verb) ?: throw IllegalArgumentException("jitConsentRequest: no verb ${o.verb} in Omega")
        return IntentRuntime.jitConsentRequest(vs, o, l.acceptance(o), intentRef, mapDigest)
    }

    /** Record the principal's consent decision (approve = 1, deny = 0 and the cell is vetoed) as a runtime observation. */
    @JvmStatic
    fun recordJitDecision(l: IntentLearner, req: Map<String, Any?>, decision: String?): Map<String, Any?> {
        val vals = LinkedHashMap<String, Any?>()
        for ((k, v) in IntentOmega.obj(req["values"])) vals[k] = if (IntentOmega.isNumber(v)) IntentOmega.dbl(v) else v
        return IntentMapKit.applyDivergence(l, Outcome(req["verb"] as String, vals), if ("approve" == decision) 1 else 0)
    }

    private fun toPpm(x: Double): Any? = if (!x.isNaN() && !x.isInfinite()) IntentJs.normalize(IntentMapKit.jsRound(x * 1000000.0)) else null

    /** Verify a panel's verdicts for one action and produce the IC-Att. [opts]: judgeKeys, k, calibration?, pqPins?. */
    @JvmStatic
    fun intentConformanceAttestation(input: Map<String, Any?>, verdicts: List<Any?>, opts: Map<String, Any?>, attestationGate: ((Map<String, Any?>) -> Boolean)?): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["judgeKeys"] = opts["judgeKeys"]
        o["k"] = opts["k"]
        o["goalCommitment"] = input["goalCommitment"]
        o["actionDigest"] = input["actionDigest"]
        if (opts["calibration"] != null) o["calibration"] = opts["calibration"]
        if (opts["pqPins"] != null) o["pqPins"] = opts["pqPins"]
        val r = IntentSemantic.verifySemanticThreshold(verdicts, o, attestationGate)
        val digests = verdicts.map { IntentRuntime.verdictDigest(it) }.sorted()
        val att = lm()
        att["v"] = 1L
        att["kind"] = "pca-ic-att"
        att["intent_ref"] = input["intentRef"]
        att["map_digest"] = input["mapDigest"]
        att["action_digest"] = input["actionDigest"]
        att["goal_commitment"] = input["goalCommitment"]
        att["verdict_digests"] = ArrayList<Any?>(digests)
        att["calibration_digest"] = if (opts["calibration"] != null) IntentRuntime.calibrationDigest(IntentOmega.obj(opts["calibration"])) else null
        att["k"] = opts["k"]
        att["ok"] = r["ok"]
        att["agree_count"] = r["agreeCount"]
        val agg = toPpm(r["aggregateScore"] as Double)
        att["aggregate_score_ppm"] = agg ?: 0L
        att["cutoff_ppm"] = if (r.containsKey("cutoff")) toPpm(r["cutoff"] as Double) else null
        if (r["reason"] != null) att["reason"] = r["reason"]
        return att
    }

    /** A judge panel: any set of model judges. Returns their signed verdicts. */
    fun interface JudgePanel { fun verdicts(input: Map<String, Any?>): List<Any?> }

    /** Ask the panel and attest: {att, verdicts}. */
    @JvmStatic
    fun checkIntentConformance(panel: JudgePanel, input: Map<String, Any?>, opts: Map<String, Any?>, attestationGate: ((Map<String, Any?>) -> Boolean)?): Map<String, Any?> {
        val verdicts = panel.verdicts(input)
        val r = lm()
        r["att"] = intentConformanceAttestation(input, verdicts, opts, attestationGate)
        r["verdicts"] = verdicts
        return r
    }

    /** Re-verify an IC-Att from the verdicts it names: {ok, problems}. */
    @JvmStatic
    fun verifyICAtt(att: Any?, input: Map<String, Any?>, verdicts: List<Any?>, opts: Map<String, Any?>, attestationGate: ((Map<String, Any?>) -> Boolean)?): Map<String, Any?> {
        val again = intentConformanceAttestation(input, verdicts, opts, attestationGate)
        val problems = ArrayList<Any?>()
        if (IntentRuntime.icAttDigest(again) != IntentRuntime.icAttDigest(att)) problems.add("IC-Att does not match the recomputation from its verdicts")
        if (again["ok"] != true) problems.add("panel does not pass: " + (again["reason"] ?: "unknown"))
        val r = lm()
        r["ok"] = problems.isEmpty()
        r["problems"] = problems
        return r
    }
}
