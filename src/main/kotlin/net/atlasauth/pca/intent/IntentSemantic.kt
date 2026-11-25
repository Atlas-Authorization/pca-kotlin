package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * The k-of-n semantic judge threshold: signed judge verdicts bound to one action and goal, one key one vote, an optional split-conformal
 * cutoff on the aggregate score. Verdicts are JSON {judge, actionDigest, goalCommitment, faithful, score, judgeMeasurement, sig, alg?, pq_pk?, pq_sig?}.
 * The attested-judge gate (a hardware-attested enclave appraisal) is injected as a predicate over a verdict: when given, a verdict it rejects does not vote.
 */
@Suppress("UNCHECKED_CAST")
object IntentSemantic {
    const val SEMANTIC_JUDGE_DOMAIN = "atlas-pca/semantic-judge/v1\u0000"
    const val SCORE_SCALE = 1000000.0

    private fun fin(x: Double): Boolean = !x.isNaN() && !x.isInfinite()

    /** A score on the integer grid [0, 1e6]; non-finite is 0. */
    @JvmStatic
    fun quantizeScore(score: Double): Long {
        if (!fin(score)) return 0L
        val q = IntentMapKit.jsRound(score * SCORE_SCALE) + 0
        return (if (q < 0) 0.0 else if (q > SCORE_SCALE) SCORE_SCALE else q).toLong()
    }

    /** `String(x ?? "")`. */
    private fun measurementText(jm: Any?): String = if (jm == null) "" else if (jm is String) jm else if (IntentOmega.isNumber(jm)) AttestUtil.jsNumString(IntentOmega.dbl(jm)) else jm.toString()

    /** The exact bytes a judge signs: `SEMANTIC_JUDGE_DOMAIN || strictCanonical(statement)`. Throws on a member with no canonical form. */
    @JvmStatic
    fun semanticJudgeMessage(statement: Any?): ByteArray = IntentKit.message(SEMANTIC_JUDGE_DOMAIN, statement)

    /** Digest of a verdict for ledger anchoring and challenge: strict canonical over the full verdict. */
    @JvmStatic
    fun verdictDigest(verdict: Any?): String = Pca.hashCanonical(net.atlasauth.pca.verifier.IntentJs.normalize(verdict))

    /**
     * Produce a signed verdict over `{actionDigest, goalCommitment, faithful, score, judgeMeasurement?}` as `signer` (Ed25519, ML-DSA-65 or hybrid): `judge` is the signer's
     * Ed25519 key, `faithful` is carried as `=== true`, and the score is signed as its quantized parts per million. A non-default suite adds `alg` and `pq_pk` (signed) and,
     * for a hybrid, `pq_sig`.
     */
    @JvmStatic
    fun signJudgeVerdict(signer: net.atlasauth.pca.verifier.Keys.SuiteKey, v: Map<String, Any?>): Map<String, Any?> {
        val jm = measurementText(v["judgeMeasurement"])
        val id = (signer.ed ?: throw IllegalArgumentException("signJudgeVerdict: the judge needs an Ed25519 identity")).id()
        val input = LinkedHashMap(v)
        input["judgeMeasurement"] = jm
        input.remove("alg")
        input.remove("pq_pk")
        if (signer.alg != "ed25519") {
            input["alg"] = signer.alg
            input["pq_pk"] = signer.pqPk()
        }
        val sg = signer.sign(semanticJudgeMessage(statementOf(input)))
        val out = LinkedHashMap<String, Any?>()
        out["judge"] = id
        out["actionDigest"] = v["actionDigest"]
        out["goalCommitment"] = v["goalCommitment"]
        out["faithful"] = v["faithful"] == true
        out["score"] = v["score"]
        out["judgeMeasurement"] = jm
        out["sig"] = sg.first
        if (signer.alg != "ed25519") {
            out["alg"] = signer.alg
            out["pq_pk"] = signer.pqPk()
        }
        if (sg.second != null) out["pq_sig"] = sg.second
        return out
    }

    /**
     * Bind a judge's SIGNED `judgeMeasurement` to a verified measured TEE, the way an agent is bound: the attestation must be verified and bound (`ok` and `bound`
     * strictly true) and carry a measured identity; its `runtime_measurement` must equal the signed label; and the measured identity is appraised against `approved`
     * (the same `agent_binding` an agent is appraised with). Total. `{ok, reason?, measured?}`.
     */
    @JvmStatic
    fun verifyJudgeAttestation(judgeMeasurement: Any?, attestation: Any?, approved: Any?): Map<String, Any?> {
        fun no(reason: Any?): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)
        val att = attestation as? Map<String, Any?>
        if (att == null || att["ok"] != true) {
            val why = (attestation as? Map<*, *>)?.get("reason")
            return no(why ?: "no verified attestation for this judge (fail-closed)")
        }
        if (att["bound"] != true) return no("judge attestation not bound to a TEE report (report_data binding unconfirmed)")
        val measured = att["measured"]
        if (measured !is Map<*, *> && measured !is List<*>) return no("judge attestation carries no measured identity")
        if (judgeMeasurement !is String || judgeMeasurement.isEmpty()) return no("verdict carries no judgeMeasurement to bind to the attested identity")
        if (!net.atlasauth.pca.verifier.ZkJs.strictEq(net.atlasauth.pca.verifier.ZkJs.get(measured, "runtime_measurement"), judgeMeasurement)) {
            return no("attested enclave measurement does not match the signed judgeMeasurement")
        }
        val appraisal = net.atlasauth.pca.verifier.Attestation.matchAgentBinding(measured, approved)
        if (appraisal != null) return no(appraisal)
        return linkedMapOf("ok" to true, "measured" to measured)
    }

    /**
     * The attested-judge gate: with `require` true each candidate verdict must also pass [verifyJudgeAttestation] (the attestation [resolve]d for it, appraised against
     * [approved]) or its vote does not count. With `require` false nothing changes (unattested verdicts count).
     */
    class SemanticAttestation(val resolve: (Map<String, Any?>) -> Any?, val approved: Any? = null, val require: Boolean = false)

    /** The vote predicate of an attested-judge gate: null when the gate is absent or not required. */
    @JvmStatic
    fun attestationGate(att: SemanticAttestation?): ((Map<String, Any?>) -> Boolean)? =
        if (att != null && att.require) { v -> verifyJudgeAttestation(v["judgeMeasurement"], att.resolve(v), att.approved)["ok"] == true } else null

    /** [verifySemanticThreshold] with the attested-judge gate given as its options object. */
    @JvmStatic
    fun verifySemanticThreshold(verdicts: Any?, opts: Map<String, Any?>, attestation: SemanticAttestation?): MutableMap<String, Any?> =
        verifySemanticThreshold(verdicts, opts, attestationGate(attestation))

    /**
     * A semantic verifier hook `(ctx) -> {enforced, ok?, reason?}`. [verdicts] finds the ensemble for an action and [goalCommitment] the principal's goal commitment (null
     * from either is "not available": fail closed, or not enforced with [optionalWhenAbsent]). [actionDigest] overrides the digest the verdicts must bind to (default:
     * the digest of `ctx.pcactn.action`); [attestation] resolves the attested-judge gate per action.
     */
    @JvmStatic @JvmOverloads
    fun createSemanticVerifier(
        judgeKeys: Any?, k: Any?, verdicts: (Any?) -> Any?, goalCommitment: (Any?) -> Any?, calibration: Any? = null, actionDigest: ((Any?) -> String)? = null,
        optionalWhenAbsent: Boolean = false, attestation: ((Any?) -> SemanticAttestation?)? = null,
    ): (Any?) -> Map<String, Any?> {
        val digestOf: (Any?) -> String = actionDigest ?: { ctx ->
            val pc = net.atlasauth.pca.verifier.IntentJs.get(ctx, "pcactn")
            if (pc !is Map<*, *> || !pc.containsKey("action")) throw IllegalArgumentException("Cannot read properties of undefined (reading 'action')")
            Pca.hashCanonical(net.atlasauth.pca.verifier.IntentJs.normalize(pc["action"]))
        }
        return { ctx ->
            val gc = goalCommitment(ctx)
            val vs = verdicts(ctx)
            if (gc !is String || vs == null) {
                if (optionalWhenAbsent) linkedMapOf<String, Any?>("enforced" to false)
                else linkedMapOf("enforced" to true, "ok" to false, "reason" to "no semantic ensemble available for this action (fail-closed)")
            } else {
                val att = attestation?.invoke(ctx)
                val o = LinkedHashMap<String, Any?>()
                o["judgeKeys"] = judgeKeys
                o["k"] = k
                o["goalCommitment"] = gc
                o["actionDigest"] = digestOf(ctx)
                if (calibration != null) o["calibration"] = calibration
                val res = verifySemanticThreshold(vs, o, att)
                if (res["ok"] == true) linkedMapOf<String, Any?>("enforced" to true, "ok" to true)
                else linkedMapOf("enforced" to true, "ok" to false, "reason" to (res["reason"] ?: "semantic threshold not met"))
            }
        }
    }

    /** Soft risk contribution: `1 - aggregateScore` clamped to [0, 1]; a non-number or non-finite score is the maximum risk, 1. Weaker agreement can only raise risk. */
    @JvmStatic
    fun semanticRiskContribution(aggregateScore: Any?): Double {
        val x = if (IntentOmega.isNumber(aggregateScore)) IntentOmega.dbl(aggregateScore) else null
        if (x == null || !fin(x)) return 1.0
        val r = 1 - x
        return if (r < 0) 0.0 else if (r > 1) 1.0 else r
    }

    /** The signed statement of a verdict (suite fields bound in for a non-ed25519 suite). */
    @JvmStatic
    fun statementOf(v: Map<String, Any?>): Map<String, Any?> {
        val base = LinkedHashMap<String, Any?>()
        base["v"] = 1L
        base["actionDigest"] = v["actionDigest"]
        base["goalCommitment"] = v["goalCommitment"]
        base["faithful"] = v["faithful"] == true
        val sc = IntentKit.num(v["score"])
        base["score_ppm"] = quantizeScore(sc ?: Double.NaN)
        base["judgeMeasurement"] = measurementText(v["judgeMeasurement"])
        return IntentKit.bindSuiteFields(base, v["alg"], v.containsKey("alg"), v["pq_pk"], v.containsKey("pq_pk"))
    }

    /** Verify ONE verdict against an expected action / goal binding. Total: never throws. */
    @JvmStatic
    fun verifyJudgeVerdict(vo: Any?, expectedAction: String?, expectedGoal: String?, pqPins: Map<String, Any?>?): Boolean {
        try {
            if (vo !is Map<*, *>) return false
            val v = vo as Map<String, Any?>
            val judge = v["judge"]
            if (judge !is String || Pca.decodeB64uStrict(judge, 32) == null) return false
            if (v["actionDigest"] !is String || v["goalCommitment"] !is String) return false
            if (v["actionDigest"] != expectedAction || v["goalCommitment"] != expectedGoal) return false
            if (v["faithful"] !is Boolean) return false
            val score = IntentKit.num(v["score"])
            if (score == null || !fin(score) || score < 0 || score > 1) return false
            if (v["judgeMeasurement"] !is String) return false
            if (v["sig"] !is String) return false
            val algPresent = v.containsKey("alg")
            if (IntentKit.suiteName(v["alg"], algPresent) == null) return false
            val msg = IntentKit.message(SEMANTIC_JUDGE_DOMAIN, statementOf(v))
            return IntentKit.verifyPinnedSuite(v["alg"], algPresent, judge, v["pq_pk"], msg, v["sig"], v["pq_sig"], pqPins)
        } catch (e: RuntimeException) {
            return false
        }
    }

    private fun clampAlpha(alpha: Any?): Double {
        val a = if (alpha != null && IntentOmega.isNumber(alpha)) IntentOmega.dbl(alpha) else null
        if (a == null || !fin(a)) return 1.0
        if (a <= 0) return java.lang.Double.MIN_VALUE
        return if (a > 1) 1.0 else a
    }

    private fun unfaithful(samples: Any?): MutableList<Double> {
        val out = ArrayList<Double>()
        if (samples !is List<*>) return out
        for (so in samples) {
            if (so is Map<*, *>) {
                val sc = so["score"]
                if (so["faithful"] == false && sc != null && IntentOmega.isNumber(sc) && fin(IntentOmega.dbl(sc))) out.add(IntentOmega.dbl(sc))
            }
        }
        return out
    }

    /** The split-conformal upper quantile of the unfaithful scores (+Infinity when too few to certify alpha). */
    @JvmStatic
    fun conformalThreshold(calibration: Any?): Double {
        val c = if (calibration is Map<*, *>) calibration else null
        val alpha = clampAlpha(c?.get("alpha"))
        val u = unfaithful(c?.get("samples"))
        val m = u.size
        if (m == 0) return Double.POSITIVE_INFINITY
        val rank = Math.ceil((m + 1) * (1 - alpha))
        if (rank > m) return Double.POSITIVE_INFINITY
        u.sort()
        return u[Math.max(rank, 1.0).toInt() - 1]
    }

    /** Fraction of the unfaithful samples whose score exceeds the cutoff (0 with none). */
    @JvmStatic
    fun empiricalFalseAllowRate(samples: Any?, cutoff: Double): Double {
        var m = 0
        var allowed = 0
        if (samples is List<*>) {
            for (so in samples) {
                if (so is Map<*, *>) {
                    val sc = so["score"]
                    if (so["faithful"] == false && sc != null && IntentOmega.isNumber(sc) && fin(IntentOmega.dbl(sc))) {
                        m++
                        if (IntentOmega.dbl(sc) > cutoff) allowed++
                    }
                }
            }
        }
        return if (m == 0) 0.0 else allowed.toDouble() / m
    }

    private fun jsStr(k: Any?): String {
        if (k == null) return "null"
        if (IntentOmega.isNumber(k)) return AttestUtil.jsNumString(IntentOmega.dbl(k))
        return k.toString()
    }

    private fun result(ok: Boolean, agree: Int, score: Double, cutoff: Double?, reason: String?): MutableMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["ok"] = ok
        r["agreeCount"] = agree.toLong()
        r["aggregateScore"] = score
        if (cutoff != null) r["cutoff"] = cutoff
        if (reason != null) r["reason"] = reason
        return r
    }

    /**
     * Verify a k-of-n ensemble. [opts]: judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?. Returns {ok, agreeCount, aggregateScore,
     * cutoff?, reason?}. [attestationGate] (optional) must accept a verdict for it to vote.
     */
    @JvmStatic
    fun verifySemanticThreshold(verdicts: Any?, opts: Map<String, Any?>, attestationGate: ((Map<String, Any?>) -> Boolean)?): MutableMap<String, Any?> {
        val k = opts["k"]
        val allow = LinkedHashSet<String>()
        val jk = opts["judgeKeys"]
        if (jk is List<*>) {
            for (key in jk) if (key is String && Pca.decodeB64uStrict(key, 32) != null) allow.add(key)
        }
        if (opts["actionDigest"] !is String || opts["goalCommitment"] !is String) return result(false, 0, 0.0, null, "missing action/goal binding")
        val kd = if (k != null && IntentOmega.isNumber(k)) IntentOmega.dbl(k) else null
        if (kd == null || !fin(kd) || kd != Math.floor(kd) || kd < 1) return result(false, 0, 0.0, null, "invalid quorum k=" + (if (opts.containsKey("k")) jsStr(k) else "undefined"))
        val ad = opts["actionDigest"] as String
        val gc = opts["goalCommitment"] as String
        val pins = opts["pqPins"] as? Map<String, Any?>
        val byJudge = LinkedHashMap<String, Pair<LinkedHashSet<Boolean>, LinkedHashSet<Long>>>()
        if (verdicts is List<*>) {
            for (vo in verdicts) {
                if (vo !is Map<*, *> || vo["judge"] !is String || !allow.contains(vo["judge"] as String)) continue
                val v = vo as Map<String, Any?>
                if (!verifyJudgeVerdict(v, ad, gc, pins)) continue
                if (attestationGate != null && !attestationGate(v)) continue
                val g = byJudge.getOrPut(v["judge"] as String) { Pair(LinkedHashSet(), LinkedHashSet()) }
                g.first.add(v["faithful"] == true)
                g.second.add(quantizeScore(IntentOmega.dbl(v["score"])))
            }
        }
        val agreeing = ArrayList<Pair<String, Long>>()
        for ((judge, g) in byJudge) {
            if (g.first.size == 1 && g.first.contains(true) && g.second.size == 1) agreeing.add(Pair(judge, g.second.iterator().next()))
        }
        agreeing.sortWith { a, b -> Json.compareUtf8(a.first, b.first) }
        val agree = agreeing.size
        var acc = 0.0
        for (a in agreeing) acc += a.second.toDouble() / SCORE_SCALE
        val aggregate = if (agree == 0) 0.0 else acc / agree
        if (agree < kd) return result(false, agree, aggregate, null, "only $agree distinct trusted judge(s) agree, need " + jsStr(k))
        if (opts["calibration"] != null) {
            val cutoff = conformalThreshold(opts["calibration"])
            if (!(aggregate > cutoff)) return result(false, agree, aggregate, cutoff, "aggregateScore " + AttestUtil.jsNumString(aggregate) + " does not exceed calibrated cutoff " + AttestUtil.jsNumString(cutoff))
            return result(true, agree, aggregate, cutoff, null)
        }
        return result(true, agree, aggregate, null, null)
    }
}
