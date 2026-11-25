package net.atlasauth.pca.fhe

import java.math.BigDecimal
import net.atlasauth.pca.verifier.Json

/**
 * The pure, scheme-independent parts of the homomorphic risk gate: risk-input transformation and fixed-point quantization, the public gate
 * policy, the risk claim binding read from a signed action, and the plaintext reference verdict. Values are parsed JSON (maps, lists,
 * [Json.Num]); a JavaScript number that is not finite is the fail-closed worst case, as in the reference. The BFV evaluation itself is the
 * separate pca-fhe-seal module (Microsoft SEAL); the signed-claim layer is [FheOrigin].
 */
object FheRisk {
    const val POLY_MODULUS_DEGREE = 8192
    const val PLAIN_MODULUS_BITS = 30
    const val PLAIN_MODULUS = 1_073_692_673L
    const val SIGNED_BOUND = PLAIN_MODULUS / 2
    const val DEFAULT_SCALE = 1000L
    const val RISK_DIM = 6

    private val INPUT_FIELDS = listOf("semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age")

    /** The JavaScript number value of a parsed JSON number; NaN for anything that is not a number. */
    internal fun num(o: Any?): Double = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull() ?: Double.NaN
        is Number -> o.toDouble()
        else -> Double.NaN
    }

    private fun finite(x: Double) = !x.isNaN() && !x.isInfinite()
    private fun clamp01(x: Double) = if (x < 0) 0.0 else if (x > 1) 1.0 else x
    private fun unit(x: Double, worst: Double) = if (finite(x)) clamp01(x) else worst
    private fun wt(x: Double) = if (finite(x) && x > 0) x else 0.0

    @Suppress("UNCHECKED_CAST")
    private fun obj(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")

    private fun field(m: Map<String, Any?>?, k: String): Double {
        if (m == null) throw IllegalArgumentException("cannot read a member of null")
        return num(m[k])
    }

    /** [d, 1 - rev, bl, taint, 1 - conf, age], each through `unit` with the worst case of the risk score. */
    fun transformedInputs(i: Map<String, Any?>): DoubleArray = doubleArrayOf(
        unit(field(i, "semanticDistance"), 1.0),
        1 - unit(field(i, "reversibility"), 0.0),
        unit(field(i, "blastRadius"), 1.0),
        unit(field(i, "taint"), 1.0),
        1 - unit(field(i, "confidence"), 0.0),
        unit(field(i, "age"), 1.0),
    )

    /** The weight vector of the risk score in canonical order with its clamp applied. */
    fun weightVector(w: Map<String, Any?>): DoubleArray = doubleArrayOf(
        wt(field(w, "alpha")), wt(field(w, "beta")), wt(field(w, "gamma")), wt(field(w, "delta")), wt(field(w, "epsilon")), wt(field(w, "zeta")),
    )

    /** JavaScript Math.round (ties toward +infinity), exact. */
    internal fun jsRound(x: Double): Double {
        if (!finite(x)) return x
        val f = Math.floor(x)
        return if (x - f >= 0.5) f + 1 else f
    }

    private fun requireScale(scale: Double) {
        if (!finite(scale) || scale != Math.rint(scale) || scale <= 0) throw IllegalArgumentException("scale must be a positive integer")
    }

    /** round(x_i * scale) for each transformed input: the integer vector the agent encrypts. */
    fun quantizeRiskInputs(i: Map<String, Any?>, scale: Any? = DEFAULT_SCALE): DoubleArray {
        val s = num(scale)
        requireScale(s)
        return transformedInputs(i).map { jsRound(it * s) }.toDoubleArray()
    }

    /** A JSON number value for a JavaScript number: a safe integer as a Long, else a plain decimal. */
    internal fun numVal(d: Double): Any =
        if (d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0) d.toLong()
        else Json.Num(BigDecimal(d.toString()).stripTrailingZeros().toPlainString())

    /**
     * The public gate policy from a risk policy {weights, kappa} and the trust budget B, at fixed-point scale S: weights round(w_i S),
     * kappa-weighted weights round(kappa w_i S), budget round(B S^2). Refuses a policy whose scaled values could overflow the signed
     * plain-modulus range (a wrap would silently corrupt the verdict).
     */
    fun fheRiskPolicy(core: Map<String, Any?>, budget: Any?, scaleArg: Any? = DEFAULT_SCALE): Map<String, Any?> {
        val scale = num(scaleArg)
        requireScale(scale)
        val b = num(budget)
        if (!(finite(b) && b >= 0)) throw IllegalArgumentException("budget must be finite and >= 0")
        val kappa = field(core, "kappa")
        if (!(finite(kappa) && kappa > 0)) throw IllegalArgumentException("policy.kappa must be finite and > 0")
        val w = weightVector(obj(core["weights"]))
        val ws = DoubleArray(w.size) { jsRound(w[it] * scale) }
        val kws = DoubleArray(w.size) { jsRound(kappa * w[it] * scale) }
        val budgetScaled = jsRound(b * scale * scale)
        val maxAbs = maxOf(ws.sum() * scale, kws.sum() * scale, budgetScaled)
        if (maxAbs >= SIGNED_BOUND) {
            throw IllegalArgumentException("policy/scale overflow the plain modulus: max |value| $maxAbs must be < SIGNED_BOUND $SIGNED_BOUND. Lower the scale or the weights/budget.")
        }
        return linkedMapOf(
            "scale" to numVal(scale),
            "dim" to RISK_DIM,
            "weightsScaled" to ws.map { numVal(it) },
            "kappaWeightsScaled" to kws.map { numVal(it) },
            "budgetScaled" to numVal(budgetScaled),
            "kappa" to numVal(kappa),
        )
    }

    /** The six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field is NaN (fail-closed). */
    fun riskInputsFromPCActn(p: Map<String, Any?>): Map<String, Any?> {
        val src = obj(obj(p["risk_claim"])["inputs"])
        val out = LinkedHashMap<String, Any?>()
        for (k in INPUT_FIELDS) {
            val v = src[k]
            out[k] = if (v is Json.Num || v is Number) v else Double.NaN
        }
        return out
    }

    /** The replay binding of a signed action: audience, action digest, counter and the optional nonce. */
    fun bindingFromPCActn(p: Map<String, Any?>): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("aud" to p["aud"], "actionRef" to obj(p["action"])["params_digest"], "counter" to p["counter"])
        if (p.containsKey("nonce")) m["nonce"] = p["nonce"]
        return m
    }

    /** The plaintext reference verdict: r = risk score, admit iff kappa-cost(r) <= budget. Returns {r, admit}. */
    fun plaintextVerdict(inputs: Map<String, Any?>, core: Map<String, Any?>, budget: Any?): Map<String, Any?> {
        val w = obj(core["weights"])
        val r = clamp01(
            wt(field(w, "alpha")) * unit(field(inputs, "semanticDistance"), 1.0) +
                wt(field(w, "beta")) * (1 - unit(field(inputs, "reversibility"), 0.0)) +
                wt(field(w, "gamma")) * unit(field(inputs, "blastRadius"), 1.0) +
                wt(field(w, "delta")) * unit(field(inputs, "taint"), 1.0) +
                wt(field(w, "epsilon")) * (1 - unit(field(inputs, "confidence"), 0.0)) +
                wt(field(w, "zeta")) * unit(field(inputs, "age"), 1.0),
        )
        val kappa = field(core, "kappa")
        val cost = (if (finite(kappa) && kappa > 0) kappa else 0.0) * clamp01(if (finite(r)) r else 1.0)
        return linkedMapOf("r" to numVal(r), "admit" to (num(budget).isFinite() && cost <= num(budget)))
    }
}
