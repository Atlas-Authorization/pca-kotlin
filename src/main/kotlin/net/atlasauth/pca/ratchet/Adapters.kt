package net.atlasauth.pca.ratchet

import java.math.BigDecimal
import java.math.BigInteger
import net.atlasauth.pca.verifier.Json

/**
 * Thin adapters that bind the two mechanisms to the PCA bookkeeping they replace: the ratchet leaf index is the PCActn spend-once counter, and
 * the accumulator's integer units are the core risk budget (RiskPolicy.bMax / kappa). They map values only.
 */
object Adapters {
    /** Fixed-point scale for quantizing risk scores (r in [0, 1]) into accumulator units: 1000 = millirisk resolution. */
    const val RISK_SCALE = 1000

    private val NANO: BigInteger = BigInteger.valueOf(1_000_000L)

    private fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    private fun isSafeInteger(d: Double?): Boolean = d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0

    /**
     * Map a PCActn's spend-once counter to a ratchet leaf index: spending counter c signs (and punctures) leaf c, so a counter can never be
     * re-used. Throws [RatchetError] (invalid_depth, leaf_out_of_range).
     */
    @JvmStatic
    fun counterToLeafIndex(counter: Any?, depth: Any?): Long {
        val dp = num(depth)
        if (dp == null || dp.isNaN() || dp.isInfinite() || dp != Math.rint(dp) || dp < 1 || dp > Ratchet.MAX_RATCHET_DEPTH) {
            throw RatchetError("invalid_depth", "depth must be an integer in [1, ${Ratchet.MAX_RATCHET_DEPTH}]")
        }
        val c = num(counter)
        if (c == null || !isSafeInteger(c) || c < 0 || Ratchet.isNegZero(c)) throw RatchetError("leaf_out_of_range", "counter must be a non-negative safe integer")
        if (c >= Math.pow(2.0, dp)) throw RatchetError("leaf_out_of_range", "counter ${c.toLong()} exceeds the ratchet capacity 2^${dp.toInt()}")
        return c.toLong()
    }

    /** Inverse of [counterToLeafIndex]: a leaf index is the spend-once counter it realizes. */
    @JvmStatic
    fun leafIndexToCounter(leafIndex: Any?): Long {
        val d = num(leafIndex)
        if (d == null || !isSafeInteger(d) || d < 0 || Ratchet.isNegZero(d)) throw RatchetError("leaf_out_of_range", "leafIndex must be a non-negative safe integer")
        return d.toLong()
    }

    /** The ratchet leaf index for a PCActn, read straight off its `counter` field. */
    @JvmStatic
    fun leafIndexForAction(actn: Map<String, Any?>, depth: Any?): Long = counterToLeafIndex(actn["counter"], depth)

    /** Math.round of JavaScript: floor(x + 0.5) without the precision loss, NaN and the infinities unchanged. */
    private fun jsRound(x: Double): Double {
        if (x.isNaN() || x.isInfinite()) return x
        val f = Math.floor(x)
        return if (x - f >= 0.5) f + 1 else f
    }

    private fun bigInt(d: Double): BigInteger {
        if (d.isNaN() || d.isInfinite()) throw IllegalArgumentException("cannot convert a non-finite number to a BigInt")
        return BigDecimal(d).toBigInteger()
    }

    /**
     * Quantize a core risk score (any finite r >= 0) to non-negative integer accumulator units, ROUNDING UP (a nonzero risk is never 0 units; a
     * sum of quantized risks never under-counts the true sum). A value within float noise of an exact unit keeps that unit.
     */
    @JvmStatic
    fun riskToUnits(r: Any?): BigInteger {
        val d = num(r)
        if (d == null || d.isNaN() || d.isInfinite() || d < 0) throw AccumulatorError("invalid_value", "risk must be a finite number >= 0")
        val v = d * RISK_SCALE
        val nearest = jsRound(v)
        if (Math.abs(v - nearest) <= 1e-9 * Math.max(1.0, v)) return bigInt(nearest)
        return bigInt(Math.ceil(v))
    }

    /**
     * Carry-forward quantizer: emits per-action integer units such that the running total of emitted units is ALWAYS
     * `ceil(sum of true risk * SCALE)` (never below the true cumulative sum). Stateful; one instance per budget stream.
     */
    class RiskQuantizer {
        private var nano: BigInteger = BigInteger.ZERO
        private var emitted: BigInteger = BigInteger.ZERO

        fun next(r: Any?): BigInteger {
            val d = num(r)
            if (d == null || d.isNaN() || d.isInfinite() || d < 0) throw AccumulatorError("invalid_value", "risk must be a finite number >= 0")
            // r * SCALE in millionths of a unit, rounded UP so the total can only over-approximate
            val add = bigInt(Math.ceil(d * RISK_SCALE * 1e6 - 1e-3))
            nano = nano.add(add)
            val total = nano.add(NANO).subtract(BigInteger.ONE).divide(NANO)
            val out = total.subtract(emitted)
            emitted = total
            return out
        }

        fun totalUnits(): BigInteger = emitted
    }

    /** JavaScript ToNumber of a policy member: an absent member is NaN, null is 0, a number is itself, anything else is NaN. */
    private fun member(m: Map<String, Any?>, k: String): Double {
        if (!m.containsKey(k)) return Double.NaN
        val o = m[k] ?: return 0.0
        return num(o) ?: Double.NaN
    }

    /**
     * The accumulator's budget ceiling in integer units from a RiskPolicy: the core cumulative-risk safety bound `sum(risk) <= bMax / kappa`,
     * quantized, so the zero-knowledge verifyBudget proves the SAME inequality the control plane enforces.
     */
    @JvmStatic
    fun budgetCeilingUnits(policy: Map<String, Any?>): BigInteger {
        val kappa = member(policy, "kappa")
        val bMax = member(policy, "bMax")
        val bound = if (kappa > 0) Math.max(0.0, bMax) / kappa else 0.0
        if (bound.isNaN() || bound.isInfinite() || bound < 0) throw AccumulatorError("invalid_value", "safety bound (bMax/kappa) must be finite and >= 0")
        return bigInt(Math.floor(bound * RISK_SCALE))
    }
}
