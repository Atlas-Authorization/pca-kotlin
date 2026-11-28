package net.atlasauth.pca.ratchet

import java.math.BigDecimal
import java.math.BigInteger
import net.atlasauth.pca.ratchet.Group.G
import net.atlasauth.pca.ratchet.Group.H
import net.atlasauth.pca.ratchet.Group.add
import net.atlasauth.pca.ratchet.Group.decodePoint
import net.atlasauth.pca.ratchet.Group.decodeScalar
import net.atlasauth.pca.ratchet.Group.encodePoint
import net.atlasauth.pca.ratchet.Group.encodeScalar
import net.atlasauth.pca.ratchet.Group.hashToScalar
import net.atlasauth.pca.ratchet.Group.mod
import net.atlasauth.pca.ratchet.Group.mul
import net.atlasauth.pca.ratchet.Group.numberToBytesLE
import net.atlasauth.pca.ratchet.Group.randScalar
import net.atlasauth.pca.ratchet.Group.scalarAdd
import net.atlasauth.pca.ratchet.Group.scalarMul
import net.atlasauth.pca.ratchet.Group.scalarSub
import net.atlasauth.pca.ratchet.Group.sub
import net.atlasauth.pca.ratchet.Group.utf8
import net.atlasauth.pca.ratchet.Ristretto.Point
import net.atlasauth.pca.verifier.Json

/**
 * Homomorphic risk accumulator with a zero-knowledge spend ceiling. Risk is a Pedersen commitment on ristretto255, `C = risk*G + blinding*H`;
 * commitments add, and a bit-decomposition range proof (a Fiat-Shamir OR proof per bit plus a Schnorr proof that the bits aggregate to the
 * slack commitment) shows the aggregate satisfies `sum(risk) <= bMax` without revealing the individual risks. Proofs are JSON-shaped maps
 * (`n`, `bitCommitments`, `or`, `agg`); risk units are non-negative integers (a number, a [Json.Num] or a [BigInteger]); blindings are
 * [BigInteger].
 */
object Accumulator {
    /** Range-proof bit length: the slack (bMax - sum(risk)) must lie in [0, 2^32). */
    const val N_BITS = 32

    /** Largest ceiling the range proof can express: 2^N_BITS - 1. */
    @JvmField val MAX_PROVABLE_CEILING: BigInteger = BigInteger.ONE.shiftLeft(N_BITS).subtract(BigInteger.ONE)

    private val CTX_DOMAIN = utf8("atlas-pca-ratchet/budget/ctx/v1")
    private val RISK_CTX_DOMAIN = utf8("atlas-pca-ratchet/risk-range/ctx/v1")
    private val OR_DOMAIN = utf8("atlas-pca-ratchet/budget/bit-or/v1")
    private val AGG_DOMAIN = utf8("atlas-pca-ratchet/budget/agg/v1")

    /** A risk commitment (b64u ristretto255 point) and its blinding scalar. */
    class RiskCommitment(val commitment: String, val blinding: BigInteger)

    /** Non-negative integer units from a number / [Json.Num] (integer valued) or a [BigInteger]; anything else is refused. */
    internal fun asUnits(x: Any?): BigInteger {
        if (x is BigInteger) {
            if (x.signum() < 0) throw AccumulatorError("invalid_value", "risk/budget must be >= 0")
            return x
        }
        val d: Double? = when (x) {
            is Json.Num -> x.raw.toDoubleOrNull()
            is Number -> x.toDouble()
            else -> null
        }
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d) || d < 0) {
            throw AccumulatorError("invalid_value", "risk/budget must be a non-negative integer")
        }
        return BigDecimal(d).toBigInteger()
    }

    /** Commit to a non-negative integer risk with the given blinding (a fresh random one when [blinding] is null). */
    @JvmStatic
    fun commitRisk(risk: Any?, blinding: BigInteger?): RiskCommitment {
        val v = asUnits(risk)
        val b = if (blinding == null) randScalar() else mod(blinding)
        return RiskCommitment(encodePoint(add(mul(G, v), mul(H, b))), b)
    }

    /** Homomorphic sum: a commitment to (sum risk, sum blinding). Empty input is the identity. */
    @JvmStatic
    fun addCommitments(commitments: List<*>): String {
        var acc = mul(G, BigInteger.ZERO)
        for (c in commitments) acc = add(acc, decodePoint(c))
        return encodePoint(acc)
    }

    /** True when [commitment] opens to ([risk], [blinding]). Never throws; malformed input is false. */
    @JvmStatic
    fun openCommitment(commitment: Any?, risk: Any?, blinding: BigInteger?): Boolean = try {
        val v = asUnits(risk)
        val expected = add(mul(G, v), mul(H, mod(blinding!!)))
        decodePoint(commitment).equalsPoint(expected)
    } catch (e: RuntimeException) {
        false
    }

    // ---- range proof ----

    /** A ceiling above 2^N_BITS - 1 is clamped to it: a strictly stronger statement, so a verifier is never weakened. */
    private fun effectiveCeiling(bMaxUnits: BigInteger): BigInteger = if (bMaxUnits > MAX_PROVABLE_CEILING) MAX_PROVABLE_CEILING else bMaxUnits

    private fun ctxBytes(parts: List<ByteArray>): ByteArray = numberToBytesLE(hashToScalar(*parts.toTypedArray()), 32)

    private fun contextHash(n: Int, bMaxUnits: BigInteger, commitmentSum: Point, bits: List<Point>): ByteArray {
        val parts = ArrayList<ByteArray>()
        parts.add(CTX_DOMAIN)
        parts.add(byteArrayOf((n and 0xff).toByte()))
        parts.add(numberToBytesLE(mod(bMaxUnits), 32))
        parts.add(commitmentSum.toRawBytes())
        for (b in bits) parts.add(b.toRawBytes())
        return ctxBytes(parts)
    }

    private fun riskContextHash(n: Int, commitment: Point, bits: List<Point>): ByteArray {
        val parts = ArrayList<ByteArray>()
        parts.add(RISK_CTX_DOMAIN)
        parts.add(byteArrayOf((n and 0xff).toByte()))
        parts.add(commitment.toRawBytes())
        for (b in bits) parts.add(b.toRawBytes())
        return ctxBytes(parts)
    }

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) m[k] = v
        return m
    }

    /** Prove bit commitment B (= b*G + s*H) opens to 0 or 1, knowing the bit and its blinding. */
    private fun proveBit(ctx: ByteArray, index: Int, b: Point, bit: BigInteger, s: BigInteger): Map<String, Any?> {
        val p0 = b
        val p1 = sub(b, G)
        val real = if (bit == BigInteger.ONE) 1 else 0
        val eFake = randScalar()
        val zFake = randScalar()
        val pFake = if (real == 1) p0 else p1
        val aFake = sub(mul(H, zFake), mul(pFake, eFake))
        val k = randScalar()
        val aReal = mul(H, k)
        val a0 = if (real == 0) aReal else aFake
        val a1 = if (real == 1) aReal else aFake
        val e = hashToScalar(OR_DOMAIN, ctx, byteArrayOf((index and 0xff).toByte()), a0.toRawBytes(), a1.toRawBytes())
        val eReal = scalarSub(e, eFake)
        val zReal = scalarAdd(k, scalarMul(eReal, s))
        val e0 = if (real == 0) eReal else eFake
        val e1 = if (real == 1) eReal else eFake
        val z0 = if (real == 0) zReal else zFake
        val z1 = if (real == 1) zReal else zFake
        return obj("e0" to encodeScalar(e0), "e1" to encodeScalar(e1), "z0" to encodeScalar(z0), "z1" to encodeScalar(z1))
    }

    private fun verifyBit(ctx: ByteArray, index: Int, b: Point, proof: Any?): Boolean {
        val e0 = decodeScalar(member(proof, "e0"))
        val e1 = decodeScalar(member(proof, "e1"))
        val z0 = decodeScalar(member(proof, "z0"))
        val z1 = decodeScalar(member(proof, "z1"))
        val p0 = b
        val p1 = sub(b, G)
        val a0 = sub(mul(H, z0), mul(p0, e0))
        val a1 = sub(mul(H, z1), mul(p1, e1))
        val e = hashToScalar(OR_DOMAIN, ctx, byteArrayOf((index and 0xff).toByte()), a0.toRawBytes(), a1.toRawBytes())
        return scalarAdd(e0, e1) == e
    }

    /** `o[k]` of a proof node: a missing node is a TypeError in the reference, so it throws here. */
    private fun member(o: Any?, k: String): Any? {
        if (o == null) throw NullPointerException("proof member of null")
        return if (o is Map<*, *>) o[k] else null
    }

    private fun proveSchnorr(ctx: ByteArray, d: Point, w: BigInteger): Map<String, Any?> {
        val k = randScalar()
        val a = mul(H, k)
        val e = hashToScalar(AGG_DOMAIN, ctx, d.toRawBytes(), a.toRawBytes())
        val z = scalarAdd(k, scalarMul(e, w))
        return obj("a" to encodePoint(a), "z" to encodeScalar(z))
    }

    private fun verifySchnorr(ctx: ByteArray, d: Point, proof: Any?): Boolean {
        val a = decodePoint(member(proof, "a"))
        val z = decodeScalar(member(proof, "z"))
        val e = hashToScalar(AGG_DOMAIN, ctx, d.toRawBytes(), a.toRawBytes())
        return mul(H, z).equalsPoint(add(a, mul(d, e)))
    }

    /** The shared range-proof core: V = value*G + gamma*H is known to both sides; the value is taken modulo 2^N_BITS. */
    private fun rangeProve(makeCtx: (List<Point>) -> ByteArray, v: Point, value: BigInteger, gamma: BigInteger): Map<String, Any?> {
        val mask = BigInteger.ONE.shiftLeft(N_BITS).subtract(BigInteger.ONE)
        val vMasked = value.and(mask)
        val bitCommitments = ArrayList<Point>()
        val bitBlindings = ArrayList<BigInteger>()
        val bits = ArrayList<BigInteger>()
        for (i in 0 until N_BITS) {
            val bit = vMasked.shiftRight(i).and(BigInteger.ONE)
            val s = randScalar()
            bits.add(bit)
            bitBlindings.add(s)
            bitCommitments.add(add(mul(G, bit), mul(H, s)))
        }
        val ctx = makeCtx(bitCommitments)
        val or = ArrayList<Any?>()
        for (i in 0 until N_BITS) or.add(proveBit(ctx, i, bitCommitments[i], bits[i], bitBlindings[i]))
        var sStar = BigInteger.ZERO
        var aggPoint = mul(G, BigInteger.ZERO)
        for (i in 0 until N_BITS) {
            val w = BigInteger.ONE.shiftLeft(i)
            sStar = scalarAdd(sStar, scalarMul(w, bitBlindings[i]))
            aggPoint = add(aggPoint, mul(bitCommitments[i], w))
        }
        val d = sub(aggPoint, v)
        val agg = proveSchnorr(ctx, d, scalarSub(sStar, gamma))
        val bc = ArrayList<Any?>()
        for (p in bitCommitments) bc.add(encodePoint(p))
        return obj("n" to N_BITS.toLong(), "bitCommitments" to bc, "or" to or, "agg" to agg)
    }

    private fun rangeVerify(makeCtx: (List<Point>) -> ByteArray, v: Point, proof: Any?): Boolean {
        if (proof !is Map<*, *>) return false
        val n = proof["n"]
        val bitCommitments = proof["bitCommitments"]
        val or = proof["or"]
        val agg = proof["agg"]
        val nd: Double? = when (n) {
            is Json.Num -> n.raw.toDoubleOrNull()
            is Number -> n.toDouble()
            else -> null
        }
        if (nd == null || nd != N_BITS.toDouble() || bitCommitments !is List<*> || or !is List<*>) return false
        if (bitCommitments.size != N_BITS || or.size != N_BITS) return false
        if (!(agg is Map<*, *> || agg is List<*>)) return false
        val b = ArrayList<Point>()
        for (c in bitCommitments) b.add(decodePoint(c))
        val ctx = makeCtx(b)
        for (i in 0 until N_BITS) if (!verifyBit(ctx, i, b[i], or[i])) return false
        var aggPoint = mul(G, BigInteger.ZERO)
        for (i in 0 until N_BITS) aggPoint = add(aggPoint, mul(b[i], BigInteger.ONE.shiftLeft(i)))
        return verifySchnorr(ctx, sub(aggPoint, v), agg)
    }

    /**
     * Prove that the committed aggregate satisfies sum(risk) <= bMax, in zero knowledge over the individual risks. [risks] and [blindings] are
     * the per-action values behind the commitments whose sum goes to [verifyBudget]. An over-budget aggregate (or a slack that does not fit
     * N_BITS) yields a well-formed proof that the verifier REJECTS: soundness lives in verification.
     *
     * SCOPE: the proof is about the committed VALUE of the sum; pair it with [proveRiskRange] / [verifyBoundedBudget] so no addend can be a
     * "negative" value near the group order.
     */
    @JvmStatic
    fun proveBudget(risks: List<*>, blindings: List<BigInteger?>, bMax: Any?): Map<String, Any?> {
        if (risks.size != blindings.size) throw AccumulatorError("length_mismatch", "risks and blindings must have equal length")
        val ceiling = effectiveCeiling(asUnits(bMax))
        var sumRisk = BigInteger.ZERO
        var sumBlind = BigInteger.ZERO
        for (i in risks.indices) {
            sumRisk = sumRisk.add(asUnits(risks[i] ?: BigInteger.ZERO))
            sumBlind = scalarAdd(sumBlind, blindings[i] ?: BigInteger.ZERO)
        }
        val cSum = add(mul(G, mod(sumRisk)), mul(H, sumBlind))
        val v = sub(mul(G, mod(ceiling)), cSum)
        val slack = ceiling.subtract(sumRisk)
        return rangeProve({ bits -> contextHash(N_BITS, ceiling, cSum, bits) }, v, slack, mod(sumBlind.negate()))
    }

    /**
     * Verify a budget proof against the commitment sum and ceiling: true only if every bit commitment opens to 0/1 and they aggregate to
     * `bMax*G - commitmentSum`, i.e. sum(risk) <= bMax. Never throws; malformed input is false. Scalars and points must be canonical.
     */
    @JvmStatic
    fun verifyBudget(commitmentSum: Any?, bMax: Any?, proof: Any?): Boolean = try {
        val ceiling = effectiveCeiling(asUnits(bMax))
        val cSum = decodePoint(commitmentSum)
        val v = sub(mul(G, mod(ceiling)), cSum)
        rangeVerify({ bits -> contextHash(N_BITS, ceiling, cSum, bits) }, v, proof)
    } catch (e: RuntimeException) {
        false
    }

    /** Prove that `commitRisk(risk, blinding)` holds a value in [0, 2^N_BITS): each action's commitment needs one. */
    @JvmStatic
    fun proveRiskRange(risk: Any?, blinding: BigInteger): Map<String, Any?> {
        val v = asUnits(risk)
        val b = mod(blinding)
        val c = add(mul(G, mod(v)), mul(H, b))
        return rangeProve({ bits -> riskContextHash(N_BITS, c, bits) }, c, v, b)
    }

    /** Verify [proveRiskRange] for [commitment]. Never throws; malformed input is false. */
    @JvmStatic
    fun verifyRiskRange(commitment: Any?, proof: Any?): Boolean = try {
        val c = decodePoint(commitment)
        rangeVerify({ bits -> riskContextHash(N_BITS, c, bits) }, c, proof)
    } catch (e: RuntimeException) {
        false
    }

    /**
     * The sound end-to-end budget check over per-action commitments: every commitment carries a valid range proof and the budget proof verifies
     * for their homomorphic sum. Accepting implies sum(committed risks), as integers, <= min(bMax, 2^N_BITS - 1). Never throws.
     */
    @JvmStatic
    fun verifyBoundedBudget(commitments: Any?, rangeProofs: Any?, bMax: Any?, budgetProof: Any?): Boolean = try {
        if (commitments !is List<*> || rangeProofs !is List<*> || commitments.size != rangeProofs.size) false
        else {
            var ok = true
            for (i in commitments.indices) if (ok && !verifyRiskRange(commitments[i], rangeProofs[i])) ok = false
            ok && verifyBudget(addCommitments(commitments), bMax, budgetProof)
        }
    } catch (e: RuntimeException) {
        false
    }
}
