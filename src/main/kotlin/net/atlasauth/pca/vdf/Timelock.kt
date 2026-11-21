package net.atlasauth.pca.vdf

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import net.atlasauth.pca.verifier.Pca

/**
 * PCA timelock: a mandatory, offline-verifiable cooling-off on an irreversible action, enforced by a canonical Wesolowski VDF.
 * The VDF input is bound to the action AND to a beacon (an unpredictable, time-ordered value the caller validates):
 * `x = H(domain || len||actionDigest || len||beacon) mod N`. Limits are those of the reference: a work proof, not a clock.
 */
object Timelock {
    private val X_DOMAIN = "atlas-pca/vdf/timelock/input/v2\u0000".toByteArray(Charsets.UTF_8)

    /** The derived requirement: input x, step count, modulus, and the digest x came from. */
    class TimelockRequirement internal constructor(val x: BigInteger, val steps: Long, val N: BigInteger, val actionDigest: String) {
        val kind: String = "vdf-timelock"
    }

    /** A timelock proof: canonical y, pi, and the step count it attests to (a JavaScript number, so any double). */
    class TimelockProof(val kind: String?, val y: BigInteger?, val pi: BigInteger?, val steps: Double)

    /** The digest a timelock binds to: a String is an opaque digest; a PCActn (JSON object) uses the canonical hash. */
    @JvmStatic
    fun actionDigest(action: Any?): String = if (action is String) action else Pca.hashCanonical(action)

    private fun beaconBytes(beacon: Any?): ByteArray {
        val b = if (beacon is String) Json.utf8(beacon) else beacon as? ByteArray
        require(b != null && b.isNotEmpty()) { "timelock: a non-empty beacon (unpredictable, post-action value) is required" }
        return b
    }

    private fun lp(out: ByteArrayOutputStream, b: ByteArray) {
        out.write(byteArrayOf((b.size ushr 24).toByte(), (b.size ushr 16).toByte(), (b.size ushr 8).toByte(), b.size.toByte()), 0, 4)
        out.write(b, 0, b.size)
    }

    /** `x in [2, N)` bound to the action and beacon; deterministic. */
    @JvmStatic
    fun deriveTimelockInput(action: Any?, n: BigInteger?, beacon: Any?): BigInteger {
        require(n != null && n > BigInteger.valueOf(3)) { "deriveTimelockInput: modulus N must be a bigint > 3" }
        val m = ByteArrayOutputStream()
        m.write(X_DOMAIN, 0, X_DOMAIN.size)
        lp(m, Json.utf8(actionDigest(action)))
        lp(m, beaconBytes(beacon))
        val h = MessageDigest.getInstance("SHA-256").digest(m.toByteArray())
        val raw = Vdf.bytesToBigInt(h).mod(n)
        return if (raw <= BigInteger.ONE) raw.add(BigInteger.valueOf(2)) else raw
    }

    private fun requireProductionModulus(n: BigInteger, allowInsecureDevModulus: Boolean) {
        if (allowInsecureDevModulus) return
        val c = Vdf.checkProductionModulus(n)
        require(c.ok) {
            "timelock: refusing this modulus: ${c.reason}. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true."
        }
    }

    private fun requireSteps(steps: Double): Long {
        require(!(!Vdf.isSafeSteps(steps) || steps < 1)) { "timelock: steps must be a safe integer >= 1, got $steps" }
        return steps.toLong()
    }

    /** The requirement for an action: derives the VDF input and carries steps and modulus. */
    @JvmStatic
    @JvmOverloads
    fun requireTimelock(action: Any?, steps: Long, n: BigInteger, beacon: Any?, allowInsecureDevModulus: Boolean = false): TimelockRequirement {
        val s = requireSteps(steps.toDouble())
        requireProductionModulus(n, allowInsecureDevModulus)
        val x = deriveTimelockInput(action, n, beacon)
        return TimelockRequirement(x, s, n, actionDigest(action))
    }

    /** Runs the VDF: the squarings ARE the cooling-off, so this is deliberately slow. */
    @JvmStatic
    @JvmOverloads
    fun proveTimelockElapsed(action: Any?, steps: Long, n: BigInteger, beacon: Any?, allowInsecureDevModulus: Boolean = false): TimelockProof {
        val s = requireSteps(steps.toDouble())
        requireProductionModulus(n, allowInsecureDevModulus)
        val x = deriveTimelockInput(action, n, beacon)
        val p = Vdf.vdfEvalCanonical(x, s, n)
        return TimelockProof("vdf-timelock-proof", p.y, p.pi, s.toDouble())
    }

    /** Gate release on a valid proof for THIS action, beacon, step count and modulus. Fails closed (false, never throws). */
    @JvmStatic
    @JvmOverloads
    fun verifyTimelock(action: Any?, proof: TimelockProof?, steps: Double, n: BigInteger, beacon: Any?, allowInsecureDevModulus: Boolean = false): Boolean = try {
        val required = requireSteps(steps)
        requireProductionModulus(n, allowInsecureDevModulus)
        if (proof == null || proof.kind != "vdf-timelock-proof") false
        else if (!Vdf.isSafeSteps(proof.steps) || proof.steps != required.toDouble()) false
        else if (proof.y == null || proof.pi == null) false
        else Vdf.vdfVerifyCanonical(deriveTimelockInput(action, n, beacon), proof.y, proof.pi, required, n)
    } catch (e: RuntimeException) {
        false
    }
}
