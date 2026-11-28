package net.atlasauth.pca.mpc

import java.math.BigInteger

/** Thermometer (unary) encoding of a bounded integer: ge[k] = [v >= k] for k = 1..M, so MAX is a position-wise OR. */
object Thermometer {
    /** Encodes v in {0..M}; v is clamped into range (fail-safe). v is a JS number (non-finite clamps like Math.trunc). */
    @JvmStatic fun thermometerEncode(v: Double, m: Int): IntArray {
        require(m >= 0) { "thermometerEncode: M must be a non-negative integer" }
        val tr = if (v.isNaN()) Double.NaN else if (v < 0) Math.ceil(v) else Math.floor(v)
        val clamped = if (tr.isNaN()) Double.NaN else Math.max(0.0, Math.min(m.toDouble(), tr))
        // NaN compares false: all zero (Math.max(0, NaN) is NaN in JS too)
        return IntArray(m) { k -> if (clamped >= (k + 1)) 1 else 0 }
    }

    /** Number of 1s (robust to non-monotone input). */
    @JvmStatic fun thermometerDecode(bits: IntArray): Int = bits.count { it == 1 }

    @JvmStatic fun thermometerDecode(bits: Array<BigInteger>): Int = bits.count { it == BigInteger.ONE }
}
