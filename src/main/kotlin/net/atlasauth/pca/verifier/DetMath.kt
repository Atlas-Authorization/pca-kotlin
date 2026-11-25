package net.atlasauth.pca.verifier

import java.math.BigInteger

/**
 * DETERMINISTIC MATH: the same bit pattern on every platform and in every language. libm's log, exp, log2 and pow are not correctly rounded
 * and differ in the last digit between implementations, which moves a decision that sits on a boundary. These functions use integer arithmetic
 * only: fixed point with 96 fractional bits (a value is an integer scaled by 2^96), TRUNCATING division (toward zero), and one final conversion of
 * the integer to a double with round-to-nearest-even followed by an exact power-of-two scaling.
 *
 *  - [detLn] x = m * 2^E, m = M / 2^52 in [1, 2) (M the 53-bit significand): ln x = E * LN2 + 2 * atanh((M - 2^52) / (M + 2^52)), atanh summed as
 *    z + z^3/3 + z^5/5 + ... (z2 = (z*z) / 2^96) until a term is 0; LN2 = 2 * atanh(1/3).
 *  - [detLog2] the same fixed value divided by LN2 in fixed point ((fixed * 2^96) / LN2): an exact power of two gives its exponent exactly.
 *  - [detExp] X = trunc(x * 2^96) (exact shift of the double's integer significand); k = floor((X + LN2/2) / LN2); r = X - k * LN2; e^r = sum of
 *    r^n / n! with term_0 = 2^96 and term_n = trunc(trunc(term_(n-1) * r / 2^96) / n) until a term is 0; the result is the sum as a double times
 *    2^(k - 96), the scaling split into two exact powers of two so that no intermediate overflows.
 *  - [detPowInt] b^n for an integer n >= 0: 1 multiplied by b, n times, in sequence.
 */
object DetMath {
    private const val FRAC = 96
    private val ONE: BigInteger = BigInteger.ONE.shiftLeft(FRAC)
    private val ONE_D: Double = ONE.toDouble()
    private val TWO52: BigInteger = BigInteger.ONE.shiftLeft(52)
    private val TWO: BigInteger = BigInteger.valueOf(2)

    /** 2 * atanh(num / den) in fixed point. */
    private fun atanh2(num: BigInteger, den: BigInteger): BigInteger {
        val z = num.shiftLeft(FRAC).divide(den)
        val z2 = z.multiply(z).shiftRight(FRAC)
        var term = z
        var sum = BigInteger.ZERO
        var i = BigInteger.ONE
        while (term.signum() != 0) {
            sum = sum.add(term.divide(i))
            term = term.multiply(z2).shiftRight(FRAC)
            i = i.add(TWO)
        }
        return sum.shiftLeft(1)
    }

    private val LN2: BigInteger = atanh2(BigInteger.ONE, BigInteger.valueOf(3))

    /** Fixed-point ln(x) of a positive finite double, or null when x is not positive and finite. */
    private fun lnFixed(x: Double): BigInteger? {
        if (!(x > 0) || x == Double.POSITIVE_INFINITY) return null
        var scale = 0
        var y = x
        if (y < java.lang.Double.MIN_NORMAL) {
            y = Math.scalb(y, 64)
            scale = 64
        }
        val bits = java.lang.Double.doubleToRawLongBits(y)
        val e = ((bits ushr 52) and 0x7ffL).toInt() - 1023 - scale
        val m = BigInteger.valueOf((bits and ((1L shl 52) - 1)) or (1L shl 52))
        return BigInteger.valueOf(e.toLong()).multiply(LN2).add(atanh2(m.subtract(TWO52), m.add(TWO52)))
    }

    /** ln x; 0 or -0 gives -Infinity, x < 0 or NaN gives NaN, +Infinity gives +Infinity, 1 gives exactly 0. */
    @JvmStatic
    fun detLn(x: Double): Double {
        if (x == 0.0) return Double.NEGATIVE_INFINITY
        if (!(x > 0)) return Double.NaN
        if (x == Double.POSITIVE_INFINITY) return x
        if (x == 1.0) return 0.0
        return lnFixed(x)!!.toDouble() / ONE_D
    }

    /** log2 x with the rule above. */
    @JvmStatic
    fun detLog2(x: Double): Double {
        if (x == 0.0) return Double.NEGATIVE_INFINITY
        if (!(x > 0)) return Double.NaN
        if (x == Double.POSITIVE_INFINITY) return x
        if (x == 1.0) return 0.0
        val l = lnFixed(x)!!
        return l.shiftLeft(FRAC).divide(LN2).toDouble() / ONE_D
    }

    private fun floorDiv(a: BigInteger, b: BigInteger): BigInteger {
        val qr = a.divideAndRemainder(b)
        return if (qr[1].signum() != 0 && (a.signum() < 0) != (b.signum() < 0)) qr[0].subtract(BigInteger.ONE) else qr[0]
    }

    /** e^x with the rule above; x > 709.78 gives +Infinity, x < -745.2 gives 0, NaN gives NaN. */
    @JvmStatic
    fun detExp(x: Double): Double {
        if (x.isNaN()) return x
        if (x > 709.782712893384) return Double.POSITIVE_INFINITY
        if (x < -745.2) return 0.0
        if (x == 0.0) return 1.0
        val bits = java.lang.Double.doubleToRawLongBits(Math.abs(x))
        val be = ((bits ushr 52) and 0x7ffL).toInt()
        val frac = bits and ((1L shl 52) - 1)
        val m = BigInteger.valueOf(if (be == 0) frac else frac or (1L shl 52))
        val sh = (if (be == 0) 1 else be) - 1075 + FRAC // |x| * 2^96 = m * 2^sh
        var xFixed = if (sh >= 0) m.shiftLeft(sh) else m.shiftRight(-sh)
        if (x < 0) xFixed = xFixed.negate()
        val k = floorDiv(xFixed.add(LN2.shiftRight(1)), LN2)
        val r = xFixed.subtract(k.multiply(LN2))
        var term = ONE
        var sum = ONE
        var n = 1L
        while (term.signum() != 0) {
            term = term.multiply(r).divide(ONE).divide(BigInteger.valueOf(n))
            sum = sum.add(term)
            n++
        }
        val e = k.toInt() - FRAC
        val half = e / 2
        return Math.scalb(Math.scalb(sum.toDouble(), half), e - half)
    }

    /** b^n for an integer n >= 0 by sequential multiplication (1 * b * b ... , n times). */
    @JvmStatic
    fun detPowInt(b: Double, n: Int): Double {
        var r = 1.0
        for (i in 0 until n) r *= b
        return r
    }
}
