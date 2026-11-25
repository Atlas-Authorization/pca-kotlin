package net.atlasauth.pca.wallet

import java.math.BigDecimal
import java.math.BigInteger

/**
 * Small numerics for the noise estimates: log-gamma (Lanczos), the regularized incomplete beta function (continued fraction,
 * modified Lentz) and its quantile by bisection, the exact Clopper-Pearson upper bound (binomial-tail inversion in integer
 * arithmetic) and the binary entropy. Deterministic. The transcendental functions are the fdlibm ones (StrictMath), which is
 * what the reference's runtime computes, so results agree to the last bit; operation order follows the reference exactly.
 */
object WalletStats {
    private val LANCZOS = doubleArrayOf(676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
        -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7)

    fun lnGamma(x: Double): Double {
        if (x < 0.5) return StrictMath.log(Math.PI / StrictMath.sin(Math.PI * x)) - lnGamma(1 - x)
        val z = x - 1
        var a = 0.99999999999980993
        val t = z + 7.5
        for (i in LANCZOS.indices) a += LANCZOS[i] / (z + i + 1)
        return 0.5 * StrictMath.log(2 * Math.PI) + (z + 0.5) * StrictMath.log(t) - t + StrictMath.log(a)
    }

    /** The continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300, never divided by). */
    fun betacf(a: Double, b: Double, x: Double): Double {
        val tiny = 1e-300
        val qab = a + b
        val qap = a + 1
        val qam = a - 1
        var c = 1.0
        var d = 1 - (qab * x) / qap
        if (Math.abs(d) < tiny) d = tiny
        d = 1 / d
        var h = d
        for (m in 1..300) {
            val m2 = 2 * m
            var aa = (m * (b - m) * x) / ((qam + m2) * (a + m2))
            d = 1 + aa * d
            if (Math.abs(d) < tiny) d = tiny
            c = 1 + aa / c
            if (Math.abs(c) < tiny) c = tiny
            d = 1 / d
            h *= d * c
            aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2))
            d = 1 + aa * d
            if (Math.abs(d) < tiny) d = tiny
            c = 1 + aa / c
            if (Math.abs(c) < tiny) c = tiny
            d = 1 / d
            val del = d * c
            h *= del
            if (Math.abs(del - 1) < 1e-15) break
        }
        return h
    }

    /** Regularized incomplete beta I_x(a, b), a, b > 0, x in [0, 1]. */
    fun betaInc(x: Double, a: Double, b: Double): Double {
        if (!(a > 0 && b > 0)) throw IllegalArgumentException("betaInc: a and b must be > 0")
        if (x <= 0) return 0.0
        if (x >= 1) return 1.0
        val lbt = lnGamma(a + b) - lnGamma(a) - lnGamma(b) + a * StrictMath.log(x) + b * StrictMath.log(1 - x)
        val bt = StrictMath.exp(lbt)
        if (x < (a + 1) / (a + b + 2)) return (bt * betacf(a, b, x)) / a
        return 1 - (bt * betacf(b, a, 1 - x)) / b
    }

    /** The q-quantile of Beta(a, b): the x with I_x(a, b) = q (bisection, 200 steps). */
    fun betaQuantile(q: Double, a: Double, b: Double): Double {
        if (!(q >= 0 && q <= 1)) throw IllegalArgumentException("betaQuantile: q must be in [0, 1]")
        if (q == 0.0) return 0.0
        if (q == 1.0) return 1.0
        var lo = 0.0
        var hi = 1.0
        for (i in 0 until 200) {
            val mid = (lo + hi) / 2
            if (betaInc(mid, a, b) < q) lo = mid else hi = mid
        }
        return hi
    }

    // ---- exact Clopper-Pearson ----

    private const val CP_GRID_BITS = 52
    private val A: BigInteger = BigInteger.ONE.shiftLeft(CP_GRID_BITS)
    private val TOL_UNITS: BigInteger = BigInteger.ONE.shiftLeft(CP_GRID_BITS - 44)

    private fun logFactorials(n: Int): DoubleArray {
        val lf = DoubleArray(n + 1)
        for (i in 1..n) lf[i] = lf[i - 1] + StrictMath.log(i.toDouble())
        return lf
    }

    /** P(X <= k) for X ~ Binomial(n, p) in floating point (a starting guess only; never decides a result). */
    internal fun binomialCdf(k: Int, n: Int, p: Double, lf: DoubleArray): Double {
        if (k >= n) return 1.0
        if (k < 0) return 0.0
        if (p <= 0) return 1.0
        if (p >= 1) return 0.0
        val lp = StrictMath.log(p)
        val lq = StrictMath.log1p(-p)
        var s = 0.0
        for (i in 0..k) s += StrictMath.exp(lf[n] - lf[i] - lf[n - i] + i * lp + (n - i) * lq)
        return Math.min(1.0, s)
    }

    private fun doubleToDyadic(x: Double): Pair<BigInteger, Int> {
        if (!(x > 0 && x < 1)) throw IllegalArgumentException("doubleToDyadic: need 0 < x < 1")
        var e = 0
        var y = x
        while (y != Math.rint(y)) {
            y *= 2
            e++
            if (e > 1100) throw IllegalStateException("doubleToDyadic: not reached")
        }
        return Pair(BigDecimal(y).toBigInteger(), e)
    }

    /** The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n), by the recursion of the Lean definition. */
    internal fun cdfRecNumerator(n: Int, k: Int, a: BigInteger): BigInteger {
        if (a.signum() < 0 || a.compareTo(A) > 0) throw IllegalArgumentException("cdfRecNumerator: a must be in [0, 2^52]")
        val b = A.subtract(a)
        val kk = Math.min(k, n)
        var row = Array<BigInteger>(kk + 1) { BigInteger.ONE }
        var pow = BigInteger.ONE
        for (m in 0 until n) {
            val powNext = pow.multiply(A)
            val prev = row
            row = Array(kk + 1) { j ->
                if (j >= m + 1) powNext
                else {
                    val left = if (j == 0) BigInteger.ZERO else prev[j - 1]
                    a.multiply(left).add(b.multiply(prev[j]))
                }
            }
            pow = powNext
        }
        return row[kk]
    }

    private fun cdfExceeds(n: Int, k: Int, a: BigInteger, alpha: Pair<BigInteger, Int>): Boolean {
        val num = cdfRecNumerator(n, k, a)
        return num.shiftLeft(alpha.second).compareTo(alpha.first.multiply(A.pow(n))) > 0
    }

    private fun floatGuess(k: Int, n: Int, alpha: Double): Double {
        val lf = logFactorials(n)
        var lo = k.toDouble() / n
        var hi = 1.0
        var it = 0
        while (it < 200 && hi - lo > 1e-13) {
            val mid = (lo + hi) / 2
            if (binomialCdf(k, n, mid, lf) > alpha) lo = mid else hi = mid
            it++
        }
        return hi
    }

    private fun clamp(a: BigInteger): BigInteger = if (a.signum() < 0) BigInteger.ZERO else if (a.compareTo(A) > 0) A else a

    /** A bracket [lo, hi] of at most TOL_UNITS around the point where [exceeds] (antitone) flips, from any start. */
    private fun certifyBracket(start: BigInteger, exceeds: (BigInteger) -> Boolean): Array<BigInteger> {
        var hi = start
        var step = TOL_UNITS
        while (exceeds(hi)) {
            hi = clamp(hi.add(step))
            step = step.shiftLeft(1)
        }
        var lo = clamp(hi.subtract(TOL_UNITS))
        step = TOL_UNITS
        while (lo.signum() > 0 && !exceeds(lo)) {
            hi = lo
            lo = clamp(lo.subtract(step))
            step = step.shiftLeft(1)
        }
        if (lo.signum() == 0 && !exceeds(BigInteger.ZERO)) throw IllegalStateException("clopperPearsonUpper: unreachable (cdfRec(0) = 1)")
        while (hi.subtract(lo).compareTo(TOL_UNITS) > 0) {
            val mid = lo.add(hi).shiftRight(1)
            if (exceeds(mid)) lo = mid else hi = mid
        }
        return arrayOf(hi, lo)
    }

    /**
     * One-sided exact Clopper-Pearson upper bound on a binomial rate (k successes in n trials, level 1 - alpha): a multiple of
     * 2^-52 within 2^-44 above the exact bound. Throws unless 0 <= k <= n are integers and alpha is in (0, 1).
     */
    /**
     * The upper bound q such that the Beta(a, b) posterior puts mass delta above it, for POSITIVE INTEGER a and b, exactly: I_x(a, b) = P[Bin(a + b - 1, x) >= a],
     * so the quantile at level 1 - delta is the Clopper-Pearson inversion with k = a - 1 successes in n = a + b - 1 trials (integer arithmetic, rounded
     * outward to 2^-44). The freeze and admission decisions compare this value, so it never depends on a platform's libm.
     */
    fun betaUpperExact(delta: Double, a: Double, b: Double): Double {
        if (!(a == Math.floor(a) && a >= 1 && !a.isInfinite() && b == Math.floor(b) && b >= 1 && !b.isInfinite())) throw IllegalArgumentException("betaUpperExact: a and b must be positive integers")
        return clopperPearsonUpper(a - 1, a + b - 1, delta)
    }

    fun clopperPearsonUpper(kD: Double, nD: Double, alpha: Double): Double {
        if (!(kD == Math.rint(kD) && nD == Math.rint(nD) && !kD.isInfinite() && !nD.isInfinite() && kD >= 0 && nD >= 0 && kD <= nD))
            throw IllegalArgumentException("clopperPearsonUpper: need integers 0 <= k <= n")
        if (!(alpha > 0 && alpha < 1)) throw IllegalArgumentException("clopperPearsonUpper: alpha must be in (0, 1)")
        if (nD > 100_000) throw IllegalArgumentException("clopperPearsonUpper: n too large")
        val k = kD.toInt()
        val n = nD.toInt()
        if (n == 0 || k == n) return 1.0
        val al = doubleToDyadic(alpha)
        val g = floatGuess(k, n, alpha)
        val start = clamp(BigDecimal(Math.ceil(g * 4503599627370496.0)).toBigInteger().add(TOL_UNITS))
        val r = certifyBracket(start) { a -> cdfExceeds(n, k, a, al) }
        return r[0].toDouble() / 4503599627370496.0
    }

    // ---- entropy ----

    /** Binary entropy in bits. */
    fun binEnt(p: Double): Double {
        if (p <= 0 || p >= 1) return 0.0
        return -(p * log2(p) + (1 - p) * log2(1 - p))
    }

    private const val TWO54 = 1.80143985094819840000e+16
    private const val IVLN2HI = 1.44269504072144627571e+00
    private const val IVLN2LO = 1.67517131648865118353e-10
    private const val LG1 = 6.666666666666735130e-01
    private const val LG2 = 3.999999999940941908e-01
    private const val LG3 = 2.857142874366239149e-01
    private const val LG4 = 2.222219843214978396e-01
    private const val LG5 = 1.818357216161805012e-01
    private const val LG6 = 1.531383769920937332e-01
    private const val LG7 = 1.479819860511658591e-01

    private fun kLog1p(f: Double): Double {
        val s = f / (2.0 + f)
        val z = s * s
        val w = z * z
        val t1 = w * (LG2 + w * (LG4 + w * LG6))
        val t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)))
        val r = t2 + t1
        val hfsq = 0.5 * f * f
        return s * (hfsq + r)
    }

    private fun hiWord(x: Double): Int = (java.lang.Double.doubleToRawLongBits(x) shr 32).toInt()

    private fun loWord(x: Double): Int = java.lang.Double.doubleToRawLongBits(x).toInt()

    private fun withHi(x: Double, hi: Int): Double =
        java.lang.Double.longBitsToDouble((hi.toLong() shl 32) or (java.lang.Double.doubleToRawLongBits(x) and 0xffffffffL))

    private fun withLoZero(x: Double): Double =
        java.lang.Double.longBitsToDouble(java.lang.Double.doubleToRawLongBits(x) and -4294967296L)

    /** log2 as the reference's runtime computes it (the fdlibm / FreeBSD algorithm; StrictMath has no log2). */
    fun log2(x0: Double): Double {
        var x = x0
        var hx = hiWord(x)
        val lx = loWord(x)
        var k = 0
        if (hx < 0x00100000) {
            if (((hx and 0x7fffffff) or lx) == 0) return Double.NEGATIVE_INFINITY
            if (hx < 0) return Double.NaN
            k -= 54
            x *= TWO54
            hx = hiWord(x)
        }
        if (hx >= 0x7ff00000) return x + x
        if (hx == 0x3ff00000 && lx == 0) return 0.0
        k += (hx shr 20) - 1023
        hx = hx and 0x000fffff
        val i = (hx + 0x95f64) and 0x100000
        x = withHi(x, hx or (i xor 0x3ff00000))
        k += (i shr 20)
        val y = k.toDouble()
        val f = x - 1.0
        val hfsq = 0.5 * f * f
        val r = kLog1p(f)
        val hi = withLoZero(f - hfsq)
        val lo = (f - hi) - hfsq + r
        var valHi = hi * IVLN2HI
        var valLo = (lo + hi) * IVLN2LO + lo * IVLN2HI
        val w = y + valHi
        valLo += (y - w) + valHi
        valHi = w
        return valLo + valHi
    }
}
