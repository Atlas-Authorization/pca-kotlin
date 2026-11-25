package net.atlasauth.pca.intent

import java.math.BigDecimal
import java.math.BigInteger

/**
 * Exact Clopper-Pearson upper bounds (integer arithmetic on the 2^-52 grid), the floating-point binomial CDF used for starting
 * guesses, Hoeffding half-widths and Wilson intervals. Mirrors the reference numerics bit for bit: logarithms and exponentials
 * come from StrictMath (fdlibm, as the reference engine's), square roots are exact.
 */
object IntentStats {
    const val CP_GRID_BITS = 52
    @JvmField val CP_TOLERANCE: Double = Math.scalb(1.0, -44)

    private val A: BigInteger = BigInteger.ONE.shiftLeft(CP_GRID_BITS)
    private val TOL_UNITS: BigInteger = BigInteger.ONE.shiftLeft(CP_GRID_BITS - 44)

    /** The exact binary fraction num / 2^exp of a double in (0, 1). */
    data class Dyadic(val num: BigInteger, val exp: Int)

    /** A bound on the 2^-52 grid with its certified bracket. */
    data class CPCertificate(val upper: Double, val upperUnits: BigInteger, val lowerUnits: BigInteger)

    data class Bracket(val hi: BigInteger, val lo: BigInteger)

    data class Wilson(val p: Double, val lo: Double, val hi: Double)

    fun logFactorials(n: Int): DoubleArray {
        val lf = DoubleArray(n + 1)
        for (i in 1..n) lf[i] = lf[i - 1] + StrictMath.log(i.toDouble())
        return lf
    }

    /** P(X <= k), X ~ Binomial(n, p), in floating point (guesses and diagnostics only). */
    @JvmOverloads
    fun binomialCdf(k: Int, n: Int, p: Double, lf0: DoubleArray? = null): Double {
        if (k >= n) return 1.0
        if (k < 0) return 0.0
        if (p <= 0) return 1.0
        if (p >= 1) return 0.0
        val lf = lf0 ?: logFactorials(n)
        val lp = StrictMath.log(p)
        val lq = StrictMath.log1p(-p)
        var s = 0.0
        for (i in 0..k) s += StrictMath.exp(lf[n] - lf[i] - lf[n - i] + i * lp + (n - i) * lq)
        return Math.min(1.0, s)
    }

    fun doubleToDyadic(x: Double): Dyadic {
        require(!x.isNaN() && !x.isInfinite() && x > 0 && x < 1) { "doubleToDyadic: need 0 < x < 1" }
        var e = 0
        var y = x
        while (y != Math.rint(y)) {
            y *= 2
            e++
            require(e <= 1100) { "doubleToDyadic: not reached" }
        }
        return Dyadic(BigDecimal(y).toBigIntegerExact(), e)
    }

    /** N with cdfRec(a / 2^52, n, k) = N / 2^(52 n), by the recursion of the definition. */
    fun cdfRecNumerator(n: Int, k: Int, a: BigInteger): BigInteger {
        require(a.signum() >= 0 && a <= A) { "cdfRecNumerator: a must be in [0, 2^52]" }
        val b = A.subtract(a)
        val kk = Math.min(k, n)
        require(kk >= 0) { "cdfRecNumerator: bad k" }
        var row = Array<BigInteger>(kk + 1) { BigInteger.ONE }
        var pow = BigInteger.ONE
        for (m in 0 until n) {
            val powNext = pow.multiply(A)
            val cur = row
            row = Array(kk + 1) { j ->
                if (j >= m + 1) powNext
                else {
                    val left = if (j == 0) BigInteger.ZERO else cur[j - 1]
                    a.multiply(left).add(b.multiply(cur[j]))
                }
            }
            pow = powNext
        }
        return row[kk]
    }

    /** Exactly decides alpha < cdfRec(a / 2^52, n, k). */
    fun cdfExceeds(n: Int, k: Int, a: BigInteger, alpha: Dyadic): Boolean {
        val big = cdfRecNumerator(n, k, a)
        return big.shiftLeft(alpha.exp) > alpha.num.multiply(A.pow(n))
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

    private fun clamp(a: BigInteger): BigInteger = if (a.signum() < 0) BigInteger.ZERO else if (a > A) A else a

    fun clopperPearsonCertified(kD: Double, nD: Double, alpha: Double): CPCertificate {
        require(isInt(kD) && isInt(nD) && kD >= 0 && nD >= 0 && kD <= nD) { "clopperPearsonUpper: need integers 0 <= k <= n" }
        require(alpha > 0 && alpha < 1) { "clopperPearsonUpper: alpha must be in (0, 1)" }
        val k = kD.toInt()
        val n = nD.toInt()
        if (n == 0 || k == n) return CPCertificate(1.0, A, A)
        val al = doubleToDyadic(alpha)
        val start = clamp(BigInteger.valueOf(Math.ceil(floatGuess(k, n, alpha) * Math.scalb(1.0, CP_GRID_BITS)).toLong()).add(TOL_UNITS))
        val br = certifyBracket(start) { a -> cdfExceeds(n, k, a, al) }
        return CPCertificate(br.hi.toDouble() / Math.scalb(1.0, CP_GRID_BITS), br.hi, br.lo)
    }

    private fun isInt(d: Double): Boolean = !d.isNaN() && !d.isInfinite() && d == Math.rint(d)

    /** Certifies a bracket of at most TOL_UNITS around the flip point of the antitone [exceeds]. */
    fun certifyBracket(start: BigInteger, exceeds: (BigInteger) -> Boolean): Bracket {
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
        check(!(lo.signum() == 0 && !exceeds(BigInteger.ZERO))) { "clopperPearsonUpper: unreachable (cdfRec(0) = 1)" }
        while (hi.subtract(lo) > TOL_UNITS) {
            val mid = lo.add(hi).shiftRight(1)
            if (exceeds(mid)) lo = mid else hi = mid
        }
        return Bracket(hi, lo)
    }

    fun clopperPearsonUpper(k: Double, n: Double, alpha: Double): Double = clopperPearsonCertified(k, n, alpha).upper

    @JvmOverloads
    fun hoeffdingHalfWidth(range: Double, samples: Double, deltaPrime: Double = 0.05): Double =
        range * Math.sqrt(StrictMath.log(2 / deltaPrime) / (2 * samples))

    @JvmOverloads
    fun wilsonInterval(k: Double, n: Double, z: Double = 1.959963984540054): Wilson {
        if (!(n > 0)) return Wilson(Double.NaN, 0.0, 1.0)
        val p = k / n
        val z2 = z * z
        val den = 1 + z2 / n
        val centre = (p + z2 / (2 * n)) / den
        val half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / den
        return Wilson(p, Math.max(0.0, centre - half), Math.min(1.0, centre + half))
    }
}
