package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul
import net.atlasauth.pca.mpc.Field.fneg
import net.atlasauth.pca.mpc.Field.mod

/**
 * Additive secret sharing over F_p for N parties: shares sum to the secret; reconstruction is all-or-nothing and fails closed on an
 * absent share. A shared value is an `Array<BigInteger>` with `x[i]` held by party i.
 */
object Sharing {
    /** Largest party count accepted (bounds allocation). */
    const val MAX_PARTIES = 1024

    @JvmStatic fun share(secret: BigInteger, n: Int, rng: FieldSource): Array<BigInteger> {
        require(n in 1..MAX_PARTIES) { "share: n must be an integer in [1, $MAX_PARTIES]" }
        val out = Array<BigInteger>(n) { BigInteger.ZERO }
        var acc = BigInteger.ZERO
        for (i in 0 until n - 1) {
            val s = rng.next()
            out[i] = s
            acc = fadd(acc, s)
        }
        out[n - 1] = fadd(mod(secret), fneg(acc))
        return out
    }

    @JvmStatic fun reconstruct(shares: Array<out BigInteger?>): BigInteger {
        require(shares.isNotEmpty()) { "reconstruct: no shares (fail closed)" }
        var acc = BigInteger.ZERO
        for (s in shares) {
            requireNotNull(s) { "reconstruct: missing share (fail closed)" }
            acc = fadd(acc, s)
        }
        return acc
    }

    @JvmStatic fun shareConstant(c: BigInteger, n: Int): Array<BigInteger> {
        require(n in 1..MAX_PARTIES) { "shareConstant: n must be an integer in [1, $MAX_PARTIES]" }
        val out = Array<BigInteger>(n) { BigInteger.ZERO }
        out[0] = mod(c)
        return out
    }

    @JvmStatic fun addSV(x: Array<BigInteger>, y: Array<BigInteger>): Array<BigInteger> {
        same(x, y)
        return Array(x.size) { fadd(x[it], y[it]) }
    }

    @JvmStatic fun subSV(x: Array<BigInteger>, y: Array<BigInteger>): Array<BigInteger> {
        same(x, y)
        return Array(x.size) { fadd(x[it], fneg(y[it])) }
    }

    @JvmStatic fun negSV(x: Array<BigInteger>): Array<BigInteger> = Array(x.size) { fneg(x[it]) }

    @JvmStatic fun scaleSV(x: Array<BigInteger>, c: BigInteger): Array<BigInteger> = Array(x.size) { fmul(x[it], c) }

    @JvmStatic fun addPublicSV(x: Array<BigInteger>, c: BigInteger): Array<BigInteger> {
        val o = x.clone()
        o[0] = fadd(o[0], mod(c))
        return o
    }

    @JvmStatic fun notBitSV(b: Array<BigInteger>): Array<BigInteger> = addPublicSV(negSV(b), BigInteger.ONE)

    private fun same(x: Array<BigInteger>, y: Array<BigInteger>) {
        require(x.size == y.size) { "shared values must have the same party count" }
    }
}
