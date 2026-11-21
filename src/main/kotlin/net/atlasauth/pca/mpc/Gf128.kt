package net.atlasauth.pca.mpc

import java.math.BigInteger

/**
 * GF(2^128) arithmetic with the reduction polynomial x^128 + x^7 + x^2 + x + 1: the field of the KOS correlation check. Elements are
 * 128-bit non-negative BigIntegers (bit i = coefficient of x^i); addition is XOR. Not constant-time.
 */
object Gf128 {
    private val MASK: BigInteger = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
    private val RED: BigInteger = BigInteger.valueOf(0x87)

    @JvmStatic fun add(a: BigInteger, b: BigInteger): BigInteger = a.xor(b).and(MASK)

    @JvmStatic fun mulX(v: BigInteger): BigInteger {
        val carry = v.testBit(127)
        val r = v.shiftLeft(1).and(MASK)
        return if (carry) r.xor(RED) else r
    }

    @JvmStatic fun mulByXi(v: BigInteger, i: Int): BigInteger {
        var r = v.and(MASK)
        for (k in 0 until i) r = mulX(r)
        return r
    }

    @JvmStatic fun mul(a: BigInteger, b: BigInteger): BigInteger {
        var res = BigInteger.ZERO
        var v = a.and(MASK)
        for (i in 0 until 128) {
            if (b.testBit(i)) res = res.xor(v)
            v = mulX(v)
        }
        return res.and(MASK)
    }
}
