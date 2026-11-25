package net.atlasauth.pca.mpc

import java.math.BigInteger
import java.security.SecureRandom

/** A source of uniform field elements. */
interface FieldSource {
    fun next(): BigInteger
}

/**
 * Arithmetic in the prime field F_p (p = 2^61 - 1) used for additive secret sharing, plus the field randomness sources: a deterministic
 * SplitMix64 [FieldRng] (reproducible tests behind an explicit seed) and the CSPRNG [SecureFieldRng] (the default for protocol
 * randomness). All arithmetic is exact BigInteger.
 */
object Field {
    @JvmField val PRIME: BigInteger = BigInteger.ONE.shiftLeft(61).subtract(BigInteger.ONE)
    internal const val PRIME_LONG: Long = (1L shl 61) - 1

    // The largest multiple of p that fits in 64 bits is 2^64 - 8; anything at or above it is rejected so `% p` is uniform.
    internal val LIMIT: ULong = ULong.MAX_VALUE - 7UL

    /** Canonical representative in [0, p). */
    @JvmStatic fun mod(x: BigInteger): BigInteger = x.mod(PRIME)
    @JvmStatic fun fadd(a: BigInteger, b: BigInteger): BigInteger = mod(a.add(b))
    @JvmStatic fun fsub(a: BigInteger, b: BigInteger): BigInteger = mod(a.subtract(b))
    @JvmStatic fun fmul(a: BigInteger, b: BigInteger): BigInteger = mod(a.multiply(b))
    @JvmStatic fun fneg(a: BigInteger): BigInteger = mod(a.negate())

    internal fun reduce(u: ULong): BigInteger = BigInteger.valueOf((u % PRIME_LONG.toULong()).toLong())

    /** Deterministic SplitMix64 drawing unbiased field elements by rejection sampling. */
    open class FieldRng(seed: BigInteger = BigInteger("243f6a8885a308d3", 16)) : FieldSource {
        private var s: Long = seed.toLong()

        internal fun nextU64(): Long {
            s += -0x61c8864680b583ebL // 0x9e3779b97f4a7c15
            var z = s
            z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L // 0xbf58476d1ce4e5b9
            z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L // 0x94d049bb133111eb
            return z xor (z ushr 31)
        }

        override fun next(): BigInteger {
            while (true) {
                val u = nextU64().toULong()
                if (u < LIMIT) return reduce(u)
            }
        }
    }

    /** CSPRNG-backed field source: fresh SecureRandom bytes, rejection sampled. */
    class SecureFieldRng(private val rnd: SecureRandom = SecureRandom()) : FieldRng(BigInteger.ZERO) {
        override fun next(): BigInteger {
            val b = ByteArray(8)
            while (true) {
                rnd.nextBytes(b)
                var u = 0L
                for (i in 0 until 8) u = (u shl 8) or (b[i].toLong() and 0xffL)
                val uu = u.toULong()
                if (uu < LIMIT) return reduce(uu)
            }
        }
    }

    /** CSPRNG by default, a reproducible seeded [FieldRng] only when [testSeed] is non-null. */
    @JvmStatic fun fieldRandom(testSeed: BigInteger?): FieldSource = if (testSeed == null) SecureFieldRng() else FieldRng(testSeed)
}
