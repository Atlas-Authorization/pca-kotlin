package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.Field.mod

/**
 * Privacy-amplified OT choice-bit encoding (the selective-failure remedy): the receiver chooses with m = 61 + 3s uniform bits b and takes
 * x = sum g_k b_k (mod p) for a public gadget vector g. s = 0 is the legacy plain binary encoding.
 */
object Enc {
    const val FIELD_BITS = 61
    const val STAT_SEC = 64
    const val MIN_STAT_SEC = 40

    @JvmStatic fun encBits(s: Int): Int = FIELD_BITS + 3 * s

    /** A receiver operand: its field value together with the choice bits that encode it. */
    class EncShare(val value: BigInteger, val bits: IntArray)

    @JvmStatic @JvmOverloads fun makeGadget(s: Int, next: FieldSource, unsafe: Boolean = false): Array<BigInteger> {
        require(s in 0..64) { "statSec must be an integer in [0, 64]" }
        require(!(s < MIN_STAT_SEC && !unsafe)) { "statSec $s is below $MIN_STAT_SEC: refused (tests may pass the explicit unsafe flag)" }
        val m = encBits(s)
        return Array(m) { k -> if (s == 0) mod(BigInteger.ONE.shiftLeft(k)) else next.next() }
    }

    @JvmStatic fun encValue(g: Array<BigInteger>, bits: IntArray): BigInteger {
        require(g.size == bits.size) { "encValue: gadget / bits length mismatch" }
        var v = BigInteger.ZERO
        for (k in g.indices) if (bits[k] == 1) v = v.add(g[k])
        return mod(v)
    }

    @JvmStatic fun plainShare(x: BigInteger): EncShare {
        val v = mod(x)
        return EncShare(v, IntArray(FIELD_BITS) { k -> if (v.testBit(k)) 1 else 0 })
    }

    @JvmStatic fun plainGadget(): Array<BigInteger> = Array(FIELD_BITS) { k -> mod(BigInteger.ONE.shiftLeft(k)) }

    /** m uniform bits from a field source (the 60 low bits of each draw are uniform). */
    @JvmStatic fun randomBits(m: Int, rng: FieldSource): IntArray {
        val out = IntArray(m)
        var k = 0
        while (k < m) {
            val w = rng.next()
            var i = 0
            while (i < 60 && k < m) {
                out[k] = if (w.testBit(i)) 1 else 0
                i++
                k++
            }
        }
        return out
    }

    @JvmStatic fun sampleEnc(g: Array<BigInteger>, rng: FieldSource): EncShare {
        val bits = randomBits(g.size, rng)
        return EncShare(encValue(g, bits), bits)
    }
}
