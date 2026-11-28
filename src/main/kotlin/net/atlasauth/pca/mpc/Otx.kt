package net.atlasauth.pca.mpc

import java.math.BigInteger
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Word-array kernels for the OT-extension hot path: AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four little-endian u32
 * words (an `IntArray` holds unsigned words), and the batched tweakable correlation-robust hash H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a
 * fixed-key AES-128 truncated to 64 bits.
 */
object Otx {
    /** Number of bit columns of the IKNP matrix (kappa). */
    const val COLS = 128

    private val TAG_PRG_KEY = "atlas-pca-mpc/ot-prg-aes".toByteArray(Charsets.UTF_8)
    private val TAG_CRH_KEY = "atlas-pca-mpc/ot-crh-aes-fixed-key".toByteArray(Charsets.UTF_8)
    private val TAG_TWEAK_DOMAIN = "atlas-pca-mpc/ot-crh-tweak-domain/v2".toByteArray(Charsets.UTF_8)

    private fun sha256(): MessageDigest = MessageDigest.getInstance("SHA-256")

    /** Little-endian bytes of a non-negative bigint, exactly [len] bytes (the low bytes). */
    @JvmStatic fun bigToBytes(v: BigInteger, len: Int): ByteArray {
        val out = ByteArray(len)
        var x = v
        val ff = BigInteger.valueOf(0xff)
        for (i in 0 until len) {
            out[i] = x.and(ff).toInt().toByte()
            x = x.shiftRight(8)
        }
        return out
    }

    /** The bigint with the given little-endian bytes. */
    @JvmStatic fun bytesToBig(b: ByteArray): BigInteger {
        val be = ByteArray(b.size)
        for (i in b.indices) be[i] = b[b.size - 1 - i]
        return BigInteger(1, be)
    }

    private fun prgKey(seed: ByteArray): ByteArray {
        val md = sha256()
        md.update(TAG_PRG_KEY)
        md.update(seed)
        return md.digest().copyOf(16)
    }

    private fun leWords(b: ByteArray, off: Int, n: Int): IntArray = IntArray(n) { i ->
        val o = off + 4 * i
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)
    }

    private fun leBytes(w: IntArray, n: Int): ByteArray {
        val out = ByteArray(4 * n)
        for (i in 0 until n) {
            out[4 * i] = w[i].toByte()
            out[4 * i + 1] = (w[i] ushr 8).toByte()
            out[4 * i + 2] = (w[i] ushr 16).toByte()
            out[4 * i + 3] = (w[i] ushr 24).toByte()
        }
        return out
    }

    /** [nwords] u32 words of the PRG stream of [seed] from AES block [startBlock] (high tail bits unmasked). */
    @JvmStatic fun prgColumn(seed: ByteArray, startBlock: Long, nwords: Int): IntArray {
        val iv = ByteArray(16)
        for (i in 0 until 8) iv[15 - i] = (startBlock ushr (8 * i)).toByte()
        val c = Cipher.getInstance("AES/CTR/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(prgKey(seed), "AES"), IvParameterSpec(iv))
        return leWords(c.doFinal(ByteArray(nwords * 4)), 0, nwords)
    }

    /** Clears the bits at positions >= nbits in a little-endian word column. */
    @JvmStatic fun maskTail(col: IntArray, nbits: Int) {
        val full = nbits ushr 5
        val rem = nbits and 31
        if (rem != 0) col[full] = col[full] and ((1 shl rem) - 1)
        var i = if (rem != 0) full + 1 else full
        while (i < col.size) {
            col[i] = 0
            i++
        }
    }

    /** In-place transpose of a 32x32 bit matrix held as 32 u32 words from [off]. */
    @JvmStatic fun transpose32(a: IntArray, off: Int) {
        var m = 0x0000ffff
        var j = 16
        while (j != 0) {
            var k = 0
            while (k < 32) {
                val t = ((a[off + k] ushr j) xor a[off + k + j]) and m
                a[off + k] = a[off + k] xor (t shl j)
                a[off + k + j] = a[off + k + j] xor t
                k = (k + j + 1) and j.inv()
            }
            j = j ushr 1
            m = m xor (m shl j)
        }
    }

    /** Transposes COLS bit-columns (each [W] words, concatenated) into [rows] rows of four words. */
    @JvmStatic fun transposeCols(cols: IntArray, W: Int, rows: Int): IntArray {
        val out = IntArray(rows * 4)
        val tmp = IntArray(32)
        val blocks = (rows + 31) ushr 5
        for (rb in 0 until blocks) {
            for (cb in 0 until 4) {
                for (c in 0 until 32) tmp[c] = cols[(cb * 32 + c) * W + rb]
                transpose32(tmp, 0)
                val lim = Math.min(32, rows - rb * 32)
                for (r in 0 until lim) out[(rb * 32 + r) * 4 + cb] = tmp[r]
            }
        }
        return out
    }

    /** acc ^= the four-word element at offset `vo` of `v`. */
    @JvmStatic fun gfXorInto(acc: IntArray, v: IntArray, vo: Int) {
        acc[0] = acc[0] xor v[vo]
        acc[1] = acc[1] xor v[vo + 1]
        acc[2] = acc[2] xor v[vo + 2]
        acc[3] = acc[3] xor v[vo + 3]
    }

    /** acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1). */
    @JvmStatic fun gfMulX(acc: IntArray) {
        val carry = acc[3] ushr 31
        acc[3] = (acc[3] shl 1) or (acc[2] ushr 31)
        acc[2] = (acc[2] shl 1) or (acc[1] ushr 31)
        acc[1] = (acc[1] shl 1) or (acc[0] ushr 31)
        acc[0] = (acc[0] shl 1) xor (if (carry != 0) 0x87 else 0)
    }

    /** XORs into [acc] chi[j] (four words) for every set bit j of the word column `col[off..off+len)`. */
    @JvmStatic fun accumColumn(col: IntArray, off: Int, len: Int, chi: IntArray, acc: IntArray) {
        for (w in 0 until len) {
            var x = col[off + w]
            val base = w shl 5
            while (x != 0) {
                val j = base + x.countTrailingZeroBits()
                val o = j shl 2
                acc[0] = acc[0] xor chi[o]
                acc[1] = acc[1] xor chi[o + 1]
                acc[2] = acc[2] xor chi[o + 2]
                acc[3] = acc[3] xor chi[o + 3]
                x = x and (x - 1)
            }
        }
    }

    /** sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns: the KOS combination of both roles. */
    @JvmStatic fun kosCombine(cols: IntArray, W: Int, chi: IntArray): IntArray {
        val acc = IntArray(4)
        val part = IntArray(4)
        for (i in COLS - 1 downTo 0) {
            gfMulX(acc)
            part.fill(0)
            accumColumn(cols, i * W, W, chi, part)
            gfXorInto(acc, part, 0)
        }
        return acc
    }

    @JvmStatic fun gfFromBig(v: BigInteger): IntArray = IntArray(4) { i -> v.shiftRight(32 * i).toInt() }

    @JvmStatic @JvmOverloads fun gfToBig(w: IntArray, off: Int = 0): BigInteger {
        var v = BigInteger.ZERO
        for (i in 3 downTo 0) v = v.shiftLeft(32).or(BigInteger.valueOf(w[off + i].toLong() and 0xffffffffL))
        return v
    }

    private fun crhKey(): ByteArray {
        val md = sha256()
        md.update(TAG_CRH_KEY)
        return md.digest().copyOf(16)
    }

    private fun aesEcb(buf: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(crhKey(), "AES"))
        return c.doFinal(buf)
    }

    /** The 64-bit session domain of a channel: SHA-256(tag, binding)[0..8] as two little-endian words. */
    @JvmStatic fun otTweakDomain(binding: ByteArray): IntArray {
        val md = sha256()
        md.update(TAG_TWEAK_DOMAIN)
        md.update(binding)
        return leWords(md.digest(), 0, 2)
    }

    /** Tweak of a hash call: channel-global row offset plus the 2-word session domain. */
    class OtTweak(val offset: Long, val domain: IntArray)

    /** H(tweak, row_j) for n rows of four words: two u32 words per row (the low 64 bits of the TMMO hash). */
    @JvmStatic fun tmmoCrh(rows: IntArray, n: Int, tweak: OtTweak?): IntArray {
        val offset = tweak?.offset ?: 0L
        val dom = tweak?.domain ?: IntArray(2)
        require(!(offset < 0 || offset > (1L shl 53) - 1)) { "tmmoCrh: tweak offset must be a non-negative safe integer" }
        require(dom.size == 2) { "tmmoCrh: tweak domain must be 2 words" }
        val a = aesEcb(leBytes(rows, n * 4))
        val aw = leWords(a, 0, n * 4)
        val b = IntArray(n * 4)
        for (j in 0 until n) {
            val o = j * 4
            val v = offset + j
            b[o] = aw[o] xor v.toInt()
            b[o + 1] = aw[o + 1] xor (v ushr 32).toInt()
            b[o + 2] = aw[o + 2] xor dom[0]
            b[o + 3] = aw[o + 3] xor dom[1]
        }
        val cw = leWords(aesEcb(leBytes(b, n * 4)), 0, n * 4)
        val out = IntArray(n * 2)
        for (j in 0 until n) {
            out[2 * j] = cw[4 * j] xor aw[4 * j]
            out[2 * j + 1] = cw[4 * j + 1] xor aw[4 * j + 1]
        }
        return out
    }

    /** The 64-bit value of the two words at index j of a [tmmoCrh] output. */
    @JvmStatic fun word64(h: IntArray, j: Int): BigInteger =
        BigInteger.valueOf(h[2 * j + 1].toLong() and 0xffffffffL).shiftLeft(32).or(BigInteger.valueOf(h[2 * j].toLong() and 0xffffffffL))

    internal fun wordsFromLeBytes(b: ByteArray, nwords: Int): IntArray = leWords(b, 0, nwords)
}
