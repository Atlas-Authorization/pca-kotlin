package net.atlasauth.pca.pairing

import java.math.BigInteger
import java.security.MessageDigest
import supranational.blst.P1
import supranational.blst.P1_Affine
import supranational.blst.P2
import supranational.blst.P2_Affine
import supranational.blst.PT
import supranational.blst.Scalar

/**
 * Thin helpers over blst (via jblst) shared by the pairing-based packages: scalar-field arithmetic mod r on BigInteger,
 * point multiplication by a scalar through blst's own scalar type, RFC 9380 expand_message_xmd (SHA-256), and the
 * canonical decoders. No pairing, field or curve arithmetic is implemented here.
 *
 * shortcut: scalar-field arithmetic (add/mul/inverse) is BigInteger, which is not constant-time. Point multiplication
 * (the expensive, key-dependent part) is blst's constant-time implementation.
 */
object Bls12 {
    /** The prime order r of the BLS12-381 groups. */
    val R: BigInteger = BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

    fun mod(x: BigInteger): BigInteger = x.mod(R)

    fun add(a: BigInteger, b: BigInteger): BigInteger = a.add(b).mod(R)

    fun sub(a: BigInteger, b: BigInteger): BigInteger = a.subtract(b).mod(R)

    fun mul(a: BigInteger, b: BigInteger): BigInteger = a.multiply(b).mod(R)

    /** Fermat inverse x^(r-2) mod r (fixed public exponent). Throws on zero. */
    fun inv(x: BigInteger): BigInteger {
        val v = mod(x)
        if (v.signum() == 0) throw ArithmeticException("inverse of zero")
        return v.modPow(R.subtract(BigInteger.valueOf(2)), R)
    }

    /** I2OSP: non-negative integer to fixed-length big-endian octets; throws when it does not fit. */
    fun i2osp(n: BigInteger, len: Int): ByteArray {
        if (n.signum() < 0 || n.bitLength() > 8 * len) throw IllegalArgumentException("integer does not fit $len octets")
        val be = n.toByteArray()
        val out = ByteArray(len)
        val copy = minOf(len, be.size)
        System.arraycopy(be, be.size - copy, out, len - copy, copy)
        return out
    }

    /** OS2IP: big-endian octets to a non-negative integer. */
    fun os2ip(b: ByteArray): BigInteger = BigInteger(1, b)

    /** A blst scalar from a value in [0, r): the 32-byte big-endian form. */
    fun scalar(s: BigInteger): Scalar = Scalar().from_bendian(i2osp(mod(s), 32))

    /** s * P as a new point (P is not modified); the identity when s is zero mod r. */
    fun mul(p: P1, s: BigInteger): P1 {
        val v = mod(s)
        return if (v.signum() == 0) P1() else p.dup().mult(scalar(v))
    }

    fun mul(p: P2, s: BigInteger): P2 {
        val v = mod(s)
        return if (v.signum() == 0) P2() else p.dup().mult(scalar(v))
    }

    fun add(a: P1, b: P1): P1 = a.dup().add(b)

    fun add(a: P2, b: P2): P2 = a.dup().add(b)

    fun sub(a: P1, b: P1): P1 = a.dup().add(b.dup().neg())

    /** Strict compressed-G1 decoding: compression flag set, canonical, on curve, in the prime-order subgroup. Identity is allowed (check it separately). */
    fun decodeG1(b: ByteArray?): P1 {
        if (b == null || b.size != 48 || (b[0].toInt() and 0x80) == 0) throw IllegalArgumentException("not a 48-byte compressed G1 point")
        try {
            val a = P1_Affine(b)
            if (!a.compress().contentEquals(b) || !a.on_curve() || !a.in_group()) throw IllegalArgumentException("non-canonical or invalid G1 encoding")
            return a.to_jacobian()
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (t: Throwable) {
            fatal(t)
            throw IllegalArgumentException("invalid G1 encoding", t)
        }
    }

    fun decodeG2(b: ByteArray?): P2 {
        if (b == null || b.size != 96 || (b[0].toInt() and 0x80) == 0) throw IllegalArgumentException("not a 96-byte compressed G2 point")
        try {
            val a = P2_Affine(b)
            if (!a.compress().contentEquals(b) || !a.on_curve() || !a.in_group()) throw IllegalArgumentException("non-canonical or invalid G2 encoding")
            return a.to_jacobian()
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (t: Throwable) {
            fatal(t)
            throw IllegalArgumentException("invalid G2 encoding", t)
        }
    }

    /** e(a, x) == e(b, y), by blst's pairing. */
    fun pairingEq(a: P1, x: P2, b: P1, y: P2): Boolean {
        val l = PT(x.to_affine(), a.to_affine())
        val r = PT(y.to_affine(), b.to_affine())
        return PT.finalverify(l, r)
    }

    /** A native-library failure must surface, never be read as "bad input". */
    fun fatal(t: Throwable) {
        if (t is LinkageError || t is VirtualMachineError) throw t
    }

    /** expand_message_xmd with SHA-256 (RFC 9380 5.3.1); the DST must be at most 255 octets. */
    fun expandMessageXmd(msg: ByteArray, dst: ByteArray, len: Int): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        val ell = (len + 31) / 32
        if (ell > 255 || len > 65535 || dst.size > 255 || len < 0) throw IllegalArgumentException("expand_message_xmd: invalid length or DST")
        val dstPrime = dst.copyOf(dst.size + 1)
        dstPrime[dst.size] = dst.size.toByte()
        h.update(ByteArray(64))
        h.update(msg)
        h.update(byteArrayOf((len shr 8).toByte(), len.toByte(), 0))
        h.update(dstPrime)
        val b0 = h.digest()
        h.update(b0)
        h.update(1.toByte())
        h.update(dstPrime)
        var bi = h.digest()
        val out = ByteArray(len)
        System.arraycopy(bi, 0, out, 0, minOf(32, len))
        for (i in 2..ell) {
            val x = ByteArray(32)
            for (k in 0 until 32) x[k] = (b0[k].toInt() xor bi[k].toInt()).toByte()
            h.update(x)
            h.update(i.toByte())
            h.update(dstPrime)
            bi = h.digest()
            val off = (i - 1) * 32
            System.arraycopy(bi, 0, out, off, minOf(32, len - off))
        }
        return out
    }
}
