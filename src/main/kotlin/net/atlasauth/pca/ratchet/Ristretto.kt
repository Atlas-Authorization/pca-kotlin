package net.atlasauth.pca.ratchet

import java.math.BigInteger
import java.security.MessageDigest

/**
 * The ristretto255 prime-order group (RFC 9496), a thin typed wrapper over libsodium ([Libsodium]): the group law, encode / decode and the
 * one-way map are libsodium's constant-time implementation, none of it is written out here. A [Point] is its canonical 32-byte encoding, so
 * group equality is byte equality.
 */
internal object Ristretto {
    /** Order of the prime-order group (the Ed25519 subgroup order). */
    val L: BigInteger = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))

    class Point internal constructor(private val e: ByteArray) {
        fun add(o: Point): Point {
            val r = ByteArray(32)
            if (Libsodium.S.crypto_core_ristretto255_add(r, e, o.e) != 0) throw IllegalStateException("ristretto255 add failed")
            return Point(r)
        }

        fun subtract(o: Point): Point {
            val r = ByteArray(32)
            if (Libsodium.S.crypto_core_ristretto255_sub(r, e, o.e) != 0) throw IllegalStateException("ristretto255 sub failed")
            return Point(r)
        }

        fun negate(): Point = ZERO.subtract(this)

        /** k * this for any 0 <= k < 2^256 (reduced mod L first); a zero scalar or the identity gives the identity, which libsodium itself refuses. */
        fun multiply(k: BigInteger): Point {
            val s = k.mod(L)
            if (s.signum() == 0 || equalsPoint(ZERO)) return ZERO
            val r = ByteArray(32)
            if (Libsodium.S.crypto_scalarmult_ristretto255(r, Libsodium.le32(s), e) != 0) throw IllegalStateException("ristretto255 scalarmult failed")
            return Point(r)
        }

        fun equalsPoint(o: Point): Boolean = MessageDigest.isEqual(e, o.e)

        fun toRawBytes(): ByteArray = e.clone()
    }

    val ZERO = Point(ByteArray(32))

    /** The standard generator (the encoding of the Ed25519 base point). */
    val BASE: Point = run {
        val r = ByteArray(32)
        if (Libsodium.S.crypto_scalarmult_ristretto255_base(r, Libsodium.le32(BigInteger.ONE)) != 0) throw IllegalStateException("ristretto255 base failed")
        Point(r)
    }

    private fun scalar3(op: Int, a: BigInteger, b: BigInteger): BigInteger {
        val r = ByteArray(32)
        val x = Libsodium.le32(a.mod(L))
        val y = Libsodium.le32(b.mod(L))
        when (op) {
            0 -> Libsodium.S.crypto_core_ristretto255_scalar_add(r, x, y)
            1 -> Libsodium.S.crypto_core_ristretto255_scalar_sub(r, x, y)
            else -> Libsodium.S.crypto_core_ristretto255_scalar_mul(r, x, y)
        }
        return Libsodium.fromLe(r)
    }

    fun scalarAdd(a: BigInteger, b: BigInteger): BigInteger = scalar3(0, a, b)
    fun scalarSub(a: BigInteger, b: BigInteger): BigInteger = scalar3(1, a, b)
    fun scalarMul(a: BigInteger, b: BigInteger): BigInteger = scalar3(2, a, b)

    /** Inverse mod L; throws on zero. */
    fun scalarInvert(s: BigInteger): BigInteger {
        val r = ByteArray(32)
        if (Libsodium.S.crypto_core_ristretto255_scalar_invert(r, Libsodium.le32(s.mod(L))) != 0) throw IllegalArgumentException("scalarInvert: inverse of zero")
        return Libsodium.fromLe(r)
    }

    fun le32(n: BigInteger): ByteArray = Libsodium.le32(n)

    fun fromLe(b: ByteArray, maskTop: Boolean): BigInteger {
        val c = b.clone()
        if (maskTop) c[c.size - 1] = (c[c.size - 1].toInt() and 0x7f).toByte()
        return Libsodium.fromLe(c)
    }

    /** Decode a canonical 32-byte ristretto255 encoding (RFC 9496 section 4.3.1); throws on anything non-canonical or invalid. */
    fun decode(b: ByteArray): Point {
        if (b.size != 32) throw IllegalArgumentException("ristretto255: not 32 bytes")
        if (Libsodium.S.crypto_core_ristretto255_is_valid_point(b) != 1) throw IllegalArgumentException("ristretto255: invalid encoding")
        // the native validity check can accept encodings that are not canonical (high bit set, s >= p, negative s): re-encode through a group add and require the same bytes
        val re = ByteArray(32)
        if ((b[31].toInt() and 0x80) != 0 || Libsodium.S.crypto_core_ristretto255_add(re, b, ZERO.toRawBytes()) != 0 || !MessageDigest.isEqual(re, b)) {
            throw IllegalArgumentException("ristretto255: invalid encoding")
        }
        return Point(b.copyOf())
    }

    /** The one-way map from 64 uniform bytes (RFC 9496 section 4.3.4). */
    fun hashToCurve(b64: ByteArray): Point {
        if (b64.size != 64) throw IllegalArgumentException("ristretto255: 64 bytes required")
        val r = ByteArray(32)
        if (Libsodium.S.crypto_core_ristretto255_from_hash(r, b64) != 0) throw IllegalStateException("ristretto255 from_hash failed")
        return Point(r)
    }
}
