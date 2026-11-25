package net.atlasauth.pca.ratchet

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Public handle on an Edwards25519 point (the Ed25519 group, RFC 8032 encoding) over libsodium's constant-time Ed25519 core ([Libsodium]),
 * so other packages (FROST) share one vetted curve implementation. A point is its canonical 32-byte encoding. Immutable. Unlike
 * [RistrettoElement], equality here is true point equality and decoding is the strict Ed25519 one.
 */
class EdwardsPoint private constructor(private val e: ByteArray) {
    fun add(o: EdwardsPoint): EdwardsPoint {
        val r = ByteArray(32)
        if (Libsodium.Ed.crypto_core_ed25519_add(r, e, o.e) != 0) throw IllegalStateException("ed25519 add failed")
        return EdwardsPoint(r)
    }

    /**
     * `k * this` for 0 <= k < 2^256, reduced mod L (zero or the identity gives the identity). Valid for a torsion-free point (libsodium refuses
     * any other); every caller multiplies the base point or a point already checked with [isTorsionFree].
     */
    fun multiply(k: BigInteger): EdwardsPoint {
        if (k.signum() < 0 || k.bitLength() > 256) throw IllegalArgumentException("scalar out of range")
        val s = k.mod(ORDER)
        if (s.signum() == 0 || isIdentity()) return ZERO
        val r = ByteArray(32)
        if (Libsodium.Ed.crypto_scalarmult_ed25519_noclamp(r, Libsodium.le32(s), e) != 0) {
            throw IllegalArgumentException("ed25519: scalar multiplication refused (point has a torsion component)")
        }
        return EdwardsPoint(r)
    }

    /** True point equality (not the ristretto coset equality): encodings are canonical. */
    fun sameAs(o: EdwardsPoint): Boolean = MessageDigest.isEqual(e, o.e)

    fun isIdentity(): Boolean = sameAs(ZERO)

    /** 8 * P is the identity (three doublings through libsodium's add, which accepts torsion points). */
    fun isSmallOrder(): Boolean {
        var q = this
        repeat(3) { q = q.add(q) }
        return q.isIdentity()
    }

    /** L * P is the identity, computed by double-and-add over the group add (which accepts torsion points) and also required of libsodium's own subgroup test. */
    fun isTorsionFree(): Boolean {
        if (isIdentity()) return true
        if (Libsodium.Ed.crypto_core_ed25519_is_valid_point(e) != 1) return false
        var acc = ZERO
        for (i in ORDER.bitLength() - 1 downTo 0) {
            acc = acc.add(acc)
            if (ORDER.testBit(i)) acc = acc.add(this)
        }
        return acc.isIdentity()
    }

    /** The canonical 32-byte Ed25519 encoding. */
    fun toBytes(): ByteArray = e.clone()

    companion object {
        private val ID: ByteArray = ByteArray(32).also { it[0] = 1 }

        /** The prime order L of the Ed25519 base-point subgroup. */
        @JvmField val ORDER: BigInteger = Ristretto.L
        @JvmField val ZERO = EdwardsPoint(ID)
        @JvmField val BASE: EdwardsPoint = run {
            val r = ByteArray(32)
            if (Libsodium.Ed.crypto_scalarmult_ed25519_base_noclamp(r, Libsodium.le32(BigInteger.ONE)) != 0) throw IllegalStateException("ed25519 base failed")
            EdwardsPoint(r)
        }

        /**
         * Decode a canonical 32-byte Ed25519 point encoding (RFC 8032 section 5.1.3): throws on a wrong length, a point off the curve, or any
         * non-canonical encoding (y >= p, x = 0 with the sign bit set), checked by round-tripping through libsodium. Torsion (small / mixed
         * order) is NOT checked here; see [isSmallOrder] and [isTorsionFree].
         */
        @JvmStatic
        fun fromBytes(b: ByteArray?): EdwardsPoint {
            if (b == null || b.size != 32) throw IllegalArgumentException("ed25519: point must be 32 bytes")
            val r = ByteArray(32)
            if (Libsodium.Ed.crypto_core_ed25519_add(r, b, ID) != 0) throw IllegalArgumentException("ed25519: point is not on the curve")
            if (!r.contentEquals(b)) throw IllegalArgumentException("ed25519: non-canonical point encoding")
            return EdwardsPoint(r)
        }
    }
}
