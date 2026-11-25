package net.atlasauth.pca.ratchet

import java.math.BigInteger

/**
 * Public handle on a ristretto255 group element (RFC 9496), backed by the ratchet package's group implementation, so that other packages
 * (the OPRF) share one group instead of carrying a second copy. Immutable.
 */
class RistrettoElement private constructor(private val p: Ristretto.Point) {
    /** `k * this` for a SECRET-capable scalar: refuses 0 and anything >= the group order (a fixed-iteration ladder, no scalar-dependent branch). */
    fun multiply(k: BigInteger): RistrettoElement {
        if (k.signum() <= 0 || k >= ORDER) throw IllegalArgumentException("expected valid scalar: 1 <= n < order")
        return RistrettoElement(p.multiply(k))
    }

    /** `k * this` for a PUBLIC scalar in [0, order). Same ladder; zero is allowed (gives the identity). */
    fun multiplyPublic(k: BigInteger): RistrettoElement {
        if (k.signum() < 0 || k >= ORDER) throw IllegalArgumentException("expected valid scalar: 0 <= n < order")
        return RistrettoElement(p.multiply(k))
    }

    fun add(o: RistrettoElement): RistrettoElement = RistrettoElement(p.add(o.p))

    fun toRawBytes(): ByteArray = p.toRawBytes()

    fun isIdentity(): Boolean = p.equalsPoint(Ristretto.ZERO)

    fun sameAs(o: RistrettoElement): Boolean = p.equalsPoint(o.p)

    companion object {
        /** The prime group order L. */
        @JvmField val ORDER: BigInteger = Ristretto.L
        @JvmField val ZERO = RistrettoElement(Ristretto.ZERO)
        @JvmField val BASE = RistrettoElement(Ristretto.BASE)

        /** Decode a canonical 32-byte encoding (RFC 9496 section 4.3.1); throws on a wrong length, non-canonical or invalid encoding. The identity is valid here. */
        @JvmStatic fun fromBytes(b: ByteArray): RistrettoElement = RistrettoElement(Ristretto.decode(b))

        /** Inverse mod the group order via libsodium; throws on zero. */
        @JvmStatic fun scalarInvert(s: BigInteger): BigInteger = Ristretto.scalarInvert(s)

        /** The one-way map of 64 uniform bytes (RFC 9496 section 4.3.4). */
        @JvmStatic fun fromUniformBytes(b64: ByteArray): RistrettoElement = RistrettoElement(Ristretto.hashToCurve(b64))
    }
}
