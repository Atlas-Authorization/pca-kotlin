package net.atlasauth.pca.mpc

import java.math.BigInteger
import java.security.MessageDigest
import net.atlasauth.pca.ratchet.Libsodium

/**
 * A small prime-order group for the base oblivious transfer: Ed25519 (twisted Edwards, q = 2^255 - 19), used in its prime-order subgroup
 * (order L). The group law (add, subtract, scalar multiplication, subgroup test) is libsodium's constant-time Ed25519 core, called through
 * the shared libsodium binding on the compressed encoding; nothing of it is written out here. What remains in BigInteger is only the public
 * coordinate codec (affine normalisation, RFC 8032 x-recovery) and the on-curve predicate, which touch no secret. Every point received across
 * the OT trust boundary is validated (on curve, non-identity, [L]P = O).
 */
object Ec {
    @JvmField val Q: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    @JvmField val L: BigInteger = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
    private val TWO: BigInteger = BigInteger.valueOf(2)
    private val D: BigInteger = modFq(BigInteger.valueOf(-121665).multiply(invFq(BigInteger.valueOf(121666))))
    private val SQRT_M1: BigInteger = powFq(TWO, Q.subtract(BigInteger.ONE).shiftRight(2))

    /** A curve point in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, T = XY/Z. */
    class Point(val X: BigInteger, val Y: BigInteger, val Z: BigInteger, val T: BigInteger)

    @JvmField val IDENTITY: Point = Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
    @JvmField val BASE: Point = fromAffine(
        BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
        BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"),
    )

    @JvmStatic fun modFq(x: BigInteger): BigInteger = x.mod(Q)

    private fun invFq(a: BigInteger): BigInteger = powFq(modFq(a), Q.subtract(TWO))

    private fun powFq(b: BigInteger, e: BigInteger): BigInteger = modFq(b).modPow(e, Q)

    @JvmStatic fun fromAffine(x: BigInteger, y: BigInteger): Point {
        val xx = modFq(x)
        val yy = modFq(y)
        return Point(xx, yy, BigInteger.ONE, modFq(xx.multiply(yy)))
    }

    private fun mm(a: BigInteger, b: BigInteger): BigInteger = a.multiply(b).mod(Q)

    private fun binary(sub: Boolean, p1: Point, p2: Point): Point {
        val r = ByteArray(32)
        val rc = if (sub) Libsodium.Ed.crypto_core_ed25519_sub(r, compressPoint(p1), compressPoint(p2))
        else Libsodium.Ed.crypto_core_ed25519_add(r, compressPoint(p1), compressPoint(p2))
        if (rc != 0) throw PointValidationError("point is not on the curve")
        return decompressPoint(r)
    }

    private fun add(p1: Point, p2: Point): Point = binary(false, p1, p2)

    /** Public group addition P + Q (complete on the subgroup). */
    @JvmStatic fun addPoints(p1: Point, p2: Point): Point = add(p1, p2)

    @JvmStatic fun dbl(p: Point): Point = add(p, p)

    /** [k]P with k reduced mod L (k = 0 or P = identity is the identity). P must lie in the prime-order subgroup (libsodium refuses torsion). */
    @JvmStatic fun mul(k: BigInteger, p: Point): Point {
        val s = k.mod(L)
        if (s.signum() == 0 || isIdentity(p)) return IDENTITY
        val r = ByteArray(32)
        if (Libsodium.Ed.crypto_scalarmult_ed25519_noclamp(r, Libsodium.le32(s), compressPoint(p)) != 0) {
            throw PointValidationError("scalar multiplication refused: point not in the prime-order subgroup")
        }
        return decompressPoint(r)
    }

    @JvmStatic fun mulBase(k: BigInteger): Point {
        val s = k.mod(L)
        if (s.signum() == 0) return IDENTITY
        val r = ByteArray(32)
        if (Libsodium.Ed.crypto_scalarmult_ed25519_base_noclamp(r, Libsodium.le32(s)) != 0) throw IllegalStateException("ed25519 base multiplication failed")
        return decompressPoint(r)
    }

    @JvmStatic fun neg(p: Point): Point = sub(IDENTITY, p)

    @JvmStatic fun sub(p1: Point, p2: Point): Point = binary(true, p1, p2)

    /** Affine {x, y} of a point (identity is (0, 1)). */
    @JvmStatic fun toAffine(p: Point): Array<BigInteger> {
        val zinv = invFq(p.Z)
        return arrayOf(modFq(p.X.multiply(zinv)), modFq(p.Y.multiply(zinv)))
    }

    @JvmStatic fun equal(a: Point, b: Point): Boolean =
        modFq(a.X.multiply(b.Z)) == modFq(b.X.multiply(a.Z)) && modFq(a.Y.multiply(b.Z)) == modFq(b.Y.multiply(a.Z))

    private fun feBytes(a: BigInteger): ByteArray {
        val out = ByteArray(32)
        var v = modFq(a)
        val ff = BigInteger.valueOf(0xff)
        for (i in 0 until 32) {
            out[i] = v.and(ff).toInt().toByte()
            v = v.shiftRight(8)
        }
        return out
    }

    /** Canonical 64-byte affine encoding x || y (little-endian field elements), the OT key-derivation input. */
    @JvmStatic fun encodePoint(p: Point): ByteArray {
        val xy = toAffine(p)
        val out = ByteArray(64)
        System.arraycopy(feBytes(xy[0]), 0, out, 0, 32)
        System.arraycopy(feBytes(xy[1]), 0, out, 32, 32)
        return out
    }

    /** Canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255). */
    @JvmStatic fun compressPoint(p: Point): ByteArray {
        val xy = toAffine(p)
        val out = feBytes(xy[1])
        out[31] = ((out[31].toInt() and 0xff) or ((if (xy[0].testBit(0)) 1 else 0) shl 7)).toByte()
        return out
    }

    /** Raised when a received point fails on-curve / subgroup / identity validation. */
    class PointValidationError(message: String) : RuntimeException(message)

    /** Decodes a canonical compressed encoding (RFC 8032 5.1.3 x-recovery). */
    @JvmStatic fun decompressPoint(bytes: ByteArray): Point {
        if (bytes.size != 32) throw PointValidationError("decompressPoint: expected 32 bytes")
        val sign = (bytes[31].toInt() shr 7) and 1
        var y = BigInteger.ZERO
        for (i in 0 until 32) y = y.or(BigInteger.valueOf((bytes[i].toInt() and 0xff).toLong()).shiftLeft(8 * i))
        y = y.clearBit(255)
        if (y >= Q) throw PointValidationError("decompressPoint: non-canonical y (≥ q)")
        val y2 = mm(y, y)
        val u = modFq(y2.subtract(BigInteger.ONE))
        val v = modFq(D.multiply(y2).add(BigInteger.ONE))
        val v3 = mm(mm(v, v), v)
        val v7 = mm(mm(v3, v3), v)
        var x = mm(mm(u, v3), powFq(mm(u, v7), Q.subtract(BigInteger.valueOf(5)).shiftRight(3)))
        val vx2 = mm(v, mm(x, x))
        if (vx2 == modFq(u)) {
            // x is correct as-is
        } else if (vx2 == modFq(u.negate())) {
            x = mm(x, SQRT_M1)
        } else {
            throw PointValidationError("decompressPoint: not on curve")
        }
        if (x.signum() == 0 && sign == 1) throw PointValidationError("decompressPoint: non-canonical sign")
        if ((if (x.testBit(0)) 1 else 0) != sign) x = modFq(Q.subtract(x))
        return fromAffine(x, y)
    }

    /** Whether the extended coordinates lie on the curve (projectively, no inversion). */
    @JvmStatic fun isOnCurve(p: Point): Boolean {
        if (modFq(p.Z).signum() == 0) return false
        if (modFq(p.T.multiply(p.Z)) != modFq(p.X.multiply(p.Y))) return false
        val x2 = mm(p.X, p.X)
        val y2 = mm(p.Y, p.Y)
        val z2 = mm(p.Z, p.Z)
        val lhs = modFq(y2.subtract(x2).multiply(z2))
        val z4 = mm(z2, z2)
        val dxy = mm(mm(D, x2), y2)
        return lhs == modFq(z4.add(dxy))
    }

    @JvmStatic fun isIdentity(p: Point): Boolean = equal(p, IDENTITY)

    /** The cofactor check [L]P = O (true for the identity too). */
    @JvmStatic fun hasPrimeOrder(p: Point): Boolean {
        if (!isOnCurve(p)) return false
        if (isIdentity(p)) return true
        val b = compressPoint(p)
        // the group law decides: libsodium 1.0.20 and older accept a mixed-order point through is_valid_point (its subgroup test reads only X of L*P)
        return net.atlasauth.pca.ratchet.EdwardsPoint.fromBytes(b).isTorsionFree() && Libsodium.Ed.crypto_core_ed25519_is_valid_point(b) == 1
    }

    /** A valid non-identity point of the prime-order subgroup. */
    @JvmStatic fun isInSubgroup(p: Point): Boolean = isOnCurve(p) && !isIdentity(p) && hasPrimeOrder(p)

    @JvmStatic @JvmOverloads fun assertInSubgroup(p: Point, label: String = "point") {
        if (!isOnCurve(p)) throw PointValidationError("$label: not on curve")
        if (isIdentity(p)) throw PointValidationError("$label: identity element (forbidden here)")
        if (!hasPrimeOrder(p)) throw PointValidationError("$label: not in the prime-order subgroup (small-order/cofactor)")
    }

    /** Fiat-Shamir Schnorr proof of knowledge of y with S = y*B: commitment U = r*B and z = r + e*y. */
    class SchnorrProof(val U: Point, val z: BigInteger)

    private val TAG_SCHNORR = "atlas-pca-mpc/schnorr-dlog".toByteArray(Charsets.UTF_8)

    private fun schnorrChallenge(s: Point, u: Point, ctx: ByteArray): BigInteger {
        val md = MessageDigest.getInstance("SHA-512")
        md.update(TAG_SCHNORR)
        val n = ctx.size
        md.update(byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()))
        md.update(ctx)
        md.update(encodePoint(BASE))
        md.update(encodePoint(s))
        md.update(encodePoint(u))
        return BigInteger(1, md.digest()).mod(L)
    }

    @JvmStatic fun schnorrProve(y: BigInteger, s: Point, rnd: () -> BigInteger, ctx: ByteArray?): SchnorrProof {
        require(!(ctx == null || ctx.isEmpty())) { "schnorrProve: a non-empty session binding is required" }
        val r = rnd().mod(L)
        check(r.signum() != 0) { "schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof" }
        val u = mulBase(r)
        val e = schnorrChallenge(s, u, ctx)
        val z = r.add(e.multiply(y.mod(L))).mod(L)
        return SchnorrProof(u, z)
    }

    @JvmStatic fun schnorrVerify(s: Point, proof: SchnorrProof, ctx: ByteArray?): Boolean {
        if (ctx == null || ctx.isEmpty()) return false
        if (proof.z.signum() < 0 || proof.z >= L) return false
        if (!isInSubgroup(proof.U)) return false
        val e = schnorrChallenge(s, proof.U, ctx)
        return try {
            equal(mulBase(proof.z), add(proof.U, mul(e, s)))
        } catch (err: PointValidationError) {
            false
        }
    }
}
