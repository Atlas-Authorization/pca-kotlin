package net.atlasauth.pca.ratchet

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.ratchet.Ristretto.Point
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Prime-order group layer for the homomorphic risk accumulator: ristretto255 (order L, the Ed25519 subgroup order), the two Pedersen
 * generators and the scalar arithmetic mod L. `H` is hash-to-group of a constant label: nobody knows its discrete log to `G`.
 */
internal object Group {
    val L: BigInteger = Ristretto.L
    val G: Point = Ristretto.BASE
    val ZERO: Point = Ristretto.ZERO
    private const val H_LABEL = "atlas-pca-ratchet/pedersen-generator-H/v1"
    val H: Point = Ristretto.hashToCurve(sha512(utf8(H_LABEL)))
    private val RNG = SecureRandom()

    fun utf8(s: String): ByteArray = Json.utf8(s)

    fun sha512(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(b)

    fun mod(x: BigInteger): BigInteger = x.mod(L)
    fun scalarAdd(a: BigInteger, b: BigInteger): BigInteger = Ristretto.scalarAdd(a, b)
    fun scalarSub(a: BigInteger, b: BigInteger): BigInteger = Ristretto.scalarSub(a, b)
    fun scalarMul(a: BigInteger, b: BigInteger): BigInteger = Ristretto.scalarMul(a, b)

    /** k*P with k reduced mod L; k = 0 gives the identity, with no branch on the scalar. */
    fun mul(p: Point, k: BigInteger): Point = p.multiply(mod(k))

    fun add(a: Point, b: Point): Point = a.add(b)
    fun sub(a: Point, b: Point): Point = a.subtract(b)

    /** A uniformly random non-zero scalar in [1, L). */
    fun randScalar(): BigInteger {
        while (true) {
            val b = ByteArray(64)
            RNG.nextBytes(b)
            val s = mod(Ristretto.fromLe(b, false))
            if (s.signum() != 0) return s
        }
    }

    /** Little-endian bytes of a non-negative integer; throws when it does not fit. */
    fun numberToBytesLE(n: BigInteger, len: Int): ByteArray {
        if (n.signum() < 0) throw IllegalArgumentException("numberToBytesLE: negative")
        if (n.bitLength() > 8 * len) throw IllegalArgumentException("numberToBytesLE: overflow")
        val out = ByteArray(len)
        for (i in 0 until len) out[i] = n.shiftRight(8 * i).toInt().toByte()
        return out
    }

    fun encodePoint(p: Point): String = Keys.b64u(p.toRawBytes())

    /** Decode a wire point; throws on non-canonical base64url, a length other than 32 bytes, or a non-canonical / invalid ristretto encoding. */
    fun decodePoint(s: Any?): Point {
        val b = Pca.decodeB64uStrict(s, 32) ?: throw IllegalArgumentException("decodePoint: not a canonical 32-byte base64url string")
        return Ristretto.decode(b)
    }

    fun encodeScalar(k: BigInteger): String = Keys.b64u(numberToBytesLE(mod(k), 32))

    /** Decode a wire scalar. Strict: canonical base64url, exactly 32 bytes, value below L (reducing would make every proof malleable). */
    fun decodeScalar(s: Any?): BigInteger {
        val b = Pca.decodeB64uStrict(s, 32) ?: throw IllegalArgumentException("decodeScalar: not a canonical 32-byte base64url string")
        val v = Ristretto.fromLe(b, false)
        if (v >= L) throw IllegalArgumentException("decodeScalar: non-canonical scalar (>= L)")
        return v
    }

    /** SHA-512 of the length-prefixed (4-byte big-endian) concatenation of the parts, reduced mod L. */
    fun hashToScalar(vararg parts: ByteArray): BigInteger {
        val buf = ByteArrayOutputStream()
        for (p in parts) {
            buf.write((p.size ushr 24) and 0xff)
            buf.write((p.size ushr 16) and 0xff)
            buf.write((p.size ushr 8) and 0xff)
            buf.write(p.size and 0xff)
            buf.write(p, 0, p.size)
        }
        return mod(Ristretto.fromLe(sha512(buf.toByteArray()), false))
    }
}
