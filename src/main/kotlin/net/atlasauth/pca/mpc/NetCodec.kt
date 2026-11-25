package net.atlasauth.pca.mpc

import net.atlasauth.pca.verifier.Json

import java.math.BigInteger
import java.security.MessageDigest
import net.atlasauth.pca.mpc.Ec.Point
import org.bouncycastle.util.encoders.Base64

/**
 * Canonical encodings of the OT-over-network messages (one accepted string per value) and the gadget-seed agreement helpers: strict
 * base64, minimal lowercase hex field elements, subgroup-validated points, and the commitment / signed statement of the gadget seed
 * exchange.
 */
object NetCodec {
    @JvmStatic fun b64(u: ByteArray): String = Base64.toBase64String(u)

    private val B64RE = Regex("^[A-Za-z0-9+/]*={0,2}$")

    /** Strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); [len] < 0 means any length. */
    @JvmStatic fun unb64(s: Any?, len: Int): ByteArray {
        require(s is String && B64RE.matches(s)) { "bad base64" }
        val b: ByteArray = try {
            Base64.decode(s)
        } catch (e: RuntimeException) {
            throw IllegalArgumentException("bad base64")
        }
        require(Base64.toBase64String(b) == s) { "non-canonical base64" }
        require(!(len >= 0 && b.size != len)) { "bad length" }
        return b
    }

    @JvmStatic fun ptJ(p: Point): Map<String, String> {
        val xy = Ec.toAffine(p)
        return linkedMapOf("x" to NetWire.hx(xy[0]), "y" to NetWire.hx(xy[1]))
    }

    private val HEX255 = Regex("^(0|[1-9a-f][0-9a-f]{0,63})$")

    /** Canonical lowercase hex without leading zeros of an element below the curve field prime. */
    @JvmStatic fun hexBig(s: Any?): BigInteger {
        require(s is String && HEX255.matches(s)) { "bad field element" }
        val v = BigInteger(s, 16)
        require(v < Ec.Q) { "non-canonical field element" }
        return v
    }

    /** A point from {x, y} canonical hex, validated to be a non-identity prime-order-subgroup point. */
    @JvmStatic fun jPt(v: Any?): Point {
        require(v is Map<*, *>) { "bad point" }
        val x = hexBig(v["x"])
        val y = hexBig(v["y"])
        val p = Point(x, y, BigInteger.ONE, Ec.modFq(x.multiply(y)))
        Ec.assertInSubgroup(p, "received point")
        return p
    }

    @JvmStatic fun sharingsPerTriple(partners: Int): Int = 3 + 2 * partners

    internal fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xff
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 15])
        }
        return sb.toString()
    }

    /** Commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex. */
    @JvmStatic fun gadgetCommit(sessionId: String, party: Int, seed: ByteArray): String {
        val h = MessageDigest.getInstance("SHA-256")
        h.update("atlas-pca-mpc/gadget-commit".toByteArray(Charsets.UTF_8))
        h.update(Json.utf8(sessionId))
        h.update(Json.utf8(party.toString()))
        h.update(seed)
        return hex(h.digest())
    }

    /** The exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o"). */
    @JvmStatic fun gadgetStatement(sessionId: String, round: String, signer: Int, value: String): ByteArray {
        val arr = listOf<Any?>("atlas-pca-mpc/gadget-sig/v1", sessionId, round, signer, value)
        return Json.utf8(NetWire.stringify(arr))
    }
}
