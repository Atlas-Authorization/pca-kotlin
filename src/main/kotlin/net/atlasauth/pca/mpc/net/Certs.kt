package net.atlasauth.pca.mpc.net

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex

/**
 * Identity material for the TLS mesh: one P-256 key and self-signed certificate per node. The key is fresh per run (or derived
 * from a caller seed, for reproducible tests) and the certificate is assembled in DER here and signed by the JDK's ECDSA, so no
 * external tool is needed. The key lives only on the node that generated it; only the PUBLIC certificates are exchanged and pinned.
 */
object Certs {
    /** A node identity: PKCS#8 private key PEM and X.509 certificate PEM. */
    data class Identity(val keyPem: String, val certPem: String)

    private val CN = Regex("[A-Za-z0-9._-]{1,64}")
    private val N = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    /** Generate a throw-away identity for [cn] (valid 2 days). With [seed] the P-256 key is derived from it (the certificate still carries fresh validity and signature randomness). */
    @JvmStatic @JvmOverloads
    fun generate(cn: String, seed: ByteArray? = null): Identity {
        require(CN.matches(cn)) { "certs: bad common name" }
        try {
            val params = AlgorithmParameters.getInstance("EC").also { it.init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            val d: BigInteger = if (seed == null) {
                val raw = ByteArray(48)
                SecureRandom().nextBytes(raw)
                BigInteger(1, raw).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE)
            } else {
                val h = MessageDigest.getInstance("SHA-512").digest(seed + Json.utf8(cn))
                BigInteger(1, h).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE)
            }
            val g = ECNamedCurveTable.getByName("secp256r1").g.multiply(d).normalize()
            val kf = KeyFactory.getInstance("EC")
            val priv = kf.generatePrivate(ECPrivateKeySpec(d, params))
            val pub = kf.generatePublic(ECPublicKeySpec(ECPoint(g.affineXCoord.toBigInteger(), g.affineYCoord.toBigInteger()), params))
            return Identity(pem("PRIVATE KEY", priv.encoded), pem("CERTIFICATE", selfSigned(cn, priv, pub.encoded)))
        } catch (e: Exception) {
            throw IllegalStateException("certs: identity generation failed: " + e.message, e)
        }
    }

    // ---- minimal DER ----
    private fun tlv(tag: Int, body: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(tag)
        val n = body.size
        when {
            n < 0x80 -> o.write(n)
            n < 0x100 -> { o.write(0x81); o.write(n) }
            else -> { o.write(0x82); o.write(n ushr 8); o.write(n and 0xff) }
        }
        o.write(body, 0, body.size)
        return o.toByteArray()
    }

    private fun seq(vararg parts: ByteArray): ByteArray = tlv(0x30, parts.fold(ByteArray(0)) { a, b -> a + b })
    private fun oid(vararg arcs: Int): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(arcs[0] * 40 + arcs[1])
        for (i in 2 until arcs.size) {
            var v = arcs[i]
            val tmp = ArrayList<Int>()
            tmp.add(v and 0x7f)
            v = v ushr 7
            while (v > 0) { tmp.add((v and 0x7f) or 0x80); v = v ushr 7 }
            for (j in tmp.indices.reversed()) o.write(tmp[j])
        }
        return tlv(0x06, o.toByteArray())
    }

    private fun utcTime(ms: Long): ByteArray {
        val f = SimpleDateFormat("yyMMddHHmmss'Z'")
        f.timeZone = TimeZone.getTimeZone("UTC")
        return tlv(0x17, f.format(Date(ms)).toByteArray(Charsets.US_ASCII))
    }

    private fun extension(oid: ByteArray, value: ByteArray): ByteArray = seq(oid, tlv(0x01, byteArrayOf(0xff.toByte())), tlv(0x04, value))

    private fun selfSigned(cn: String, priv: PrivateKey, spki: ByteArray): ByteArray {
        val sigAlg = seq(oid(1, 2, 840, 10045, 4, 3, 2)) // ecdsa-with-SHA256
        val name = seq(tlv(0x31, seq(oid(2, 5, 4, 3), tlv(0x0c, Json.utf8(cn)))))
        val now = System.currentTimeMillis()
        val serial = ByteArray(16)
        SecureRandom().nextBytes(serial)
        serial[0] = ((serial[0].toInt() and 0x7f) or 0x01).toByte() // positive, minimally encoded
        val exts = seq(
            extension(oid(2, 5, 29, 19), seq()), // basicConstraints CA:FALSE, critical
            extension(oid(2, 5, 29, 15), tlv(0x03, byteArrayOf(0x07, 0x80.toByte()))), // keyUsage digitalSignature, critical
            seq(oid(2, 5, 29, 37), tlv(0x04, seq(oid(1, 3, 6, 1, 5, 5, 7, 3, 1), oid(1, 3, 6, 1, 5, 5, 7, 3, 2)))), // extKeyUsage serverAuth, clientAuth
        )
        val tbs = seq(
            tlv(0xa0, tlv(0x02, byteArrayOf(2))), tlv(0x02, serial), sigAlg, name,
            seq(utcTime(now - 3_600_000L), utcTime(now + 2L * 24 * 3_600_000L)), name, spki, tlv(0xa3, exts),
        )
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(priv)
        s.update(tbs)
        return seq(tbs, sigAlg, tlv(0x03, byteArrayOf(0) + s.sign()))
    }

    private fun pem(label: String, der: ByteArray): String {
        val b64 = Base64.toBase64String(der)
        return "-----BEGIN $label-----\n" + b64.chunked(64).joinToString("\n") + "\n-----END $label-----\n"
    }

    private fun pemBody(pem: String, label: String): ByteArray {
        require(pem.contains("-----BEGIN $label-----")) { "certs: not a $label PEM" }
        val b = pem.replace("-----BEGIN $label-----", "").replace("-----END $label-----", "").replace(Regex("\\s"), "")
        require(b.isNotEmpty()) { "certs: not a $label PEM" }
        return Base64.decode(b)
    }

    @JvmStatic fun parseCert(certPem: String): X509Certificate =
        try {
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(pemBody(certPem, "CERTIFICATE"))) as X509Certificate
        } catch (e: Exception) {
            throw IllegalArgumentException("certs: bad certificate: " + e.message, e)
        }

    @JvmStatic fun parseKey(keyPem: String): PrivateKey =
        try {
            KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pemBody(keyPem, "PRIVATE KEY")))
        } catch (e: Exception) {
            throw IllegalArgumentException("certs: bad private key (PKCS#8 EC expected)", e)
        }

    /** SHA-256 fingerprint of a DER certificate, lowercase hex. */
    @JvmStatic fun fingerprint(c: X509Certificate): String =
        try {
            Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(c.encoded))
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

    @JvmStatic fun fingerprintOf(certPem: String): String = fingerprint(parseCert(certPem))
}
