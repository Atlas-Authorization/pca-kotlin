package net.atlasauth.pca.verifier

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider

/** A small DER writer, keys and certificate templates for the Kill05Cert* tests (keys are generated once, at run time). */
internal object Kill05CertKit {
    const val WRONG_TAG = AttestCert.OSSL_WRONG_TAG
    const val NESTED = AttestCert.OSSL_NESTED
    const val BITS = AttestCert.OSSL_BITS
    const val UNSUPPORTED = AttestCert.OSSL_UNSUPPORTED
    const val OK = "OK"

    val bc = BouncyCastleProvider()

    val p256: KeyPair by lazy { ec("secp256r1") }
    val rsa: KeyPair by lazy { KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.generateKeyPair() }
    val ed: KeyPair by lazy { KeyPairGenerator.getInstance("Ed25519").generateKeyPair() }

    fun ec(curve: String): KeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    fun ecBc(curve: String): KeyPair = KeyPairGenerator.getInstance("EC", bc).also { it.initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    /** The message of the AttErr `f` throws, or "OK" when it returns (any other exception fails the test). */
    fun err(f: () -> Any?): String = try {
        f()
        OK
    } catch (e: AttErr) {
        e.message ?: "<null>"
    }

    fun b(vararg v: Int): ByteArray = ByteArray(v.size) { v[it].toByte() }

    fun cat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) o.write(p)
        return o.toByteArray()
    }

    fun tlv(tag: Int, vararg parts: ByteArray): ByteArray {
        val body = cat(*parts)
        val n = body.size
        val hdr = when {
            n < 0x80 -> b(tag, n)
            n < 0x100 -> b(tag, 0x81, n)
            else -> b(tag, 0x82, n shr 8, n and 0xff)
        }
        return cat(hdr, body)
    }

    fun seq(vararg parts: ByteArray) = tlv(0x30, *parts)

    fun oid(dotted: String): ByteArray {
        val a = dotted.split(".").map { it.toLong() }
        val o = ByteArrayOutputStream()
        o.write((a[0] * 40 + a[1]).toInt())
        for (v in a.drop(2)) {
            var n = 1
            while ((v shr (7 * n)) != 0L) n++
            for (k in n - 1 downTo 0) o.write(((v shr (7 * k)) and 0x7f).toInt() or (if (k > 0) 0x80 else 0))
        }
        return tlv(0x06, o.toByteArray())
    }

    fun int(v: Long) = tlv(0x02, BigInteger.valueOf(v).toByteArray())

    fun int(v: BigInteger) = tlv(0x02, v.toByteArray())

    fun str(tag: Int, s: String) = tlv(tag, s.toByteArray(Charsets.ISO_8859_1))

    fun atv(o: String, value: ByteArray) = seq(oid(o), value)

    fun rdn(vararg atvs: ByteArray) = tlv(0x31, *atvs)

    fun cn(s: String) = seq(rdn(atv("2.5.4.3", tlv(0x0c, s.toByteArray(Charsets.UTF_8)))))

    val VERSION = tlv(0xa0, int(2))
    val ALG = seq(oid("1.2.840.10045.4.3.2"))
    val UTC = str(0x17, "250101000000Z")
    val GEN = str(0x18, "20350101000000Z")
    val VALIDITY = seq(UTC, str(0x17, "350101000000Z"))
    val ISSUER = cn("issuer")
    val SUBJECT = cn("subject")
    val SIG = tlv(0x03, b(0, 1, 2, 3, 4, 5, 6, 7))
    val SPKI: ByteArray by lazy { p256.public.encoded }

    /** The fields of a tbsCertificate, in order; `extra` is appended after the subject public key info. */
    fun tbs(
        version: ByteArray = VERSION,
        serial: ByteArray = int(258),
        alg: ByteArray = ALG,
        issuer: ByteArray = ISSUER,
        validity: ByteArray = VALIDITY,
        subject: ByteArray = SUBJECT,
        spki: ByteArray = SPKI,
        extra: ByteArray = ByteArray(0),
    ): ByteArray = seq(version, serial, alg, issuer, validity, subject, spki, extra)

    fun cert(tbs: ByteArray = tbs(), alg: ByteArray = ALG, sig: ByteArray = SIG): ByteArray = seq(tbs, alg, sig)

    fun ext(o: String, critical: ByteArray?, value: ByteArray): ByteArray =
        if (critical == null) seq(oid(o), tlv(0x04, value)) else seq(oid(o), critical, tlv(0x04, value))

    fun exts(vararg e: ByteArray) = tlv(0xa3, seq(*e))

    fun parse(tbs: ByteArray): String = err { AttestCert.parseCertDer(cert(tbs)) }

    /** A certificate object with just the signature-relevant parts set. */
    fun signed(sigOid: String, params: ByteArray?, signature: ByteArray, tbs: ByteArray): AttestCert.Cert =
        AttestCert.Cert(ByteArray(0), tbs, ByteArray(0), ByteArray(0), ByteArray(0), b(1), sigOid, params, signature, emptyList())

    fun withExts(vararg e: AttestCert.LenientExt): AttestCert.Cert =
        AttestCert.Cert(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0), b(1), "1.2.3", null, ByteArray(0), e.toList())

    fun elem(bytes: ByteArray): AttestCert.Elem = AttestCert.readElem(bytes, 0, bytes.size, 0)
}
