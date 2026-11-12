package net.atlasauth.pca.verifier

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** Keys, a tiny DER certificate writer and compact-JWS signing for the Kill05Jws* tests (keys are generated at run time). */
internal object Kill05JwsKit {
    const val NOW = 1_800_000_000_000L
    val BINDING = Attest.Binding("holder-key", "passport:abc", 0.0, "nonce-1")
    val MRTD = "ab".repeat(48)
    val RD: String by lazy { AttestUtil.hex(Attest.bindingBytes(BINDING)) }

    fun ecKey(curve: String): KeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    fun rsaKey(): KeyPair = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.generateKeyPair()

    fun otherKey(alg: String): KeyPair = KeyPairGenerator.getInstance(alg).generateKeyPair()

    fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    fun seg(json: String): String = b64u(json.toByteArray(Charsets.UTF_8))

    fun std(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    fun pem(der: ByteArray): String = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(der) + "\n-----END CERTIFICATE-----\n"

    fun pin(pub: PublicKey): String = AttestUtil.hex(AttestUtil.sha256(pub.encoded))

    fun json(v: Any?): String = Json.canonicalize(v)

    @Suppress("UNCHECKED_CAST")
    fun obj(text: String): MutableMap<String, Any?> = LinkedHashMap(Json.parseLenient(text) as Map<String, Any?>)

    /** Big-endian unsigned, left-padded / truncated to `len` bytes. */
    fun unsigned(v: BigInteger, len: Int): ByteArray {
        val b = v.toByteArray()
        val out = ByteArray(len)
        val skip = if (b.size > len) b.size - len else 0
        System.arraycopy(b, skip, out, len - (b.size - skip), b.size - skip)
        return out
    }

    // ---- DER ----

    private fun cat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) o.write(p)
        return o.toByteArray()
    }

    fun tlv(tag: Int, vararg parts: ByteArray): ByteArray {
        val body = cat(*parts)
        val n = body.size
        val hdr = when {
            n < 0x80 -> byteArrayOf(tag.toByte(), n.toByte())
            n < 0x100 -> byteArrayOf(tag.toByte(), 0x81.toByte(), n.toByte())
            else -> byteArrayOf(tag.toByte(), 0x82.toByte(), (n shr 8).toByte(), n.toByte())
        }
        return cat(hdr, body)
    }

    private fun seq(vararg parts: ByteArray) = tlv(0x30, *parts)

    private fun oid(dotted: String): ByteArray {
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

    private fun integer(v: Long) = tlv(0x02, BigInteger.valueOf(v).toByteArray())

    private fun name(cn: String) = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c, cn.toByteArray(Charsets.UTF_8)))))

    private val SIG_ALG = seq(oid("1.2.840.10045.4.3.2"))

    /** A v3 certificate for `subject` (any key type), signed by `signer` (EC, ECDSA / SHA-256), valid 2025-01-01 .. 2035-01-01. */
    /** BasicConstraints CA:TRUE, critical: what the strict chain profile asks of an issuer. */
    val CA_BC: ByteArray = seq(oid("2.5.29.19"), tlv(0x01, byteArrayOf(-1)), tlv(0x04, seq(tlv(0x01, byteArrayOf(-1)))))

    fun cert(subjectCn: String, issuerCn: String, subject: PublicKey, signer: KeyPair, vararg exts: ByteArray): ByteArray {
        val validity = seq(tlv(0x17, "250101000000Z".toByteArray(Charsets.US_ASCII)), tlv(0x17, "350101000000Z".toByteArray(Charsets.US_ASCII)))
        val extBlock = if (exts.isEmpty()) ByteArray(0) else tlv(0xa3, seq(*exts))
        val tbs = seq(tlv(0xa0, integer(2)), integer(258), SIG_ALG, name(issuerCn), validity, name(subjectCn), subject.encoded, extBlock)
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(signer.private)
        s.update(tbs)
        return seq(tbs, SIG_ALG, tlv(0x03, byteArrayOf(0), s.sign()))
    }

    // ---- compact JWS ----

    /** ES256 over b64u(header).b64u(payload) with a P-256 key: the DER signature re-encoded as raw r || s. */
    fun signEs256(key: KeyPair, header: String, payload: String): String {
        val input = seg(header) + "." + seg(payload)
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(key.private)
        s.update(input.toByteArray(Charsets.UTF_8))
        val der = s.sign()
        // SEQUENCE (one length byte for P-256) { INTEGER r, INTEGER s }
        val rl = der[3].toInt() and 0xff
        val r = BigInteger(1, der.copyOfRange(4, 4 + rl))
        val sl = der[5 + rl].toInt() and 0xff
        val sv = BigInteger(1, der.copyOfRange(6 + rl, 6 + rl + sl))
        return input + "." + b64u(unsigned(r, 32) + unsigned(sv, 32))
    }

    fun signRs256(key: KeyPair, header: String, payload: String): String {
        val input = seg(header) + "." + seg(payload)
        val s = Signature.getInstance("SHA256withRSA")
        s.initSign(key.private)
        s.update(input.toByteArray(Charsets.UTF_8))
        return input + "." + b64u(s.sign())
    }

    fun unsignedJwt(header: String, payload: String): String = seg(header) + "." + seg(payload) + ".AA"
}
