package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * Certificates as the reference's X.509 engine (OpenSSL through node:crypto) reads them. The JDK parsers refuse a certificate
 * for many reasons OpenSSL does not (a trailing byte after a DER certificate, a non-minimal length, a duplicated or ill-formed
 * extension, a second extensions block), and those are precisely the inputs on which the strict readers of the attestation
 * verifiers must give their own, specific answer. So a certificate is parsed here with the structure checks of the OpenSSL
 * template decoder (nothing more), the strict rules are applied afterwards by [AttestDer], and the JCA is used only for what it
 * is good at: public keys and signature verification.
 */
internal object AttestCert {
    const val OSSL_WRONG_TAG = "error:068000A8:asn1 encoding routines::wrong tag"
    const val OSSL_NESTED = "error:0688010A:asn1 encoding routines::nested asn1 error"
    const val OSSL_BITS = "error:0680007D:asn1 encoding routines::invalid bit string bits left"
    const val OSSL_OBJECT = "error:0688010A:asn1 encoding routines::invalid object encoding"
    const val OSSL_UNSUPPORTED = "error:1E08010C:DECODER routines::unsupported"

    /** A certificate's raw parts the verifiers compare, and the parameters of its signature. */
    class Cert(
        val raw: ByteArray,
        val rawTbs: ByteArray,
        val rawIssuer: ByteArray,
        val rawSubject: ByteArray,
        val rawSpki: ByteArray,
        val serial: ByteArray,
        val sigOid: String,
        val sigParams: ByteArray?,
        val signature: ByteArray,
        val exts: List<LenientExt>,
    ) {
        fun selfIssued(): Boolean = rawSubject.contentEquals(rawIssuer)

        /** The serial number as lowercase hex without leading zeros. */
        fun serialHex(): String = AttestUtil.hex(serial).trimStart('0')

        fun extValue(oid: String): ByteArray? = exts.firstOrNull { it.oid == oid }?.value

        /** The OCSP responder URLs of the Authority Information Access extension. */
        fun ocspServers(): List<String> {
            val v = extValue("1.3.6.1.5.5.7.1.1") ?: return emptyList()
            return try {
                val seq = readElem(v, 0, v.size, 0x30)
                val out = ArrayList<String>()
                for (d in kids(v, seq)) {
                    try {
                        val parts = kids(v, d)
                        if (parts.size != 2 || parts[0].tag != 0x06) continue
                        val method = AttestDer.oidToDotted(v, AttestDer.Tlv(parts[0].tag, parts[0].start, parts[0].end))
                        if (method != "1.3.6.1.5.5.7.48.1" || parts[1].tag != 0x86) continue
                        out.add(String(v, parts[1].start, parts[1].end - parts[1].start, Charsets.ISO_8859_1))
                    } catch (e: AttErr) {
                        continue
                    }
                }
                out
            } catch (e: AttErr) {
                emptyList()
            }
        }

        /** The extended key usage extension lists id-kp-OCSPSigning. */
        fun hasOcspSigningEku(): Boolean {
            val v = extValue("2.5.29.37") ?: return false
            return try {
                val seq = readElem(v, 0, v.size, 0x30)
                for (p in kids(v, seq)) {
                    try {
                        if (AttestDer.oidToDotted(v, AttestDer.Tlv(p.tag, p.start, p.end)) == "1.3.6.1.5.5.7.3.9") return true
                    } catch (e: AttErr) {
                        continue
                    }
                }
                false
            } catch (e: AttErr) {
                false
            }
        }
    }

    class LenientExt(val oid: String, val critical: Boolean, val value: ByteArray)

    class Elem(val tag: Int, val hdr: Int, val start: Int, val end: Int)

    fun readElem(b: ByteArray, off: Int, limit: Int, tag: Int): Elem {
        if (off >= limit) throw AttErr("error:0680007B:asn1 encoding routines::not enough data")
        val t = try {
            AttestDer.tlvAt(b, off, limit)
        } catch (e: AttErr) {
            throw AttErr(OSSL_NESTED)
        }
        if (tag != 0 && t.tag != tag) throw AttErr(OSSL_WRONG_TAG)
        return Elem(t.tag, off, t.start, t.end)
    }

    fun kids(b: ByteArray, e: Elem): List<Elem> {
        val out = ArrayList<Elem>()
        var p = e.start
        while (p < e.end) {
            val k = readElem(b, p, e.end, 0)
            out.add(k)
            p = k.end
        }
        return out
    }

    /** The OpenSSL object-identifier content check: not empty, no arc starting with 0x80, no dangling continuation. */
    private fun validOid(b: ByteArray, e: Elem): Boolean {
        if (e.tag != 0x06 || e.end <= e.start || (b[e.end - 1].toInt() and 0x80) != 0) return false
        for (i in e.start until e.end) {
            if ((b[i].toInt() and 0xff) == 0x80 && (i == e.start || (b[i - 1].toInt() and 0x80) == 0)) return false
        }
        return true
    }

    /** Reads `AlgorithmIdentifier { OID, parameters ANY OPTIONAL }`: the dotted OID and the parameters element (header included, null = absent). */
    fun algId(b: ByteArray, e: Elem): Pair<String, ByteArray?> {
        val ks = kids(b, e)
        if (ks.isEmpty() || ks.size > 2 || !validOid(b, ks[0])) throw AttErr(OSSL_NESTED)
        val dotted = try {
            AttestDer.oidToDotted(b, AttestDer.Tlv(ks[0].tag, ks[0].start, ks[0].end))
        } catch (x: AttErr) {
            throw AttErr(OSSL_OBJECT)
        }
        val params = if (ks.size == 2) b.copyOfRange(ks[1].hdr, ks[1].end) else null
        return Pair(dotted, params)
    }

    private fun checkBitString(b: ByteArray, e: Elem) {
        if (e.tag != 0x03 || e.end - e.start < 1) throw AttErr(OSSL_WRONG_TAG)
        if ((b[e.start].toInt() and 0xff) > 7) throw AttErr(OSSL_BITS)
    }

    private val NAME_VALUE_TAGS = setOf(0x0c, 0x12, 0x13, 0x14, 0x16, 0x1c, 0x1e, 0x03, 0x30)

    /** Validates a Name: `SEQUENCE OF SET OF SEQUENCE { OID, string }`. */
    private fun checkName(b: ByteArray, e: Elem) {
        for (rdn in kids(b, e)) {
            if (rdn.tag != 0x31) throw AttErr(OSSL_WRONG_TAG)
            for (atv in kids(b, rdn)) {
                if (atv.tag != 0x30) throw AttErr(OSSL_WRONG_TAG)
                val kv = kids(b, atv)
                if (kv.size != 2 || !validOid(b, kv[0]) || kv[1].tag !in NAME_VALUE_TAGS) throw AttErr(OSSL_NESTED)
            }
        }
    }

    /** Parses a DER certificate like `d2i_X509`: its structure is checked, trailing bytes after it are ignored. */
    fun parseCertDer(der: ByteArray): Cert {
        val outer = readElem(der, 0, der.size, 0x30)
        val tbs = readElem(der, outer.start, outer.end, 0x30)
        val alg = readElem(der, tbs.end, outer.end, 0x30)
        val sig = readElem(der, alg.end, outer.end, 0x03)
        if (sig.end != outer.end) throw AttErr(OSSL_NESTED)
        checkBitString(der, sig)
        val rawTbs = der.copyOfRange(tbs.hdr, tbs.end)
        val signature = der.copyOfRange(sig.start + 1, sig.end)
        val (sigOid, sigParams) = algId(der, alg)

        var p = tbs.start
        if (p < tbs.end && (der[p].toInt() and 0xff) == 0xa0) {
            val v = readElem(der, p, tbs.end, 0xa0)
            val inner = readElem(der, v.start, v.end, 0x02)
            if (inner.end != v.end) throw AttErr(OSSL_NESTED)
            p = v.end
        }
        val serialE = readElem(der, p, tbs.end, 0x02)
        if (serialE.end == serialE.start) throw AttErr("error:0688010A:asn1 encoding routines::illegal zero content")
        val serial = der.copyOfRange(serialE.start, serialE.end)
        p = serialE.end
        val inner = readElem(der, p, tbs.end, 0x30) // signature algorithm
        algId(der, inner)
        p = inner.end
        val issuer = readElem(der, p, tbs.end, 0x30)
        checkName(der, issuer)
        val rawIssuer = der.copyOfRange(issuer.hdr, issuer.end)
        p = issuer.end
        val validity = readElem(der, p, tbs.end, 0x30)
        val times = kids(der, validity)
        if (times.size != 2 || (times[0].tag != 0x17 && times[0].tag != 0x18) || (times[1].tag != 0x17 && times[1].tag != 0x18)) throw AttErr(OSSL_NESTED)
        p = validity.end
        val subject = readElem(der, p, tbs.end, 0x30)
        checkName(der, subject)
        val rawSubject = der.copyOfRange(subject.hdr, subject.end)
        p = subject.end
        val spki = readElem(der, p, tbs.end, 0x30)
        val sk = kids(der, spki)
        if (sk.size != 2 || sk[0].tag != 0x30) throw AttErr(OSSL_NESTED)
        algId(der, sk[0])
        checkBitString(der, sk[1])
        val rawSpki = der.copyOfRange(spki.hdr, spki.end)
        p = spki.end
        for (uid in intArrayOf(0x81, 0x82)) {
            if (p < tbs.end && (der[p].toInt() and 0xff) == uid) {
                val u = readElem(der, p, tbs.end, uid)
                p = u.end
            }
        }
        val exts = ArrayList<LenientExt>()
        if (p < tbs.end && (der[p].toInt() and 0xff) == 0xa3) {
            val wrap = readElem(der, p, tbs.end, 0xa3)
            val seq = readElem(der, wrap.start, wrap.end, 0x30)
            if (seq.end != wrap.end) throw AttErr(OSSL_NESTED)
            for (e in kids(der, seq)) {
                if (e.tag != 0x30) throw AttErr(OSSL_WRONG_TAG)
                val parts = kids(der, e)
                if (parts.size < 2 || parts.size > 3 || !validOid(der, parts[0])) throw AttErr(OSSL_NESTED)
                val oid = try {
                    AttestDer.oidToDotted(der, AttestDer.Tlv(parts[0].tag, parts[0].start, parts[0].end))
                } catch (x: AttErr) {
                    throw AttErr(OSSL_OBJECT)
                }
                var critical = false
                var next = 1
                if (parts.size == 3) {
                    if (parts[1].tag != 0x01 || parts[1].end - parts[1].start != 1) throw AttErr(OSSL_NESTED)
                    critical = der[parts[1].start].toInt() != 0
                    next = 2
                }
                if (parts[next].tag != 0x04) throw AttErr(OSSL_WRONG_TAG)
                exts.add(LenientExt(oid, critical, der.copyOfRange(parts[next].start, parts[next].end)))
            }
            p = wrap.end
        }
        if (p != tbs.end) throw AttErr(OSSL_NESTED)

        // the certificate as DER: the outer length in its minimal form, the content as supplied
        val content = der.copyOfRange(outer.start, outer.end)
        val raw = derLengthHeader(0x30, content.size) + content
        return Cert(raw, rawTbs, rawIssuer, rawSubject, rawSpki, serial, sigOid, sigParams, signature, exts)
    }

    private fun derLengthHeader(tag: Int, n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(tag.toByte(), n.toByte())
        n < 0x100 -> byteArrayOf(tag.toByte(), 0x81.toByte(), n.toByte())
        n < 0x10000 -> byteArrayOf(tag.toByte(), 0x82.toByte(), (n shr 8).toByte(), n.toByte())
        n < 0x1000000 -> byteArrayOf(tag.toByte(), 0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        else -> byteArrayOf(tag.toByte(), 0x84.toByte(), (n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
    }

    private val PEM_BLOCK = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")
    private val PEM_BODY = Regex("-----BEGIN CERTIFICATE-----([\\s\\S]*?)-----END CERTIFICATE-----")

    fun pemCertBlocks(text: String): List<String> = PEM_BLOCK.findAll(text).map { it.value }.toList()

    /** Parses the first certificate block of a PEM text (`PEM_read_bio_X509_AUX`: bytes after the certificate inside the block are an error). */
    fun certFromPem(text: String): Cert {
        val m = PEM_BODY.find(text) ?: throw AttErr("error:0480006C:PEM routines::no start line")
        val body = StringBuilder()
        for (ch in m.groupValues[1]) if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') body.append(ch)
        val der = AttestUtil.base64Std(body.toString()) ?: throw AttErr(OSSL_UNSUPPORTED)
        val c = parseCertDer(der)
        val outer = readElem(der, 0, der.size, 0x30)
        if (outer.end != der.size) throw AttErr(OSSL_NESTED)
        return c
    }

    // ---- certificate names (OpenSSL's multi-line rendering) ----

    private val DN_SHORT_NAMES = mapOf(
        "2.5.4.3" to "CN", "2.5.4.6" to "C", "2.5.4.7" to "L", "2.5.4.8" to "ST", "2.5.4.10" to "O", "2.5.4.11" to "OU",
        "2.5.4.5" to "serialNumber", "2.5.4.9" to "street", "2.5.4.17" to "postalCode", "2.5.4.4" to "SN", "2.5.4.42" to "GN",
        "2.5.4.12" to "title", "2.5.4.46" to "dnQualifier", "1.2.840.113549.1.9.1" to "emailAddress",
        "0.9.2342.19200300.100.1.25" to "DC", "0.9.2342.19200300.100.1.1" to "UID",
    )

    private fun escapeDnValue(s: String): String {
        val sb = StringBuilder()
        val cps = ArrayList<Int>()
        var k = 0
        while (k < s.length) {
            val cp = s.codePointAt(k)
            cps.add(cp)
            k += Character.charCount(cp)
        }
        for ((i, r) in cps.withIndex()) {
            when {
                r == ','.code || r == '+'.code || r == '"'.code || r == '\\'.code || r == '<'.code || r == '>'.code || r == ';'.code -> {
                    sb.append('\\')
                    sb.appendCodePoint(r)
                }
                (i == 0 && (r == ' '.code || r == '#'.code)) || (i == cps.size - 1 && r == ' '.code) -> {
                    sb.append('\\')
                    sb.appendCodePoint(r)
                }
                r < 0x20 || r == 0x7f -> sb.append(String.format("\\%02X", r))
                else -> sb.appendCodePoint(r)
            }
        }
        return sb.toString()
    }

    /** `asn1.Unmarshal` of a string-typed AttributeValue: the text, or null for a tag the reference cannot read. */
    private fun atvString(b: ByteArray, e: Elem): String? {
        val raw = b.copyOfRange(e.start, e.end)
        return when (e.tag) {
            0x0c -> String(raw, Charsets.UTF_8)
            0x13 -> if (raw.all { printable(it.toInt() and 0xff) }) String(raw, Charsets.ISO_8859_1) else null
            0x16 -> if (raw.all { (it.toInt() and 0xff) < 0x80 }) String(raw, Charsets.ISO_8859_1) else null
            0x14 -> String(raw, Charsets.ISO_8859_1)
            0x12 -> if (raw.all { val c = it.toInt() and 0xff; (c in '0'.code..'9'.code) || c == ' '.code }) String(raw, Charsets.ISO_8859_1) else null
            0x1e -> if (raw.size % 2 == 0) String(raw, Charsets.UTF_16BE) else null
            else -> null
        }
    }

    private fun printable(c: Int): Boolean =
        (c >= 'a'.code && c <= 'z'.code) || (c >= 'A'.code && c <= 'Z'.code) || (c >= '0'.code && c <= '9'.code) ||
            c == ' '.code || c == '\''.code || c == '('.code || c == ')'.code || c == '+'.code || c == ','.code || c == '-'.code ||
            c == '.'.code || c == '/'.code || c == ':'.code || c == '='.code || c == '?'.code || c == '*'.code

    /** Renders a DER Name the way Node renders a certificate subject / issuer: one `KEY=value` per attribute, in encoded order, joined by newlines; "" when unreadable. */
    fun nameText(raw: ByteArray): String {
        try {
            val top = readElem(raw, 0, raw.size, 0x30)
            if (top.end != raw.size) return ""
            val lines = ArrayList<String>()
            for (set in kids(raw, top)) {
                if (set.tag != 0x31) return ""
                val parts = ArrayList<String>()
                for (atv in kids(raw, set)) {
                    if (atv.tag != 0x30) return ""
                    val kv = kids(raw, atv)
                    if (kv.size != 2 || kv[0].tag != 0x06) return ""
                    val oid = AttestDer.oidToDotted(raw, AttestDer.Tlv(kv[0].tag, kv[0].start, kv[0].end))
                    val key = DN_SHORT_NAMES[oid] ?: oid
                    val v = atvString(raw, kv[1]) ?: return ""
                    parts.add(key + "=" + escapeDnValue(v))
                }
                lines.add(parts.joinToString(" + "))
            }
            return lines.joinToString("\n")
        } catch (e: AttErr) {
            return ""
        }
    }

    // ---- keys and signatures ----

    /** A certificate's public key with the details the rules ask about (Node's asymmetricKeyType / namedCurve). */
    class CertKey(val pub: PublicKey?, val typ: String, val curve: String, val spki: ByteArray, val rawKey: ByteArray? = null) {
        fun spkiSha256(): String = AttestUtil.hex(AttestUtil.sha256(spki))
        fun spkiSha384(): String = AttestUtil.hex(AttestUtil.sha384(spki))
    }

    private const val OID_RSA = "1.2.840.113549.1.1.1"
    private const val OID_RSA_PSS = "1.2.840.113549.1.1.10"
    private const val OID_EC = "1.2.840.10045.2.1"
    private const val OID_ED25519 = "1.3.101.112"

    fun curveOpenSslName(bits: Int): String = when (bits) {
        256 -> "prime256v1"
        384 -> "secp384r1"
        521 -> "secp521r1"
        224 -> "secp224r1"
        else -> "unknown"
    }

    /** The Go curve name of a key's group (`P-256` ...), for the messages the reference words that way. */
    fun goCurveName(k: CertKey): String {
        val ec = k.pub as? ECPublicKey ?: return k.curve
        return when (ec.params.order.bitLength()) {
            256 -> "P-256"
            384 -> "P-384"
            521 -> "P-521"
            224 -> "P-224"
            else -> k.curve
        }
    }

    fun keyInfoOf(pub: PublicKey, spki: ByteArray): CertKey = when (pub) {
        is ECPublicKey -> CertKey(pub, "ec", curveOpenSslName(pub.params.order.bitLength()), spki)
        is RSAPublicKey -> CertKey(pub, "rsa", "", spki)
        else -> CertKey(pub, "unknown", "", spki)
    }

    /** Strict `RSAPublicKey { n, e }` (PKCS#1): positive minimal INTEGERs, nothing after the SEQUENCE. */
    private fun parsePkcs1(b: ByteArray): RSAPublicKey {
        val outer = AttestDer.readTlvStrict(b, 0, b.size)
        if (outer.tag != 0x30 || outer.end != b.size) throw AttErr(OSSL_UNSUPPORTED)
        val n = AttestDer.readTlvStrict(b, outer.start, outer.end)
        val e = AttestDer.readTlvStrict(b, n.end, outer.end)
        if (n.tag != 0x02 || e.tag != 0x02 || e.end != outer.end) throw AttErr(OSSL_UNSUPPORTED)
        fun pos(t: AttestDer.Tlv): BigInteger {
            if (t.end - t.start < 1 || (b[t.start].toInt() and 0x80) != 0) throw AttErr(OSSL_UNSUPPORTED)
            if (t.end - t.start > 1 && b[t.start].toInt() == 0 && (b[t.start + 1].toInt() and 0x80) == 0) throw AttErr(OSSL_UNSUPPORTED)
            return BigInteger(b.copyOfRange(t.start, t.end))
        }
        val modulus = pos(n)
        val exponent = pos(e)
        if (modulus.signum() <= 0 || exponent.signum() <= 0 || exponent.bitLength() > 31) throw AttErr(OSSL_UNSUPPORTED)
        return try {
            KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent)) as RSAPublicKey
        } catch (x: java.security.GeneralSecurityException) {
            throw AttErr(OSSL_UNSUPPORTED)
        }
    }

    /**
     * The certificate's subject public key. An RSASSA-PSS key (which the JDK does not read) is read from its SubjectPublicKeyInfo
     * as the RSAPublicKey it carries.
     */
    fun keyOfCert(c: Cert): CertKey = keyOfSpki(c.rawSpki)

    fun keyOfSpki(spkiDer: ByteArray): CertKey {
        val spki = readElem(spkiDer, 0, spkiDer.size, 0x30)
        val ks = kids(spkiDer, spki)
        if (ks.size != 2) throw AttErr(OSSL_NESTED)
        val (oid, _) = algId(spkiDer, ks[0])
        val bits = spkiDer.copyOfRange(ks[1].start + 1, ks[1].end)
        when (oid) {
            OID_RSA, OID_RSA_PSS -> {
                val rk = parsePkcs1(bits)
                val k = keyInfoOf(rk, spkiDer)
                return if (oid == OID_RSA_PSS) CertKey(rk, "rsa-pss", "", spkiDer) else k
            }
            OID_ED25519 -> {
                if (bits.size != 32) throw AttErr(OSSL_UNSUPPORTED)
                return CertKey(null, "ed25519", "", spkiDer, bits)
            }
            OID_EC -> {
                val pub = try {
                    AttestUtil.ecKeyOf(X509EncodedKeySpec(spkiDer))
                } catch (x: java.security.GeneralSecurityException) {
                    throw AttErr(OSSL_UNSUPPORTED)
                }
                if (pub !is ECPublicKey || !AttestUtil.onCurve(pub.params, pub.w.affineX, pub.w.affineY)) throw AttErr(OSSL_UNSUPPORTED)
                return keyInfoOf(pub, spkiDer)
            }
        }
        throw AttErr(OSSL_UNSUPPORTED)
    }

    private val SIG_HASH_NAMES = mapOf(
        "1.2.840.10045.4.3.2" to "SHA-256",
        "1.2.840.10045.4.3.3" to "SHA-384",
        "1.2.840.10045.4.3.4" to "SHA-512",
        "1.2.840.113549.1.1.11" to "SHA-256",
        "1.2.840.113549.1.1.12" to "SHA-384",
        "1.2.840.113549.1.1.13" to "SHA-512",
    )

    private val HASH_OIDS = mapOf(
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
        "1.3.14.3.2.26" to "SHA-1",
    )

    /** `RSASSA-PSS-params`: the hash, the salt length, and whether the profile is one this verifier checks (MGF1 over the same hash, trailer 1). */
    private fun pssParams(raw: ByteArray?): Triple<String, Int, Boolean> {
        val badP = Triple("", 0, false)
        if (raw == null || raw.isEmpty()) return Triple("SHA-1", 20, true)
        try {
            val seq = readElem(raw, 0, raw.size, 0x30)
            var h = "SHA-1"
            var salt = 20
            var mgfHash = "SHA-1"
            for (k in kids(raw, seq)) {
                val inner = kids(raw, k)
                if (inner.size != 1) return badP
                when (k.tag) {
                    0xa0 -> {
                        val (oid, _) = algId(raw, inner[0])
                        h = HASH_OIDS[oid] ?: return badP
                    }
                    0xa1 -> {
                        val (oid, params) = algId(raw, inner[0])
                        if (oid != "1.2.840.113549.1.1.8" || params == null) return badP
                        val pe = readElem(params, 0, params.size, 0x30)
                        val (hoid, _) = algId(params, pe)
                        mgfHash = HASH_OIDS[hoid] ?: return badP
                    }
                    0xa2, 0xa3 -> {
                        if (inner[0].tag != 0x02) return badP
                        val v = BigInteger(1, raw.copyOfRange(inner[0].start, inner[0].end))
                        if (v.bitLength() > 62 || v.toLong() > (1L shl 20)) return badP
                        if (k.tag == 0xa2) salt = v.toInt() else if (v.toLong() != 1L) return badP
                    }
                    else -> return badP
                }
            }
            return Triple(h, salt, mgfHash == h)
        } catch (e: AttErr) {
            return badP
        }
    }

    private fun jcaHashSuffix(h: String): String = h.replace("-", "")

    /** `X509Certificate.verify(publicKey)`: the certificate's signature under the key (no name or role checks). */
    fun certSigOk(child: Cert, k: CertKey): Boolean = try {
        certSigOkUnchecked(child, k)
    } catch (e: java.security.GeneralSecurityException) {
        false
    } catch (e: RuntimeException) {
        false
    }

    private fun certSigOkUnchecked(child: Cert, k: CertKey): Boolean {
        if (child.sigOid == "1.3.101.112") {
            val raw = k.rawKey
            if (k.typ != "ed25519" || raw == null) return false
            if (child.signature.size != 64) return false
            return Ed25519.verify(child.signature, 0, raw, 0, child.rawTbs, 0, child.rawTbs.size)
        }
        if (child.sigOid == "1.2.840.113549.1.1.10") {
            val pk = k.pub as? RSAPublicKey ?: return false
            val (h, salt, good) = pssParams(child.sigParams)
            if (!good) return false
            val s = Signature.getInstance("RSASSA-PSS")
            s.setParameter(PSSParameterSpec(h, "MGF1", MGF1ParameterSpec(h), salt, 1))
            s.initVerify(pk)
            s.update(child.rawTbs)
            return s.verify(child.signature)
        }
        val h = SIG_HASH_NAMES[child.sigOid] ?: return false
        val pub = k.pub
        if (pub is ECPublicKey) {
            if (!child.sigOid.startsWith("1.2.840.10045.4.3.")) return false
            val digest = java.security.MessageDigest.getInstance(h).digest(child.rawTbs)
            return AttestUtil.verifyDerEcdsa(pub, digest, child.signature)
        }
        if (pub is RSAPublicKey) {
            if (!child.sigOid.startsWith("1.2.840.113549.1.1.")) return false
            val s = Signature.getInstance(jcaHashSuffix(h) + "withRSA")
            s.initVerify(pub)
            s.update(child.rawTbs)
            return s.verify(child.signature)
        }
        return false
    }

    /** [certSigOk] under the subject key of `parent` (false when that key cannot be read). */
    fun certSigOkBy(child: Cert, parent: Cert): Boolean {
        val k = try { keyOfCert(parent) } catch (e: AttErr) { return false }
        return certSigOk(child, k)
    }

    /** The uncompressed SEC1 point of an EC key on exactly the named curve (`P-256` or `P-384`); an [AttErr] otherwise. */
    fun ecPointOfKey(k: CertKey, curveName: String): ByteArray {
        val pk = k.pub as? ECPublicKey
        if (k.typ != "ec" || pk == null) throw AttErr("public key is not EC (got ${k.typ})")
        val want = if (curveName == "P-256") 32 else 48
        val got = goCurveName(k)
        if (got != curveName) throw AttErr("public key is not on $curveName (got $got)")
        val out = ByteArray(1 + 2 * want)
        out[0] = 4
        val x = pk.w.affineX.toByteArray()
        val y = pk.w.affineY.toByteArray()
        for (i in 0 until want) {
            out[1 + want - 1 - i] = if (i < x.size) x[x.size - 1 - i] else 0
            out[1 + 2 * want - 1 - i] = if (i < y.size) y[y.size - 1 - i] else 0
        }
        return out
    }

    /** The subjectPublicKey BIT STRING content of a certificate (without the unused-bits octet). */
    fun spkiKeyBits(c: Cert): ByteArray {
        val spki = readElem(c.rawSpki, 0, c.rawSpki.size, 0x30)
        val ks = kids(c.rawSpki, spki)
        if (ks.size != 2) throw AttErr("malformed SubjectPublicKeyInfo")
        return c.rawSpki.copyOfRange(ks[1].start + 1, ks[1].end)
    }
}
