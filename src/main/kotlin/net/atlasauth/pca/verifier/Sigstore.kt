package net.atlasauth.pca.verifier

import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URI
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.Base64

/**
 * Offline Sigstore bundle verification for build provenance (track K9; port of `packages/pca-attest-eat/src/sigstore.ts`,
 * replayed on `conformance/sigstore-vectors.json`).
 *
 * Verifies a Sigstore bundle carrying a DSSE in-toto Statement against a pinned `trusted_root.json`, with no network: every
 * RFC 3161 timestamp and the Rekor v1 SET when present (at least one verified time); one Rekor entry (`dsse/0.0.1`,
 * `intoto/0.0.2`, or Rekor v2 `hashedrekord/0.0.2` over the DSSE PAE); RFC 9162 inclusion to a checkpoint signed by the pinned
 * log (Ed25519 signed note under the base-URL host for v2, ECDSA for v1); the certificate path to a pinned Fulcio CA at every
 * verified time, the code-signing EKU, the embedded SCT when the root lists CT logs; the entry body names this envelope; the
 * DSSE signature; the Fulcio identity; the Statement. [verifySigstoreBundle] then reads the SLSA v1 predicate into the facts
 * [ProvenanceGate.provenanceGate] checks. JCA plus the BouncyCastle Ed25519 the module already uses (sigstore-java needs the
 * artifact digest, exposes no verified time sources, and is not an Android dependency). Never throws on a bundle.
 */
@Suppress("UNCHECKED_CAST")
object Sigstore {
    val BUNDLE_MEDIA_TYPES = listOf(
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle.v0.3+json",
    )
    const val INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
    private const val OID_FULCIO = "1.3.6.1.4.1.57264.1."
    private const val OID_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"
    private const val OID_SAN = "2.5.29.17"
    private const val EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
    private const val EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
    private const val OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
    private const val OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
    private const val OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
    private const val OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
    private val DIGEST_OIDS = mapOf("2.16.840.1.101.3.4.2.1" to "sha256", "2.16.840.1.101.3.4.2.2" to "sha384", "2.16.840.1.101.3.4.2.3" to "sha512")
    private const val MAX_SAFE = 9007199254740991L

    // ---- trusted root ----

    /** A pinned log. [v2Name] (the host of its base URL) and [ed25519] are set for Rekor v2 (signed-note) logs. */
    class PinnedLog internal constructor(val keyId: ByteArray, val key: PublicKey?, val ed25519: ByteArray?, val start: Long, val end: Long, val v2Name: String?)
    class PinnedCa internal constructor(val chain: List<X509Certificate>, val start: Long, val end: Long)
    class PinnedRoots internal constructor(val tlogs: List<PinnedLog>, val ctlogs: List<PinnedLog>, val cas: List<PinnedCa>, val tsas: List<PinnedCa>)

    private fun obj(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun objOrEmpty(o: Any?): Map<String, Any?> = obj(o) ?: emptyMap()
    private fun arr(o: Any?): List<Any?> = o as? List<Any?> ?: emptyList()
    private fun at(o: Any?, k: String): Any? = obj(o)?.get(k)
    private fun bad(msg: String): Nothing = throw IllegalArgumentException(msg)

    private val B64 = Regex("[A-Za-z0-9+/]*={0,2}")
    internal fun b64(s: Any?): ByteArray {
        if (s !is String || !B64.matches(s) || s.length % 4 != 0) bad("not base64")
        return Base64.getDecoder().decode(s)
    }

    // RFC 3339 exactly as the reference reads it: seconds required, 'T' and 'Z' upper case, offset +HH:MM, a real date
    private val RFC3339 = Regex("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?(?:Z|[+-]\\d{2}:\\d{2})")

    internal fun rfc3339(v: String, what: String): Long {
        if (!RFC3339.matches(v)) bad(what)
        return try { OffsetDateTime.parse(v).toInstant().toEpochMilli() } catch (x: java.time.DateTimeException) { bad(what) }
    }

    internal fun validity(v: Any?): LongArray {
        val s = at(v, "start") as? String ?: bad("validFor.start missing")
        val e = at(v, "end")
        return longArrayOf(
            rfc3339(s, "validFor.start missing"),
            if (e is String) rfc3339(e, "validFor.end malformed") else Long.MAX_VALUE,
        )
    }

    private fun sha(alg: String, vararg parts: ByteArray): ByteArray {
        val d = MessageDigest.getInstance(alg.uppercase().replace("SHA", "SHA-"))
        for (p in parts) d.update(p)
        return d.digest()
    }

    private fun spki(alg: String, der: ByteArray): PublicKey = KeyFactory.getInstance(alg).generatePublic(X509EncodedKeySpec(der))

    internal fun pinnedLog(t: Any?, transparency: Boolean): PinnedLog? {
        val pk = obj(at(t, "publicKey"))
        if (pk == null || obj(at(t, "logId")) == null) bad("log entry malformed")
        val der = b64(pk["rawBytes"])
        val keyId = b64(at(at(t, "logId"), "keyId"))
        val v = validity(pk["validFor"])
        return when (pk["keyDetails"]) {
            "PKIX_ECDSA_P256_SHA_256" -> {
                if (!sha("sha256", der).contentEquals(keyId)) bad("log id is not the SHA-256 of its key")
                PinnedLog(keyId, spki("EC", der), null, v[0], v[1], null)
            }
            "PKCS1_RSA_PKCS1V5" -> {
                if (transparency) return null
                try { AttestCert.parsePkcs1(der) } catch (x: AttErr) { bad("RSA log key is out of range") }
                // PKCS#1 RSAPublicKey -> SPKI {rsaEncryption, NULL}
                val alg = byteArrayOf(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)
                val s = enc(0x30, cat(alg, enc(0x03, byteArrayOf(0) + der)))
                if (!sha("sha256", s).contentEquals(keyId)) bad("log id is not the SHA-256 of its key")
                PinnedLog(keyId, spki("RSA", s), null, v[0], v[1], null)
            }
            "PKIX_ED25519" -> {
                if (!transparency) return null
                // SPKI {id-Ed25519} || BIT STRING of 32 bytes
                if (der.size != 44 || !der.copyOfRange(0, 12).contentEquals(byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00))) bad("not an Ed25519 key")
                val raw = der.copyOfRange(12, 44)
                val name = (at(t, "baseUrl") as? String)?.let { urlHostname(it) } ?: ""
                if (name.isEmpty() || !sha("sha256", "$name\n".toByteArray(Charsets.UTF_8), byteArrayOf(1), raw).contentEquals(keyId)) bad("log id is not the signed-note key hash of its key")
                PinnedLog(keyId, null, raw, v[0], v[1], name)
            }
            else -> null
        }
    }

    /**
     * The reference's `new URL(u).hostname`: WHATWG preprocessing (leading / trailing C0 controls and spaces stripped, tab / CR / LF
     * removed anywhere), then the host, lower-cased. Throws on a URL with no host.
     */
    internal fun urlHostname(u: String): String {
        val t = u.replace(Regex("^[\\x00-\\x20]+|[\\x00-\\x20]+$"), "").replace(Regex("[\\t\\n\\r]"), "")
        val h = URI.create(t).host ?: bad("Invalid URL") // java.net.URI never reports an empty host: no host is null
        return h.lowercase(java.util.Locale.ROOT)
    }

    internal fun x509(der: ByteArray): X509Certificate = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    internal fun pinnedChain(c: Any?): PinnedCa {
        val certs = arr(at(at(c, "certChain"), "certificates"))
        if (certs.isEmpty()) bad("certificate authority entry malformed")
        val v = validity(at(c, "validFor"))
        return PinnedCa(certs.map { x509(b64(at(it, "rawBytes"))) }, v[0], v[1])
    }

    /**
     * Parse a Sigstore `trusted_root.json` (v0.1) tree ([Json.parseLenient]): transparency logs, CT logs, Fulcio CAs and
     * timestamp authorities. Throws IllegalArgumentException on anything malformed. A root with no CT log does not require SCTs.
     */
    fun parseTrustedRoot(json: Any?): PinnedRoots {
        try {
            val j = obj(json)
            if (j == null || j["mediaType"] != "application/vnd.dev.sigstore.trustedroot+json;version=0.1") bad("not a trusted root v0.1")
            val tlogs = arr(j["tlogs"]).mapNotNull { pinnedLog(it, true) }
            val ctlogs = arr(j["ctlogs"]).mapNotNull { pinnedLog(it, false) }
            val cas = arr(j["certificateAuthorities"]).map { pinnedChain(it) }
            val tsas = arr(j["timestampAuthorities"]).map { pinnedChain(it) }
            if (tlogs.isEmpty() || cas.isEmpty()) bad("a trusted root needs a transparency log and a CA")
            return PinnedRoots(tlogs, ctlogs, cas, tsas)
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: Exception) {
            throw IllegalArgumentException("trusted root malformed: ${e.message}", e)
        }
    }

    // ---- DER ----

    internal class Tlv(val tag: Int, val start: Int, val body: Int, val end: Int)

    internal fun tlv(b: ByteArray, off: Int, limit: Int = b.size): Tlv {
        if (off + 2 > limit) bad("DER truncated")
        val tag = b[off].toInt() and 0xff
        if (tag and 0x1f == 0x1f) bad("DER multi-byte tag")
        var len = (b[off + 1].toInt() and 0xff).toLong()
        var body = off + 2
        if (len and 0x80L != 0L) {
            val n = (len and 0x7fL).toInt()
            if (n == 0 || n > 4 || body + n > limit) bad("DER length")
            len = 0
            for (i in 0 until n) len = len * 256 + (b[body + i].toInt() and 0xff)
            body += n
        }
        if (body + len > limit) bad("DER overrun")
        return Tlv(tag, off, body, (body + len).toInt())
    }

    internal fun kids(b: ByteArray, t: Tlv): List<Tlv> {
        val out = ArrayList<Tlv>()
        var o = t.body
        while (o < t.end) {
            val c = tlv(b, o, t.end)
            out.add(c)
            o = c.end
        }
        return out
    }

    /** A bundle carrying more RFC 3161 timestamps than this is refused: each one costs a full CMS, chain and signature check. */
    private const val MAX_TIMESTAMPS = 8

    internal fun oidText(b: ByteArray, t: Tlv): String {
        if (t.tag != 0x06 || t.end <= t.body) bad("not an OID")
        val parts = ArrayList<Long>()
        var v = 0L
        for (i in t.body until t.end) {
            if (v > (Long.MAX_VALUE shr 7)) bad("OID arc too large")
            if (b[i].toInt() and 0xff == 0x80 && (i == t.body || b[i - 1].toInt() and 0x80 == 0)) bad("OID arc is not minimally encoded")
            v = v * 128 + (b[i].toInt() and 0x7f)
            if (b[i].toInt() and 0x80 == 0) {
                parts.add(v)
                v = 0
            }
        }
        // past this test the last byte closed an arc, so parts is not empty
        if (b[t.end - 1].toInt() and 0x80 != 0) bad("OID ends inside an arc")
        val first = parts.removeAt(0)
        val a = minOf(2L, first / 40)
        return (listOf(a, first - a * 40) + parts).joinToString(".")
    }

    private fun cat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) o.write(p, 0, p.size)
        return o.toByteArray()
    }

    private fun enc(tag: Int, content: ByteArray): ByteArray {
        val n = content.size
        val len = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
            else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        }
        return cat(byteArrayOf(tag.toByte()), len, content)
    }

    internal class Ext(val oid: String, val value: ByteArray, val tlv: Tlv)
    internal class ParsedCert(val der: ByteArray, val top: List<Tlv>, val tbs: Tlv, val tbsKids: List<Tlv>, val extsWrapper: Tlv, val exts: List<Ext>) {
        fun ext(oid: String): Ext? = exts.firstOrNull { it.oid == oid }
    }

    internal fun parseCert(der: ByteArray): ParsedCert {
        val cert = tlv(der, 0)
        if (cert.tag != 0x30 || cert.end != der.size) bad("certificate is not one SEQUENCE")
        val top = kids(der, cert)
        if (top.size != 3) bad("certificate is not tbs, algorithm, signature")
        val tbs = top[0]
        if (tbs.tag != 0x30) bad("no TBSCertificate")
        val tbsKids = kids(der, tbs)
        val extsWrapper = tbsKids.firstOrNull { it.tag == 0xa3 } ?: bad("no extensions")
        val wrapped = kids(der, extsWrapper)
        if (wrapped.size != 1 || wrapped[0].tag != 0x30) bad("extensions malformed")
        val seq = wrapped[0]
        val seen = HashSet<String>()
        val exts = kids(der, seq).map { e ->
            // OpenSSL (the reference's parser) refuses anything but Extension ::= SEQUENCE { OID, critical BOOLEAN OPTIONAL, OCTET STRING }
            if (e.tag != 0x30) bad("extension is not a SEQUENCE")
            val parts = kids(der, e)
            if (parts.size < 2 || parts.size > 3 || (parts.size == 3 && parts[1].tag != 0x01)) bad("extension malformed")
            val oct = parts[parts.size - 1]
            if (oct.tag != 0x04) bad("extension value is not an OCTET STRING")
            val oid = oidText(der, parts[0])
            if (!seen.add(oid)) bad("duplicate extension $oid")
            Ext(oid, der.copyOfRange(oct.body, oct.end), e)
        }
        return ParsedCert(der, top, tbs, tbsKids, extsWrapper, exts)
    }

    internal fun utf8Strict(b: ByteArray): String {
        val s = try {
            Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(b)).toString() // a new decoder REPORTs malformed input by default
        } catch (e: java.nio.charset.CharacterCodingException) {
            bad("not UTF-8")
        }
        return if (s.startsWith("﻿")) s.substring(1) else s // TextDecoder drops a leading BOM
    }

    /** Fulcio extension `.1.n`: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8. */
    internal fun fulcioExt(c: ParsedCert, n: Int): String? {
        val e = c.ext("$OID_FULCIO$n") ?: return null
        if (n <= 6) return utf8Strict(e.value)
        val t = tlv(e.value, 0)
        if (t.tag != 0x0c || t.end != e.value.size) bad("extension .1.$n is not a DER UTF8String")
        return utf8Strict(e.value.copyOfRange(t.body, t.end))
    }

    /** Exactly one SAN, a URI or an email. */
    internal fun sanIdentity(c: ParsedCert): String {
        val e = c.ext(OID_SAN) ?: bad("no subjectAltName")
        val seq = tlv(e.value, 0)
        val names = kids(e.value, seq)
        if (seq.tag != 0x30 || names.size != 1) bad("subjectAltName must hold exactly one name")
        val n = names[0]
        if (n.tag != 0x86 && n.tag != 0x81) bad("subjectAltName must be a URI or an email")
        return utf8Strict(e.value.copyOfRange(n.body, n.end))
    }

    private val STAND_IN_SAN: ByteArray = enc(
        0x30, cat(enc(0x06, byteArrayOf(0x55, 0x1d, 0x11)), enc(0x01, byteArrayOf(0xff.toByte())), enc(0x04, enc(0x30, enc(0x86, "https://x".toByteArray(Charsets.US_ASCII))))),
    )

    /**
     * The leaf as the JDK may parse it. The JDK decodes the subjectAltName eagerly (and refuses an empty subject without a critical
     * one); OpenSSL, the reference's parser, decodes it lazily and the verifier reads the SAN itself ([sanIdentity]). So the JDK sees
     * a copy whose SAN is a critical stand-in; the signature is checked over the original TBS ([leafIssuedBy]).
     */
    private fun leafX509(pc: ParsedCert): X509Certificate {
        val der = pc.der
        val exts = ByteArrayOutputStream()
        var put = false
        for (e in pc.exts) {
            if (e.oid == OID_SAN) {
                exts.write(STAND_IN_SAN, 0, STAND_IN_SAN.size)
                put = true
            } else exts.write(der, e.tlv.start, e.tlv.end - e.tlv.start)
        }
        if (!put) exts.write(STAND_IN_SAN, 0, STAND_IN_SAN.size)
        val tbs = ByteArrayOutputStream()
        for (k in pc.tbsKids) {
            if (k === pc.extsWrapper) enc(0xa3, enc(0x30, exts.toByteArray())).let { tbs.write(it, 0, it.size) }
            else tbs.write(der, k.start, k.end - k.start)
        }
        val alg = pc.top[1]
        val sig = pc.top[2]
        return x509(enc(0x30, cat(enc(0x30, tbs.toByteArray()), der.copyOfRange(alg.start, alg.end), der.copyOfRange(sig.start, sig.end))))
    }

    /** OpenSSL decodes GeneralNames when it checks an issuer: a SAN that does not decode means "not issued". */
    internal fun generalNamesDecode(v: ByteArray): Boolean = try {
        val seq = tlv(v, 0)
        // shortcut: the constructed choices (otherName, x400Address, directoryName, ediPartyName) are not decoded inside; Fulcio never issues them
        seq.tag == 0x30 && seq.end == v.size && kids(v, seq).all { it.tag in setOf(0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88) }
    } catch (e: RuntimeException) {
        false
    }

    /** [issuedBy] for the leaf seen through [leafX509]: the signature is checked over the ORIGINAL TBS bytes. */
    internal fun leafIssuedBy(c: X509Certificate, pc: ParsedCert, up: X509Certificate): Boolean {
        if (!namedBy(c, up) || pkcs1UnderPss(c, up)) return false
        val san = pc.ext(OID_SAN)
        if (san != null && !generalNamesDecode(san.value)) return false
        val inner = pc.tbsKids.firstOrNull { it.tag == 0x30 } ?: return false // the TBS signature AlgorithmIdentifier
        val outer = pc.top[1]
        if (!pc.der.copyOfRange(inner.start, inner.end).contentEquals(pc.der.copyOfRange(outer.start, outer.end))) return false
        return try {
            val s = Signature.getInstance(c.sigAlgName)
            s.initVerify(up.publicKey)
            s.update(pc.der, pc.tbs.start, pc.tbs.end - pc.tbs.start)
            s.verify(c.signature)
        } catch (e: Exception) {
            false
        }
    }

    // ---- crypto helpers ----

    /** ECDSA (DER) or RSA PKCS#1 v1.5 by the key type, with [hash]. */
    internal fun sigOk(hash: String, k: PublicKey?, data: ByteArray, sig: ByteArray): Boolean = try {
        val alg = when (k?.algorithm) {
            "EC" -> hash.uppercase() + "withECDSA"
            "RSA" -> hash.uppercase() + "withRSA"
            else -> null
        }
        if (alg == null) {
            false
        } else {
            val s = Signature.getInstance(alg)
            s.initVerify(k)
            s.update(data)
            s.verify(sig)
        }
    } catch (e: Exception) {
        false
    }

    internal fun logSigOk(log: PinnedLog, data: ByteArray, sig: ByteArray): Boolean =
        if (log.ed25519 != null) {
            try {
                sig.size == Ed25519.SIGNATURE_SIZE && Ed25519.verify(sig, 0, log.ed25519, 0, data, 0, data.size)
            } catch (e: Exception) {
                false
            }
        } else {
            sigOk("sha256", log.key, data, sig)
        }

    private fun inside(c: X509Certificate, at: Long) = c.notBefore.time <= at && at <= c.notAfter.time
    private fun isCa(c: X509Certificate) = c.basicConstraints >= 0

    /** [c] names [up] as issuer (and [up] may sign certificates) and carries its signature. */
    internal fun issuedBy(c: X509Certificate, up: X509Certificate): Boolean {
        if (!namedBy(c, up) || pkcs1UnderPss(c, up)) return false
        return try {
            c.verify(up.publicKey)
            true
        } catch (e: Exception) {
            false
        }
    }

    /** A PKCS#1 signature under an rsa-pss key: X509_verify refuses it, and the JDK's RSA signature may not. */
    internal fun pkcs1UnderPss(c: X509Certificate, up: X509Certificate): Boolean =
        up.publicKey.algorithm == "RSASSA-PSS" && c.sigAlgOID != "1.2.840.113549.1.1.10"

    /** [c] names [up] as issuer (names, AKI / SKI) and [up] may sign certificates. */
    internal fun namedBy(c: X509Certificate, up: X509Certificate): Boolean {
        if (c.issuerX500Principal != up.subjectX500Principal || !akidOk(c, up)) return false
        val ku = up.keyUsage
        return ku == null || (ku.size >= 6 && ku[5])
    }

    /** [AttestCert.issuerLinkOk]; malformed = not issued. The JDK's parser refuses a repeated extension. */
    internal fun akidOk(c: X509Certificate, up: X509Certificate): Boolean = try {
        fun exts(x: X509Certificate) = (x.criticalExtensionOIDs.orEmpty() + x.nonCriticalExtensionOIDs.orEmpty()).map { oid ->
            val v = x.getExtensionValue(oid)
            val o = tlv(v, 0)
            if (o.tag != 0x04) throw AttErr("malformed extension")
            AttestCert.LenientExt(oid, false, v.copyOfRange(o.body, o.end))
        }
        AttestCert.issuerLinkOk(exts(c), exts(up), up.serialNumber.toByteArray(), up.issuerX500Principal.encoded)
    } catch (e: Exception) {
        false
    }

    internal fun hasEku(c: X509Certificate, eku: String): Boolean = try {
        c.extendedKeyUsage?.contains(eku) == true
    } catch (e: Exception) {
        false
    }

    /** Chain (leaf first, self-signed root last): issuer links, signatures, CA flags; every certificate valid at [at]. */
    internal fun chainOk(chain: List<X509Certificate>, at: Long): Boolean {
        for (i in chain.indices) {
            val c = chain[i]
            val up = if (i + 1 < chain.size) chain[i + 1] else c
            if (!issuedBy(c, up) || !inside(c, at)) return false
            if (i > 0 && !isCa(c)) return false
        }
        return true
    }

    // ---- SCT (RFC 6962 3.2) ----

    internal fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    internal fun verifySct(leaf: ParsedCert, issuer: X509Certificate, roots: PinnedRoots): String? {
        val e = leaf.ext(OID_SCT_LIST) ?: return "no embedded SCT"
        val outer = tlv(e.value, 0)
        if (outer.tag != 0x04) return "SCT list is not an OCTET STRING"
        val list = e.value.copyOfRange(outer.body, outer.end)
        if (list.size < 2 || u16(list, 0) != list.size - 2) return "SCT list length"
        val der = leaf.der
        val extSeq = kids(der, leaf.extsWrapper)[0]
        val kept = ByteArrayOutputStream()
        for (k in kids(der, extSeq)) if (k.start != e.tlv.start) kept.write(der, k.start, k.end - k.start)
        val tbsBody = ByteArrayOutputStream()
        for (k in leaf.tbsKids) {
            if (k === leaf.extsWrapper) {
                val w = enc(0xa3, enc(0x30, kept.toByteArray()))
                tbsBody.write(w, 0, w.size)
            } else {
                tbsBody.write(der, k.start, k.end - k.start)
            }
        }
        val tbs = enc(0x30, tbsBody.toByteArray())
        val issuerKeyHash = sha("sha256", issuer.publicKey.encoded)
        var why = "no SCT from a pinned CT log"
        var o = 2
        while (o < list.size) {
            if (o + 2 > list.size) return "SCT truncated"
            val n = u16(list, o)
            if (o + 2 + n > list.size || n < 47) return "SCT truncated"
            val s = list.copyOfRange(o + 2, o + 2 + n)
            o += 2 + n
            if (s[0].toInt() != 0) continue
            val logId = s.copyOfRange(1, 33)
            val ts = ByteBuffer.wrap(s, 33, 8).long
            val extLen = u16(s, 41)
            if (43 + extLen > s.size) return "SCT truncated"
            val ext = s.copyOfRange(43, 43 + extLen)
            val p = 43 + extLen
            if (p + 4 > s.size) return "SCT truncated"
            val hashAlg = s[p].toInt() and 0xff
            val sigAlg = s[p + 1].toInt() and 0xff
            val sigLen = u16(s, p + 2)
            if (p + 4 + sigLen != s.size) return "SCT malformed"
            val sig = s.copyOfRange(p + 4, p + 4 + sigLen)
            val log = roots.ctlogs.firstOrNull { it.keyId.contentEquals(logId) } ?: continue
            if (hashAlg != 4 || (sigAlg != 3 && sigAlg != 1)) {
                why = "SCT is not SHA-256 with ECDSA or RSA"
                continue
            }
            // ts is a uint64 (negative here at or above 2^63); past 2^53-1 the reference refuses it before the log validity
            if (ts < 0 || ts > 9007199254740991L) {
                why = "SCT timestamp out of range"
                continue
            }
            if (ts < log.start || ts > log.end) {
                why = "SCT log key not valid at its timestamp"
                continue
            }
            val head = ByteArray(12)
            System.arraycopy(s, 33, head, 2, 8) // v1, certificate_timestamp, timestamp
            head[11] = 1 // precert_entry
            val signed = cat(
                head, issuerKeyHash, byteArrayOf((tbs.size shr 16).toByte(), (tbs.size shr 8).toByte(), tbs.size.toByte()), tbs,
                byteArrayOf((ext.size shr 8).toByte(), ext.size.toByte()), ext,
            )
            if (sigOk("sha256", log.key, signed, sig)) return null
            why = "SCT signature invalid"
        }
        return why
    }

    // ---- RFC 3161 timestamps ----

    internal fun digestOf(b: ByteArray, t: Tlv): String = DIGEST_OIDS[oidText(b, kids(b, t)[0])] ?: bad("unsupported digest algorithm")

    private val GEN_TIME = Regex("(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(?:\\.(\\d{1,9}))?Z")

    internal fun generalizedTime(b: ByteArray, t: Tlv): Long {
        if (t.tag != 0x18) bad("genTime is not a GeneralizedTime")
        val m = GEN_TIME.matchEntire(String(b, t.body, t.end - t.body, Charsets.ISO_8859_1)) ?: bad("genTime malformed")
        val g = m.groupValues
        val ms = LocalDateTime.of(g[1].toInt(), g[2].toInt(), g[3].toInt(), g[4].toInt(), g[5].toInt(), g[6].toInt()).toInstant(ZoneOffset.UTC).toEpochMilli()
        // exact truncation to ms (no float)
        return if (g[7].isNotEmpty()) ms + g[7].padEnd(3, '0').substring(0, 3).toLong() else ms
    }

    /**
     * Verify an RFC 3161 TimeStampResp (or bare TimeStampToken) over [data] (the raw signature bytes): CMS SignedData with
     * TSTInfo content, messageImprint = hash of [data], signed attributes carrying the content type and the TSTInfo digest, the
     * signature over the DER SET of signed attributes under the leaf of a pinned TSA whose chain and validFor cover genTime,
     * with the timeStamping EKU. Returns genTime (ms); throws IllegalArgumentException otherwise.
     */
    fun verifyRfc3161(token: ByteArray, data: ByteArray, tsas: List<PinnedCa>): Long {
        var ci = tlv(token, 0)
        if (ci.end != token.size || ci.tag != 0x30) bad("timestamp is not one SEQUENCE")
        var parts = kids(token, ci)
        if (parts.isNotEmpty() && parts[0].tag == 0x30 && parts[0].end - parts[0].body >= 3 && token[kids(token, parts[0])[0].start].toInt() == 0x02) {
            val st = kids(token, parts[0])[0]
            val status = token.copyOfRange(st.body, st.end)
            if (!(status.size == 1 && (status[0].toInt() == 0 || status[0].toInt() == 1))) bad("timestamp status is not granted")
            if (parts.size < 2) bad("no timeStampToken")
            ci = parts[1]
            parts = kids(token, ci)
        }
        if (parts.size < 2 || oidText(token, parts[0]) != OID_SIGNED_DATA || parts[1].tag != 0xa0) bad("not CMS SignedData")
        val sd = kids(token, parts[1])[0]
        val sdk = kids(token, sd)
        val encap = sdk.withIndex().firstOrNull { it.index > 1 && it.value.tag == 0x30 }?.value ?: bad("no encapsulated content")
        val ek = kids(token, encap)
        if (ek.size < 2 || oidText(token, ek[0]) != OID_TST_INFO || ek[1].tag != 0xa0) bad("content is not TSTInfo")
        val octet = kids(token, ek[1])[0]
        if (octet.tag != 0x04) bad("TSTInfo is not an OCTET STRING")
        val tstBytes = token.copyOfRange(octet.body, octet.end)
        val tk = kids(tstBytes, tlv(tstBytes, 0))
        val mi = kids(tstBytes, tk[2])
        val miAlg = digestOf(tstBytes, mi[0])
        if (!sha(miAlg, data).contentEquals(tstBytes.copyOfRange(mi[1].body, mi[1].end))) bad("messageImprint is not the hash of the signature")
        val genTime = generalizedTime(tstBytes, tk[4])
        val signerInfos = sdk[sdk.size - 1]
        if (signerInfos.tag != 0x31) bad("no signerInfos")
        val sis = kids(token, signerInfos)
        if (sis.size != 1) bad("exactly one SignerInfo is required")
        val si = kids(token, sis[0])
        val dAlg = digestOf(token, si[2])
        val attrs = si[3]
        if (attrs.tag != 0xa0) bad("signed attributes are required")
        var ctOk = false
        var mdOk = false
        for (a in kids(token, attrs)) {
            val av = kids(token, a)
            val vals = kids(token, av[1])
            val o = oidText(token, av[0])
            if (vals.size != 1) bad("an attribute must have one value")
            if (o == OID_CONTENT_TYPE) ctOk = oidText(token, vals[0]) == OID_TST_INFO
            if (o == OID_MESSAGE_DIGEST) mdOk = sha(dAlg, tstBytes).contentEquals(token.copyOfRange(vals[0].body, vals[0].end))
        }
        if (!ctOk || !mdOk) bad("signed attributes do not commit to the TSTInfo")
        val signedAttrs = cat(byteArrayOf(0x31), token.copyOfRange(attrs.start + 1, attrs.end))
        val sigT = si[5]
        if (sigT.tag != 0x04) bad("signature is not an OCTET STRING")
        val sig = token.copyOfRange(sigT.body, sigT.end)
        for (tsa in tsas) {
            if (genTime < tsa.start || genTime > tsa.end) continue
            val leaf = tsa.chain[0]
            if (!hasEku(leaf, EKU_TIME_STAMPING)) continue
            if (!sigOk(dAlg, leaf.publicKey, signedAttrs, sig)) continue
            if (!chainOk(tsa.chain, genTime)) continue
            return genTime
        }
        bad("no pinned timestamp authority signed it (valid at its time)")
    }

    // ---- Rekor ----

    private val SIZE = Regex("[1-9][0-9]*")
    private val NOTE_SIG = Regex("— (\\S+) ([A-Za-z0-9+/=]+)")

    /** Signed-note checkpoint: origin, size, root, a blank line, then `— <name> <b64(hint4 || sig)>` lines. Null when good. */
    internal fun verifyCheckpoint(text: String, log: PinnedLog, size: Long, root: ByteArray): String? {
        val cut = text.indexOf("\n\n")
        if (cut < 0) return "checkpoint has no signature block"
        val body = text.substring(0, cut + 1)
        val lines = body.split("\n")
        if (lines.size < 4 || lines[0].isEmpty()) return "checkpoint body too short or without an origin"
        if (!SIZE.matches(lines[1]) || BigInteger(lines[1]) != BigInteger.valueOf(size)) return "checkpoint size differs from the proof"
        if (!b64(lines[2]).contentEquals(root)) return "checkpoint root differs from the proof"
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        for (l in text.substring(cut + 2).split("\n")) {
            val m = NOTE_SIG.matchEntire(l) ?: continue
            val raw = b64(m.groupValues[2])
            if (raw.size < 5 || !raw.copyOfRange(0, 4).contentEquals(log.keyId.copyOfRange(0, 4))) continue
            if (log.v2Name != null && m.groupValues[1] != log.v2Name) continue
            if (logSigOk(log, bodyBytes, raw.copyOfRange(4, raw.size))) return null
        }
        return "no checkpoint signature by the pinned log key"
    }

    private val DEC = Regex("0|[1-9][0-9]{0,15}")
    internal fun decInt(v: Any?): Long {
        if (v !is String || !DEC.matches(v)) bad("not a decimal integer string")
        val n = v.toLong()
        if (n > MAX_SAFE) bad("integer out of range")
        return n
    }

    /** DSSE PAE (secure-systems-lab/dsse protocol.md). */
    fun dssePae(payloadType: String, payload: ByteArray): ByteArray {
        val t = payloadType.toByteArray(Charsets.UTF_8)
        return cat("DSSEv1 ${t.size} ".toByteArray(Charsets.UTF_8), t, " ${payload.size} ".toByteArray(Charsets.UTF_8), payload)
    }

    // by the exact named curve (every domain parameter), not the field size: brainpoolP256r1 / P384r1 are refused as in the reference
    internal fun leafHashAlg(k: PublicKey): String? {
        if (k !is ECPublicKey) return null
        return when (AttestCert.curveOpenSslName(k.params)) {
            "prime256v1" -> "sha256"
            "secp384r1" -> "sha384"
            else -> null
        }
    }

    private fun hex(b: ByteArray) = b.joinToString("") { String.format("%02x", it.toInt() and 0xff) }

    private val PEM = Regex("-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?")
    internal fun pemDer(pem: String): ByteArray = PEM.matchEntire(pem)?.let { b64(it.groupValues[1].replace("\n", "")) } ?: ByteArray(0)

    // ---- the verifier ----

    /** `{ok, core, statement}` or `{ok: false, code, detail}`; [core] holds the shared vector's `core` members. */
    class CoreResult internal constructor(val ok: Boolean, val core: Map<String, Any?>?, val statement: Map<String, Any?>?, val code: String?, val detail: String?)

    /** `{ok, facts}` (the `facts` of [ProvenanceGate.provenanceGate]) or `{ok: false, code, detail}`. */
    class Result internal constructor(val ok: Boolean, val facts: Map<String, Any?>?, val code: String?, val detail: String?)

    private fun no(code: String, detail: String) = CoreResult(false, null, null, code, detail)

    /** Verify a Sigstore bundle (a [Json.parseLenient] tree) carrying a DSSE in-toto statement. Never throws. */
    fun verifySigstoreBundleCore(bundle: Any?, roots: PinnedRoots?): CoreResult {
        var stage = "malformed"
        try {
            val b = obj(bundle)
            val vm = obj(b?.get("verificationMaterial"))
            if (b == null || roots == null || vm == null) return no("malformed", "not a bundle")
            val mt = b["mediaType"]
            if (mt !is String || mt !in BUNDLE_MEDIA_TYPES) return no("media_type", "unsupported media type ${if (b.containsKey("mediaType")) mt else "undefined"}")
            val v03 = mt != BUNDLE_MEDIA_TYPES[0]
            val holder = obj(if (v03) vm["certificate"] else arr(at(vm["x509CertificateChain"], "certificates")).firstOrNull())
            // a present rawBytes (even null) goes on to the base64 check (cert_parse); only an absent one means "not keyless"
            if (holder == null || !holder.containsKey("rawBytes")) return no("not_keyless", "no Fulcio certificate (public-key bundles are not supported)")
            val certRaw = holder["rawBytes"]
            val env = obj(b["dsseEnvelope"])
            if (env == null || b.containsKey("messageSignature")) return no("envelope", "not a DSSE bundle")
            if (env["payloadType"] != INTOTO_PAYLOAD_TYPE) return no("envelope", "payloadType is not application/vnd.in-toto+json")
            val sigs0 = env["signatures"]
            if (sigs0 !is List<*> || sigs0.size != 1 || obj(sigs0[0]) == null) return no("envelope", "a DSSE envelope must carry exactly one signature")
            val payload = b64(env["payload"])
            val dsseSig = b64(at(sigs0[0], "sig"))
            val pae = dssePae(INTOTO_PAYLOAD_TYPE, payload)
            stage = "cert_parse"
            val leafDer = b64(certRaw)
            val pc = parseCert(leafDer)
            val leaf = leafX509(pc)
            val alg = leafHashAlg(leaf.publicKey)

            // ---- the log entry and its log
            stage = "tlog_count"
            val entries = arr(vm["tlogEntries"])
            if (entries.size != 1 || obj(entries[0]) == null) return no("tlog_count", "exactly one transparency log entry is required")
            val t = obj(entries[0])!!
            stage = "tlog_kind"
            val kvo = obj(t["kindVersion"])
            val kv = if (kvo != null && kvo["kind"] is String && kvo["version"] is String) "${kvo["kind"]}/${kvo["version"]}" else ""
            if (kv !in listOf("dsse/0.0.1", "intoto/0.0.2", "hashedrekord/0.0.2")) return no("tlog_kind", "unsupported entry $kv")
            val v2 = kv == "hashedrekord/0.0.2"
            stage = "tlog_key"
            val keyId = b64(at(t["logId"], "keyId"))
            val log = roots.tlogs.firstOrNull { it.keyId.contentEquals(keyId) } ?: return no("tlog_key", "the entry names a log the verifier did not pin")
            if (v2 != (log.v2Name != null)) return no("tlog_key", "the entry type does not match the log version")
            val logIndex = decInt(t["logIndex"])
            val body = b64(t["canonicalizedBody"])

            // ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
            stage = "tsa"
            val times = ArrayList<Long>()
            val tss = arr(at(vm["timestampVerificationData"], "rfc3161Timestamps"))
            if (tss.size > MAX_TIMESTAMPS) return no("tsa", "too many RFC 3161 timestamps (${tss.size}, at most $MAX_TIMESTAMPS)")
            for (ts in tss) times.add(verifyRfc3161(b64(at(ts, "signedTimestamp")), dsseSig, roots.tsas))
            val tsaCount = times.size
            var set = false
            if (!v2 && obj(t["inclusionPromise"]) != null) {
                stage = "tlog_set"
                val integrated = decInt(t["integratedTime"])
                // canonicalizedBody passed b64() above, so it needs no JSON escaping
                val setMsg = "{\"body\":\"${t["canonicalizedBody"]}\",\"integratedTime\":$integrated,\"logID\":\"${hex(keyId)}\",\"logIndex\":$logIndex}"
                if (!logSigOk(log, setMsg.toByteArray(Charsets.UTF_8), b64(at(t["inclusionPromise"], "signedEntryTimestamp")))) return no("tlog_set", "signed entry timestamp invalid")
                times.add(integrated * 1000)
                set = true
            }
            if (times.isEmpty()) return no("no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp")
            if (times.any { it < log.start || it > log.end }) return no("tlog_key", "the log key was not valid at a signing time")

            // ---- inclusion
            stage = "tlog_inclusion"
            val ip = obj(t["inclusionProof"])
            val hashesO = ip?.get("hashes")
            if (ip == null || hashesO !is List<*> || obj(ip["checkpoint"]) == null) return no("tlog_inclusion", "no inclusion proof")
            val root = b64(ip["rootHash"])
            val size = decInt(ip["treeSize"])
            val proofIndex = decInt(ip["logIndex"])
            if (!ProvenanceGate.verifyRfc9162Inclusion(ProvenanceGate.rfc9162LeafHash(body), proofIndex, size, hashesO.map { b64(it) }, root)) {
                return no("tlog_inclusion", "the inclusion proof does not lead to the root")
            }
            // the reported index must be a verified one: the SET signs the entry's (v1 sharded, global) logIndex; without a SET (Rekor v2,
            // v1 TSA-only) the entry's own logIndex is unauthenticated, so the inclusion proof's verified index is reported instead
            val verifiedIndex = if (set) logIndex else proofIndex
            stage = "tlog_checkpoint"
            val envelope = at(ip["checkpoint"], "envelope") as? String ?: return no("tlog_checkpoint", "the checkpoint envelope is not a string")
            val cpe = verifyCheckpoint(envelope, log, size, root)
            if (cpe != null) return no("tlog_checkpoint", cpe)

            // ---- certificate path at every verified time (hybrid model), CT
            stage = "cert_chain"
            var issuer: X509Certificate? = null
            for (ca in roots.cas) {
                if (times.any { it < ca.start || it > ca.end }) continue
                val first = ca.chain[0]
                if (!leafIssuedBy(leaf, pc, first)) continue
                if (times.all { chainOk(ca.chain, it) } && ca.chain.all { isCa(it) }) {
                    issuer = first
                    break
                }
            }
            if (issuer == null) return no("cert_chain", "no pinned CA issued the certificate, valid at every signing time")
            if (isCa(leaf)) return no("cert_chain", "the leaf is a CA certificate")
            if (!times.all { inside(leaf, it) }) return no("cert_time", "the certificate was not valid at a signing time")
            if (!hasEku(leaf, EKU_CODE_SIGNING)) return no("cert_eku", "the certificate lacks the code-signing EKU")
            if (roots.ctlogs.isNotEmpty()) {
                stage = "sct"
                val sct = verifySct(pc, issuer, roots)
                if (sct != null) return no("sct", sct)
            }

            // ---- the entry body names this envelope
            stage = "tlog_body"
            val eb = objOrEmpty(Json.parseLenient(String(body, Charsets.UTF_8)))
            val spec = objOrEmpty(eb["spec"])
            if (eb["kind"] !is String || eb["apiVersion"] !is String || "${eb["kind"]}/${eb["apiVersion"]}" != kv) return no("tlog_body", "the entry body is not the kind the bundle names")
            val payloadSha = hex(sha("sha256", payload))
            when (kv) {
                "dsse/0.0.1" -> {
                    val ph = objOrEmpty(spec["payloadHash"])
                    if (ph["algorithm"] != "sha256" || ph["value"] != payloadSha) return no("tlog_body", "the entry names another payload")
                    val sigs = arr(spec["signatures"])
                    if (sigs.size != 1 || obj(sigs[0]) == null) return no("tlog_body", "the entry must name exactly one signature")
                    if (!b64(at(sigs[0], "signature")).contentEquals(dsseSig)) return no("tlog_body", "the entry names another signature")
                    if (!pemDer(String(b64(at(sigs[0], "verifier")), Charsets.UTF_8)).contentEquals(leafDer)) return no("tlog_body", "the entry names another certificate")
                }
                "intoto/0.0.2" -> {
                    // Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
                    val c = objOrEmpty(spec["content"])
                    val ph = objOrEmpty(c["payloadHash"])
                    if (ph["algorithm"] != "sha256" || ph["value"] != payloadSha) return no("tlog_body", "the entry names another payload")
                    val sigs = arr(at(c["envelope"], "signatures"))
                    if (sigs.size != 1 || obj(sigs[0]) == null) return no("tlog_body", "the entry must name exactly one signature")
                    if (!b64(String(b64(at(sigs[0], "sig")), Charsets.ISO_8859_1)).contentEquals(dsseSig)) return no("tlog_body", "the entry names another signature")
                    if (!pemDer(String(b64(at(sigs[0], "publicKey")), Charsets.UTF_8)).contentEquals(leafDer)) return no("tlog_body", "the entry names another certificate")
                }
                else -> {
                    // Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
                    val h = objOrEmpty(spec["hashedRekordV002"])
                    val data = objOrEmpty(h["data"])
                    val hashName = when (data["algorithm"]) {
                        "SHA2_256" -> "sha256"
                        "SHA2_384" -> "sha384"
                        "SHA2_512" -> "sha512"
                        else -> null
                    }
                    if (hashName == null || hashName != alg) return no("tlog_body", "the entry digest algorithm is not the signing key's")
                    if (!b64(data["digest"]).contentEquals(sha(hashName, pae))) return no("tlog_body", "the entry names another envelope")
                    val sg = objOrEmpty(h["signature"])
                    if (!b64(sg["content"]).contentEquals(dsseSig)) return no("tlog_body", "the entry names another signature")
                    if (!b64(at(at(sg["verifier"], "x509Certificate"), "rawBytes")).contentEquals(leafDer)) return no("tlog_body", "the entry names another certificate")
                }
            }

            // ---- DSSE signature
            stage = "signature"
            if (alg == null) return no("signature", "unsupported leaf key type")
            if (!sigOk(alg, leaf.publicKey, pae, dsseSig)) return no("signature", "DSSE signature invalid")

            // ---- identity
            stage = "identity"
            val identity = sanIdentity(pc)
            val issV2 = fulcioExt(pc, 8)
            val issV1 = fulcioExt(pc, 1)
            if (issV2 != null && issV1 != null && issV2 != issV1) return no("identity", "the two issuer extensions disagree")
            val oidcIssuer = issV2 ?: issV1
            if (oidcIssuer.isNullOrEmpty()) return no("identity", "no OIDC issuer extension")
            val sourceRepo = fulcioExt(pc, 12)
            val sourceDigest = fulcioExt(pc, 13)
            val sourceRef = fulcioExt(pc, 14)

            // ---- statement
            stage = "statement"
            val st = obj(Json.parseLenient(utf8Strict(payload)))
            if (st == null || st["_type"] != ProvenanceGate.INTOTO_STATEMENT_V1) return no("statement", "not an in-toto Statement v1")
            val subj = st["subject"]
            if (subj !is List<*> || subj.isEmpty()) return no("statement", "no subject")
            val subjects = ArrayList<Any?>()
            for (s in subj) {
                val d = objOrEmpty(at(s, "digest"))
                for (a in listOf("sha256", "sha512")) if (d[a] is String) subjects.add(linkedMapOf("alg" to a, "digest" to d[a]))
            }
            if (subjects.isEmpty() || subjects.size > 64) return no("statement", "no sha256/sha512 subject digest (or more than 64)")
            if (st["predicateType"] !is String) return no("statement", "no predicateType")
            val core = LinkedHashMap<String, Any?>()
            core["identity"] = identity
            core["oidc_issuer"] = oidcIssuer
            if (sourceRepo != null) core["source_repo"] = sourceRepo
            if (sourceRef != null) core["source_ref"] = sourceRef
            if (sourceDigest != null) core["source_digest"] = sourceDigest
            core["predicate_type"] = st["predicateType"]
            core["subjects"] = subjects
            core["signed_time"] = Math.floorDiv(times.minOrNull()!!, 1000L)
            core["rekor_log_index"] = verifiedIndex
            core["rekor"] = if (v2) "v2" else "v1"
            core["timestamps"] = linkedMapOf("tsa" to tsaCount.toLong(), "set" to set)
            return CoreResult(true, core, st, null, null)
        } catch (e: Exception) {
            return no(stage, "fail closed: ${e.message}")
        } catch (e: StackOverflowError) {
            return no(stage, "fail closed: too deep")
        }
    }

    /** [verifySigstoreBundleCore], then the SLSA v1 predicate: the `facts` [ProvenanceGate.provenanceGate] checks. */
    fun verifySigstoreBundle(bundle: Any?, roots: PinnedRoots?): Result {
        val r = verifySigstoreBundleCore(bundle, roots)
        if (!r.ok) return Result(false, null, r.code, r.detail)
        val st = r.statement!!
        val c = r.core!!
        if (st["predicateType"] != ProvenanceGate.SLSA_PROVENANCE_V1) return Result(false, null, "predicate", "predicate ${st["predicateType"]} is not SLSA provenance v1")
        val pr = objOrEmpty(st["predicate"])
        val bd = objOrEmpty(pr["buildDefinition"])
        val rd = objOrEmpty(pr["runDetails"])
        val builderId = at(rd["builder"], "id")
        if (bd["buildType"] !is String || builderId !is String || obj(bd["externalParameters"]) == null) {
            return Result(false, null, "predicate", "buildType, externalParameters and builder.id are required (SLSA Build L1)")
        }
        val dep0 = obj(arr(bd["resolvedDependencies"]).firstOrNull())
        val depCommit = at(dep0?.get("digest"), "gitCommit")
        val f = LinkedHashMap<String, Any?>()
        f["v"] = 1L
        f["predicate_type"] = ProvenanceGate.SLSA_PROVENANCE_V1
        f["build_type"] = bd["buildType"]
        f["builder_id"] = builderId
        f["subjects"] = c["subjects"]
        f["identity"] = c["identity"]
        f["oidc_issuer"] = c["oidc_issuer"]
        for (k in listOf("source_repo", "source_ref", "source_digest")) if (c.containsKey(k)) f[k] = c[k]
        if (dep0 != null && dep0["uri"] is String) {
            val ps = linkedMapOf<String, Any?>("uri" to dep0["uri"])
            if (depCommit is String) ps["git_commit"] = depCommit
            f["provenance_source"] = ps
        }
        f["integrated_time"] = c["signed_time"]
        f["rekor_log_index"] = c["rekor_log_index"]
        return Result(true, f, null, null)
    }
}
