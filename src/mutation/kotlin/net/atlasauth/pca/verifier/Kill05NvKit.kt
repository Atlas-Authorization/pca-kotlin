package net.atlasauth.pca.verifier

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * A synthetic NVIDIA device PKI (ECDSA P-384 keys generated at run time) and the DER / OCSP / CRL / RIM / SPDM builders of the
 * Kill05Nv* tests. Tests run their bodies as `nv { ... }` so every member here is in scope.
 */
internal object Kill05NvKit {
    const val NOW = 1_800_000_000_000L // 2027-01-15T08:00:00Z, a whole second
    const val SEC = 1_000L
    const val HOUR = 3_600_000L
    const val DAY = 24 * HOUR
    const val OCSP_URL = "http://ocsp.ndis.nvidia.com"
    const val EC256 = "1.2.840.10045.4.3.2"
    const val EC384 = "1.2.840.10045.4.3.3"
    const val EC512 = "1.2.840.10045.4.3.4"
    const val RSA256 = "1.2.840.113549.1.1.11"
    const val RSA384 = "1.2.840.113549.1.1.12"
    const val RSA512 = "1.2.840.113549.1.1.13"
    const val SHA1 = "1.3.14.3.2.26"
    const val SHA256 = "2.16.840.1.101.3.4.2.1"
    const val SHA384 = "2.16.840.1.101.3.4.2.2"
    const val SHA512 = "2.16.840.1.101.3.4.2.3"
    const val OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"
    const val KP_OCSP = "1.3.6.1.5.5.7.3.9"
    const val KP_SERVER = "1.3.6.1.5.5.7.3.1"
    const val ROOT_CN = "NVIDIA Device Identity CA"
    const val INTER_CN = "NVIDIA GH100 Identity"
    const val LEAF_CN = "GH100 A01 FSP BROM"
    private val HASH_JCA = mapOf(SHA1 to "SHA-1", SHA256 to "SHA-256", SHA384 to "SHA-384", SHA512 to "SHA-512")

    // ---- DER ----

    val NONE = ByteArray(0)

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
            n < 0x10000 -> b(tag, 0x82, n shr 8, n and 0xff)
            else -> b(tag, 0x83, n shr 16, (n shr 8) and 0xff, n and 0xff)
        }
        return cat(hdr, body)
    }

    fun seq(vararg parts: ByteArray): ByteArray = tlv(0x30, *parts)

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

    fun int(v: Long): ByteArray = tlv(0x02, BigInteger.valueOf(v).toByteArray())

    fun octets(v: ByteArray): ByteArray = tlv(0x04, v)

    fun bits(v: ByteArray): ByteArray = tlv(0x03, b(0), v)

    fun text(tag: Int, s: String): ByteArray = tlv(tag, s.toByteArray(Charsets.ISO_8859_1))

    // ---- times ----

    private val GEN_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC)
    private val UTC_FMT = DateTimeFormatter.ofPattern("yyMMddHHmmss").withZone(ZoneOffset.UTC)

    /** GeneralizedTime text of `ms`; a fraction (shortest form) only when `ms` is not a whole second. */
    fun genText(ms: Long): String {
        val whole = Math.floorDiv(ms, 1000L) * 1000L
        val frac = ms - whole
        val base = GEN_FMT.format(Instant.ofEpochMilli(whole))
        return if (frac == 0L) base + "Z" else base + "." + String.format("%03d", frac).trimEnd('0') + "Z"
    }

    fun gen(ms: Long): ByteArray = text(0x18, genText(ms))

    fun utc(ms: Long): ByteArray = text(0x17, UTC_FMT.format(Instant.ofEpochMilli(ms)) + "Z")

    // ---- names, keys, certificates ----

    fun name(vararg rdns: Pair<String, String>): ByteArray =
        seq(*rdns.map { tlv(0x31, seq(oid(it.first), tlv(0x0c, it.second.toByteArray(Charsets.UTF_8)))) }.toTypedArray())

    fun dn(cn: String): ByteArray = name("2.5.4.10" to "NVIDIA Corporation", "2.5.4.3" to cn)

    /** The one-line subject the verifiers print for `dn(cn)`. */
    fun line(cn: String): String = "O=NVIDIA Corporation, CN=$cn"

    fun p384(): KeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()

    fun sign(alg: String, k: PrivateKey, data: ByteArray): ByteArray {
        val s = Signature.getInstance(alg)
        s.initSign(k)
        s.update(data)
        return s.sign()
    }

    /** A raw `r || s` (96-byte) ECDSA P-384 / SHA-384 signature. */
    fun rawSign(k: PrivateKey, data: ByteArray): ByteArray = sign("SHA384withECDSAinP1363Format", k, data)

    fun md(alg: String, d: ByteArray): ByteArray = MessageDigest.getInstance(alg).digest(d)

    fun b64(d: ByteArray): String = java.util.Base64.getEncoder().encodeToString(d)

    fun ext(o: String, critical: Boolean, value: ByteArray): ByteArray =
        if (critical) seq(oid(o), tlv(0x01, b(0xff)), octets(value)) else seq(oid(o), octets(value))

    val BC_CA = ext("2.5.29.19", true, seq(tlv(0x01, b(0xff))))
    val KU_CA = ext("2.5.29.15", true, tlv(0x03, b(1, 0x06)))

    fun aia(url: String = OCSP_URL): ByteArray = ext("1.3.6.1.5.5.7.1.1", false, seq(seq(oid("1.3.6.1.5.5.7.48.1"), text(0x86, url))))

    fun eku(vararg purposes: String): ByteArray = ext("2.5.29.37", false, seq(*purposes.map { oid(it) }.toTypedArray()))

    class Issued(val der: ByteArray, val cert: AttestCert.Cert, val key: KeyPair?)

    /** A certificate signed (ecdsa-with-SHA384) by `signer`. */
    fun issue(
        subject: ByteArray,
        issuer: ByteArray,
        signer: PrivateKey,
        key: KeyPair?,
        spki: ByteArray = key!!.public.encoded,
        serial: ByteArray = int(1),
        exts: List<ByteArray> = emptyList(),
        notBefore: ByteArray = utc(NOW - 365 * DAY),
        notAfter: ByteArray = utc(NOW + 365 * DAY),
    ): Issued {
        val alg = seq(oid(EC384))
        val extBlock = if (exts.isEmpty()) NONE else tlv(0xa3, seq(*exts.toTypedArray()))
        val tbs = seq(tlv(0xa0, int(2)), serial, alg, issuer, seq(notBefore, notAfter), subject, spki, extBlock)
        val der = seq(tbs, alg, bits(sign("SHA384withECDSA", signer, tbs)))
        return Issued(der, AttestCert.parseCertDer(der), key)
    }

    fun pem(der: ByteArray): String =
        "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) + "\n-----END CERTIFICATE-----\n"

    val rootKey = p384()
    val interKey = p384()
    val leafKey = p384()
    val root = issue(dn(ROOT_CN), dn(ROOT_CN), rootKey.private, rootKey, serial = int(1), exts = listOf(BC_CA, KU_CA))
    val inter = issue(dn(INTER_CN), dn(ROOT_CN), rootKey.private, interKey, serial = int(2), exts = listOf(BC_CA, KU_CA, aia()))

    /** Serial 0x009a01: DER keeps a leading zero byte (high bit), which the OCSP serial comparison strips. */
    val leaf = issue(dn(LEAF_CN), dn(INTER_CN), interKey.private, leafKey, serial = tlv(0x02, b(0x00, 0x9a, 0x01)), exts = listOf(aia()))
    val CHAIN = listOf(leaf.cert, inter.cert, root.cert)
    val ROOT_PIN = AttestCert.keyOfCert(root.cert).spkiSha256()

    // ---- OCSP ----

    val respKey = p384()

    /** A delegated OCSP responder certificate (by default: issued by the intermediate, id-kp-OCSPSigning, valid now). */
    fun responder(
        cn: String = "NVIDIA OCSP Responder",
        issuer: ByteArray = dn(INTER_CN),
        signer: PrivateKey = interKey.private,
        key: KeyPair? = respKey,
        spki: ByteArray = key!!.public.encoded,
        exts: List<ByteArray> = listOf(eku(KP_OCSP)),
        notBefore: ByteArray = utc(NOW - DAY),
        notAfter: ByteArray = utc(NOW + DAY),
    ): Issued = issue(dn(cn), issuer, signer, key, spki, int(77), exts, notBefore, notAfter)

    val DELEGATE = responder()

    fun certId(
        cert: AttestCert.Cert,
        issuer: AttestCert.Cert,
        hashOid: String = SHA384,
        serial: ByteArray = tlv(0x02, cert.serial),
        nameHash: ByteArray? = null,
        keyHash: ByteArray? = null,
    ): ByteArray {
        val h = HASH_JCA[hashOid] ?: "SHA-384"
        return seq(seq(oid(hashOid), b(0x05, 0)), octets(nameHash ?: md(h, issuer.rawSubject)), octets(keyHash ?: md(h, AttestCert.spkiKeyBits(issuer))), serial)
    }

    val GOOD = b(0x80, 0)
    val UNKNOWN = b(0x82, 0)
    val REVOKED = tlv(0xa1, text(0x18, "20261019120000Z"))

    /** One SingleResponse (by default: the leaf under the intermediate, good, thisUpdate an hour ago, nextUpdate in 30 days). */
    fun single(
        cert: AttestCert.Cert = leaf.cert,
        issuer: AttestCert.Cert = inter.cert,
        status: ByteArray = GOOD,
        thisUpdate: ByteArray = gen(NOW - HOUR),
        next: ByteArray? = tlv(0xa0, gen(NOW + 30 * DAY)),
        id: ByteArray = certId(cert, issuer),
        tag: Int = 0x30,
    ): ByteArray = tlv(tag, id, status, thisUpdate, next ?: NONE)

    fun byName(c: AttestCert.Cert): ByteArray = tlv(0xa1, c.rawSubject)

    fun byKey(c: AttestCert.Cert): ByteArray = tlv(0xa2, octets(AttestUtil.sha1(AttestCert.spkiKeyBits(c))))

    /** tbsResponseData: [version], responderID, producedAt, responses, then `tail`. */
    fun rdata(
        vararg singles: ByteArray,
        rid: ByteArray = byName(inter.cert),
        produced: ByteArray = gen(NOW - HOUR),
        version: Boolean = false,
        tail: ByteArray = NONE,
    ): ByteArray = seq(if (version) tlv(0xa0, int(0)) else NONE, rid, produced, seq(*singles), tail)

    fun basic(
        tbs: ByteArray,
        signer: PrivateKey = interKey.private,
        jca: String = "SHA384withECDSA",
        sigOid: String = EC384,
        certs: ByteArray? = null,
        sig: ByteArray? = null,
    ): ByteArray = seq(tbs, seq(oid(sigOid)), bits(sig ?: sign(jca, signer, tbs)), certs ?: NONE)

    /** The [0] certs field of a BasicOCSPResponse. */
    fun embed(vararg certs: ByteArray): ByteArray = tlv(0xa0, seq(*certs))

    fun response(basic: ByteArray): ByteArray = seq(tlv(0x0a, b(0)), tlv(0xa0, seq(oid(OCSP_BASIC), octets(basic))))

    fun ocsp(
        vararg singles: ByteArray,
        rid: ByteArray = byName(inter.cert),
        signer: PrivateKey = interKey.private,
        jca: String = "SHA384withECDSA",
        sigOid: String = EC384,
        certs: ByteArray? = null,
    ): ByteArray = response(basic(rdata(*singles, rid = rid), signer, jca, sigOid, certs))

    /** "OK:<status>" or the failure reason of verifyOcspResponse. */
    fun ocspWhy(
        der: ByteArray,
        cert: AttestCert.Cert = leaf.cert,
        issuer: AttestCert.Cert = inter.cert,
        chain: List<AttestCert.Cert> = CHAIN,
        now: Long = NOW,
    ): String {
        val r = AttestNvidiaCollateral.verifyOcspResponse(der, cert, issuer, chain, now)
        return if (r.ok) "OK:" + r.status else r.reason
    }

    // ---- CRL ----

    /** A CRL (ecdsa-with-SHA256) named `issuerDn`, signed by `signer`, fresh now, listing `revokedSerials` (INTEGER contents). */
    fun crl(issuerDn: ByteArray, signer: PrivateKey, vararg revokedSerials: ByteArray): ByteArray {
        val entries = revokedSerials.map { seq(tlv(0x02, it), utc(NOW - 2 * DAY)) }
        val alg = seq(oid(EC256))
        val list = if (entries.isEmpty()) NONE else seq(*entries.toTypedArray())
        val tbs = seq(int(1), alg, issuerDn, utc(NOW - DAY), utc(NOW + DAY), list)
        return seq(tbs, alg, bits(sign("SHA256withECDSA", signer, tbs)))
    }

    // ---- RIM ----

    const val DS = "http://www.w3.org/2000/09/xmldsig#"
    const val SWID = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
    const val C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
    const val ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    const val ECDSA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    const val DIGEST384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"

    val rimKey = p384()
    val rimSigner = issue(dn("NVIDIA RIM Signer"), dn(ROOT_CN), rootKey.private, rimKey, serial = int(9))
    val RIM_PINS = listOf(ROOT_PIN)
    val RIM_CERTS = "<ds:X509Certificate>${b64(rimSigner.der)}</ds:X509Certificate><ds:X509Certificate>${b64(root.der)}</ds:X509Certificate>"
    val KEY_INFO = "<ds:KeyInfo><ds:X509Data>$RIM_CERTS</ds:X509Data></ds:KeyInfo>"
    val C14N_EL = "<ds:CanonicalizationMethod Algorithm=\"$C14N11\"/>"
    val METHOD_EL = "<ds:SignatureMethod Algorithm=\"$ECDSA384\"/>"
    val TRANSFORMS = "<ds:Transforms><ds:Transform Algorithm=\"$ENVELOPED\"/><ds:Transform Algorithm=\"$C14N11\"/></ds:Transforms>"
    val DIGEST_EL = "<ds:DigestMethod Algorithm=\"$DIGEST384\"/>"

    /** One Measurement resource (Hash0, Hash1 ... in order). */
    fun res(
        index: String,
        hashes: List<String>,
        active: String = "true",
        alts: String = hashes.size.toString(),
        size: String = (hashes[0].length / 2).toString(),
        type: String = "Measurement",
    ): String {
        val hs = hashes.withIndex().joinToString("") { " Hash" + it.index + "=\"" + it.value + "\"" }
        return "<Resource type=\"$type\" index=\"$index\" active=\"$active\" alternatives=\"$alts\" size=\"$size\"$hs/>"
    }

    val META = "<Meta product=\"GH100\" colloquialVersion=\"535.86.10\"/>"
    val PAYLOAD = "<Payload>" + res("0", listOf("aabbccdd")) + "</Payload>"

    private fun sigOf(root: AttestXml.Node): AttestXml.Node = root.elementChildrenNs(DS, "Signature")[0]

    /** A RIM whose DigestValue and SignatureValue are computed (by `key`) over the document as assembled from these parts. */
    fun rim(
        payload: String = PAYLOAD,
        meta: String = META,
        c14n: String = C14N_EL,
        method: String = METHOD_EL,
        transforms: String = TRANSFORMS,
        digestMethod: String = DIGEST_EL,
        dv: (String) -> String = { "<ds:DigestValue>$it</ds:DigestValue>" },
        sv: (String) -> String = { "<ds:SignatureValue>$it</ds:SignatureValue>" },
        keyInfo: String = KEY_INFO,
        key: PrivateKey = rimKey.private,
        digestOf: (String) -> String = { it },
    ): String {
        fun doc(d: String, s: String): String =
            "<SoftwareIdentity xmlns=\"$SWID\" xmlns:ds=\"$DS\">$meta$payload<ds:Signature><ds:SignedInfo>$c14n$method" +
                "<ds:Reference URI=\"\">$transforms$digestMethod${dv(d)}</ds:Reference></ds:SignedInfo>${sv(s)}$keyInfo</ds:Signature></SoftwareIdentity>"
        val root0 = AttestXml.parse(doc("", "")).root
        val digest = digestOf(b64(AttestUtil.sha384(AttestXml.canonicalize(root0, emptyMap(), sigOf(root0)).toByteArray(Charsets.UTF_8))))
        val root1 = AttestXml.parse(doc(digest, "")).root
        val si = sigOf(root1).elementChildrenNs(DS, "SignedInfo")[0]
        val canon = AttestXml.canonicalize(si, si.parent!!.scope(), null)
        return doc(digest, b64(rawSign(key, canon.toByteArray(Charsets.UTF_8))))
    }

    /** "OK" or the verifyRim failure reason. */
    fun rimWhy(xml: String, pins: List<String> = RIM_PINS): String {
        val (r, why) = AttestNvidiaCollateral.verifyRim(xml, pins, NOW)
        return if (r != null) "OK" else why
    }

    // ---- SPDM ----

    fun le16(v: Int): ByteArray = b(v and 0xff, (v shr 8) and 0xff)

    /** A DMTF measurement block: index, spec, size; then type, value size, value. */
    fun block(index: Int, value: ByteArray): ByteArray = cat(b(index, 1), le16(3 + value.size), b(1), le16(value.size), value)

    fun opaqueTlv(t: Int, v: ByteArray): ByteArray = cat(le16(t), le16(v.size), v)

    /** GET_MEASUREMENTS request || MEASUREMENTS response, signed (raw P-384) by `key` (zeros when null). */
    fun transcript(nonce: ByteArray, blocks: List<ByteArray>, opaque: ByteArray, key: PrivateKey? = leafKey.private): ByteArray {
        val req = ByteArray(37)
        req[0] = 0x11
        req[1] = 0xe0.toByte()
        System.arraycopy(nonce, 0, req, 4, 32)
        val rec = cat(*blocks.toTypedArray())
        val head = b(0x11, 0x60, 0, 0, blocks.size, rec.size and 0xff, (rec.size shr 8) and 0xff, (rec.size shr 16) and 0xff)
        val signed = cat(req, head, rec, ByteArray(32), le16(opaque.size), opaque)
        return cat(signed, if (key == null) ByteArray(96) else rawSign(key, signed))
    }

    fun report(measurements: List<AttestNvidia.Measurement>, opaque: Map<Int, ByteArray>): AttestNvidia.Report =
        AttestNvidia.Report(0x11, 0x11, ByteArray(32), measurements, opaque, ByteArray(0), ByteArray(0))
}

/** Runs a test body with every [Kill05NvKit] member in scope. */
internal fun nv(body: Kill05NvKit.() -> Unit) = Kill05NvKit.body()
