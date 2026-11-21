package net.atlasauth.pca.verifier

import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.time.ZoneOffset

/** A transport response: the HTTP status and the body bytes. */
class NvidiaHttpResponse(val status: Int, val body: ByteArray) {
    val ok: Boolean get() = status in 200..299
}

/**
 * The injected transport of the NVIDIA fetch helpers: one request, `method` GET or POST, an optional `content-type` and body. Fetching is never automatic; a throw
 * is a transport failure.
 */
fun interface NvidiaFetch {
    fun fetch(url: String, method: String, contentType: String?, body: ByteArray?): NvidiaHttpResponse
}

@Suppress("UNCHECKED_CAST")
private object NvidiaShared {
    private val MONTHS = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

    /** OpenSSL's rendering of a certificate time: `Oct  8 23:00:00 2026 GMT`. */
    fun opensslTime(i: AttestDer.Instant): String {
        if (!i.ok) return "Bad time value"
        val t = Instant.ofEpochMilli(i.ms).atZone(ZoneOffset.UTC)
        return "%s %2d %02d:%02d:%02d %d GMT".format(MONTHS[t.monthValue - 1], t.dayOfMonth, t.hour, t.minute, t.second, t.year)
    }

    /** The serial as OpenSSL prints it: uppercase hex, two digits per byte, without the sign-padding zero bytes. */
    fun serialHex(c: AttestCert.Cert): String {
        var i = 0
        while (i < c.serial.size - 1 && c.serial[i].toInt() == 0) i++
        return AttestUtil.hex(c.serial.copyOfRange(i, c.serial.size)).uppercase()
    }

    fun certSummary(c: AttestCert.Cert): Map<String, Any?> {
        val (from, to) = AttestDer.derValidity(c.raw)
        return linkedMapOf(
            "subject" to AttestCert.nameText(c.rawSubject), "issuer" to AttestCert.nameText(c.rawIssuer), "serial" to serialHex(c), "notBefore" to opensslTime(from),
            "notAfter" to opensslTime(to), "spkiSha256" to AttestCert.keyOfCert(c).spkiSha256(), "rawSha256" to AttestUtil.hex(AttestUtil.sha256(c.raw)), "ca" to AttestNvidia.certIsCa(c),
        )
    }

    /** Split a PEM bundle into certificates, leaf first; throws on none or more than five. */
    fun parsePemChain(pem: String): List<AttestCert.Cert> {
        val blocks = AttestCert.pemCertBlocks(pem)
        if (blocks.isEmpty()) throw IllegalArgumentException("parsePemChain: no certificates found")
        if (blocks.size > 5) throw IllegalArgumentException("parsePemChain: chain longer than 5")
        return blocks.map { AttestCert.certFromPem(it) }
    }

    fun parseReport(evidence: ByteArray): AttestNvidia.Report = AttestNvidia.parseSpdmEvidence(evidence)
}

/**
 * NVIDIA GPU confidential-computing attestation, SPDM half (Hopper, Blackwell): the GET_MEASUREMENTS transcript parse, the device certificate chain pinned to a
 * NVIDIA root, the report signature (ECDSA P-384 / SHA-384) and the PCA challenge that binds the report to a holder, grant, epoch and nonce through the SPDM
 * request nonce. Results are JSON trees; a certificate is summarised as `{subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca}`.
 */
@Suppress("UNCHECKED_CAST")
object AttestNvidiaSpdm {
    const val NVIDIA_SPDM_SUITE = "nvidia-gpu-spdm-ecdsa-p384-sha384"

    /** The opaque-data TLV field ids the report surfaces by name. */
    @JvmField val NVIDIA_OPAQUE: Map<String, Int> = linkedMapOf(
        "CERT_ISSUER_NAME" to 1, "CERT_AUTHORITY_KEY_IDENTIFIER" to 2, "DRIVER_VERSION" to 3, "GPU_INFO" to 4, "SKU" to 5, "VBIOS_VERSION" to 6, "MANUFACTURER_ID" to 7,
        "TAMPER_DETECTION" to 8, "MSRSCNT" to 12, "BOARD_ID" to 14, "FWID" to 20, "OPAQUE_DATA_VERSION" to 34, "CHIP_INFO" to 35, "FEATURE_FLAG" to 36,
    )

    /**
     * Parse a request || response SPDM transcript. Total: throws on any structural problem and never returns a partial report. The summary is
     * `{request: {version, code, param1, param2, nonce, slot}, response: {version, code, numBlocks, measurements: [{index, valueType, digest}], responderNonce,
     * opaque: {<type>: bytes}, signature}, signedBytesLength, signedBytesSha256}`.
     */
    @JvmStatic
    fun parseNvidiaSpdmEvidence(bytes: ByteArray): Map<String, Any?> {
        val r = NvidiaShared.parseReport(bytes)
        val opaque = LinkedHashMap<String, Any?>()
        for (k in r.opaque.keys.sorted()) opaque[k.toString()] = r.opaque.getValue(k)
        return linkedMapOf(
            "request" to linkedMapOf(
                "version" to IntentJs.ofLong(r.requestVersion.toLong()), "code" to IntentJs.ofLong(r.requestCode.toLong()), "param1" to IntentJs.ofLong(r.param1.toLong()),
                "param2" to IntentJs.ofLong(r.param2.toLong()), "nonce" to r.requestNonce, "slot" to IntentJs.ofLong(r.slot.toLong()),
            ),
            "response" to linkedMapOf(
                "version" to IntentJs.ofLong(r.responseVersion.toLong()), "code" to IntentJs.ofLong(r.responseCode.toLong()), "numBlocks" to IntentJs.ofLong(r.numBlocks.toLong()),
                "measurements" to r.measurements.map { linkedMapOf("index" to IntentJs.ofLong(it.index.toLong()), "valueType" to IntentJs.ofLong(it.valueType.toLong()), "digest" to it.digest) },
                "responderNonce" to r.responderNonce, "opaque" to opaque, "signature" to r.signature,
            ),
            "signedBytesLength" to IntentJs.ofLong(r.signedBytes.size.toLong()), "signedBytesSha256" to AttestUtil.hex(AttestUtil.sha256(r.signedBytes)),
        )
    }

    /** NVIDIA's VBIOS version rendering: byte-reverse, then re-pair as dotted hex (`96.00.9f.00.04`). */
    @JvmStatic fun formatVbiosVersion(raw: ByteArray): String = AttestNvidia.formatVbiosVersion(raw)

    /** SHA-256 of a certificate's SubjectPublicKeyInfo DER, lowercase hex: the pin format of a root. Throws on a certificate that does not parse. */
    @JvmStatic fun spkiSha256Hex(certPem: String): String = AttestCert.keyOfCert(AttestCert.certFromPem(certPem)).spkiSha256()

    /** Split a PEM bundle into certificate summaries, leaf first; throws on none, more than five, or one that does not parse. */
    @JvmStatic fun parsePemChain(pem: String): List<Map<String, Any?>> = NvidiaShared.parsePemChain(pem).map { NvidiaShared.certSummary(it) }

    /**
     * Verify the device chain (leaf first): every link signed, every issuer a CA, every certificate inside its validity window, ECDSA P-384 throughout, the root
     * self-signed and its SPKI SHA-256 in `pins` (case-insensitive). `{ok: true, leaf, chain}` or `{ok: false, reason}`.
     */
    @JvmStatic
    fun verifyNvidiaDeviceChain(pem: String, pins: List<String>, nowMs: Double): Map<String, Any?> {
        val (chain, why) = AttestNvidia.verifyDeviceChain(pem, pins, Math.floor(nowMs).toLong())
        if (chain == null) return linkedMapOf("ok" to false, "reason" to why)
        val sums = chain.map { NvidiaShared.certSummary(it) }
        return linkedMapOf("ok" to true, "leaf" to sums[0], "chain" to sums)
    }

    /** ECDSA P-384 / SHA-384 verification of the report signature (IEEE P1363 r || s) under the leaf key of `chainPem`. Throws on a report or chain that does not parse. */
    @JvmStatic
    fun verifyNvidiaSpdmSignature(evidence: ByteArray, chainPem: String): Boolean {
        val rep = NvidiaShared.parseReport(evidence)
        val leaf = NvidiaShared.parsePemChain(chainPem)[0]
        val pub = AttestCert.keyOfCert(leaf).pub as? ECPublicKey ?: return false
        return AttestUtil.verifyRawEcdsa(pub, AttestUtil.sha384(rep.signedBytes), rep.signature)
    }

    /** The 32-byte SPDM challenge that carries the PCA binding: `sha256(attestationBinding(expected))`. Throws on a malformed expected binding. */
    @JvmStatic fun nvidiaSpdmChallenge(expected: Any?): ByteArray = AttestUtil.sha256(Attestation.attestationBinding(expected))
}

/**
 * NVIDIA Reference Integrity Manifests (SWID / CoRIM XML under an enveloped XMLDSig, strict profile, C14N 1.1, ECDSA P-384 / SHA-384), the RIM ids a report names,
 * the golden comparison (NVIDIA's merge, alternatives and NVDEC0 rules), CRL revocation, the post-verification collateral hook with its firmware policy, and the
 * guarded fetch helpers. Fetching is never automatic.
 */
@Suppress("UNCHECKED_CAST")
object AttestNvidiaRim {
    const val NVIDIA_RIM_BASE_URL = "https://rim.attestation.nvidia.com/v1/rim/"
    @JvmField val NVIDIA_GH100_CRL_URLS: List<String> = listOf("https://crl.ndis.nvidia.com/crl/l2-gh100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl")
    @JvmField val NVIDIA_GB100_CRL_URLS: List<String> = listOf("https://crl.ndis.nvidia.com/crl/l2-gb100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl")
    private val RIM_ID = Regex("[A-Za-z0-9_.-]+")

    private fun summary(r: AttestNvidiaCollateral.Rim): Map<String, Any?> = linkedMapOf(
        "tagId" to r.tagId, "product" to r.product, "version" to r.version,
        "golden" to r.golden.values.sortedBy { it.index }.map {
            linkedMapOf("index" to IntentJs.ofLong(it.index.toLong()), "active" to it.active, "alternatives" to IntentJs.ofLong(it.alternatives.toLong()), "size" to IntentJs.ofLong(it.size.toLong()), "hashes" to it.hashes)
        },
        "signerSubject" to r.signerSubject,
    )

    private fun rimOf(m: Map<String, Any?>): AttestNvidiaCollateral.Rim {
        val g = LinkedHashMap<Int, AttestNvidiaCollateral.Golden>()
        for (x in m["golden"] as List<Any?>) {
            val e = x as Map<String, Any?>
            val index = IntentJs.num(e["index"])!!.toInt()
            g[index] = AttestNvidiaCollateral.Golden(index, e["active"] == true, IntentJs.num(e["alternatives"])!!.toInt(), IntentJs.num(e["size"])!!.toInt(), (e["hashes"] as List<Any?>).map { it as String })
        }
        return AttestNvidiaCollateral.Rim(m["product"] as String, m["version"] as String, g, (m["tagId"] as? String) ?: "", (m["signerSubject"] as? String) ?: "")
    }

    /**
     * Verify a RIM document (XML text; anything else is refused) against the pinned RIM root SPKI SHA-256 pins at `nowMs` and return its golden measurements:
     * `{ok: true, rim: {tagId, product, version, golden: [{index, active, alternatives, size, hashes}], signerSubject}}` or `{ok: false, reason}`.
     */
    @JvmStatic
    fun verifyNvidiaRim(xml: Any?, rimRootSpkiSha256: List<String>, nowMs: Double): Map<String, Any?> {
        val (rim, why) = AttestNvidiaCollateral.verifyRim(if (xml is String) xml else "", rimRootSpkiSha256, Math.floor(nowMs).toLong())
        if (rim == null) return linkedMapOf("ok" to false, "reason" to why)
        return linkedMapOf("ok" to true, "rim" to summary(rim))
    }

    /**
     * The RIM ids a report requires, read from the GPU's own signed opaque data: `{chip, driver, vbios, driverVersion, vbiosVersion}`, or null when the report lacks
     * the fields or carries a malformed chip name (fail closed). Hopper reports carry no chip field (`GH100`); a Blackwell report names its chip.
     */
    @JvmStatic
    fun nvidiaRimIdsForReport(evidence: ByteArray): Map<String, Any?>? {
        val i = AttestNvidiaCollateral.rimIdsForReport(AttestNvidia.parseSpdmEvidence(evidence)) ?: return null
        return linkedMapOf("chip" to i.chip, "driver" to i.driver, "vbios" to i.vbios, "driverVersion" to i.driverVersion, "vbiosVersion" to i.vbiosVersion)
    }

    /**
     * Compare a report with the verified driver and VBIOS RIMs (`rim` objects of [verifyNvidiaRim]): `{ok: true, checked}` or `{ok: false, reason, mismatches?:
     * [{index, source}]}`.
     */
    @JvmStatic
    fun compareReportToRims(evidence: ByteArray, driver: Map<String, Any?>, vbios: Map<String, Any?>): Map<String, Any?> {
        val c = AttestNvidiaCollateral.compareReport(AttestNvidia.parseSpdmEvidence(evidence), rimOf(driver), rimOf(vbios))
        if (c.ok) return linkedMapOf("ok" to true, "checked" to IntentJs.ofLong(c.checked.toLong()))
        val out = linkedMapOf<String, Any?>("ok" to false, "reason" to c.reason)
        c.mismatches?.let { ms -> out["mismatches"] = ms.map { linkedMapOf("index" to IntentJs.ofLong(it.index.toLong()), "source" to it.source) } }
        return out
    }

    /**
     * Check the device chain (`chainPem`) against CRLs: every CRL must verify under one chain certificate and be fresh, no chain certificate may be listed by its
     * issuer's CRL, each `requireIssuers` substring needs a verified CRL from a matching issuer, and `requireFor` (`"cdp"`: each non-root certificate that names a
     * CRL distribution point, `"all"`, `"none"`, or a list of chain indices) must be covered by a verified CRL from the certificate's issuer.
     * `{ok: true, verifiedCrls}` or `{ok: false, reason}`.
     */
    @JvmStatic @JvmOverloads
    fun checkNvidiaChainRevocation(chainPem: String, crls: List<ByteArray>, nowMs: Double, requireIssuers: List<String> = emptyList(), requireFor: Any? = "cdp"): Map<String, Any?> {
        val why = AttestNvidiaCollateral.checkChainRevocation(NvidiaShared.parsePemChain(chainPem), crls, Math.floor(nowMs).toLong(), requireIssuers, requireFor)
        return if (why == "") linkedMapOf("ok" to true, "verifiedCrls" to IntentJs.ofLong(crls.size.toLong())) else linkedMapOf("ok" to false, "reason" to why)
    }

    /** The post-verification collateral check of [createNvidiaCollateralHook]. */
    class CollateralHook internal constructor(private val hook: AttestNvidiaCollateral.Hook) {
        /**
         * Check the collateral `bundle` (`{driverRimXml, vbiosRimXml, crls?: [bytes], ocsp?: [bytes]}`, null when none was supplied) against a report and its chain
         * at `nowMs`: the chip family of the leaf, the firmware policy, both RIMs (signature, product, versions), the golden comparison and revocation. Returns the
         * refusal reason, or null when the collateral holds.
         */
        fun check(bundle: Map<String, Any?>?, evidence: ByteArray, chainPem: String, nowMs: Double): String? {
            val b: Map<String, Any?>? = bundle?.let {
                linkedMapOf(
                    "driverRimXml" to it["driverRimXml"], "vbiosRimXml" to it["vbiosRimXml"],
                    "crls" to ((it["crls"] as List<ByteArray>?) ?: emptyList()).map { x -> java.util.Base64.getEncoder().encodeToString(x) },
                    "ocsp" to ((it["ocsp"] as List<ByteArray>?) ?: emptyList()).map { x -> java.util.Base64.getEncoder().encodeToString(x) },
                )
            }
            val why = hook.withBundle(b).run(AttestNvidia.parseSpdmEvidence(evidence), NvidiaShared.parsePemChain(chainPem), Math.floor(nowMs).toLong())
            return if (why == "") null else why
        }
    }

    /**
     * Build the collateral hook from `opts`: `rimRootSpkiSha256` (required), `revocation` (`crl` default, `ocsp` or `both`; supplied evidence is enforced even when
     * not required), `requireCrls` (false makes CRLs optional), `requireCrlIssuers`, `requireCrlFor` and `firmware` `{minDriverVersion, minVbiosVersion,
     * denyDriverVersions, denyVbiosVersions}`. Throws on a malformed option.
     */
    @JvmStatic fun createNvidiaCollateralHook(opts: Map<String, Any?>): CollateralHook = CollateralHook(AttestNvidiaCollateral.newHook(opts))

    /** Fetch a RIM document from the NVIDIA RIM service through the injected transport and return its XML text. Throws on a bad id, a non-2xx status or a body without `rim`. */
    @JvmStatic @JvmOverloads
    fun fetchNvidiaRim(id: String, fetch: NvidiaFetch, baseUrl: String? = null): String {
        if (!RIM_ID.matches(id)) throw IllegalArgumentException("fetchNvidiaRim: invalid RIM id")
        val res = fetch.fetch((baseUrl ?: NVIDIA_RIM_BASE_URL) + id, "GET", null, null)
        if (!res.ok) throw IllegalStateException("RIM fetch failed: HTTP ${res.status} for $id")
        val body = Json.parseLenient(String(res.body, Charsets.UTF_8)) as? Map<*, *> ?: throw IllegalStateException("RIM fetch: response has no rim field")
        val rim = body["rim"] as? String ?: throw IllegalStateException("RIM fetch: response has no rim field")
        return String(AttestUtil.nodeB64(rim), Charsets.UTF_8)
    }

    /** Fetch a DER CRL through the injected transport. Throws on a non-2xx status. */
    @JvmStatic
    fun fetchNvidiaCrl(url: String, fetch: NvidiaFetch): ByteArray {
        val res = fetch.fetch(url, "GET", null, null)
        if (!res.ok) throw IllegalStateException("CRL fetch failed: HTTP ${res.status} for $url")
        return res.body
    }
}

/**
 * NVIDIA OCSP (RFC 6960) for the device chain: the request builder (SHA-384 CertID by default, optional nonce), the response verifier (issuer or delegated
 * responder, nonce echo, freshness with skew and age bounds, certificate status) and the chain policy. Fetching is never automatic.
 */
@Suppress("UNCHECKED_CAST")
object AttestNvidiaOcsp {
    const val NVIDIA_OCSP_URL = "http://ocsp.ndis.nvidia.com/"
    const val NVIDIA_OCSP_DEFAULT_MAX_AGE_MS: Long = AttestNvidiaCollateral.OCSP_DEFAULT_MAX_MS

    private val HASH_OIDS = mapOf(
        "md5" to Pair("MD5", ByteArray(0)), // no OID is registered for it: the AlgorithmIdentifier carries an empty OBJECT IDENTIFIER, as the reference's encoder writes it
        "sha1" to Pair("SHA-1", byteArrayOf(0x2B, 0x0E, 0x03, 0x02, 0x1A)),
        "sha256" to Pair("SHA-256", byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)),
        "sha384" to Pair("SHA-384", byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)),
        "sha512" to Pair("SHA-512", byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)),
    )
    private val OID_NONCE = byteArrayOf(0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02)

    private fun der(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val len = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
            else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        }
        return byteArrayOf(tag.toByte()) + len + body
    }

    /**
     * Build a DER OCSPRequest for `certPem` (issued by `issuerPem`): a CertID over the issuer's name and key under `hash` (`sha1`, `sha256`, `sha384` by default or
     * `sha512`) and, when given, a nonce of 1..32 bytes. Throws on an unsupported hash, a bad nonce or a certificate that does not parse.
     */
    @JvmStatic @JvmOverloads
    fun buildNvidiaOcspRequest(certPem: String, issuerPem: String, nonce: ByteArray? = null, hash: String? = null): ByteArray {
        val h = HASH_OIDS[hash ?: "sha384"] ?: throw IllegalArgumentException("unsupported hash '$hash'")
        val cert = AttestCert.certFromPem(certPem)
        val issuer = AttestCert.certFromPem(issuerPem)
        val md = { b: ByteArray -> java.security.MessageDigest.getInstance(h.first).digest(b) }
        val alg = der(0x30, der(0x06, h.second) + byteArrayOf(0x05, 0x00))
        val certId = der(0x30, alg + der(0x04, md(issuer.rawSubject)) + der(0x04, md(AttestCert.spkiKeyBits(issuer))) + der(0x02, cert.serial))
        val requestList = der(0x30, der(0x30, certId)) // SEQUENCE OF Request, a Request being { reqCert }
        var tbs = der(0x30, requestList)
        if (nonce != null) {
            if (nonce.isEmpty() || nonce.size > 32) throw IllegalArgumentException("nonce must be 1..32 bytes")
            val ext = der(0x30, der(0x06, OID_NONCE) + der(0x04, der(0x04, nonce)))
            tbs = der(0x30, requestList + der(0xA2, der(0x30, ext)))
        }
        return der(0x30, tbs)
    }

    private fun pemAt(chain: List<AttestCert.Cert>, i: Int): AttestCert.Cert = chain.getOrNull(i) ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'raw')")

    private fun resultMap(r: AttestNvidiaCollateral.OcspResult): Map<String, Any?> {
        if (!r.ok) return linkedMapOf("ok" to false, "reason" to r.reason)
        val m = linkedMapOf<String, Any?>("ok" to true, "status" to r.status, "thisUpdate" to IntentJs.ofLong(r.thisUpdate))
        r.nextUpdate?.let { m["nextUpdate"] = IntentJs.ofLong(it) }
        m["producedAt"] = IntentJs.ofLong(r.producedAt)
        r.revokedAt?.let { m["revokedAt"] = IntentJs.ofLong(it) }
        r.revocationReason?.let { m["revocationReason"] = IntentJs.ofLong(it.toLong()) }
        m["responder"] = r.responder
        return m
    }

    /**
     * Verify one DER OCSPResponse for chain certificate `certIndex` (issued by `issuerIndex`, default the next one) of `chainPem`. Never throws. `opts`:
     * `maxAgeMs` (default 7 days; also applied when `nextUpdate` is absent), `clockSkewMs` (default 0) and `expectedNonce` (the response must echo exactly it).
     * `{ok: true, status, thisUpdate, nextUpdate?, producedAt, revokedAt?, revocationReason?, responder}` or `{ok: false, reason}`.
     */
    @JvmStatic @JvmOverloads
    fun verifyNvidiaOcspResponse(responseDer: ByteArray, chainPem: String, certIndex: Int, nowMs: Double, issuerIndex: Int? = null, opts: Map<String, Any?> = emptyMap()): Map<String, Any?> = try {
        val chain = NvidiaShared.parsePemChain(chainPem)
        val o = AttestNvidiaCollateral.OcspOptions(
            if (opts["maxAgeMs"] != null) IntentJs.num(opts["maxAgeMs"])!! else AttestNvidiaCollateral.OCSP_DEFAULT_MAX_MS.toDouble(),
            if (opts["clockSkewMs"] != null) IntentJs.num(opts["clockSkewMs"])!! else 0.0, opts["expectedNonce"] as ByteArray?,
        )
        resultMap(AttestNvidiaCollateral.verifyOcspResponse(responseDer, pemAt(chain, certIndex), pemAt(chain, issuerIndex ?: (certIndex + 1)), chain, Math.floor(nowMs).toLong(), o))
    } catch (e: RuntimeException) {
        linkedMapOf("ok" to false, "reason" to "OCSP response rejected: ${e.message ?: "malformed"}")
    }

    /** The OCSP responder URLs a certificate advertises in its Authority Information Access extension. */
    @JvmStatic fun nvidiaCertOcspUrls(certPem: String): List<String> = AttestCert.certFromPem(certPem).ocspServers()

    /**
     * Check the device chain with OCSP responses: every response must verify for exactly one chain certificate, any REVOKED fails, and the certificates
     * `requireGood` names (`"aia"` default: each non-root certificate that advertises a responder, `"all"`, or chain indices) need a GOOD response. `opts`:
     * `requireGood`, `maxAgeMs`, `clockSkewMs`, `expectedNonces` (a nonce or null per chain index). `{ok: true, verifiedCrls: 0, verifiedOcsp, statuses}` or
     * `{ok: false, reason, statuses?}`; `statuses` maps each non-root chain index to good, revoked, unknown or absent.
     */
    @JvmStatic @JvmOverloads
    fun checkNvidiaChainOcsp(chainPem: String, responses: List<ByteArray>, nowMs: Double, opts: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val co = AttestNvidiaCollateral.ChainOcspOptions(
            opts["requireGood"], opts["maxAgeMs"]?.let { IntentJs.num(it) }, opts["clockSkewMs"]?.let { IntentJs.num(it) }, opts["expectedNonces"] as List<ByteArray?>?,
        )
        val r = AttestNvidiaCollateral.checkChainOcspFull(NvidiaShared.parsePemChain(chainPem), responses, Math.floor(nowMs).toLong(), co)
        val st = r.statuses?.let { s -> LinkedHashMap<String, Any?>().also { m -> for ((k, v) in s) m[k.toString()] = v } }
        if (r.ok) return linkedMapOf("ok" to true, "verifiedCrls" to IntentJs.ofLong(0), "verifiedOcsp" to IntentJs.ofLong(r.verified.toLong()), "statuses" to st)
        val out = linkedMapOf<String, Any?>("ok" to false, "reason" to r.reason)
        if (st != null) out["statuses"] = st
        return out
    }

    /** POST an OCSPRequest for `certPem` to the responder (default [NVIDIA_OCSP_URL]) through the injected transport; `{request, response}` are DER. Explicit use only. */
    @JvmStatic @JvmOverloads
    fun fetchNvidiaOcsp(certPem: String, issuerPem: String, fetch: NvidiaFetch, url: String? = null, nonce: ByteArray? = null): Map<String, Any?> {
        val request = buildNvidiaOcspRequest(certPem, issuerPem, nonce)
        val res = fetch.fetch(url ?: NVIDIA_OCSP_URL, "POST", "application/ocsp-request", request)
        if (!res.ok) throw IllegalStateException("OCSP fetch failed: HTTP ${res.status}")
        return linkedMapOf("request" to request, "response" to res.body)
    }

    /**
     * True when every UTCTime and GeneralizedTime inside the DER value is a well-formed DER time with in-range fields (no calendar roll-over); the contents of
     * OCTET STRING and BIT STRING are opaque and never inspected. A value the reader cannot parse is false.
     */
    @JvmStatic fun allAsn1TimesWellFormed(der: ByteArray): Boolean = AttestNvidiaCollateral.asn1TimesWellFormed(der)
}
