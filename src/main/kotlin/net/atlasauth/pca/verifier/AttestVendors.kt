package net.atlasauth.pca.verifier

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The public names of the hardware-attestation vendor modules of the reference (`attest-amd-snp`, `attest-intel-dcap`, `attest-intel-tdx`,
 * `attest-intel-collateral`, `attest-azure-maa`, `attest-gcp-confidential-space`, `attest-nvidia-spdm`): the suite and trust-anchor constants, the
 * verifier constructors (each is [Attest.verifierFromConfig] for its vendor: the configuration is the language-neutral one of the conformance vectors), the
 * wire parsers, the Intel PCK chain and PCS collateral verifiers, and the JWKS fetchers over an injected transport. Everything here verifies exactly what
 * the vendor verifiers verify and fails closed; a parser throws [IllegalArgumentException] with the reference's message on a structural violation.
 */
@Suppress("UNCHECKED_CAST")
object AttestVendors {
    const val AMD_SNP_SUITE = "amd-sev-snp-ecdsa-p384"
    const val INTEL_DCAP_SUITE = "intel-tdx-dcap-ecdsa-p256"
    const val AZURE_MAA_SUITE = "azure-maa-jwt"
    const val GCP_CS_SUITE = "gcp-confidential-space-jwt"
    const val GCP_CS_DEFAULT_ISSUER = "https://confidentialcomputing.googleapis.com"
    const val INTEL_SGX_ROOT_CA_SPKI_SHA256 = AttestIntel.SGX_ROOT_CA_SPKI_SHA256

    /** The built-in AMD root (ARK) SPKI SHA-384 pins by processor family (`milan`, `genoa`, `turin`). */
    @JvmField val AMD_ARK_SPKI_SHA384: Map<String, String> = LinkedHashMap(AttestAmd.ARK_SPKI_SHA384)
    @JvmField val AZURE_MAA_SUITES: List<String> = listOf("ES256", "RS256")
    @JvmField val GCP_CS_SUITES: List<String> = listOf("RS256", "ES256")
    /** The TCB statuses the collateral verifier accepts by default. */
    @JvmField val DEFAULT_ACCEPTED_STATUSES: List<String> = AttestIntel.DEFAULT_ACCEPTED_STATUSES

    // ---- verifier constructors ----

    @JvmStatic fun createAmdSnpVerifier(config: Map<String, Any?>?): Attest.VendorVerifier = Attest.verifierFromConfig("amd-sev-snp", config)
    @JvmStatic fun createIntelDcapVerifier(config: Map<String, Any?>?): Attest.VendorVerifier = Attest.verifierFromConfig("intel-tdx-dcap", config)
    @JvmStatic fun createAzureMaaVerifier(config: Map<String, Any?>?): Attest.VendorVerifier = Attest.verifierFromConfig("azure-maa", config)
    @JvmStatic fun createGcpConfidentialSpaceVerifier(config: Map<String, Any?>?): Attest.VendorVerifier = Attest.verifierFromConfig("gcp-confidential-space", config)
    @JvmStatic fun createNvidiaSpdmVerifier(config: Map<String, Any?>?): Attest.VendorVerifier = Attest.verifierFromConfig("nvidia-gpu-spdm", config)

    /** The NVIDIA post-verification collateral hook (see [AttestNvidiaRim.createNvidiaCollateralHook]). */
    @JvmStatic fun nvidiaCollateralHook(opts: Map<String, Any?>): AttestNvidiaRim.CollateralHook = AttestNvidiaRim.createNvidiaCollateralHook(opts)

    /** A fresh in-memory MAA key-state store (tests, one process); production callers persist durably ([AttestMaaKeys.durableMaaKeyStateStore]). */
    @JvmStatic fun createMemoryMaaKeyStateStore(): AttestMaaKeys.MemoryMaaKeyStateStore = AttestMaaKeys.MemoryMaaKeyStateStore()

    // ---- Intel TDX / DCAP ----

    /** A NIST P-256 public key as the uncompressed SEC1 point (`0x04 || X || Y`, 65 bytes). */
    class EcdsaP256PublicKey internal constructor(val point: ByteArray)

    /** Wrap and validate a P-256 public key (uncompressed or compressed SEC1). Throws on an off-curve point. */
    @JvmStatic
    fun ecdsaP256PublicKey(sec1: ByteArray): EcdsaP256PublicKey {
        require(sec1.size == 33 || sec1.size == 65) { "invalid Point, expected length of 33, or uncompressed 65, got ${sec1.size}" }
        val curve = org.bouncycastle.asn1.nist.NISTNamedCurves.getByName("P-256").curve
        return EcdsaP256PublicKey(curve.decodePoint(sec1).getEncoded(false))
    }

    private fun <T> typed(f: () -> T): T = try {
        f()
    } catch (e: AttErr) {
        throw IllegalArgumentException(e.message ?: "invalid")
    }

    /**
     * Parse a genuine Intel DCAP v4 / ECDSA-P256 / TDX quote: `{version, attKeyType, teeType, header, tdReportBody, quoteSignature, akPubRaw, qeReportBody,
     * qeReportSignature, qeAuthData, pckChainPem}`. Bounds-checked; throws on any structural violation (non-zero bytes after the declared signature data included).
     */
    @JvmStatic
    fun parseDcapQuote(quote: ByteArray): Map<String, Any?> {
        val q = typed { AttestIntel.parseQuote(quote) }
        val le = ByteBuffer.wrap(q.header).order(ByteOrder.LITTLE_ENDIAN)
        return Issue.obj(
            "version" to IntentJs.ofLong((le.getShort(0).toInt() and 0xffff).toLong()), "attKeyType" to IntentJs.ofLong((le.getShort(2).toInt() and 0xffff).toLong()),
            "teeType" to IntentJs.ofLong(le.getInt(4).toLong() and 0xffffffffL), "header" to q.header, "tdReportBody" to q.tdReportBody,
            "quoteSignature" to q.quoteSignature, "akPubRaw" to q.akPubRaw, "qeReportBody" to q.qeReportBody, "qeReportSignature" to q.qeReportSignature,
            "qeAuthData" to q.qeAuthData, "pckChainPem" to q.pckChainPem,
        )
    }

    private const val TD_REPORT_LEN = 584

    /** Parse a genuine 584-byte TD10 report body: `{teeTcbSvn, mrSeam, mrSignerSeam, tdAttributes, mrTd, mrConfigId, rtmr0..rtmr3, reportData, raw}`. */
    @JvmStatic
    fun parseDcapTdReport(body: ByteArray): Map<String, Any?> {
        if (body.size < TD_REPORT_LEN) throw IllegalArgumentException("parseDcapTdReport: body too short (${body.size} < $TD_REPORT_LEN)")
        fun at(off: Int, len: Int) = body.copyOfRange(off, off + len)
        return Issue.obj(
            "teeTcbSvn" to at(0, 16), "mrSeam" to at(16, 48), "mrSignerSeam" to at(64, 48), "tdAttributes" to at(120, 8), "mrTd" to at(136, 48), "mrConfigId" to at(184, 48),
            "rtmr0" to at(328, 48), "rtmr1" to at(376, 48), "rtmr2" to at(424, 48), "rtmr3" to at(472, 48), "reportData" to at(520, 64), "raw" to at(0, TD_REPORT_LEN),
        )
    }

    private fun point(k: java.security.interfaces.ECPublicKey): ByteArray {
        fun fixed(v: java.math.BigInteger): ByteArray {
            val b = v.toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
            return ByteArray(32 - b.size) + b
        }
        return byteArrayOf(4) + fixed(k.w.affineX) + fixed(k.w.affineY)
    }

    /**
     * X.509-verify an Intel PCK certificate chain (PEM) to the PINNED Intel SGX Root CA (`trustAnchorRootCaSpkiSha256`, default the built-in pin) at `nowMs`
     * (default the clock): `{ok, reason?, leafKey?: EcdsaP256PublicKey, leafDer?, depth?, failure?: "validity"}`.
     */
    @JvmStatic @JvmOverloads
    fun verifyIntelPckChainX509(pckChainPem: String, trustAnchorRootCaSpkiSha256: String? = null, nowMs: Long? = null): Map<String, Any?> {
        val r = AttestIntel.verifyPckChain(pckChainPem, trustAnchorRootCaSpkiSha256 ?: INTEL_SGX_ROOT_CA_SPKI_SHA256, nowMs ?: System.currentTimeMillis())
        if (!r.ok) return Issue.obj("ok" to false, "reason" to r.reason).also { if (r.validity) it["failure"] = "validity" }
        return Issue.obj(
            "ok" to true, "leafKey" to EcdsaP256PublicKey(point(r.leafKey!!)), "leafDer" to r.leaf!!.raw, "depth" to IntentJs.ofLong(r.depth.toLong()),
        )
    }

    /** Is the serial (hex, any case, leading zeros ignored) in the CRL's revoked list (as returned by [verifyCrl]: lowercase hex without leading zeros)? */
    @JvmStatic
    fun serialIsRevoked(revoked: Collection<String>, serialHex: String): Boolean = revoked.contains(serialHex.lowercase().trimStart('0'))

    /** Decode a PCS issuer-chain HTTP header value (URL-encoded PEM) to PEM: `decodeURIComponent`, so `+` stays `+`; malformed escapes and invalid UTF-8 throw. */
    @JvmStatic
    fun decodeIssuerChainHeader(value: String): String {
        val out = StringBuilder()
        var i = 0
        while (i < value.length) {
            if (value[i] != '%') { out.append(value[i++]); continue }
            val run = java.io.ByteArrayOutputStream()
            while (i < value.length && value[i] == '%') {
                val hi = if (i + 2 < value.length) Character.digit(value[i + 1], 16) else -1
                val lo = if (i + 2 < value.length) Character.digit(value[i + 2], 16) else -1
                if (hi < 0 || lo < 0) throw IllegalArgumentException("URI malformed")
                run.write(hi * 16 + lo)
                i += 3
            }
            try {
                out.append(Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(run.toByteArray())))
            } catch (e: java.nio.charset.CharacterCodingException) {
                throw IllegalArgumentException("URI malformed")
            }
        }
        return out.toString()
    }

    /**
     * Verify a genuine Intel DCAP TDX quote and then its Intel PCS collateral at `nowMs`, returning the evaluated TCB status and the policy decision. The
     * collateral is `{tcbInfoJson, tcbInfoIssuerChainPem, qeIdentityJson, qeIdentityIssuerChainPem, pckCrlDer, rootCrlDer}`; the policy `{acceptStatuses?, minTcbEvaluationDataNumber?}` (`minEval` is accepted too); the JSON members are text or UTF-8 bytes.
     * Fail closed. `{ok, reason?, status?, platformStatus?, tdxModuleStatus?, qeStatus?, advisoryIds?, tcbEvaluationDataNumber?, fmspc?}`.
     */
    @JvmStatic @JvmOverloads
    fun verifyIntelTdxCollateral(
        quote: ByteArray, collateral: Map<String, Any?>?, nowMs: Long, policy: Map<String, Any?>? = null, trustAnchorRootCaSpkiSha256: String? = null, allowDebug: Boolean = false,
    ): Map<String, Any?> {
        val pol = if (policy == null) null else AttestIntel.CollateralPolicy(
            (policy["acceptStatuses"] as? List<Any?>)?.map { it as String }, IntentJs.num(policy["minTcbEvaluationDataNumber"] ?: policy["minEval"]),
        )
        val c = if (collateral == null) null else AttestIntel.collateralFromWire(collateral)
        val r = AttestIntel.verifyTdxCollateral(quote, c, nowMs, pol, trustAnchorRootCaSpkiSha256 ?: INTEL_SGX_ROOT_CA_SPKI_SHA256, allowDebug)
        val out = Issue.obj("ok" to r.ok)
        if (r.reason.isNotEmpty()) out["reason"] = r.reason
        if (r.status.isNotEmpty()) {
            out["status"] = r.status
            out["platformStatus"] = r.platformStatus
            out["tdxModuleStatus"] = r.tdxModuleStatus
            out["qeStatus"] = r.qeStatus
            out["advisoryIds"] = ArrayList<Any?>(r.advisoryIds)
            val evalNum = r.tcbEvaluationDataNumber
            if (evalNum != null) out["tcbEvaluationDataNumber"] = StoreJs.num(evalNum)
            out["fmspc"] = r.fmspc
        }
        return out
    }

    // ---- byte / text helpers ----

    /** Lowercase hex of the bytes. */
    @JvmStatic fun toHex(b: ByteArray): String = AttestUtil.hex(b)

    private val PEM_CERT = Regex("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL)
    private val JS_SPACE = Regex("[\\s\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]+")

    /** The DER of the FIRST certificate block of a PEM text (base64 body, whitespace removed, decoded the way the reference does); throws when there is none. */
    @JvmStatic
    fun pemToDer(pem: String): ByteArray {
        val body = PEM_CERT.find(pem)?.groupValues?.get(1)
        if (body.isNullOrEmpty()) throw IllegalArgumentException("pemToDer: no certificate found")
        return AttestUtil.nodeB64(body.replace(JS_SPACE, ""))
    }

    private fun strings(v: Any?): List<String> = (v as? List<*>)?.filterIsInstance<String>() ?: emptyList()

    /** An expected binding from its wire map; a missing or mistyped member stays invalid so the binding check names it. */
    private fun bindingOfWire(e: Map<String, Any?>): Attest.Binding =
        Attest.Binding(e["holderPub"] as? String ?: "", e["grantRef"] as? String ?: "", IntentJs.num(e["epoch"]) ?: Double.NaN, e["nonce"] as? String ?: "")

    /**
     * The 5 fields of a PCK leaf's Intel SGX extension: `{fmspc, sgxTcbComponents (16), pcesvn, cpusvn}`. Throws on a missing or malformed extension.
     */
    @JvmStatic
    fun extractPckFmspcAndTcb(leafDer: ByteArray): Map<String, Any?> = pckTcbMap(typed { AttestIntel.extractPckFmspcAndTcb(leafDer) })

    private fun pckTcbMap(t: AttestIntel.PckTcb): Map<String, Any?> =
        Issue.obj("fmspc" to t.fmspc, "sgxTcbComponents" to t.sgx, "pcesvn" to IntentJs.ofLong(t.pcesvn.toLong()), "cpusvn" to t.cpusvn)

    /**
     * Verify a genuine Intel DCAP v4 / ECDSA-P256 / TDX quote end to end, offline: the PCK chain to the pinned Intel root at `nowMs` (default the clock),
     * the QE report and quote signatures, optionally the PCA binding (`expected = {holderPub, grantRef, epoch, nonce}`) and the acceptance policy
     * `{mrtds?, fmspcs?, rtmrs?, mrSeams?, mrSignerSeams?, allowDebug?}` (an empty `mrSeams` / `mrSignerSeams` list refuses everything; an empty
     * `mrtds` / `fmspcs` / `rtmrs` list is not gated). `{ok, reason?, report?, fmspc?, pckTcb?, akPub?, chainDepth?, measured?}`. Fails closed.
     */
    @JvmStatic @JvmOverloads
    fun verifyGenuineTdxQuote(
        quote: ByteArray, nowMs: Long? = null, trustAnchorRootCaSpkiSha256: String? = null, expected: Map<String, Any?>? = null, policy: Map<String, Any?>? = null,
    ): Map<String, Any?> {
        fun low(k: String): List<String> = strings(policy?.get(k)).map { it.lowercase() }
        val pol = if (policy == null) null else AttestIntel.QuotePolicy(
            low("mrtds"), low("fmspcs"), low("rtmrs"),
            if (policy["mrSeams"] is List<*>) low("mrSeams") else null, if (policy["mrSignerSeams"] is List<*>) low("mrSignerSeams") else null, policy["allowDebug"] == true,
        )
        val r = AttestIntel.verifyGenuineTdxQuote(quote, trustAnchorRootCaSpkiSha256 ?: INTEL_SGX_ROOT_CA_SPKI_SHA256, nowMs ?: System.currentTimeMillis(), pol, false, expected?.let { bindingOfWire(it) })
        if (!r.ok) return Issue.obj("ok" to false, "reason" to r.reason)
        return Issue.obj(
            "ok" to true, "report" to parseDcapTdReport(AttestIntel.parseQuote(quote).tdReportBody), "fmspc" to r.fmspc, "pckTcb" to pckTcbMap(r.pck!!),
            "akPub" to EcdsaP256PublicKey(byteArrayOf(4) + r.akPubRaw!!), "chainDepth" to IntentJs.ofLong(r.depth.toLong()), "measured" to AttestUtil.newMeasured(AttestUtil.hex(r.mrTd!!), ""),
        )
    }

    /** Verify a DER CRL under the issuer public key (`issuerSpkiDer`, its SubjectPublicKeyInfo) at `nowMs`: `{ok: true, revoked: [sorted lowercase hex serials]}` or `{ok: false, reason}`. */
    @JvmStatic
    fun verifyCrl(crlDer: ByteArray, issuerSpkiDer: ByteArray, nowMs: Long): Map<String, Any?> {
        val (revoked, why) = AttestIntel.verifyCrl(crlDer, typed { AttestCert.keyOfSpki(issuerSpkiDer) }, nowMs)
        return if (revoked != null && why.isEmpty()) Issue.obj("ok" to true, "revoked" to ArrayList<Any?>(revoked.sorted())) else Issue.obj("ok" to false, "reason" to why)
    }

    /**
     * Verify a signed PCS document `{"<name>":{...},"signature":"<128 hex>"}`: the ECDSA P-256 / SHA-256 signature is over the exact source bytes of the
     * named object. `{body}` on success, `{error}` otherwise.
     */
    @JvmStatic
    fun verifySignedJson(text: String, name: String, issuerSpkiDer: ByteArray): Map<String, Any?> {
        val (body, why) = AttestIntel.verifySignedJson(text, name, typed { AttestCert.keyOfSpki(issuerSpkiDer) })
        return if (body != null && why.isEmpty()) Issue.obj("body" to body) else Issue.obj("error" to why)
    }

    /**
     * The Azure runtime-data binding of a TDX quote: sha256(runtime data) equals the report data and the runtime `user-data` carries the PCA binding of
     * `expected = {holderPub, grantRef, epoch, nonce}`. The failure reason, or null when it holds.
     */
    @JvmStatic
    fun checkAzureRuntimeDataBinding(reportData: ByteArray, runtimeData: ByteArray, expected: Map<String, Any?>): String? =
        AttestUtil.checkAzureRuntimeDataBinding(reportData, runtimeData, bindingOfWire(expected)).ifEmpty { null }

    /**
     * Verify an Azure MAA signing x5c chain (base64 DER, leaf first) at `nowMs` to the anchors `{rootCertsPem?, rootSpkiSha256?}` (a pinned key anywhere in the
     * chain, or a root certificate): `{ok, reason?, leafDer?, leafSpkiSha256?}`.
     */
    @JvmStatic @JvmOverloads
    fun verifyX5cChain(x5c: List<Any?>?, anchors: Map<String, Any?>?, nowMs: Long, clockSkewMs: Double? = null): Map<String, Any?> {
        val skew = if (clockSkewMs != null && clockSkewMs.isFinite()) Math.max(0.0, clockSkewMs) else 0.0
        val (leaf, why) = AttestMaa.verifyX5cChain(AttestMaa.Anchors(strings(anchors?.get("rootCertsPem")), strings(anchors?.get("rootSpkiSha256"))), x5c ?: emptyList(), nowMs, skew)
        if (leaf == null || why.isNotEmpty()) return Issue.obj("ok" to false, "reason" to why)
        return Issue.obj("ok" to true, "leafDer" to leaf.raw, "leafSpkiSha256" to typed { AttestCert.keyOfCert(leaf) }.spkiSha256())
    }

    /**
     * Verify a Confidential Space JWK `x5c` chain at `nowMs` (each certificate inside its validity window widened by `skewMs`) to the anchors
     * `{trustedKeySpki?, rootCertsPem?}`: null when it anchors, else the failure reason.
     */
    @JvmStatic
    fun verifyJwkX5cChain(x5c: List<Any?>?, anchors: Map<String, Any?>?, nowMs: Long, skewMs: Double): String? =
        AttestGcp.verifyJwkX5cChain(
            x5c ?: emptyList(), strings(anchors?.get("trustedKeySpki")).map { it.lowercase() }.toSet(), strings(anchors?.get("rootCertsPem")), nowMs, skewMs,
        ).ifEmpty { null }

    // ---- JWT parsers (Azure MAA, Google Confidential Space) ----

    private fun jwt(token: String, prefix: String): Map<String, Any?> {
        val t = typed { AttestJws.parseJwt(token, prefix) }
        val header = Issue.obj("alg" to t.alg)
        t.kidOpt?.let { header["kid"] = it }
        t.jku?.let { header["jku"] = it }
        t.x5cOpt?.let { header["x5c"] = ArrayList<Any?>(it) }
        t.typ?.let { header["typ"] = it }
        return Issue.obj("header" to header, "payload" to t.payload, "signingInput" to t.signingInput, "signature" to t.signature)
    }

    /** Parse a compact-JWS MAA token into `{header, payload, signingInput, signature}`; verifies nothing. Throws on a structurally invalid token. */
    @JvmStatic fun parseMaaJwt(token: String): Map<String, Any?> = jwt(token, "parseMaaJwt")

    /** Parse a compact-JWS Confidential Space token into `{header, payload, signingInput, signature}`; verifies nothing. Throws on a structurally invalid token. */
    @JvmStatic fun parseGcpCsJwt(token: String): Map<String, Any?> = jwt(token, "parseGcpCsJwt")

    /** Map a Confidential Space `hwmodel` to its isolation family (`sev-snp`, `tdx`), or null when unrecognized. */
    @JvmStatic
    fun teeTypeOfHwModel(hwmodel: String): String? {
        val up = hwmodel.uppercase()
        if (up.startsWith("GCP_AMD_SEV")) return "sev-snp"
        if (up.startsWith("GCP_INTEL_TDX")) return "tdx"
        return null
    }

    // ---- JWKS fetchers over an injected transport ----

    private fun jwksBody(res: AttestMaaKeys.MaaHttpResponse, what: String, url: String, members: List<String>): Map<String, Any?> {
        if (!res.ok) throw IllegalStateException("$what fetch failed: HTTP ${res.status} for $url")
        val rec = Json.parseLenient(String(res.body, Charsets.UTF_8)) as? Map<String, Any?>
        val keys = rec?.get("keys") as? List<Any?> ?: throw IllegalStateException("$what fetch: response has no keys array")
        val out = ArrayList<Any?>()
        for (k in keys) {
            val kr = k as? Map<String, Any?> ?: continue
            val row = Issue.obj()
            for (m in members) {
                val v = kr[m]
                if (m == "x5c") { if (v is List<*> && v.all { it is String }) row[m] = ArrayList<Any?>(v) } else if (v is String) row[m] = v
            }
            out.add(row)
        }
        return Issue.obj("keys" to out)
    }

    /**
     * Fetch an MAA instance's JWKS from `<issuer><certsPath>` (default `/certs`) through the injected transport (NETWORK I/O: never auto-invoked): `{keys: [{kid?,
     * kty?, alg?, x5c?}]}`. Throws on a non-2xx response or a malformed body. (For the hardened variant with a timeout and a size limit use [AttestMaaKeys.fetchMaaCerts].)
     */
    @JvmStatic @JvmOverloads
    fun fetchMaaJwks(issuer: String, fetch: AttestMaaKeys.MaaFetch, certsPath: String = "/certs"): Map<String, Any?> {
        val url = issuer.trimEnd('/') + certsPath
        return jwksBody(fetch.fetch(url), "MAA JWKS", url, listOf("kid", "kty", "alg", "x5c"))
    }

    /**
     * Fetch the Google attestation issuer's JWKS through the injected transport: resolves `<issuer>/.well-known/openid-configuration` to its `jwks_uri` unless
     * `jwksUri` is given, then fetches the keys: `{keys: [{kid?, kty?, alg?, use?, n?, e?, crv?, x?, y?, x5c?}]}`. Throws on a non-2xx response or a malformed body.
     */
    @JvmStatic @JvmOverloads
    fun fetchGcpConfidentialSpaceJwks(issuer: String, fetch: AttestMaaKeys.MaaFetch, jwksUri: String? = null): Map<String, Any?> {
        val uri: String = if (!jwksUri.isNullOrEmpty()) jwksUri else {
            val confUrl = issuer.trimEnd('/') + "/.well-known/openid-configuration"
            val res = fetch.fetch(confUrl)
            if (!res.ok) throw IllegalStateException("Confidential Space OpenID config fetch failed: HTTP ${res.status} for $confUrl")
            val conf = Json.parseLenient(String(res.body, Charsets.UTF_8)) as? Map<String, Any?>
            (conf?.get("jwks_uri") as? String)?.takeIf { it.isNotEmpty() } ?: throw IllegalStateException("Confidential Space OpenID config carries no jwks_uri")
        }
        return jwksBody(fetch.fetch(uri), "Confidential Space JWKS", uri, listOf("kid", "kty", "alg", "use", "n", "e", "crv", "x", "y", "x5c"))
    }
}
