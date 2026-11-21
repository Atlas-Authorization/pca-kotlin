package net.atlasauth.pca.attesteat

import java.math.BigDecimal
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.scitt.ScittPrivateKey
import net.atlasauth.pca.scitt.ScittPublicKey
import net.atlasauth.pca.verifier.AttestCert
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.util.BigIntegers

/**
 * Per-session attestation FRESHNESS and CHANNEL BINDING for PCA: emit TEE evidence as an EAT (RFC 9711, a compact JWS with typ
 * `eat+jwt`), bind it to the live channel and a fresh nonce (IETF SEAT / RA-TLS), and appraise it against RATS endorsements and
 * reference values (RFC 9334). The post-quantum co-signature is [AttestEatPq], admission [AttestEatAdmission], build provenance
 * [AttestEatProvenance].
 *
 * This layer holds NO AMD certificate or report-signature cryptography of its own: [verifyAmdAttestation] runs the core's hardened
 * SEV-SNP checks. Claims, policies and verdicts are JSON-shaped maps with the reference's member names ([Json.Num] / Long numbers);
 * keys are the SCITT key types (Ed25519 or P-256). Everything fails CLOSED.
 */
object AttestEat {
    const val EAT_TYP = "eat+jwt"
    const val DEFAULT_EAT_ALG = "EdDSA"
    const val DEFAULT_MAX_AGE_MS = 5 * 60_000L
    const val CHANNEL_BINDING_DOMAIN = "atlas-pca/eat-channel/v1"
    const val AMD_SEV_SNP_SIGNED_REGION_END = 0x2a0
    const val AMD_SEV_SNP_HARDWARE_ROOT_LABEL = "amd-sev-snp/ecdsa-p384 (VCEK→ASK→ARK; classical hardware root, not post-quantum)"
    val KNOWN_REPORT_VERSIONS: List<Int> = listOf(2, 3, 5)

    /** The pinned AMD ARK SPKI SHA-384 (hex) per family: milan, genoa, turin. */
    val KNOWN_AMD_ARK_SPKI_SHA384: Map<String, String> = java.util.Collections.unmodifiableMap(linkedMapOf(
        "milan" to "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        "genoa" to "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        "turin" to "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
    ))
    val AMD_MILAN_ARK_SPKI_SHA384: String = KNOWN_AMD_ARK_SPKI_SHA384.getValue("milan")

    private val SUPPORTED_ALGS = listOf("EdDSA", "ES256")
    private val DBGSTAT_VALUES = listOf("enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently")

    // ---- helpers ----

    @Suppress("UNCHECKED_CAST")
    internal fun rec(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    internal fun arr(o: Any?): List<Any?>? = o as? List<Any?>

    private fun num(o: Any?): Double? = Js.num(o)

    private fun finite(d: Double?): Boolean = d != null && !d.isNaN() && !d.isInfinite()

    private fun utf8(s: String): ByteArray = Json.utf8(s)

    private fun b64u(b: ByteArray): String = Pca.b64(b)

    /** Constant-time string equality over UTF-8 bytes. */
    internal fun strEq(a: String, b: String): Boolean = MessageDigest.isEqual(utf8(a), utf8(b))

    private fun msg(e: Throwable): String = e.message ?: "unknown"

    private fun isSupportedAlg(v: Any?): Boolean = v is String && SUPPORTED_ALGS.contains(v)

    /** RFC 7515 section 4.1.9: a media type is compared case-insensitively and a `typ` without a slash is the application/ form. */
    private fun normalizeTyp(typ: String): String {
        val t = typ.lowercase(java.util.Locale.ROOT)
        return if (t.contains("/")) t else "application/$t"
    }

    // ---- keys + JWS ----

    /** An EAT signing key pair. */
    class EatKeyPair(@JvmField val priv: ScittPrivateKey, @JvmField val pub: ScittPublicKey)

    private val p256: ECDomainParameters by lazy {
        val x9 = CustomNamedCurves.getByName("secp256r1")
        ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
    }

    /** Generate an EAT signing key pair for [alg] (EdDSA: Ed25519, ES256: P-256). */
    fun generateEatKeyPair(alg: String = DEFAULT_EAT_ALG): EatKeyPair {
        val rng = SecureRandom()
        if (alg == "EdDSA") {
            val seed = ByteArray(32).also { rng.nextBytes(it) }
            return EatKeyPair(ScittPrivateKey.Ed25519(seed), ScittPublicKey.Ed25519(Keys.edFromSeed(seed).pub))
        }
        if (alg == "ES256") {
            var d: BigInteger
            do { d = BigInteger(256, rng) } while (d.signum() == 0 || d >= p256.n)
            val q = p256.g.multiply(d).normalize()
            val pub = ScittPublicKey.P256(BigIntegers.asUnsignedByteArray(32, q.affineXCoord.toBigInteger()), BigIntegers.asUnsignedByteArray(32, q.affineYCoord.toBigInteger()))
            return EatKeyPair(ScittPrivateKey.P256(BigIntegers.asUnsignedByteArray(32, d)), pub)
        }
        throw IllegalArgumentException("generateEatKeyPair: unsupported alg '$alg'")
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun signJws(alg: String, key: ScittPrivateKey, signingInput: String): String {
        val data = utf8(signingInput)
        if (alg == "EdDSA") {
            if (key !is ScittPrivateKey.Ed25519) throw IllegalArgumentException("Unsupported crypto operation")
            return b64u(Keys.edFromSeed(key.seed).sign(data))
        }
        if (key !is ScittPrivateKey.P256) throw IllegalArgumentException("Unsupported crypto operation")
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(BigInteger(1, key.d), p256))
        val rs = signer.generateSignature(sha256(data))
        return b64u(BigIntegers.asUnsignedByteArray(32, rs[0]) + BigIntegers.asUnsignedByteArray(32, rs[1]))
    }

    /** May throw (a key of the wrong type): the reference throws as well. */
    private fun verifyJws(alg: String, key: ScittPublicKey?, signingInput: String, sig: ByteArray): Boolean {
        val data = utf8(signingInput)
        if (alg == "EdDSA") {
            if (key !is ScittPublicKey.Ed25519) throw IllegalArgumentException("Unsupported crypto operation")
            return Pca.ed25519Strict(key.raw, data, sig)
        }
        if (key !is ScittPublicKey.P256) throw IllegalArgumentException("Unsupported crypto operation")
        val q = p256.curve.validatePoint(BigInteger(1, key.x), BigInteger(1, key.y))
        if (sig.size != 64) return false
        val v = ECDSASigner()
        v.init(false, ECPublicKeyParameters(q, p256))
        return v.verifySignature(sha256(data), BigInteger(1, sig.copyOfRange(0, 32)), BigInteger(1, sig.copyOfRange(32, 64)))
    }

    // ---- nonce ----

    /**
     * Mint a fresh, single-use nonce: `{value, issuedAt}` where value is b64u(random) + "." + issue time in base 36. [now] may be
     * null (the clock); [bytes] is the random length (minimum 16, default 32).
     */
    fun issueNonce(now: Long? = null, bytes: Int? = null): Map<String, Any?> {
        val t = now ?: System.currentTimeMillis()
        val n = Math.max(16, bytes ?: 32)
        val r = ByteArray(n)
        SecureRandom().nextBytes(r)
        return linkedMapOf("value" to (b64u(r) + "." + java.lang.Long.toString(t, 36)), "issuedAt" to t)
    }

    // ---- evidence projection + tolerant parse ----

    /** The JSON-safe EAT evidence projection of a parsed report. */
    fun evidenceFromReport(report: Map<String, Any?>): Map<String, Any?> {
        val ev = LinkedHashMap<String, Any?>()
        ev["version"] = report["version"]
        ev["measurement"] = report["measurement"]
        ev["reported_tcb"] = report["reported_tcb"]
        ev["guest_svn"] = report["guest_svn"]
        ev["chip_id"] = report["chip_id"]
        ev["debug"] = report["debug"]
        return ev
    }

    /** The PCA measured identity of a parsed report: runtime_measurement = launch measurement, operator = chip id, no weights. */
    fun measuredFromReport(report: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["model_id"] = ""
        m["weights_digest"] = ""
        m["weights_measured"] = false
        m["runtime_measurement"] = report["measurement"]
        m["operator"] = report["chip_id"]
        return m
    }

    private const val FULL_REPORT_MIN_LEN = 0x2e8 + 72

    private fun u32(b: ByteArray, off: Int): Long? {
        if (off + 4 > b.size) return null
        return (b[off].toLong() and 0xff) or ((b[off + 1].toLong() and 0xff) shl 8) or ((b[off + 2].toLong() and 0xff) shl 16) or ((b[off + 3].toLong() and 0xff) shl 24)
    }

    private fun u64(b: ByteArray, off: Int): Long? {
        if (off + 8 > b.size) return null
        val lo = u32(b, off)!!
        val hi = u32(b, off + 4)!!
        return lo or (hi shl 32)
    }

    private fun slice(b: ByteArray, off: Int, len: Int): ByteArray? = if (off + len > b.size) null else b.copyOfRange(off, off + len)

    private fun tolerant(ok: Boolean, version: Long, known: Boolean, degraded: Boolean, notes: List<Any?>, report: Map<String, Any?>?, evidence: Map<String, Any?>?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        m["version"] = version
        m["known"] = known
        m["degraded"] = degraded
        m["notes"] = notes
        if (report != null) m["report"] = report
        if (evidence != null) m["evidence"] = evidence
        return m
    }

    /**
     * Parse an AMD SEV-SNP ATTESTATION_REPORT DEFENSIVELY across format versions: a known version with a full buffer is the core's full
     * parse; an unknown version or a short buffer reads the version-stable header fields and is marked degraded. Never throws.
     * Result: {ok, version, known, degraded, notes, report?, evidence?}.
     */
    fun parseReportTolerant(bytes: ByteArray?): Map<String, Any?> {
        val notes = ArrayList<Any?>()
        if (bytes == null) {
            notes.add("input is not a Uint8Array")
            return tolerant(false, 0, false, true, notes, null, null)
        }
        val version = u32(bytes, 0)
        if (version == null) {
            notes.add("buffer too short to read the report version")
            return tolerant(false, 0, false, true, notes, null, null)
        }
        val known = KNOWN_REPORT_VERSIONS.contains(version.toInt()) && version == version.toInt().toLong()
        if (known && bytes.size >= FULL_REPORT_MIN_LEN) {
            try {
                val report = AmdGenuine.parseReport(bytes)
                return tolerant(true, report["version"] as Long, true, false, notes, report, evidenceFromReport(report))
            } catch (e: RuntimeException) {
                notes.add("full parse failed, falling back to the stable header: " + msg(e))
            }
        } else if (!known) {
            notes.add("unknown report version $version — parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)")
        } else {
            notes.add("buffer length ${bytes.size} < full report $FULL_REPORT_MIN_LEN — degraded header-only parse")
        }
        val measurement = slice(bytes, 0x090, 48)
        if (measurement == null) {
            notes.add("buffer too short to read the launch measurement")
            return tolerant(false, version, known, true, notes, null, null)
        }
        val ev = LinkedHashMap<String, Any?>()
        ev["version"] = version
        ev["measurement"] = AttestUtil.hex(measurement)
        ev["degraded"] = true
        val svn = u32(bytes, 0x004)
        if (svn != null) ev["guest_svn"] = svn
        val policy = u64(bytes, 0x008)
        if (policy != null) ev["debug"] = (policy and (1L shl 19)) != 0L
        val tcb = u64(bytes, 0x180)
        if (tcb != null) ev["reported_tcb"] = java.lang.Long.toUnsignedString(tcb)
        val chip = slice(bytes, 0x1a0, 64)
        if (chip != null) ev["chip_id"] = AttestUtil.hex(chip)
        return tolerant(true, version, known, true, notes, null, ev)
    }

    // ---- channel binding ----

    /** `cnf.tls_exporter` for a TLS channel id: b64u(sha256(DOMAIN || channelId)); plus `jkt` when a thumbprint is given. */
    fun deriveChannelCnf(channelId: Any?, holderKeyThumbprint: Any? = null): Map<String, Any?> {
        if (channelId !is String || channelId.isEmpty()) throw IllegalArgumentException("deriveChannelCnf: channelId is required")
        val md = MessageDigest.getInstance("SHA-256")
        md.update(utf8(CHANNEL_BINDING_DOMAIN))
        md.update(utf8(channelId))
        val cnf = LinkedHashMap<String, Any?>()
        cnf["tls_exporter"] = b64u(md.digest())
        if (holderKeyThumbprint is String && holderKeyThumbprint.isNotEmpty()) cnf["jkt"] = holderKeyThumbprint
        return cnf
    }

    /** Bind attestation evidence to a channel id and a per-session nonce: `{evidence, nonce, cnf}`. */
    fun bindChannel(evidence: Any?, channelId: Any?, nonce: Any?): Map<String, Any?> {
        if (nonce !is String || nonce.isEmpty()) throw IllegalArgumentException("bindChannel: a per-session nonce is required for freshness")
        val m = LinkedHashMap<String, Any?>()
        m["evidence"] = evidence
        m["nonce"] = nonce
        m["cnf"] = deriveChannelCnf(channelId)
        return m
    }

    // ---- buildEAT / verifyEAT ----

    private fun resolveCnf(args: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        if (args.containsKey("channelId")) {
            val d = deriveChannelCnf(args["channelId"])
            if (d["tls_exporter"] != null) out["tls_exporter"] = d["tls_exporter"]
        }
        if (args.containsKey("channelBinding")) {
            val cbO = args["channelBinding"] ?: throw IllegalArgumentException("Cannot read properties of null (reading 'tls_exporter')")
            val cb = rec(cbO)
            if (cb != null && cb["tls_exporter"] is String) out["tls_exporter"] = cb["tls_exporter"]
            if (cb != null && cb["jkt"] is String) out["jkt"] = cb["jkt"]
        }
        return out
    }

    /**
     * Build a signed EAT over the given evidence: a compact JWS with the `eat+jwt` typ header, `iss`, `iat`, the `eat_nonce` challenge,
     * the `cnf` channel binding and the optional `measured` / `sevsnp` / `measurements` / `ueid` / `sueid` / `oemid` / `dbgstat` claims.
     * [args]: issuer, key (a [ScittPrivateKey]), alg?, nonce, channelBinding?, channelId?, measured?, sevsnp?, measurements?, ueid?, sueid?,
     * dbgstat?, oemid?, now?. Requires a nonce AND a channel binding.
     */
    fun buildEAT(args: Map<String, Any?>): String {
        val issuer = args["issuer"]
        if (issuer !is String || issuer.isEmpty()) throw IllegalArgumentException("buildEAT: issuer is required")
        val nonce = args["nonce"]
        if (nonce !is String || nonce.isEmpty()) throw IllegalArgumentException("buildEAT: nonce (eat_nonce) is required for freshness")
        val alg: Any? = if (args.containsKey("alg") && args["alg"] != null) args["alg"] else DEFAULT_EAT_ALG
        if (!isSupportedAlg(alg)) throw IllegalArgumentException("buildEAT: unsupported alg '${Js.template(alg)}'")
        val cnf = resolveCnf(args)
        if (cnf["tls_exporter"] == null && cnf["jkt"] == null) {
            throw IllegalArgumentException("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) — refusing to emit unbound evidence")
        }
        val nowD = num(args["now"])
        val iatMs = if (finite(nowD)) nowD!! else System.currentTimeMillis().toDouble()

        val claims = LinkedHashMap<String, Any?>()
        claims["iss"] = issuer
        claims["iat"] = Math.floor(iatMs / 1000).toLong()
        claims["eat_nonce"] = nonce
        claims["cnf"] = cnf
        for (k in listOf("ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp")) {
            if (args.containsKey(k)) claims[k] = args[k]
        }
        val header = linkedMapOf<String, Any?>("alg" to alg, "typ" to EAT_TYP)
        val signingInput = b64u(utf8(Jose.stringify(header))) + "." + b64u(utf8(Jose.stringify(claims)))
        val key = args["key"]
        if (key !is ScittPrivateKey) throw IllegalArgumentException("buildEAT: key is required")
        return signingInput + "." + signJws(alg as String, key, signingInput)
    }

    private fun parseCnf(v: Any?): Map<String, Any?>? {
        val r = rec(v) ?: return null
        val out = LinkedHashMap<String, Any?>()
        if (r["tls_exporter"] is String) out["tls_exporter"] = r["tls_exporter"]
        if (r["jkt"] is String) out["jkt"] = r["jkt"]
        return if (out.isEmpty()) null else out
    }

    private fun parseMeasurements(v: Any?): List<Any?>? {
        val l = arr(v) ?: return null
        val out = ArrayList<Any?>()
        for (e in l) {
            val r = rec(e)
            if (r != null && r["type"] is String && r["value"] is String) out.add(linkedMapOf("type" to r["type"], "value" to r["value"]))
        }
        return if (out.isEmpty()) null else out
    }

    private fun parseTcbVersion(v: Any?): Any? {
        if (v is String) return v
        val d = num(v)
        if (d != null) return if (finite(d)) v else null
        val r = rec(v) ?: return null
        val o = LinkedHashMap<String, Any?>()
        for (k in listOf("bootloader", "tee", "snp", "microcode")) if (num(r[k]) != null) o[k] = r[k]
        return o
    }

    private fun parseMeasured(v: Any?): Map<String, Any?>? {
        val r = rec(v) ?: return null
        for (k in listOf("model_id", "weights_digest", "runtime_measurement", "operator")) if (r[k] !is String) return null
        val out = LinkedHashMap<String, Any?>()
        out["model_id"] = r["model_id"]
        out["weights_digest"] = r["weights_digest"]
        out["runtime_measurement"] = r["runtime_measurement"]
        out["operator"] = r["operator"]
        if (r["weights_measured"] is Boolean) out["weights_measured"] = r["weights_measured"]
        if (r["system_prompt_digest"] is String) out["system_prompt_digest"] = r["system_prompt_digest"]
        if (r["tool_manifest_digest"] is String) out["tool_manifest_digest"] = r["tool_manifest_digest"]
        return out
    }

    private fun parseSevSnp(v: Any?): Map<String, Any?>? {
        val r = rec(v)
        if (r == null || num(r["version"]) == null || r["measurement"] !is String) return null
        val out = LinkedHashMap<String, Any?>()
        out["version"] = r["version"]
        out["measurement"] = r["measurement"]
        val tcb = parseTcbVersion(r["reported_tcb"])
        if (tcb != null) out["reported_tcb"] = tcb
        if (num(r["guest_svn"]) != null) out["guest_svn"] = r["guest_svn"]
        if (r["chip_id"] is String) out["chip_id"] = r["chip_id"]
        if (r["debug"] is Boolean) out["debug"] = r["debug"]
        if (r["degraded"] is Boolean) out["degraded"] = r["degraded"]
        return out
    }

    /**
     * Verify an EAT's signature, `typ` and `iss` and parse it into claims. Throws on an invalid signature, wrong key, failed `iss`/`typ`
     * check, an unsupported `alg` or a missing `iss`/`iat`. A claim of the wrong type is dropped so downstream checks fail closed.
     * [opts]: issuer? (string or list), algorithms? (list), typ?, requireTyp?.
     */
    fun verifyEAT(eat: Any?, verifyKey: ScittPublicKey?, opts: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        if (eat !is String) throw IllegalArgumentException("EAT invalid: token is not a string")
        val canon = try {
            Jose.assertCanonicalCompactJws(eat, 3, 1 shl 20, true)
        } catch (e: RuntimeException) {
            throw IllegalArgumentException("EAT invalid: " + msg(e))
        }
        val parts = eat.split(".")
        if (parts.size != 3) throw IllegalArgumentException("EAT invalid: expected a compact JWS (header.payload.signature)")
        val h = parts[0]
        val p = parts[1]
        val s = parts[2]
        if (h.isEmpty() || p.isEmpty() || s.isEmpty()) throw IllegalArgumentException("EAT invalid: empty JWS segment")
        val header = canon.header
        val alg = header["alg"]
        if (!isSupportedAlg(alg)) throw IllegalArgumentException("EAT invalid: missing or unsupported `alg` header")
        val allowedO = opts["algorithms"]
        // a string has `includes` too (a substring test)
        val allowed: List<Any?> = if (allowedO == null || allowedO is String) ArrayList<Any?>(SUPPORTED_ALGS) else (arr(allowedO) ?: throw IllegalArgumentException("opts.algorithms.includes is not a function"))
        if (if (allowedO is String) !allowedO.contains(alg as String) else !allowed.contains(alg)) throw IllegalArgumentException("EAT invalid: alg ${Js.template(alg)} not in the allowed set")
        if (opts["requireTyp"] != false) {
            val wantO = opts["typ"] ?: EAT_TYP
            if (wantO !is String) throw IllegalArgumentException("typ.toLowerCase is not a function")
            val ht = header["typ"]
            if (ht !is String || normalizeTyp(ht) != normalizeTyp(wantO)) {
                throw IllegalArgumentException("EAT invalid: typ ${Js.template(ht)} is not $wantO")
            }
        }
        if (!verifyJws(alg as String, verifyKey, "$h.$p", Jose.decodeCanonicalBase64url(s))) throw IllegalArgumentException("EAT invalid: signature does not verify")

        val payload = canon.payload!!
        if (payload["iss"] !is String) throw IllegalArgumentException("EAT invalid: missing or non-string `iss`")
        if (!finite(num(payload["iat"]))) throw IllegalArgumentException("EAT invalid: missing or non-numeric `iat`")
        if (opts.containsKey("issuer")) {
            val io = opts["issuer"]
            val allowedIss: List<Any?> = if (io is List<*>) io else listOf(io)
            if (!allowedIss.contains(payload["iss"])) throw IllegalArgumentException("EAT invalid: iss ${payload["iss"]} is not an accepted issuer")
        }
        val claims = LinkedHashMap<String, Any?>()
        claims["iss"] = payload["iss"]
        claims["iat"] = payload["iat"]
        if (payload["eat_nonce"] is String) claims["eat_nonce"] = payload["eat_nonce"]
        val cnf = parseCnf(payload["cnf"])
        if (cnf != null) claims["cnf"] = cnf
        if (payload["ueid"] is String) claims["ueid"] = payload["ueid"]
        if (payload["sueid"] is String) claims["sueid"] = payload["sueid"]
        val measurements = parseMeasurements(payload["measurements"])
        if (measurements != null) claims["measurements"] = measurements
        if (payload["dbgstat"] is String && DBGSTAT_VALUES.contains(payload["dbgstat"])) claims["dbgstat"] = payload["dbgstat"]
        if (payload["oemid"] is String) claims["oemid"] = payload["oemid"]
        val measured = parseMeasured(payload["measured"])
        if (measured != null) claims["measured"] = measured
        val sevsnp = parseSevSnp(payload["sevsnp"])
        if (sevsnp != null) claims["sevsnp"] = sevsnp
        return claims
    }

    // ---- freshness + channel binding ----

    private fun check(ok: Boolean, reason: String?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (reason != null) m["reason"] = reason
        return m
    }

    /**
     * ANTI-REPLAY FRESHNESS: the EAT's `eat_nonce` must equal the server-issued challenge AND its `iat` must lie within
     * [now - maxAgeMs, now] (allowing `clockSkewMs`). [opts]: expectedNonce, maxAgeMs, now?, clockSkewMs?. Result {ok, reason?}.
     */
    fun verifyFreshness(eat: Map<String, Any?>, opts: Map<String, Any?>): Map<String, Any?> {
        val nowD = num(opts["now"])
        val now = if (finite(nowD)) nowD!! else System.currentTimeMillis().toDouble()
        // A present skew that is not a finite number (NaN, Infinity, a string, null) would disable the age window: refuse it.
        val skewD = num(opts["clockSkewMs"])
        if (opts.containsKey("clockSkewMs") && !finite(skewD)) return check(false, "invalid clockSkewMs (must be a finite number)")
        val skew = if (skewD == null) 0.0 else Math.max(0.0, skewD)
        val expected = opts["expectedNonce"]
        if (expected !is String || expected.isEmpty()) return check(false, "no expected (server-issued) nonce supplied (fail closed)")
        val nonce = eat["eat_nonce"]
        if (nonce !is String || nonce.isEmpty()) return check(false, "EAT carries no eat_nonce — cannot establish freshness (replayable)")
        if (!strEq(nonce, expected)) return check(false, "eat_nonce does not match the server-issued challenge (replayed or relayed evidence)")
        val iat = num(eat["iat"])
        if (!finite(iat)) return check(false, "EAT has no valid iat (cannot establish age)")
        val maxD = num(opts["maxAgeMs"])
        if (!finite(maxD)) return check(false, "invalid maxAgeMs")
        val max = maxD!!
        if (max <= 0) return check(false, "invalid maxAgeMs")
        val iatMs = iat!! * 1000
        if (iatMs - skew > now) return check(false, "EAT iat is in the future")
        if (now - iatMs > max + skew) return check(false, "EAT is stale (iat older than maxAgeMs) — expired/replayed attestation")
        return check(true, null)
    }

    /**
     * CHANNEL BINDING (RA-TLS): every field of the expected cnf (derived from `channelId` and/or an explicit `expectedCnf`) must be
     * present and equal in the token's `cnf`; a token with no cnf, or bound to another channel or key, fails closed. Result {ok, reason?}.
     */
    fun verifyChannelBinding(eat: Map<String, Any?>, opts: Map<String, Any?>): Map<String, Any?> {
        val exp = LinkedHashMap<String, Any?>()
        val cid = opts["channelId"]
        if (cid is String && cid.isNotEmpty()) {
            val d = deriveChannelCnf(cid)
            if (d["tls_exporter"] != null) exp["tls_exporter"] = d["tls_exporter"]
        }
        if (opts.containsKey("expectedCnf")) {
            val ecO = opts["expectedCnf"] ?: throw IllegalArgumentException("Cannot read properties of null (reading 'tls_exporter')")
            val ec = rec(ecO)
            if (ec != null) {
                if (ec["tls_exporter"] is String) exp["tls_exporter"] = ec["tls_exporter"]
                if (ec["jkt"] is String) exp["jkt"] = ec["jkt"]
            }
        }
        if (exp.isEmpty()) return check(false, "no expected channel binding supplied (fail closed)")
        val cnf = rec(eat["cnf"])
        if (cnf == null || (cnf["tls_exporter"] == null && cnf["jkt"] == null)) {
            return check(false, "EAT carries no channel/key binding (cnf) — evidence is not bound to a live channel (RA-TLS)")
        }
        val et = exp["tls_exporter"]
        if (et != null && !(cnf["tls_exporter"] is String && strEq(cnf["tls_exporter"] as String, et as String))) {
            return check(false, "TLS-exporter channel binding mismatch (evidence lifted to another channel?)")
        }
        val ej = exp["jkt"]
        if (ej != null && !(cnf["jkt"] is String && strEq(cnf["jkt"] as String, ej as String))) {
            return check(false, "holder-key thumbprint (cnf.jkt) mismatch")
        }
        return check(true, null)
    }

    // ---- RATS appraisal ----

    private fun comp(r: Map<String, Any?>?, k: String): BigInteger? {
        if (r == null || !r.containsKey(k)) return BigInteger.ZERO
        val d = num(r[k])
        if (d == null || d != Math.floor(d) || d.isInfinite() || d < 0 || (d == 0.0 && 1 / d < 0) || d > 255) return null
        return BigInteger.valueOf(d.toLong())
    }

    /** Pack a TCB version (a number, a decimal string, or the SEV-SNP components) into a comparable integer; null when its shape is unknown. */
    internal fun packTcb(v: Any?): BigInteger? {
        val d = num(v)
        if (d != null) return if (!d.isNaN() && !d.isInfinite() && d >= 0) BigDecimal(Math.floor(d)).toBigInteger() else null
        if (v is String) {
            val t = AttestUtil.jsTrim(v)
            return if (Regex("[0-9]+").matches(t)) BigInteger(t) else null
        }
        if (v == null || v is Boolean || v is List<*>) return null // true / [] / null are not a TCB version
        val r = rec(v)
        val bl = comp(r, "bootloader")
        val tee = comp(r, "tee")
        val snp = comp(r, "snp")
        val uc = comp(r, "microcode")
        if (bl == null || tee == null || snp == null || uc == null) return null
        return bl.or(tee.shiftLeft(8)).or(snp.shiftLeft(48)).or(uc.shiftLeft(56))
    }

    private fun lc(s: Any?): String {
        if (s !is String) throw IllegalArgumentException("s.toLowerCase is not a function")
        return s.lowercase(java.util.Locale.ROOT)
    }

    private fun lcIncludes(list: List<Any?>, needle: String): Boolean {
        var hit = false
        for (o in list) if (lc(o) == needle) hit = true // every element is lower-cased (as .map(lc) does), a non-string throws
        return hit
    }

    private fun prop(o: Any?, k: String): Any? = rec(o)?.get(k)

    private fun nonEmptyList(o: Any?): Boolean = arr(o)?.isNotEmpty() == true

    private fun verdict(tier: String, trustworthy: Boolean, reasons: List<Any?>): Map<String, Any?> =
        linkedMapOf("tier" to tier, "trustworthy" to trustworthy, "reasons" to reasons)

    private fun plusReason(reasons: List<Any?>, reason: String): List<Any?> = ArrayList(reasons).also { it.add(reason) }

    private fun launchMeasurement(eat: Map<String, Any?>): String? {
        val measured = eat["measured"]
        val rm = prop(measured, "runtime_measurement")
        if (measured != null && measured != false && rm is String && rm.isNotEmpty()) return rm
        val sevsnp = eat["sevsnp"]
        val sm = prop(sevsnp, "measurement")
        if (sevsnp != null && sm is String) return sm
        return findMeasurement(eat["measurements"], "launch", "measurement")
    }

    private fun findMeasurement(measurements: Any?, vararg types: String): String? {
        if (measurements == null) return null
        val l = arr(measurements) ?: throw IllegalArgumentException("eat.measurements?.find is not a function")
        for (e in l) {
            val t = prop(e, "type")
            for (ty in types) if (ty == t) { val v = prop(e, "value"); return v as? String }
        }
        return null
    }

    private fun weightsMeasurement(eat: Map<String, Any?>): String? {
        val measured = eat["measured"]
        val wd = prop(measured, "weights_digest")
        if (measured != null && wd is String && wd.isNotEmpty()) return wd
        return findMeasurement(eat["measurements"], "weights")
    }

    /** True/false when the debug status is known, else null (the caller fails closed). */
    private fun isDebugDisabled(eat: Map<String, Any?>): Boolean? {
        // a present dbgstat that is not an RFC 9711 value (hand-built claims) is unknown, never "disabled"
        if (eat.containsKey("dbgstat")) return if (eat["dbgstat"] is String && DBGSTAT_VALUES.contains(eat["dbgstat"])) "enabled" != eat["dbgstat"] else null
        val sevsnp = eat["sevsnp"]
        if (sevsnp != null && prop(sevsnp, "debug") is Boolean) return prop(sevsnp, "debug") == false
        return null
    }

    /**
     * APPRAISE an EAT's evidence against RATS reference values and endorsements (RFC 9334), kept as distinct arguments. Result
     * {tier, trustworthy, reasons}; tiers: affirming-hw-rooted, affirming, warning, contraindicated, rejected. [extras]:
     * hardwareVerified?, hardwareRootLabel?. An empty policy is rejected. Does NOT re-verify the AMD chain or report signature.
     */
    fun appraise(
        evidence: Map<String, Any?>,
        referenceValues: Map<String, Any?>? = emptyMap(),
        endorsements: Map<String, Any?>? = emptyMap(),
        extras: Map<String, Any?>? = emptyMap(),
    ): Map<String, Any?> {
        val reasons = ArrayList<Any?>()
        if (referenceValues == null || endorsements == null || extras == null) throw IllegalArgumentException("Cannot read properties of null (reading 'issuers')")
        val rv = referenceValues
        val en = endorsements
        val ex = extras

        val hasEndorsements = nonEmptyList(en["issuers"]) || nonEmptyList(en["oemids"]) || nonEmptyList(en["operators"])
        val hasReferenceValues = nonEmptyList(rv["measurements"]) || nonEmptyList(rv["models"]) || nonEmptyList(rv["weightsMeasurements"]) ||
            rv["requireMeasuredWeights"] == true || rv.containsKey("minTcb") || num(rv["minGuestSvn"]) != null ||
            rv["requireDebugDisabled"] == true
        if (!hasEndorsements && !hasReferenceValues) {
            return verdict("rejected", false, arrayListOf<Any?>("empty appraisal policy: no endorsements or reference values to appraise against (fail closed)"))
        }

        if (nonEmptyList(en["issuers"])) {
            if (!arr(en["issuers"])!!.contains(evidence["iss"])) return verdict("rejected", false, plusReason(reasons, "issuer ${Js.template(evidence["iss"])} is not an endorsed attester"))
            reasons.add("issuer endorsed")
        }
        if (nonEmptyList(en["oemids"])) {
            if (evidence["oemid"] !is String || !arr(en["oemids"])!!.contains(evidence["oemid"])) return verdict("rejected", false, plusReason(reasons, "oemid absent or not endorsed (fail closed)"))
            reasons.add("oemid endorsed")
        }
        if (nonEmptyList(en["operators"])) {
            val op = prop(evidence["measured"], "operator")
            if (op !is String || op.isEmpty() || !arr(en["operators"])!!.contains(op)) return verdict("rejected", false, plusReason(reasons, "hardware operator absent or not endorsed (fail closed)"))
            reasons.add("operator endorsed")
        }

        if (nonEmptyList(rv["measurements"])) {
            val m = launchMeasurement(evidence)
                ?: return verdict("rejected", false, plusReason(reasons, "no launch measurement in evidence to compare against reference values (fail closed)"))
            if (!lcIncludes(arr(rv["measurements"])!!, m.lowercase(java.util.Locale.ROOT))) return verdict("contraindicated", false, plusReason(reasons, "launch measurement not in reference values"))
            reasons.add("launch measurement matches a reference value")
        }
        if (nonEmptyList(rv["models"])) {
            val model = prop(evidence["measured"], "model_id")
            if (model !is String || model.isEmpty()) return verdict("rejected", false, plusReason(reasons, "no model id in evidence (fail closed)"))
            if (!arr(rv["models"])!!.contains(model)) return verdict("contraindicated", false, plusReason(reasons, "model id not in reference values (model swap?)"))
            reasons.add("model id matches a reference value")
        }
        if (rv["requireMeasuredWeights"] == true) {
            if (prop(evidence["measured"], "weights_measured") != true) {
                return verdict("contraindicated", false, plusReason(reasons, "weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)"))
            }
            reasons.add("weights digest is hardware-measured")
        }
        if (nonEmptyList(rv["weightsMeasurements"])) {
            val w = weightsMeasurement(evidence)
            if (w == null || w.isEmpty()) return verdict("rejected", false, plusReason(reasons, "no measured-weights digest in evidence (fail closed)"))
            if (!lcIncludes(arr(rv["weightsMeasurements"])!!, w.lowercase(java.util.Locale.ROOT))) return verdict("contraindicated", false, plusReason(reasons, "weights measurement not in reference values (model swap / fine-tune?)"))
            reasons.add("weights measurement matches a reference value")
        }
        if (rv.containsKey("minTcb")) {
            val min = packTcb(rv["minTcb"]) ?: return verdict("rejected", false, plusReason(reasons, "reference minTcb is not a comparable TCB version"))
            val rawTcb = prop(evidence["sevsnp"], "reported_tcb")
            val got = if (rawTcb != null) packTcb(rawTcb) else null
            if (got == null) return verdict("rejected", false, plusReason(reasons, "evidence TCB version is absent or an unknown format — failing closed (see 2025-10-27 GCP firmware drift)"))
            if (got.compareTo(min) < 0) return verdict("contraindicated", false, plusReason(reasons, "reported TCB is below the reference minimum (downgrade / rollback)"))
            reasons.add("TCB at or above reference minimum")
        }
        if (num(rv["minGuestSvn"]) != null) {
            val svn = num(prop(evidence["sevsnp"], "guest_svn"))
            if (!finite(svn)) return verdict("rejected", false, plusReason(reasons, "guest_svn absent (fail closed)"))
            val min = num(rv["minGuestSvn"])!!
            if (svn!! < min) return verdict("contraindicated", false, plusReason(reasons, "guest_svn ${AttestUtil.jsNumString(svn)} below reference minimum ${AttestUtil.jsNumString(min)}"))
            reasons.add("guest_svn at or above reference minimum")
        }
        if (rv["requireDebugDisabled"] == true) {
            val disabled = isDebugDisabled(evidence) ?: return verdict("rejected", false, plusReason(reasons, "debug status unknown — failing closed"))
            if (!disabled) return verdict("contraindicated", false, plusReason(reasons, "debug is enabled (host can inspect the guest — no confidentiality)"))
            reasons.add("debug disabled")
        }

        if (prop(evidence["sevsnp"], "degraded") == true) {
            return verdict("warning", true, plusReason(reasons, "evidence came from a degraded (version-tolerant) parse — review"))
        }
        if (ex["hardwareVerified"] == true) {
            val label: Any? = if (ex.containsKey("hardwareRootLabel") && ex["hardwareRootLabel"] != null) ex["hardwareRootLabel"] else AMD_SEV_SNP_HARDWARE_ROOT_LABEL
            return verdict("affirming-hw-rooted", true, plusReason(reasons, "AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — ${Js.template(label)}"))
        }
        return verdict("affirming", true, reasons)
    }

    // ---- AMD hardware root of trust (delegated to the core checks) ----

    private val PEM_CERT = Regex("-----BEGIN CERTIFICATE-----([\\s\\S]*?)-----END CERTIFICATE-----")

    private fun certToDer(input: Any?): ByteArray {
        if (input is ByteArray) return input
        if (input !is String) throw IllegalArgumentException("certificate input must be DER bytes or a PEM string")
        val blocks = AttestCert.pemCertBlocks(input)
        if (blocks.size != 1) throw IllegalArgumentException("expected exactly one PEM certificate, found ${blocks.size}")
        val m = PEM_CERT.find(blocks[0])
        if (m == null || m.groupValues[1].isEmpty()) throw IllegalArgumentException("pemToDer: no certificate found")
        return AttestUtil.nodeB64(m.groupValues[1].replace(Regex("\\s+"), ""))
    }

    private fun derToPem(der: ByteArray): String {
        val b64 = org.bouncycastle.util.encoders.Base64.toBase64String(der).replace(Regex("(.{64})"), "\$1\n")
        return "-----BEGIN CERTIFICATE-----\n$b64\n-----END CERTIFICATE-----\n"
    }

    private fun amdResult(ok: Boolean, reason: String?, report: Map<String, Any?>?, withEvidence: Boolean): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (reason != null) m["reason"] = reason
        m["hardwareRoot"] = AMD_SEV_SNP_HARDWARE_ROOT_LABEL
        if (report != null) m["report"] = report
        if (withEvidence && report != null) {
            m["evidence"] = evidenceFromReport(report)
            m["measured"] = measuredFromReport(report)
        }
        return m
    }

    /**
     * Verify an AMD SEV-SNP report end to end (per-family ARK pin, CA roles, critical extensions, validity windows against `nowMs`,
     * VCEK-to-report binding, ECDSA-P384 report signature), then project the verified report into EAT evidence. [opts]: vcek, ask, ark
     * (DER bytes or a PEM string), family XOR trustAnchorArkSpkiSha384, nowMs, clockSkewMs?, expectedMeasurement?, allowDebug?. Result
     * {ok, reason?, hardwareRoot, report?, evidence?, measured?}; never throws.
     */
    fun verifyAmdAttestation(rawReport: ByteArray, opts: Map<String, Any?>): Map<String, Any?> {
        try {
            val hasFamily = opts.containsKey("family")
            val hasPin = opts.containsKey("trustAnchorArkSpkiSha384")
            if (hasFamily == hasPin) return amdResult(false, "exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)", null, false)
            val pin: String
            if (hasFamily) {
                val f = opts["family"]
                val fromFamily = (if (f is String) KNOWN_AMD_ARK_SPKI_SHA384[f] else null)
                    ?: return amdResult(false, "unknown AMD family ${Js.template(f)} (expected milan | genoa | turin)", null, false)
                pin = fromFamily
            } else {
                pin = opts["trustAnchorArkSpkiSha384"] as? String ?: throw IllegalArgumentException("pin.toLowerCase is not a function")
            }
            val vcekDer: ByteArray
            val askArkPem: String
            try {
                vcekDer = certToDer(opts["vcek"])
                askArkPem = derToPem(certToDer(opts["ask"])) + derToPem(certToDer(opts["ark"]))
            } catch (e: RuntimeException) {
                return amdResult(false, "certificate parse failed: " + msg(e), null, false)
            }
            val parsed: Map<String, Any?>? = try {
                AmdGenuine.parseReport(rawReport)
            } catch (e: RuntimeException) {
                null
            }
            val now = num(opts["nowMs"])
            if (!finite(now)) return amdResult(false, "cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check", parsed, false)
            val expected = opts["expectedMeasurement"]
            val expectedM = if (expected is String && expected.isNotEmpty()) expected else null
            val (reason, report) = AmdGenuine.verify(rawReport, vcekDer, askArkPem, pin, now!!.toLong(), opts["clockSkewMs"], expectedM, opts["allowDebug"] == true)
            if (reason.isNotEmpty() || report == null) return amdResult(false, if (reason.isEmpty()) "AMD SEV-SNP verification failed" else reason, parsed, false)
            return amdResult(true, null, report, true)
        } catch (e: RuntimeException) {
            return amdResult(false, "AMD attestation verification error (fail closed): " + msg(e), null, false)
        }
    }

    // ---- composition: verify + freshness + channel binding + appraisal ----

    private fun fresh(ok: Boolean, tier: String?, reasons: List<Any?>, claims: Map<String, Any?>?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (tier != null) m["tier"] = tier
        m["reasons"] = reasons
        if (claims != null) m["claims"] = claims
        return m
    }

    /**
     * The end-to-end check a resource server runs: verify the EAT's signature, then its FRESHNESS, its CHANNEL BINDING and finally
     * APPRAISE it against the RATS policy; the first failing gate stops the pipeline and names the reason. [opts]: verifyKey
     * ([ScittPublicKey]), amd? (rawReport, vcek, ask, ark, family | trustAnchorArkSpkiSha384, clockSkewMs?, allowDebug?,
     * expectedMeasurement?), nonce, channelId?, channelBinding?, policy {endorsements?, referenceValues?}, now?, maxAgeMs?, clockSkewMs?,
     * issuer?, algorithms?, typ?, requireTyp?. Result {ok, tier?, reasons, claims?}.
     */
    fun verifyFreshAttestedEAT(eat: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val reasons = ArrayList<Any?>()
        val claims: Map<String, Any?>
        try {
            val vo = LinkedHashMap<String, Any?>()
            for (k in listOf("issuer", "algorithms", "typ", "requireTyp")) if (opts.containsKey(k)) vo[k] = opts[k]
            claims = verifyEAT(eat, opts["verifyKey"] as ScittPublicKey?, vo)
        } catch (e: RuntimeException) {
            return fresh(false, null, arrayListOf<Any?>("EAT signature/claims invalid: " + msg(e)), null)
        }
        reasons.add("signature + typ/iss verified")

        val nowD = num(opts["now"])
        val now = if (finite(nowD)) nowD!! else System.currentTimeMillis().toDouble()
        val fo = LinkedHashMap<String, Any?>()
        fo["expectedNonce"] = opts["nonce"]
        fo["maxAgeMs"] = if (opts.containsKey("maxAgeMs") && opts["maxAgeMs"] != null) opts["maxAgeMs"] else DEFAULT_MAX_AGE_MS
        fo["now"] = now
        if (opts.containsKey("clockSkewMs") && opts["clockSkewMs"] != null) fo["clockSkewMs"] = opts["clockSkewMs"]
        val f = verifyFreshness(claims, fo)
        if (f["ok"] != true) return fresh(false, null, plusReason(reasons, if (f["reason"] != null) f["reason"] as String else "not fresh"), claims)
        reasons.add("fresh (nonce + iat within window)")

        val co = LinkedHashMap<String, Any?>()
        if (opts.containsKey("channelId") && opts["channelId"] != null) co["channelId"] = opts["channelId"]
        if (opts.containsKey("channelBinding")) co["expectedCnf"] = opts["channelBinding"]
        val c = verifyChannelBinding(claims, co)
        if (c["ok"] != true) return fresh(false, null, plusReason(reasons, if (c["reason"] != null) c["reason"] as String else "channel binding failed"), claims)
        reasons.add("channel-bound (cnf matches live channel)")

        val extras = LinkedHashMap<String, Any?>()
        if (opts.containsKey("amd")) {
            val amd = rec(opts["amd"]) ?: throw IllegalArgumentException("Cannot read properties of null (reading 'expectedMeasurement')")
            val expectedMeasurement: Any? = amd["expectedMeasurement"] ?: launchMeasurement(claims)
            val ao = LinkedHashMap<String, Any?>()
            for (k in listOf("vcek", "ask", "ark", "family", "trustAnchorArkSpkiSha384", "clockSkewMs", "allowDebug")) if (amd.containsKey(k)) ao[k] = amd[k]
            ao["nowMs"] = now
            if (expectedMeasurement != null) ao["expectedMeasurement"] = expectedMeasurement
            val raw = amd["rawReport"]
            // the pin options are judged before the report is read: a missing report with neither or both of them is refused for that
            val hw = if (raw is ByteArray) verifyAmdAttestation(raw, ao)
            else if (ao.containsKey("family") == ao.containsKey("trustAnchorArkSpkiSha384")) amdResult(false, "exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)", null, false)
            else amdResult(false, "report parse failed: parseSevSnpReport: expected Uint8Array", null, false)
            if (hw["ok"] != true) {
                return fresh(false, "contraindicated", plusReason(reasons, "AMD hardware root verification failed: " + (hw["reason"] ?: "unknown")), claims)
            }
            reasons.add("AMD SEV-SNP hardware root verified (${hw["hardwareRoot"]})")
            extras["hardwareVerified"] = true
            extras["hardwareRootLabel"] = hw["hardwareRoot"]
        }
        val pol = rec(opts["policy"]) ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'referenceValues')")
        val rvIn = rec(pol["referenceValues"])
        val enIn = rec(pol["endorsements"])
        val app = appraise(claims, rvIn ?: LinkedHashMap(), enIn ?: LinkedHashMap(), extras)
        val all = ArrayList<Any?>(reasons)
        all.addAll(arr(app["reasons"])!!)
        return fresh(app["trustworthy"] == true, app["tier"] as String?, all, claims)
    }
}
