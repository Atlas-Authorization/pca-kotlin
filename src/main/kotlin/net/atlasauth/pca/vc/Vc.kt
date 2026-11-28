package net.atlasauth.pca.vc

import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import net.atlasauth.pca.dpop.Dpop
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * Emits the PCA agent passport in the converging verifiable-identity formats: a W3C Verifiable Credential 2.0 secured as an SD-JWT VC
 * (EdDSA), `did:key` identifiers (Ed25519, multicodec 0xed01 + base58btc), and RFC 9421 HTTP Message Signatures with the Web Bot Auth
 * `Signature-Agent` pattern. A bridge, not a replacement: the passport stays the source of truth. Options and results are JSON-shaped
 * maps with the reference's member names; keys are raw Ed25519 bytes (a 32-byte seed to sign, a 32-byte public key to verify) or JWK
 * maps. `now` (epoch milliseconds) is the clock hook of the operations that read time.
 */
@Suppress("UNCHECKED_CAST")
object Vc {
    const val VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
    const val AGENT_PASSPORT_CONTEXT = "https://atlasauth.net/credentials/agent-passport/v1"
    const val AGENT_PASSPORT_VC_TYPE = "AgentPassportCredential"

    private val SD_DIGEST_FIELDS = listOf("weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement")
    private val RANDOM = SecureRandom()

    private fun asMap(o: Any?) = o as? Map<String, Any?>

    private fun bad(m: String): Nothing = throw IllegalArgumentException(m)

    private fun sha256b64u(ascii: String): String = Jose.b64u(Jose.sha256(ByteArray(ascii.length) { ascii[it].code.toByte() }))

    private fun asString(v: Any?, label: String): String = v as? String ?: bad("pca-vc: expected string for $label")

    // ---- base58btc / did:key ----

    private const val B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private const val MAX_BASE58_INPUT = 1024

    /** Base58 (Bitcoin alphabet) encoding, as multibase `z`. */
    @JvmStatic
    fun base58btcEncode(bytes: ByteArray): String {
        var zeros = 0
        while (zeros < bytes.size && bytes[zeros] == 0.toByte()) zeros++
        val digits = ArrayList<Int>()
        for (i in zeros until bytes.size) {
            var carry = bytes[i].toInt() and 0xff
            for (j in digits.indices) {
                carry += digits[j] shl 8
                digits[j] = carry % 58
                carry /= 58
            }
            while (carry > 0) {
                digits.add(carry % 58)
                carry /= 58
            }
        }
        return "1".repeat(zeros) + digits.asReversed().joinToString("") { B58[it].toString() }
    }

    /** Inverse of [base58btcEncode]; throws on a character outside the alphabet or an input over 1024 characters. */
    @JvmStatic
    fun base58btcDecode(str: String): ByteArray {
        if (str.length > MAX_BASE58_INPUT) bad("pca-vc: base58btc input too long")
        var zeros = 0
        while (zeros < str.length && str[zeros] == '1') zeros++
        val bytes = ArrayList<Int>()
        for (i in zeros until str.length) {
            var carry = B58.indexOf(str[i])
            if (carry < 0) bad("pca-vc: invalid base58btc character")
            for (j in bytes.indices) {
                carry += bytes[j] * 58
                bytes[j] = carry and 0xff
                carry = carry shr 8
            }
            while (carry > 0) {
                bytes.add(carry and 0xff)
                carry = carry shr 8
            }
        }
        val out = ByteArray(zeros + bytes.size)
        for (i in bytes.indices) out[zeros + bytes.size - 1 - i] = bytes[i].toByte()
        return out
    }

    /** A `did:key` identifier for an Ed25519 public key (32 raw bytes). */
    @JvmStatic
    fun didKeyFromEd25519(publicKey: ByteArray): String {
        if (publicKey.size != 32) bad("pca-vc: Ed25519 public key must be 32 bytes")
        return "did:key:z" + base58btcEncode(byteArrayOf(0xed.toByte(), 0x01) + publicKey)
    }

    /** The 32-byte Ed25519 public key of an Ed25519 `did:key`. Inverse of [didKeyFromEd25519]. */
    @JvmStatic
    fun ed25519FromDidKey(did: String): ByteArray {
        val prefix = "did:key:z"
        if (!did.startsWith(prefix)) bad("pca-vc: not a did:key:z… identifier")
        if (did.length > prefix.length + 64) bad("pca-vc: did:key is not an Ed25519 (0xed01) key")
        val mc = base58btcDecode(did.substring(prefix.length))
        if (mc.size != 34 || (mc[0].toInt() and 0xff) != 0xed || mc[1] != 0x01.toByte()) bad("pca-vc: did:key is not an Ed25519 (0xed01) key")
        return mc.copyOfRange(2, 34)
    }

    // ---- bundled JSON-LD context ----

    private const val V = "https://atlasauth.net/credentials/agent-passport/v1#"
    private const val XSD = "http://www.w3.org/2001/XMLSchema#"

    private fun term(id: String, type: String) = linkedMapOf<String, Any?>("@id" to V + id, "@type" to XSD + type)

    /** The JSON-LD context for AgentPassportCredential, bundled so a verifier resolves it offline. Terms are protected. */
    @JvmField
    val AGENT_PASSPORT_CONTEXT_DOC: Map<String, Any?> = run {
        val inner = linkedMapOf<String, Any?>(
            "@protected" to true, "id" to "@id", "type" to "@type",
            "passport_id" to term("passportId", "string"), "model_id" to term("modelId", "string"), "operator" to term("operator", "string"),
            "hardware_rooted" to term("hardwareRooted", "boolean"), "weights_measured" to term("weightsMeasured", "boolean"),
            "issued_at" to term("issuedAt", "integer"), "weights_digest" to term("weightsDigest", "string"),
            "system_prompt_digest" to term("systemPromptDigest", "string"), "tool_manifest_digest" to term("toolManifestDigest", "string"),
            "runtime_measurement" to term("runtimeMeasurement", "string"),
            "_sd" to linkedMapOf<String, Any?>("@id" to V + "selectiveDisclosureDigest", "@container" to "@set"),
        )
        val cred = linkedMapOf<String, Any?>("@id" to V + "AgentPassportCredential", "@context" to inner)
        java.util.Collections.unmodifiableMap(linkedMapOf<String, Any?>("@context" to linkedMapOf<String, Any?>("@protected" to true, "AgentPassportCredential" to cred)))
    }

    /** SHA-256 (hex) of the key-sorted JSON of [AGENT_PASSPORT_CONTEXT_DOC]; changes whenever any term changes. */
    @JvmField
    val AGENT_PASSPORT_CONTEXT_DIGEST: String = Jose.sha256(Jose.utf8(Json.canonicalize(AGENT_PASSPORT_CONTEXT_DOC))).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** A document loader for JSON-LD processors: the bundled document for its IRI, null for anything else (never fetched). */
    @JvmStatic
    fun resolveAgentPassportContext(iri: Any?): Map<String, Any?>? = if (iri == AGENT_PASSPORT_CONTEXT) AGENT_PASSPORT_CONTEXT_DOC else null

    // ---- key plumbing ----

    private fun ed25519Jwk(raw: ByteArray, seed: ByteArray?) = linkedMapOf<String, Any?>("kty" to "OKP", "crv" to "Ed25519", "x" to Jose.b64u(raw)).apply {
        if (seed != null) put("d", Jose.b64u(seed))
    }

    /** A signing key: a 32-byte seed or a private JWK map. */
    private fun privateKey(key: Any?): Map<String, Any?> {
        if (key is ByteArray) {
            if (key.size != 32) bad("pca-vc: Ed25519 seed must be 32 bytes")
            return ed25519Jwk(Keys.edFromSeed(key).pub, key)
        }
        return asMap(key) ?: bad("pca-vc: not a signing key")
    }

    /** A verification key: a 32-byte public key or a public JWK map. */
    private fun publicKey(key: Any?): Map<String, Any?> {
        if (key is ByteArray) {
            if (key.size != 32) bad("pca-vc: Ed25519 public key must be 32 bytes")
            return ed25519Jwk(key, null)
        }
        return asMap(key) ?: bad("pca-vc: not a verification key")
    }

    private fun nowMs(o: Any?): Double = if (o != null) Js.num(o)!! else System.currentTimeMillis().toDouble()

    // ---- W3C VC 2.0 as an SD-JWT VC ----

    /**
     * Emits an AgentPassport (a map) as a W3C VC 2.0 secured as an SD-JWT VC (EdDSA): `<jwt>~<disclosure>~...~`. The credential subject
     * carries a salted hash of each present passport digest in `_sd`; the model id, operator, hardware flag and passport id stay in the
     * clear. Options: `issuerKey` (32-byte seed or private JWK), `issuerDid`, `subjectDid`, `ttlSec` (null counts as 0), `now` (ms).
     */
    @JvmStatic
    fun passportToVC(passport: Map<String, Any?>?, args: Map<String, Any?>): String {
        if (passport == null) bad("Cannot read properties of null")
        val disclosures = ArrayList<String>()
        val sd = ArrayList<Any?>()
        for (field in SD_DIGEST_FIELDS) {
            if (!passport.containsKey(field)) continue
            val salt = ByteArray(16).also { RANDOM.nextBytes(it) }
            val disclosure = Jose.b64u(Jose.utf8(Jose.stringify(listOf(Jose.b64u(salt), field, passport[field]))))
            disclosures.add(disclosure)
            sd.add(sha256b64u(disclosure))
        }
        val cs = LinkedHashMap<String, Any?>()
        if (args.containsKey("subjectDid")) cs["id"] = args["subjectDid"]
        for (k in listOf("id", "model_id", "operator", "hardware_rooted", "issued_at")) {
            if (passport.containsKey(k)) cs[if (k == "id") "passport_id" else k] = passport[k]
        }
        if (passport.containsKey("weights_measured")) cs["weights_measured"] = passport["weights_measured"]
        if (sd.isNotEmpty()) cs["_sd"] = sd

        val vc = linkedMapOf<String, Any?>(
            "@context" to listOf(VC_CONTEXT, AGENT_PASSPORT_CONTEXT),
            "type" to listOf("VerifiableCredential", AGENT_PASSPORT_VC_TYPE),
            "credentialSubject" to cs,
        )
        val now = Math.floor(nowMs(args["now"]) / 1000)
        val payload = linkedMapOf<String, Any?>("vc" to vc)
        if (sd.isNotEmpty()) payload["_sd_alg"] = "sha-256"
        if (args.containsKey("issuerDid")) payload["iss"] = args["issuerDid"]
        if (args.containsKey("subjectDid")) payload["sub"] = args["subjectDid"]
        payload["iat"] = Js.jsNum(now)
        if (args.containsKey("ttlSec")) {
            val ttl = when (val t = args["ttlSec"]) {
                null -> 0.0
                is Boolean -> if (t) 1.0 else 0.0
                else -> Js.num(t) ?: throw Jose.JoseException("Invalid time period format")
            }
            payload["exp"] = Js.jsNum(now + ttl)
        }
        val header = linkedMapOf<String, Any?>("alg" to "EdDSA", "typ" to "vc+sd-jwt")
        val jwt = Jose.signJwt(header, payload, privateKey(args["issuerKey"]))
        return "$jwt~" + disclosures.joinToString("") { "$it~" }
    }

    /**
     * Verifies an SD-JWT VC produced by [passportToVC] and reconstructs the passport: {passport, issuerDid, subjectDid}. The signature is
     * checked under [issuerVerifyKey] (EdDSA only); every presented disclosure must hash to a digest in `credentialSubject._sd`. Options:
     * `expectedIssuerDid`, `now` (ms). Throws on any failure.
     */
    @JvmStatic
    fun verifyPassportVC(vcO: Any?, issuerVerifyKey: Any?, options: Map<String, Any?>?): Map<String, Any?> {
        if (vcO !is String) bad("vc.split is not a function")
        val parts = vcO.split("~")
        val jwt = parts[0]
        if (jwt.isEmpty()) bad("pca-vc: empty SD-JWT")
        val disclosures = parts.drop(1).filter { it.isNotEmpty() }
        Jose.assertCanonicalCompactJws(jwt)
        for (d in disclosures) Jose.decodeCanonicalBase64url(d)

        val nowO = options?.get("now")
        val res = Jose.jwtVerify(jwt, publicKey(issuerVerifyKey), Jose.JwtOptions(algorithms = listOf("EdDSA"), currentDateMs = if (nowO != null) Js.num(nowO) else null))
        val payload = res.payload
        if (res.protectedHeader["typ"] != "vc+sd-jwt") bad("pca-vc: header typ must be 'vc+sd-jwt'")
        val vcClaim = asMap(payload["vc"]) ?: bad("pca-vc: missing vc claim")
        val ctx = vcClaim["@context"]
        if (ctx !is List<*> || ctx.isEmpty() || ctx[0] != VC_CONTEXT) bad("pca-vc: @context must begin with $VC_CONTEXT")
        if (ctx.size != 2 || ctx[1] != AGENT_PASSPORT_CONTEXT) bad("pca-vc: @context must be exactly [$VC_CONTEXT, $AGENT_PASSPORT_CONTEXT]")
        val types = vcClaim["type"]
        if (types !is List<*> || "VerifiableCredential" !in types || AGENT_PASSPORT_VC_TYPE !in types) {
            bad("pca-vc: type must include VerifiableCredential and $AGENT_PASSPORT_VC_TYPE")
        }
        val cs = asMap(vcClaim["credentialSubject"]) ?: bad("pca-vc: missing credentialSubject")
        if (cs.containsKey("_sd_alg")) bad("pca-vc: _sd_alg must be a top-level claim")
        if (payload.containsKey("_sd_alg") && payload["_sd_alg"] != "sha-256") bad("pca-vc: unsupported _sd_alg (require sha-256)")

        val sdList = (cs["_sd"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
        val recovered = LinkedHashMap<String, String>()
        val seen = HashSet<String>()
        for (disclosure in disclosures) {
            val digest = sha256b64u(disclosure)
            if (digest !in sdList) bad("pca-vc: disclosure does not match any _sd digest")
            if (!seen.add(digest)) bad("pca-vc: duplicate disclosure")
            val decoded = try {
                Json.parseNoDuplicates(String(Keys.unb64u(disclosure), Charsets.UTF_8))
            } catch (e: RuntimeException) {
                bad("pca-vc: malformed disclosure")
            }
            if (decoded !is List<*> || decoded.size != 3) bad("pca-vc: malformed disclosure")
            val name = asString(decoded[1], "disclosure name")
            if (name !in SD_DIGEST_FIELDS) bad("pca-vc: unexpected disclosure claim '$name'")
            if (recovered.containsKey(name)) bad("pca-vc: disclosure claim '$name' appears more than once")
            recovered[name] = asString(decoded[2], "disclosure value")
        }

        val passport = linkedMapOf<String, Any?>(
            "id" to asString(cs["passport_id"], "passport_id"),
            "model_id" to asString(cs["model_id"], "model_id"),
            "operator" to asString(cs["operator"], "operator"),
        )
        if (cs["hardware_rooted"] !is Boolean) bad("pca-vc: expected boolean for hardware_rooted")
        passport["hardware_rooted"] = cs["hardware_rooted"]
        if (Js.num(cs["issued_at"]) == null) bad("pca-vc: expected number for issued_at")
        passport["issued_at"] = cs["issued_at"]
        if (cs.containsKey("weights_measured")) {
            if (cs["weights_measured"] !is Boolean) bad("pca-vc: expected boolean for weights_measured")
            passport["weights_measured"] = cs["weights_measured"]
        }
        for (field in SD_DIGEST_FIELDS) recovered[field]?.let { passport[field] = it }

        val issuerDid = asString(payload["iss"], "iss")
        val subjectDid = asString(cs["id"], "credentialSubject.id")
        if (subjectDid != payload["sub"]) bad("pca-vc: sub does not match credentialSubject.id")
        if (options != null && options.containsKey("expectedIssuerDid") && issuerDid != options["expectedIssuerDid"]) bad("pca-vc: iss does not match expectedIssuerDid")
        return linkedMapOf("passport" to passport, "issuerDid" to issuerDid, "subjectDid" to subjectDid)
    }

    // ---- RFC 9421 HTTP Message Signatures + Web Bot Auth ----

    private const val SIG_LABEL = "sig1"
    private const val WS = "[\\u0009-\\u000d\\u0020\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]"
    private val WS_RUN = Regex("$WS+")
    private val COMPONENT_TOKEN = Regex("^\"(.*)\"\\z")
    private val ALG_PARAM = Regex(";alg=\"([^\"]*)\"")
    private val CREATED_PARAM = Regex(";created=(\\d+)")
    private val WRAPPED_SIG = Regex("^:(.*):\\z")
    private val B64_BODY = Regex("[A-Za-z0-9+/]*")

    /** Lower-case header keys; a later duplicate wins. A non-string value reads as absent (every normalized header is covered). */
    private fun normalizeHeaders(headers: Any?): MutableMap<String, String?> {
        val h = asMap(headers) ?: bad("Cannot convert undefined or null to object")
        val out = LinkedHashMap<String, String?>()
        for ((k, v) in h) out[k.lowercase(Locale.ROOT)] = v as? String
        return out
    }

    private fun componentValue(name: String, method: String, url: String, headers: Map<String, String?>): String = when (name) {
        "@method" -> method.uppercase(Locale.ROOT)
        "@target-uri" -> url
        "@authority" -> Dpop.urlHost(url)
        else -> AttestUtil.jsTrim(headers[name] ?: bad("pca-vc: covered header '$name' absent from request"))
    }

    private fun signatureBase(components: List<String>, sigParamsValue: String, method: String, url: String, headers: Map<String, String?>): String =
        (components.map { "\"$it\": " + componentValue(it, method, url, headers) } + "\"@signature-params\": $sigParamsValue").joinToString("\n")

    /**
     * Signs an HTTP request per RFC 9421 (EdDSA) with the Web Bot Auth `Signature-Agent` pattern. args: `method`, `url`, `headers` (map),
     * `key` (32-byte seed or private JWK), `keyid`, `created` (null = now), `signatureAgent` (present, even null, adds the agent header,
     * the covered component and the `web-bot-auth` tag), `now` (ms). Returns {signatureInput, signature, signatureAgent?}.
     */
    @JvmStatic
    fun signRequestMessage(args: Map<String, Any?>): Map<String, Any?> {
        val method = args["method"] as String
        val url = args["url"] as String
        val createdO = args["created"]
        val created = if (createdO != null) Js.template(createdO) else Js.template(Js.jsNum(Math.floor(nowMs(args["now"]) / 1000)))
        val headers = normalizeHeaders(args["headers"])
        if (!headers.containsKey("host")) headers["host"] = Dpop.urlHost(url)
        val agent = args.containsKey("signatureAgent")
        val agentValue = "\"" + Js.template(args["signatureAgent"]) + "\""
        if (agent) headers["signature-agent"] = agentValue

        val components = listOf("@method", "@target-uri") + headers.keys.sorted()
        var params = ";created=$created;keyid=\"${Js.template(args["keyid"])}\";alg=\"ed25519\""
        if (agent) params += ";tag=\"web-bot-auth\""
        val sigParamsValue = components.joinToString(" ", "(", ")") { "\"$it\"" } + params

        val base = signatureBase(components, sigParamsValue, method, url, headers)
        val sig = Jose.signRaw("EdDSA", privateKey(args["key"]), Jose.utf8(base))
        return linkedMapOf<String, Any?>(
            "signatureInput" to "$SIG_LABEL=$sigParamsValue",
            "signature" to "$SIG_LABEL=:" + Base64.getEncoder().encodeToString(sig) + ":",
        ).apply { if (agent) put("signatureAgent", agentValue) }
    }

    private fun parseComponents(sigParamsValue: String): List<String> {
        val open = sigParamsValue.indexOf('(')
        val close = sigParamsValue.indexOf(')')
        if (open != 0 || close < 0) bad("pca-vc: malformed @signature-params")
        val inner = AttestUtil.jsTrim(sigParamsValue.substring(open + 1, close))
        if (inner.isEmpty()) return emptyList()
        return inner.split(WS_RUN).map { tok -> COMPONENT_TOKEN.find(tok)?.groupValues?.get(1) ?: bad("pca-vc: malformed component identifier") }
    }

    private fun toNumber(v: Any?): Double = when {
        v == null -> 0.0
        Js.num(v) != null -> Js.num(v)!!
        v is Boolean -> if (v) 1.0 else 0.0
        else -> Double.NaN
    }

    /**
     * Verifies an RFC 9421 signature produced by [signRequestMessage]. args: `method`, `url`, `headers`, `signatureInput`, `signature`,
     * `signatureAgent`, `requiredComponents`, `maxAgeSec`, `nowSec`, `now` (ms; the clock when `nowSec` is absent). False on any mismatch.
     */
    @JvmStatic
    fun verifyRequestSignature(args: Map<String, Any?>, verifyKey: Any?): Boolean = try {
        verifyUnchecked(args, verifyKey)
    } catch (e: RuntimeException) {
        false
    }

    private fun verifyUnchecked(args: Map<String, Any?>, verifyKey: Any?): Boolean {
        val signatureInput = args["signatureInput"] as String
        val eq = signatureInput.indexOf('=')
        if (eq < 0) return false
        val sigParamsValue = signatureInput.substring(eq + 1)
        val components = parseComponents(sigParamsValue)
        (args["requiredComponents"] as List<*>?)?.let { req -> if (req.any { it !in components }) return false }
        ALG_PARAM.find(sigParamsValue)?.let { if (it.groupValues[1] != "ed25519") return false }
        if (args.containsKey("maxAgeSec")) {
            val created = CREATED_PARAM.find(sigParamsValue) ?: return false
            val now = args["nowSec"]?.let { Js.num(it)!! } ?: Math.floor(nowMs(args["now"]) / 1000)
            val c = created.groupValues[1].toDouble()
            if (!now.isFinite() || !c.isFinite() || !(now - c <= toNumber(args["maxAgeSec"])) || !(c - now <= 5)) return false
        }
        val url = args["url"] as String
        val headers = normalizeHeaders(args["headers"])
        if (!headers.containsKey("host")) headers["host"] = Dpop.urlHost(url)
        if ("signature-agent" in components && !headers.containsKey("signature-agent")) {
            // absent: refused; a non-string value fails when the header is read
            headers["signature-agent"] = args["signatureAgent"] as? String ?: return false
        }
        val base = signatureBase(components, sigParamsValue, args["method"] as String, url, headers)

        val signature = args["signature"] as String
        val sigEq = signature.indexOf('=')
        if (sigEq < 0) return false
        val m = WRAPPED_SIG.find(AttestUtil.jsTrim(signature.substring(sigEq + 1))) ?: return false
        return Jose.verifySignature("EdDSA", publicKey(verifyKey), nodeBase64(m.groupValues[1]), Jose.utf8(base))
    }

    /** Node-style lenient base64 (either alphabet, optional padding, stops at the first '='). */
    private fun nodeBase64(s: String): ByteArray {
        val eq = s.indexOf('=')
        val t = (if (eq >= 0) s.substring(0, eq) else s).replace('-', '+').replace('_', '/')
        if (!B64_BODY.matches(t) || t.length % 4 == 1) return ByteArray(0)
        return Base64.getDecoder().decode(t.padEnd((t.length + 3) / 4 * 4, '='))
    }
}
