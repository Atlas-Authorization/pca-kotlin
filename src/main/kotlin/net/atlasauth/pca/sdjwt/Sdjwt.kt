package net.atlasauth.pca.sdjwt

import java.security.SecureRandom
import java.util.Locale
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * SD-JWT serialization of a PCActn (IETF SD-JWT, RFC 9901 family): the issuer-signed JWT carries salted-hash digests of the selectively
 * disclosable capability claims, the holder presents a subset and appends a key-binding JWT (typ `kb+jwt`). A bridge: the PCActn's own
 * signature (a claim) stays the source of truth ([verifyRecovered] re-verifies it with the core). Options are JSON-shaped maps with the
 * reference's member names (an absent member differs from a JSON null one); keys are JWK maps ([importEd25519PrivateKey],
 * [importEd25519PublicKey]). EdDSA is the only issuance algorithm; verification also accepts ES256 / RS256 / PS256 / ... keys through
 * `algorithms`. Verification fails closed: every refusal is {ok:false, reason}.
 */
@Suppress("UNCHECKED_CAST")
object Sdjwt {
    const val SD_ALG = "sha-256"
    const val PCA_SD_JWT_TYP = "pca+sd-jwt"
    const val KB_JWT_TYP = "kb+jwt"
    const val DEFAULT_SIGNING_ALG = "EdDSA"

    /** The PCActn fields carried as selectively disclosable capability claims by default. */
    @JvmField
    val PCA_CAPABILITY_CLAIMS: List<String> = listOf(
        "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "nonce", "caution",
        "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "alg", "pq_pk", "sig", "pq_sig", "threshold",
        "zk_compliance", "bond_ref",
    )

    private val STANDARD_MAPPED = setOf("aud", "iat", "exp")
    private const val CLEAR_DISCRIMINATOR = "ver"
    private val CRITICAL_CLAIMS = setOf("iss", "aud", "exp", "nbf", "cnf", "status")
    private val RESERVED_CLAIMS = setOf("iss", "sub", "aud", "iat", "exp", "_sd", "_sd_alg", "cnf")

    private val RANDOM = SecureRandom()

    /** base64url(SHA-256(ASCII(input))): each UTF-16 unit contributes its low byte, as an ASCII write does. */
    private fun sha256b64u(ascii: String): String = Jose.b64u(Jose.sha256(ByteArray(ascii.length) { ascii[it].code.toByte() }))

    private fun asMap(o: Any?) = o as? Map<String, Any?>

    private fun isJwk(v: Any?) = asMap(v)?.get("kty") is String

    /** JavaScript ToNumber of a parsed JSON value (null is 0, a non-numeric string NaN). */
    private fun toNumber(v: Any?): Double {
        if (v == null) return 0.0
        Js.num(v)?.let { return it }
        return when (v) {
            is Boolean -> if (v) 1.0 else 0.0
            is String -> v.trim().let { t -> if (t.isEmpty()) 0.0 else t.toDoubleOrNull() ?: Double.NaN }
            else -> Double.NaN
        }
    }

    private fun sameJs(a: Any?, b: Any?): Boolean {
        if (a == null || b == null) return a == null && b == null
        if (a is String || b is String || a is Boolean || b is Boolean) return a == b
        val x = Js.num(a)
        val y = Js.num(b)
        return x != null && y != null && x == y
    }

    // ---- Ed25519 raw key <-> JWK ----

    /** A {kty:'OKP', crv:'Ed25519', x} JWK for a raw 32-byte Ed25519 public key. */
    @JvmStatic
    fun ed25519PublicJwk(raw: ByteArray?): MutableMap<String, Any?> {
        if (!(raw != null && raw.size == 32)) throw IllegalArgumentException("pca-sdjwt: Ed25519 public key must be 32 bytes")
        return linkedMapOf("kty" to "OKP", "crv" to "Ed25519", "x" to Jose.b64u(raw))
    }

    /** A private JWK (usable to sign) for a raw 32-byte Ed25519 SEED. */
    @JvmStatic
    fun importEd25519PrivateKey(rawSeed: ByteArray?): Map<String, Any?> {
        if (!(rawSeed != null && rawSeed.size == 32)) throw IllegalArgumentException("pca-sdjwt: Ed25519 private seed must be 32 bytes")
        return ed25519PublicJwk(Keys.edFromSeed(rawSeed).pub).apply { put("d", Jose.b64u(rawSeed)) }
    }

    /** A public JWK (usable to verify) for a raw 32-byte Ed25519 public key. */
    @JvmStatic
    fun importEd25519PublicKey(raw: ByteArray?): Map<String, Any?> = ed25519PublicJwk(raw)

    /** The public members of a JWK (a key object imported from a JWK carries no private members or hints). */
    private fun publicOnly(jwk: Map<String, Any?>): Map<String, Any?> =
        LinkedHashMap<String, Any?>().also { out -> for (k in listOf("kty", "crv", "x", "y", "n", "e")) if (jwk.containsKey(k)) out[k] = jwk[k] }

    // ---- issuance ----

    private fun leafHolderJwk(pcActn: Map<String, Any?>): Map<String, Any?> {
        val chain = pcActn["cap_chain"] as? List<*>
        val leaf = if (chain != null && chain.isNotEmpty()) asMap(chain.last()) else null
        val holder = leaf?.get("holder")
        if (!(holder is String && holder.isNotEmpty())) throw IllegalArgumentException("pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing")
        return ed25519PublicJwk(Jose.decodeB64Lenient(holder))
    }

    private fun resolveCnfJwk(pcActn: Map<String, Any?>, kb: Map<String, Any?>): Map<String, Any?> {
        if (!kb.containsKey("holderPublicKey")) return leafHolderJwk(pcActn)
        val hp = kb["holderPublicKey"]
        if (hp is ByteArray) return ed25519PublicJwk(hp)
        if (isJwk(hp)) return asMap(hp)!!
        throw IllegalArgumentException("pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key")
    }

    private fun numericDate(ms: Any?, label: String, ceil: Boolean): Double {
        val d = Js.num(ms)
        if (!(d != null && !d.isNaN() && !d.isInfinite())) throw IllegalArgumentException("pca-sdjwt: PCActn.$label must be a finite number (epoch ms)")
        return if (ceil) Math.ceil(d / 1000) else Math.floor(d / 1000)
    }

    /** JSON.stringify([salt, name, value]) -> (encoded, digest). */
    private fun makeDisclosure(name: String, value: Any?): Pair<String, String> {
        val salt = ByteArray(16).also { RANDOM.nextBytes(it) }
        val encoded = Jose.b64u(Jose.utf8(Jose.stringify(listOf(Jose.b64u(salt), name, value))))
        return encoded to sha256b64u(encoded)
    }

    private fun algOf(v: Any?): String = (v ?: DEFAULT_SIGNING_ALG) as? String ?: throw Jose.JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")

    /**
     * Serializes a signed PCActn as an IETF SD-JWT: `<issuer JWT>~<Disclosure 1>~...~<Disclosure N>~`. Options: `issuerKey` (private JWK,
     * required), `disclosable` (claim names; null = all of [PCA_CAPABILITY_CLAIMS]), `keyBinding` ({holderPublicKey?} embeds a `cnf` key;
     * absent / null / false = none), `iss`, `sub`, `typ`, `signingAlg`. No KB-JWT is attached at issuance.
     */
    @JvmStatic
    fun issuePcaSdJwt(pcActn: Map<String, Any?>?, options: Map<String, Any?>): String {
        if (!(pcActn != null)) throw IllegalArgumentException("pca-sdjwt: pcActn must be an object")
        val chain = pcActn["cap_chain"] as? List<*>
        if (!(chain != null && chain.isNotEmpty())) throw IllegalArgumentException("pca-sdjwt: pcActn.cap_chain must be a non-empty array")
        val root = asMap(chain.first())
        val leaf = asMap(chain.last())
        if (!(root != null && root["issuer"] is String)) throw IllegalArgumentException("pca-sdjwt: cap_chain root issuer is missing")
        if (!(leaf != null && leaf["holder"] is String)) throw IllegalArgumentException("pca-sdjwt: cap_chain leaf holder is missing")
        if (!((pcActn["aud"] as? String)?.isNotEmpty() == true)) throw IllegalArgumentException("pca-sdjwt: pcActn.aud is required")

        val iat = numericDate(pcActn["iat"], "iat", false)
        var exp = numericDate(pcActn["exp"], "exp", true)
        if (exp <= iat) exp = iat + 1

        val disclosable: Set<String> = when (val dis = options["disclosable"]) {
            null -> PCA_CAPABILITY_CLAIMS.toSet()
            is List<*> -> dis.filterIsInstance<String>().toSet()
            else -> throw IllegalArgumentException("pca-sdjwt: disclosable must be an array")
        }

        val payload = linkedMapOf<String, Any?>(
            "iss" to (options["iss"] ?: root["issuer"]),
            "sub" to (options["sub"] ?: leaf["holder"]),
            "aud" to pcActn["aud"],
            "iat" to Js.jsNum(iat),
            "exp" to Js.jsNum(exp),
        )
        if (pcActn.containsKey(CLEAR_DISCRIMINATOR)) payload[CLEAR_DISCRIMINATOR] = pcActn[CLEAR_DISCRIMINATOR]
        payload["iat_ms"] = pcActn["iat"]
        payload["exp_ms"] = pcActn["exp"]
        payload["_sd_alg"] = SD_ALG
        val disclosures = ArrayList<String>()
        val sd = ArrayList<Any?>()
        for ((key, value) in pcActn) {
            if (key in STANDARD_MAPPED || key == CLEAR_DISCRIMINATOR) continue
            if (key in disclosable) {
                val (enc, dig) = makeDisclosure(key, value)
                disclosures.add(enc)
                sd.add(dig)
            } else {
                payload[key] = value
            }
        }
        if (sd.isNotEmpty()) payload["_sd"] = sd

        val kbO = options["keyBinding"]
        if (Js.truthy(kbO)) payload["cnf"] = linkedMapOf("jwk" to resolveCnfJwk(pcActn, asMap(kbO) ?: emptyMap()))

        val header = linkedMapOf<String, Any?>("alg" to algOf(options["signingAlg"]), "typ" to (options["typ"] ?: PCA_SD_JWT_TYP))
        val jwt = Jose.signJwt(header, payload, asMap(options["issuerKey"]) ?: throw Jose.JoseException("Invalid key input"))
        return disclosures.joinToString("") { "$it~" }.let { "$jwt~$it" }
    }

    // ---- parsing ----

    private class ParsedSdJwt(val jwt: String, val disclosures: List<String>, val kbJwt: String?, val presentationHead: String)

    private fun parseSdJwt(sdjwtO: Any?): ParsedSdJwt {
        if (!(sdjwtO is String && sdjwtO.isNotEmpty())) throw IllegalArgumentException("pca-sdjwt: empty SD-JWT")
        val segments = sdjwtO.split("~")
        if (!(segments.size >= 2)) throw IllegalArgumentException("pca-sdjwt: malformed SD-JWT (missing ~ separator)")
        val jwt = segments[0]
        if (!(jwt.isNotEmpty())) throw IllegalArgumentException("pca-sdjwt: empty issuer JWT")
        val last = segments.last()
        val disclosures = segments.subList(1, segments.size - 1).toList()
        if (!(disclosures.none { it.isEmpty() })) throw IllegalArgumentException("pca-sdjwt: empty disclosure segment")
        Jose.assertCanonicalCompactJws(jwt)
        if (last.isNotEmpty()) Jose.assertCanonicalCompactJws(last)
        return if (last.isEmpty()) ParsedSdJwt(jwt, disclosures, null, sdjwtO)
        else ParsedSdJwt(jwt, disclosures, last, sdjwtO.substring(0, sdjwtO.length - last.length))
    }

    private fun decodeDisclosureParts(encoded: String): List<Any?> {
        val parsed = try {
            Jose.decodeCanonicalJsonSegment(encoded)
        } catch (e: RuntimeException) {
            throw IllegalArgumentException("pca-sdjwt: disclosure is not canonical base64url strict JSON")
        }
        if (!(parsed is List<*> && (parsed.size == 2 || parsed.size == 3))) throw IllegalArgumentException("pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair")
        if (!(parsed[0] is String)) throw IllegalArgumentException("pca-sdjwt: disclosure salt must be a string")
        return parsed as List<Any?>
    }

    // ---- holder presentation ----

    private fun collectDigests(node: Any?, out: MutableList<String>) {
        when (node) {
            is List<*> -> for (x in node) collectDigests(x, out)
            is Map<*, *> -> for ((k, v) in node) {
                if (k == "_sd" && v is List<*>) { for (x in v) if (x is String) out.add(x) }
                else if (k == "..." && v is String) out.add(v)
                else collectDigests(v, out)
            }
        }
    }

    private fun include(digest: String, byDigest: Map<String, String>, kept: MutableSet<String>) {
        val encoded = byDigest[digest]
        if (encoded == null || digest in kept) return
        kept.add(digest)
        val parts = decodeDisclosureParts(encoded)
        val nested = ArrayList<String>()
        collectDigests(parts.last(), nested)
        for (d in nested) include(d, byDigest, kept)
    }

    /** The names a `new Set(selectClaims)` holds: a list's elements, a string's code points, nothing for null; anything else throws. */
    private fun keepSet(select: Any?): Set<String> = when (select) {
        null -> emptySet()
        is List<*> -> select.filterIsInstance<String>().toSet()
        is String -> {
            val keep = HashSet<String>()
            var i = 0
            while (i < select.length) {
                val cp = select.codePointAt(i)
                keep.add(String(Character.toChars(cp)))
                i += Character.charCount(cp)
            }
            keep
        }
        else -> throw IllegalArgumentException("object is not iterable")
    }

    /**
     * A holder presentation of an issued SD-JWT that discloses ONLY [selectClaims] (claim names; a list, or null for none) and drops every
     * other Disclosure; a selected claim is disclosed in full. Any existing KB-JWT is stripped. Options: `keyBinding` {holderKey (private
     * JWK), audience, nonce, iat, alg} appends a fresh KB-JWT over the new presentation.
     */
    @JvmStatic
    fun present(sdjwt: Any?, selectClaims: Any?, options: Map<String, Any?>?): String {
        val parsed = parseSdJwt(sdjwt)
        val keep = keepSet(selectClaims)
        val byDigest = LinkedHashMap<String, String>()
        for (e in parsed.disclosures) byDigest[sha256b64u(e)] = e
        val kept = LinkedHashSet<String>()
        val payload = try {
            val segs = parsed.jwt.split(".")
            Json.parseLenient(String(Jose.decodeB64Lenient(if (segs.size > 1) segs[1] else ""), Charsets.UTF_8))
        } catch (e: RuntimeException) {
            throw IllegalArgumentException("pca-sdjwt: issuer JWT payload is not valid base64url JSON")
        }
        asMap(payload)?.let { pm ->
            (pm["_sd"] as? List<*>)?.forEach { digest ->
                if (digest !is String) return@forEach
                val encoded = byDigest[digest] ?: return@forEach
                val parts = decodeDisclosureParts(encoded)
                if (parts[1] is String && parts.size == 3 && parts[1] in keep) include(digest, byDigest, kept)
            }
            for (key in pm.keys) {
                if (key != "_sd" && key in keep) {
                    val ds = ArrayList<String>()
                    collectDigests(pm[key], ds)
                    for (d in ds) include(d, byDigest, kept)
                }
            }
        }
        val head = StringBuilder(parsed.jwt)
        for (e in parsed.disclosures) if (sha256b64u(e) in kept) head.append('~').append(e)
        head.append('~')
        val kb = asMap(options?.get("keyBinding")) ?: return head.toString()

        val kbPayload = linkedMapOf<String, Any?>("iat" to (kb["iat"] ?: Js.jsNum(Math.floor(System.currentTimeMillis() / 1000.0))))
        if (kb.containsKey("audience")) kbPayload["aud"] = kb["audience"]
        kbPayload["sd_hash"] = sha256b64u(head.toString())
        if (kb.containsKey("nonce")) kbPayload["nonce"] = kb["nonce"]
        val kbHeader = linkedMapOf<String, Any?>("alg" to algOf(kb["alg"]), "typ" to KB_JWT_TYP)
        return head.toString() + Jose.signJwt(kbHeader, kbPayload, asMap(kb["holderKey"]) ?: throw Jose.JoseException("Invalid key input"))
    }

    // ---- verification ----

    private class SdJwtProcessingError(m: String) : RuntimeException(m)

    private class DecodedDisclosure(val parts: List<Any?>) {
        var used = false
    }

    /** RFC 9901 s7.1 payload processing (resolve `_sd` digests and {"...": digest} array elements): (processed, disclosed top-level). */
    private fun processDisclosures(payload: Map<String, Any?>, byDigest: Map<String, DecodedDisclosure>): Pair<MutableMap<String, Any?>, Map<String, Any?>> {
        val seen = HashSet<String>()
        val disclosedTop = LinkedHashMap<String, Any?>()
        val p = walk(payload, true, byDigest, seen, disclosedTop) as? MutableMap<String, Any?> ?: throw SdJwtProcessingError("payload is not an object")
        p.remove("_sd_alg")
        if (byDigest.values.any { !it.used }) throw SdJwtProcessingError("a presented disclosure is not referenced by any digest in the payload")
        return p to disclosedTop
    }

    private fun claimDigest(d: String, byDigest: Map<String, DecodedDisclosure>, seen: MutableSet<String>): DecodedDisclosure? {
        if (!seen.add(d)) throw SdJwtProcessingError("a digest appears more than once in the payload")
        return byDigest[d]
    }

    private fun walk(node: Any?, top: Boolean, byDigest: Map<String, DecodedDisclosure>, seen: MutableSet<String>, disclosedTop: MutableMap<String, Any?>): Any? {
        if (node is List<*>) {
            val out = ArrayList<Any?>()
            for (el in node) {
                val em = asMap(el)
                if (em != null && em.size == 1 && em.containsKey("...")) {
                    val digest = em["..."] as? String ?: throw SdJwtProcessingError("an array '...' entry must reference a string digest")
                    val d = claimDigest(digest, byDigest, seen) ?: continue
                    if (d.parts.size != 2) throw SdJwtProcessingError("an array-element disclosure must be [salt, value]")
                    d.used = true
                    out.add(walk(d.parts[1], false, byDigest, seen, disclosedTop))
                } else {
                    out.add(walk(el, false, byDigest, seen, disclosedTop))
                }
            }
            return out
        }
        if (node is Map<*, *>) {
            val nm = node as Map<String, Any?>
            val out = LinkedHashMap<String, Any?>()
            for (key in nm.keys) if (key != "_sd") out[key] = walk(nm[key], false, byDigest, seen, disclosedTop)
            if (nm.containsKey("_sd")) {
                val sd = nm["_sd"]
                if (sd !is List<*> || sd.any { it !is String }) throw SdJwtProcessingError("_sd must be an array of strings")
                for (digest in sd) {
                    val d = claimDigest(digest as String, byDigest, seen) ?: continue
                    if (d.parts.size != 3) throw SdJwtProcessingError("an object-property disclosure must be [salt, name, value]")
                    val n = d.parts[1] as? String ?: throw SdJwtProcessingError("disclosure claim name must be a string")
                    if (n == "_sd" || n == "...") throw SdJwtProcessingError("disclosure claim name '$n' is reserved")
                    if (out.containsKey(n)) throw SdJwtProcessingError("disclosure claim '$n' collides with an existing claim")
                    if (top && n in CRITICAL_CLAIMS) throw SdJwtProcessingError("'$n' is security-critical and must not be selectively disclosable")
                    d.used = true
                    val value = walk(d.parts[2], false, byDigest, seen, disclosedTop)
                    out[n] = value
                    if (top) disclosedTop[n] = value
                }
            }
            return out
        }
        return node
    }

    private fun failResult(reason: String?): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    private val SECS = Regex(
        "^(\\+|\\-)? ?(\\d+|\\d+\\.\\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$",
        RegexOption.IGNORE_CASE,
    )

    /** The reference library's time-period parser (a clock tolerance given as text, e.g. "10 seconds"). */
    private fun secs(str: String): Double {
        val m = SECS.matchEntire(str)
        val sign = m?.groups?.get(1)?.value
        val suffix = m?.groups?.get(4)?.value
        if (m == null || (suffix != null && sign != null)) throw Jose.JoseException("Invalid time period format")
        val value = m.groupValues[2].toDouble()
        val mult = when (m.groupValues[3].lowercase(Locale.ROOT)) {
            "sec", "secs", "second", "seconds", "s" -> 1.0
            "minute", "minutes", "min", "mins", "m" -> 60.0
            "hour", "hours", "hr", "hrs", "h" -> 3600.0
            "day", "days", "d" -> 86400.0
            "week", "weeks", "w" -> 604800.0
            else -> 31557600.0
        }
        val n = Js.round(value * mult)
        return if (sign == "-" || suffix == "ago") -n else n
    }

    /** The JWT options of an issuer or KB verification ([hasAud]: whether an audience option was given at all, then its value). */
    private fun jwtOptions(options: Map<String, Any?>, hasAud: Boolean, audValue: Any?, algs: List<String>): Jose.JwtOptions {
        val audience: List<String>? = if (!hasAud) null else when {
            audValue is String -> listOf(audValue)
            audValue is List<*> -> audValue.map { it as? String ?: "\u0000not-a-string" }
            !Js.truthy(audValue) -> listOf("") // presence is required, the value is not compared
            else -> listOf("\u0000never") // a truthy non-string, non-list option never matches
        }
        val now: Double? = if (!options.containsKey("now")) null else options["now"].let { nw -> if (nw == null) 0.0 else Js.num(nw) ?: Double.NaN }
        val tol: Double? = if (!options.containsKey("clockToleranceSec")) null else options["clockToleranceSec"].let { t ->
            if (t is String) secs(t) else Js.num(t) ?: throw Jose.JoseException("Invalid clockTolerance option type")
        }
        return Jose.JwtOptions(audience = audience, clockTolerance = tol, currentDateMs = now, algorithms = algs)
    }

    private fun algorithmList(v: Any?, dflt: String): List<String> {
        if (v == null) return listOf(dflt)
        if (v !is List<*> || v.any { it !is String }) throw Jose.JoseException("\"algorithms\" option must be an array of strings")
        return v.map { it as String }
    }

    private fun thumbX(k: Any?): String? = when {
        k is ByteArray -> Jose.b64u(k)
        isJwk(k) -> asMap(k)!!["x"] as? String
        else -> throw Jose.JoseException("Invalid key input")
    }

    /**
     * Verifies a PCA SD-JWT, FAIL-CLOSED. Options: `issuerKey` (public JWK, required), `requiredDisclosures`, `expectedAudience`,
     * `keyBindingKey` (JWK map or raw bytes; requires a KB-JWT bound to it), `expectedKbAudience`, `expectedNonce`, `requireKeyBinding`,
     * `algorithms` (default EdDSA), `kbAlgorithms`, `now` (ms), `kbMaxAgeSec`, `clockToleranceSec`. Returns {ok:true, payload, processed,
     * protectedHeader, disclosed, claims, keyBinding} or {ok:false, reason}.
     */
    @JvmStatic
    fun verifyPcaSdJwt(sdjwt: Any?, options: Map<String, Any?>): Map<String, Any?> = try {
        verifyUnchecked(sdjwt, options)
    } catch (e: RuntimeException) {
        failResult(e.message ?: e.javaClass.simpleName)
    }

    private fun verifyUnchecked(sdjwt: Any?, options: Map<String, Any?>): Map<String, Any?> {
        // a non-finite clock, tolerance or window would slip past the date checks (every comparison with NaN is false, and -Infinity is "before" every expiry)
        if (listOf("now", "clockToleranceSec", "kbMaxAgeSec").any { options.containsKey(it) && Js.num(options[it])?.isFinite() != true }) {
            return failResult("now, clockToleranceSec and kbMaxAgeSec must be finite")
        }
        val parsed = parseSdJwt(sdjwt)
        val algorithms = algorithmList(options["algorithms"], DEFAULT_SIGNING_ALG)
        val issuerKey = asMap(options["issuerKey"]) ?: throw Jose.JoseException("Invalid key input")

        val verified = Jose.jwtVerify(parsed.jwt, publicOnly(issuerKey), jwtOptions(options, options.containsKey("expectedAudience"), options["expectedAudience"], algorithms))
        val payload = verified.payload
        if (payload.containsKey("_sd_alg") && payload["_sd_alg"] != SD_ALG) return failResult("unsupported _sd_alg (require \"$SD_ALG\")")
        val byDigest = LinkedHashMap<String, DecodedDisclosure>()
        for (encoded in parsed.disclosures) {
            val digest = sha256b64u(encoded)
            if (byDigest.containsKey(digest)) return failResult("duplicate disclosure")
            byDigest[digest] = DecodedDisclosure(decodeDisclosureParts(encoded))
        }
        val (processedPayload, disclosed) = try {
            processDisclosures(payload, byDigest)
        } catch (e: SdJwtProcessingError) {
            val msg = e.message!!
            return failResult(if ("not referenced" in msg) "a presented disclosure does not match any _sd digest (tampered)" else msg)
        }

        options["requiredDisclosures"]?.let { req ->
            val names: List<Any?> = when (req) {
                is List<*> -> req
                is String -> req.map { it.toString() }
                else -> throw IllegalArgumentException("requiredDisclosures is not iterable")
            }
            for (required in names) {
                val key = required as? String ?: if (required == null) "null" else Json.canonicalize(required)
                if (!disclosed.containsKey(key)) return failResult("required disclosure '$key' was not presented")
            }
        }

        val cnfJwk = asMap(asMap(payload["cnf"])?.get("jwk"))?.takeIf { isJwk(it) }
        val keyBinding = linkedMapOf<String, Any?>("presented" to (parsed.kbJwt != null), "verified" to false)

        if (parsed.kbJwt != null) {
            if (cnfJwk == null) return failResult("KB-JWT presented but issuer JWT has no cnf key")
            if (options.containsKey("keyBindingKey")) {
                val want = thumbX(options["keyBindingKey"])
                val have = thumbX(cnfJwk)
                if (want == null || have == null || want != have) return failResult("cnf key does not match the expected keyBindingKey")
            }
            if (cnfJwk["kty"] == "oct") {
                return failResult("KB-JWT signature/claims invalid: Key for the EdDSA algorithm must be one of type KeyObject, CryptoKey, or JSON Web Key.")
            }
            val kb = try {
                val kbAud = options["expectedKbAudience"]
                val hasAud = kbAud != null || options.containsKey("expectedAudience")
                Jose.jwtVerify(parsed.kbJwt, publicOnly(cnfJwk), jwtOptions(options, hasAud, kbAud ?: options["expectedAudience"], algorithmList(options["kbAlgorithms"], DEFAULT_SIGNING_ALG)))
            } catch (e: RuntimeException) {
                return failResult("KB-JWT signature/claims invalid: " + e.message)
            }
            if (kb.protectedHeader["typ"] != KB_JWT_TYP) return failResult("KB-JWT typ must be \"$KB_JWT_TYP\"")
            val kbIat = Js.num(kb.payload["iat"]) ?: return failResult("KB-JWT iat is required")
            if (options.containsKey("kbMaxAgeSec")) {
                val nw = options["now"]
                val nowSec = Math.floor((if (nw != null) toNumber(nw) else System.currentTimeMillis().toDouble()) / 1000)
                if (!(nowSec - kbIat <= toNumber(options["kbMaxAgeSec"]))) return failResult("KB-JWT is older than the accepted window")
                val tol = options["clockToleranceSec"]
                if (!(kbIat - nowSec <= (if (tol != null) toNumber(tol) else 0.0))) return failResult("KB-JWT iat is in the future")
            }
            val kbAudClaim = kb.payload["aud"]
            if (kbAudClaim !is String && kbAudClaim !is List<*>) return failResult("KB-JWT aud is required")
            if (sha256b64u(parsed.presentationHead) != kb.payload["sd_hash"]) return failResult("KB-JWT sd_hash does not cover this presentation")
            if (options.containsKey("expectedNonce")) {
                val same = kb.payload.containsKey("nonce") && sameJs(kb.payload["nonce"], options["expectedNonce"])
                if (!same) return failResult("KB-JWT nonce does not match")
            }
            keyBinding["verified"] = true
            if (kbAudClaim is String) keyBinding["aud"] = kbAudClaim
            (kb.payload["nonce"] as? String)?.let { keyBinding["nonce"] = it }
        } else if (options.containsKey("keyBindingKey") || Js.truthy(options["requireKeyBinding"])) {
            return failResult("key binding required but no KB-JWT was presented")
        }

        val claims = processedPayload.filterKeys { it !in RESERVED_CLAIMS }
        return linkedMapOf(
            "ok" to true, "payload" to payload, "processed" to processedPayload, "protectedHeader" to verified.protectedHeader,
            "disclosed" to disclosed, "claims" to LinkedHashMap(claims), "keyBinding" to keyBinding,
        )
    }

    // ---- recovery through the core ----

    /** The outcome of [verifyRecovered]: allow, the reason of the first failed check (or this package's own), the core checks. */
    class RecoveredResult internal constructor(val allow: Boolean, val reason: String?, val checks: Map<String, Boolean>)

    private fun deny(reason: String) = RecoveredResult(false, reason, emptyMap())

    /**
     * Re-verifies a verified SD-JWT with the PCA core: rebuilds the PCActn from the recovered claims and runs the core verification.
     * FAIL-CLOSED: a withheld required claim, missing or inconsistent `iat_ms`/`exp_ms`, or an `iss`/`sub` that disagrees with the chain
     * denies. [grant] is the verifier's OWN stored grant. [audience] follows the core's tri-state: [Pca.Audience.Of] must equal the
     * PCActn's `aud`, [Pca.Audience.Any] is the explicit opt-out, [Pca.Audience.Unset] fails closed. [nowMs] null = now;
     * [insecureSkipPlanRootCheck] is the loud opt-out of the plan-root check.
     */
    @JvmStatic
    @JvmOverloads
    fun verifyRecovered(
        res: Map<String, Any?>,
        grant: Map<String, Any?>?,
        audience: Pca.Audience,
        nowMs: Long? = null,
        insecureSkipPlanRootCheck: Boolean = false,
    ): RecoveredResult {
        val c = asMap(res["claims"])!!
        val p = asMap(res["processed"])!!
        val rest = LinkedHashMap(c)
        val iatMs = rest.remove("iat_ms")
        val expMs = rest.remove("exp_ms")
        val iatD = Js.num(iatMs)
        val expD = Js.num(expMs)
        if (iatD == null || expD == null) return deny("pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn")
        val pIat = Js.num(p["iat"])
        val pExp = Js.num(p["exp"])
        if (pIat == null || Math.floor(iatD / 1000) != pIat) return deny("pca-sdjwt: iat_ms disagrees with iat")
        if (pExp == null || Math.max(Math.ceil(expD / 1000), Math.floor(iatD / 1000) + 1) != pExp) return deny("pca-sdjwt: exp_ms disagrees with exp")
        for (k in listOf("action", "cap_chain", "plan", "sig", "grant_ref", "counter")) {
            if (!rest.containsKey(k)) return deny("pca-sdjwt: required claim '$k' was not disclosed")
        }
        if (p["aud"] !is String) return deny("pca-sdjwt: aud must be a string")
        val chain = rest["cap_chain"] as? List<*>
        if (chain == null || chain.isEmpty()) return deny("pca-sdjwt: cap_chain is empty")
        val first = chain.first() ?: throw IllegalArgumentException("Cannot read properties of null (reading 'issuer')")
        if (!sameJs(p["iss"], asMap(first)?.get("issuer"))) return deny("pca-sdjwt: iss does not match the chain root issuer")
        val last = chain.last() ?: throw IllegalArgumentException("Cannot read properties of null (reading 'holder')")
        if (!sameJs(p["sub"], asMap(last)?.get("holder"))) return deny("pca-sdjwt: sub does not match the chain leaf holder")
        val pcActn = LinkedHashMap<String, Any?>(rest)
        if (p.containsKey("ver")) pcActn["ver"] = p["ver"] else pcActn.remove("ver")
        pcActn["aud"] = p["aud"]
        pcActn["iat"] = iatMs
        pcActn["exp"] = expMs
        if (grant == null) return deny("pca-sdjwt: core verification threw: no grant")
        val v = Pca.verifyPcactn(pcActn, grant, nowMs ?: System.currentTimeMillis(), audience, insecureSkipPlanRootCheck = insecureSkipPlanRootCheck)
        return RecoveredResult(v.allow, v.reason, LinkedHashMap(v.checks))
    }
}
