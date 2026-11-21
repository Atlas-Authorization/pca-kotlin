package net.atlasauth.pca.oidc

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.Jws
import net.atlasauth.pca.oauth.Fetch
import net.atlasauth.pca.oauth.WhatwgUrl
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/** The error of any OIDC discovery failure (network, non-2xx, bad JSON, issuer mismatch). */
class OidcDiscoveryError(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * The error of ID-token verification. [code] is one of: config, invalid_token, signature, issuer, audience, expired, issued_at,
 * not_before, nonce, azp, at_hash, c_hash, keys, claims.
 */
class OidcVerificationError(val code: String, message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * A caching JWKS key resolver that FAILS CLOSED on stale or unreachable keys: keys are cached for `cacheMaxAgeSec`; after that they
 * are refetched and, if the refetch fails, verification is REFUSED (a stale key set is never used). A `kid` not in the cached set
 * triggers at most one refetch per `cooldownSec`. Options (reference names): jwksUri, fetch ([Fetch]), cacheMaxAgeSec (600),
 * cooldownSec (30), maxBytes (1 MiB), requireHttps (true), timeoutMs (5000), now (a `() -> Long` of epoch ms).
 */
class OidcJwks(opts: Map<String, Any?>) : Jws.KeyResolver {
    private val jwksUri: String
    private val fetch: Fetch
    private val now: () -> Long
    private val maxAgeMs: Double
    private val cooldownMs: Double
    private val maxBytes: Double
    private val timeoutMs: Double
    private var cache: Jws.KeyResolver? = null
    private var cacheAt = 0L
    private var kids: Set<String> = emptySet()
    private var lastFetch = Double.NEGATIVE_INFINITY

    init {
        val uri = opts["jwksUri"]
        require(uri is String && uri.isNotEmpty()) { "createOidcJwks: jwksUri is required" }
        jwksUri = uri as String
        val rh = opts["requireHttps"]
        require(!((rh == null || Js.truthy(rh)) && !jwksUri.regionMatches(0, "https://", 0, 8, ignoreCase = true))) {
            "createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)"
        }
        fetch = opts["fetch"] as? Fetch ?: Fetch.http()
        @Suppress("UNCHECKED_CAST")
        now = opts["now"] as? () -> Long ?: { System.currentTimeMillis() }
        // A NaN or infinite age / cooldown would make every staleness comparison false and serve one key set forever.
        for (name in listOf("cacheMaxAgeSec", "cooldownSec", "maxBytes", "timeoutMs")) {
            val v = opts[name] ?: continue
            val d = Js.num(v)
            require(d != null && !d.isNaN() && !d.isInfinite() && d >= 0) { "createOidcJwks: $name must be a finite number >= 0" }
        }
        maxAgeMs = num(opts, "cacheMaxAgeSec", 600.0) * 1000
        cooldownMs = num(opts, "cooldownSec", 30.0) * 1000
        maxBytes = num(opts, "maxBytes", 1024.0 * 1024)
        timeoutMs = num(opts, "timeoutMs", DEFAULT_JWKS_TIMEOUT_MS.toDouble())
    }

    private fun num(o: Map<String, Any?>, k: String, dflt: Double): Double = Js.num(o[k]) ?: dflt

    private fun refetch() {
        lastFetch = now().toDouble()
        val jwks: Map<*, *>
        val resolve: Jws.KeyResolver
        try {
            val res = fetch.get(jwksUri, mapOf("accept" to "application/json"), timeoutMs.toLong())
            check(res.ok) { "HTTP ${res.status}" }
            check(Json.utf8(res.text).size <= maxBytes) { "response exceeds $maxBytes bytes" }
            val parsed = Json.parseLenient(res.text)
            check(parsed is Map<*, *> && parsed["keys"] is List<*>) { "not a JWK Set" }
            jwks = parsed as Map<*, *>
            resolve = Jws.localJwks(parsed)
        } catch (e: Exception) {
            throw OidcVerificationError("keys", "could not fetch the issuer signing keys from $jwksUri", e)
        }
        kids = (jwks["keys"] as List<*>).mapNotNull { (it as Map<*, *>)["kid"] as? String }.toSet()
        cache = resolve
        cacheAt = now()
    }

    @Synchronized
    override fun getKey(protectedHeader: Map<String, Any?>): Any? {
        val t = now()
        if (cache == null || t - cacheAt >= maxAgeMs) {
            cache = null // never serve a stale set, even if the refetch below fails
            refetch()
        } else {
            val kid = protectedHeader["kid"]
            if (kid is String && kid !in kids && t - lastFetch >= cooldownMs) refetch()
        }
        return cache!!.getKey(protectedHeader)
    }

    companion object {
        /** Default timeout of one key-set request (5 s). */
        const val DEFAULT_JWKS_TIMEOUT_MS = 5000L
    }
}

/**
 * Root a Proof-Carrying Authority grant in a real OIDC-authenticated human: provider discovery (OpenID Connect Discovery 1.0 section 4),
 * ID-token verification (OpenID Connect Core 3.1.3.7: signature, iss / aud / exp / nbf / iat, nonce, azp, at_hash, c_hash) and the
 * mapping of verified claims onto a PCA principal descriptor. Options use the reference's names; `key` takes a [Jws.KeyResolver], a
 * public key, a [Jws.VerifyKey] or a public JWK map, `fetch` a [Fetch]. A verification failure throws [OidcVerificationError]; a
 * discovery failure [OidcDiscoveryError].
 */
object Oidc {
    const val OIDC_SUBJECT_CAVEAT = "oidc_subject"
    /** Default size cap for a discovery document (1 MiB). */
    const val DEFAULT_MAX_DISCOVERY_BYTES = 1024L * 1024
    const val DEFAULT_JWKS_TIMEOUT_MS = OidcJwks.DEFAULT_JWKS_TIMEOUT_MS
    /** The asymmetric OIDC signing algorithms allowed by default (symmetric algorithms are excluded). */
    val DEFAULT_ID_TOKEN_ALGS: List<String> = listOf("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")

    private const val WELL_KNOWN = "/.well-known/openid-configuration"
    private val systemClock: () -> Long = { System.currentTimeMillis() }

    // ---- discovery ----

    private fun isHttps(u: Any?): Boolean = u is String && WhatwgUrl.parse(u)?.protocol == "https:"

    /** The discovery URL of an issuer: the well-known path appended, one trailing slash of the issuer dropped. */
    fun discoveryUrl(issuer: String): String = issuer.removeSuffix("/") + WELL_KNOWN

    /** Fetch and parse `<issuer>/.well-known/openid-configuration` (opts: fetch, maxBytes, requireHttps). */
    fun discoverOidc(issuer: String?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val o = opts ?: emptyMap()
        if (issuer.isNullOrEmpty()) throw OidcDiscoveryError("discoverOidc: issuer must be a non-empty string")
        val requireHttps = o["requireHttps"] != false
        if (requireHttps && !isHttps(issuer)) throw OidcDiscoveryError("discoverOidc: issuer '$issuer' is not an https URL")
        val fetch = o["fetch"] as? Fetch ?: Fetch.http()
        val url = discoveryUrl(issuer)
        val res = try {
            fetch.get(url, mapOf("accept" to "application/json"), 0)
        } catch (e: Exception) {
            throw OidcDiscoveryError("discoverOidc: fetch of $url failed", e)
        }
        if (!res.ok) throw OidcDiscoveryError("discoverOidc: $url returned HTTP ${res.status}")
        val maxBytes = if (o["maxBytes"] == null) DEFAULT_MAX_DISCOVERY_BYTES.toDouble() else Js.num(o["maxBytes"]) ?: Double.NaN
        val tooBig = "discoverOidc: $url response exceeds ${maxBytes.toLong()} bytes"
        val declared = declaredLength(res.contentLength)
        if (!declared.isNaN() && !declared.isInfinite() && declared > maxBytes) throw OidcDiscoveryError(tooBig)
        if (Json.utf8(res.text).size > maxBytes) throw OidcDiscoveryError(tooBig)
        val body = try {
            Json.parseLenient(res.text)
        } catch (e: RuntimeException) {
            throw OidcDiscoveryError("discoverOidc: $url did not return valid JSON", e)
        }
        val meta = asMetadata(body)
        if (issuer != meta["issuer"]) throw OidcDiscoveryError("discoverOidc: metadata issuer '${meta["issuer"]}' does not match requested '$issuer'")
        if (requireHttps && !isHttps(meta["jwks_uri"])) throw OidcDiscoveryError("discoverOidc: jwks_uri '${meta["jwks_uri"]}' is not an https URL")
        return meta
    }

    /** Number(headers.get('content-length')): null reads as 0, an unparseable value as NaN. */
    private fun declaredLength(v: String?): Double {
        val t = v?.trim() ?: return 0.0
        return if (t.isEmpty()) 0.0 else t.toDoubleOrNull() ?: Double.NaN
    }

    private fun asMetadata(body: Any?): Map<String, Any?> {
        if (body !is Map<*, *>) throw OidcDiscoveryError("discoverOidc: metadata is not a JSON object")
        val issuer = body["issuer"]
        if (!Js.nonEmptyString(issuer)) throw OidcDiscoveryError("discoverOidc: metadata is missing a string \"issuer\"")
        val jwksUri = body["jwks_uri"]
        if (!Js.nonEmptyString(jwksUri)) throw OidcDiscoveryError("discoverOidc: metadata is missing a string \"jwks_uri\"")
        val meta = Js.obj("issuer" to issuer, "jwks_uri" to jwksUri)
        for ((k, v) in body) if (k != "issuer" && k != "jwks_uri") meta[k as String] = v
        return meta
    }

    // ---- JWKS resolver ----

    /** A fail-closed caching JWKS resolver (see [OidcJwks]); pass it as `key`. */
    fun createOidcJwks(opts: Map<String, Any?>): OidcJwks = OidcJwks(opts)

    /** Discover the issuer's jwks_uri (https unless requireHttps is false) and build the resolver. */
    fun createOidcJwksFromIssuer(issuer: String, opts: Map<String, Any?>? = null): OidcJwks {
        val o = opts ?: emptyMap()
        val meta = discoverOidc(issuer, mapOf("requireHttps" to o["requireHttps"], "fetch" to o["fetch"]))
        return OidcJwks(LinkedHashMap(o).also { it["jwksUri"] = meta["jwks_uri"] })
    }

    // ---- ID-token verification ----

    /** Verify an ID token and return its verified claims. [clock] supplies the verification time (epoch ms). */
    fun verifyIdToken(idToken: String?, opts: Map<String, Any?>?, clock: () -> Long = systemClock): Map<String, Any?> {
        if (idToken.isNullOrEmpty()) throw OidcVerificationError("invalid_token", "verifyIdToken: idToken must be a non-empty string")
        if (opts == null) throw OidcVerificationError("config", "verifyIdToken: opts is required")
        val issuer = opts["issuer"]
        if (!Js.nonEmptyString(issuer)) throw OidcVerificationError("config", "verifyIdToken: opts.issuer is required")
        val audience = opts["audience"]
        if (audience !is String && audience !is List<*>) throw OidcVerificationError("config", "verifyIdToken: opts.audience is required")

        // A non-finite skew tolerance would make every expiry comparison pass; a NaN age limit would disable the age check.
        if (opts["clockToleranceSec"] != null) {
            val tol = Js.num(opts["clockToleranceSec"]) ?: Double.NaN
            if (!(tol.isFinite() && tol >= 0)) throw OidcVerificationError("config", "verifyIdToken: clockToleranceSec must be a finite number >= 0")
        }
        if (opts["maxTokenAgeSec"] != null) {
            val age = Js.num(opts["maxTokenAgeSec"]) ?: Double.NaN
            if (!(age >= 0)) throw OidcVerificationError("config", "verifyIdToken: maxTokenAgeSec must be a number >= 0")
        }

        val canon = try {
            Jws.assertCanonicalCompactJws(idToken)
        } catch (cause: RuntimeException) {
            throw OidcVerificationError("invalid_token", cause.message ?: "invalid token")
        }
        val key = resolveKey(opts)
        val algs = when (val ao = opts["algorithms"]) {
            null -> DEFAULT_ID_TOKEN_ALGS
            is List<*> -> ao.map { it as? String ?: throw IllegalArgumentException("\"algorithms\" option must be an array of strings") }
            else -> throw IllegalArgumentException("verifyIdToken: algorithms must be an array")
        }
        val vo = Jws.JwtOptions(issuer = issuer, audience = audience, algorithms = algs, clockTolerance = opts["clockToleranceSec"], maxTokenAge = opts["maxTokenAgeSec"])
        val verified = try {
            Jws.jwtVerify(idToken, canon, key, vo, clock())
        } catch (cause: RuntimeException) {
            throw mapJoseError(cause)
        }
        val claims = projectClaims(verified.payload, opts)
        val alg = canon.header["alg"]
        if (opts["accessToken"] != null) checkHalfHash("at_hash", claims["at_hash"], opts["accessToken"], alg)
        if (opts["code"] != null) checkHalfHash("c_hash", claims["c_hash"], opts["code"], alg)
        return claims
    }

    /** OIDC Core 3.1.3.6: base64url(left half of H(value)), H chosen by the ID token's alg (EdDSA = SHA-512). */
    private fun checkHalfHash(name: String, actual: Any?, value: Any?, alg: Any?) {
        if (actual == null) throw OidcVerificationError(name, "id token is missing the expected $name")
        val bits = when {
            alg == "EdDSA" -> "512"
            alg is String && (alg.endsWith("256") || alg.endsWith("384") || alg.endsWith("512")) -> alg.takeLast(3)
            else -> throw OidcVerificationError(name, "cannot compute $name for alg $alg")
        }
        if (value !is String) throw IllegalArgumentException("verifyIdToken: $name source must be a string")
        val raw = ByteArray(value.length) { value[it].code.toByte() } // 'ascii' encoding keeps the low byte
        val digest = MessageDigest.getInstance("SHA-$bits").digest(raw)
        if (Keys.b64u(digest.copyOf(digest.size / 2)) != actual) throw OidcVerificationError(name, "id token $name does not match the supplied value")
    }

    /** `key` wins, then `jwksUri`, then `discover`; a URI is wrapped in the fail-closed resolver, built per call. */
    private fun resolveKey(opts: Map<String, Any?>): Any {
        opts["key"]?.let { return it }
        val requireHttps = opts["requireHttps"]
        var jwksUri = opts["jwksUri"]
        if (jwksUri == null && opts["discover"] == true) {
            jwksUri = discoverOidc(opts["issuer"] as String, mapOf("requireHttps" to requireHttps, "fetch" to opts["fetch"]))["jwks_uri"]
        }
        if (jwksUri == null) throw OidcVerificationError("config", "verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)")
        return try {
            OidcJwks(mapOf("jwksUri" to jwksUri, "requireHttps" to requireHttps))
        } catch (cause: RuntimeException) {
            throw OidcVerificationError("config", "verifyIdToken: ${cause.message}", cause)
        }
    }

    private fun asString(v: Any?): String? = (v as? String)?.takeIf { it.isNotEmpty() }

    private fun asFiniteNumber(v: Any?): Double? = (if (v is Json.Num || v is Number) Js.num(v) else null)?.takeIf { !it.isNaN() && !it.isInfinite() }

    private fun projectClaims(payload: Map<String, Any?>, opts: Map<String, Any?>): Map<String, Any?> {
        val iss = asString(payload["iss"]) ?: throw OidcVerificationError("issuer", "id token is missing the \"iss\" claim")
        val sub = asString(payload["sub"]) ?: throw OidcVerificationError("claims", "id token is missing the \"sub\" claim")
        val aud = payload["aud"] ?: throw OidcVerificationError("audience", "id token is missing the \"aud\" claim")
        if (asFiniteNumber(payload["iat"]) == null) throw OidcVerificationError("issued_at", "id token is missing a numeric \"iat\" claim")
        if (asFiniteNumber(payload["exp"]) == null) throw OidcVerificationError("expired", "id token is missing a numeric \"exp\" claim")

        val nonce = asString(payload["nonce"])
        val azp = asString(payload["azp"])
        val expectedNonce = opts["nonce"]
        if (expectedNonce != null && expectedNonce != nonce) {
            throw OidcVerificationError("nonce", if (nonce == null) "id token is missing the expected nonce" else "id token nonce does not match the expected value")
        }
        val audCount = (aud as? List<*>)?.size ?: 1
        val expectedAzp = opts["authorizedParty"] ?: opts["audience"] as? String
        if (audCount > 1 && azp == null) throw OidcVerificationError("azp", "id token has multiple audiences but no azp (authorized party)")
        if (azp != null && expectedAzp != null && azp != expectedAzp) throw OidcVerificationError("azp", "id token azp does not match the authorized party")

        val c = Js.obj("iss" to iss, "sub" to sub, "aud" to aud, "iat" to payload["iat"], "exp" to payload["exp"])
        if (nonce != null) c["nonce"] = nonce
        if (azp != null) c["azp"] = azp
        for (k in listOf("at_hash", "c_hash")) if (asString(payload[k]) != null) c[k] = payload[k]
        if (asFiniteNumber(payload["auth_time"]) != null) c["auth_time"] = payload["auth_time"]
        if (asString(payload["email"]) != null) c["email"] = payload["email"]
        if (payload["email_verified"] is Boolean) c["email_verified"] = payload["email_verified"]
        for (k in listOf("name", "preferred_username", "given_name", "family_name", "picture")) if (asString(payload[k]) != null) c[k] = payload[k]
        (payload["cnf"] as? Map<*, *>)?.let { cnf -> c["cnf"] = LinkedHashMap<String, Any?>().also { m -> for ((k, v) in cnf) m[k as String] = v } }
        return c
    }

    private fun mapJoseError(e: RuntimeException): OidcVerificationError {
        if (e is OidcVerificationError) return e
        if (e !is Jws.JoseException) return OidcVerificationError("invalid_token", "id token verification failed", e)
        return when (e.kind) {
            "expired" -> if (e.claim == "iat") OidcVerificationError("issued_at", "id token is older than the maximum accepted age", e)
            else OidcVerificationError("expired", "id token has expired", e)
            "claim" -> OidcVerificationError(
                when (e.claim) { "iss" -> "issuer"; "aud" -> "audience"; "iat" -> "issued_at"; "nbf" -> "not_before"; else -> "claims" },
                e.message ?: "claim check failed", e,
            )
            "signature" -> OidcVerificationError("signature", "id token signature verification failed", e)
            else -> OidcVerificationError("invalid_token", e.message ?: "invalid token", e)
        }
    }

    // ---- principal ----

    /** Map verified OIDC claims onto a PCA principal descriptor. Throws on a missing iss / sub or a bad key. */
    fun oidcPrincipal(claims: Map<String, Any?>, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val iss = claims["iss"]
        val sub = claims["sub"]
        require(Js.nonEmptyString(iss)) { "oidcPrincipal: claims.iss is required" }
        require(Js.nonEmptyString(sub)) { "oidcPrincipal: claims.sub is required" }
        val fromToken = ed25519PublicFromCnf(claims["cnf"])
        var principalPublic = fromToken
        if (opts != null && opts.containsKey("principalPublic")) {
            val provided = canonicalEd25519B64u(opts["principalPublic"]) ?: throw IllegalArgumentException("oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key")
            check(fromToken == null || fromToken == provided) { "oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token" }
            principalPublic = provided
        }
        val p = Js.obj(
            "iss" to iss, "sub" to sub, "principalId" to "$iss#$sub",
            "subjectCaveat" to Js.obj("type" to OIDC_SUBJECT_CAVEAT, "iss" to iss, "sub" to sub), "claims" to claims,
        )
        if (principalPublic != null) p["principalPublic"] = principalPublic
        for ((from, to) in listOf("email" to "email", "email_verified" to "emailVerified", "name" to "name", "preferred_username" to "preferredUsername", "auth_time" to "authTime")) {
            if (claims.containsKey(from)) p[to] = claims[from]
        }
        return p
    }

    /** Narrowing guard for an oidc_subject caveat. */
    fun isOidcSubjectCaveat(cv: Any?): Boolean =
        cv is Map<*, *> && cv["type"] == OIDC_SUBJECT_CAVEAT && Js.nonEmptyString(cv["iss"]) && Js.nonEmptyString(cv["sub"])

    private fun ed25519PublicFromCnf(cnf: Any?): String? {
        val j = Js.get(cnf, "jwk") as? Map<*, *> ?: return null
        if (j["kty"] != "OKP" || j["crv"] != "Ed25519" || j["x"] !is String) return null
        return canonicalEd25519B64u(j["x"])
    }

    /** [s] iff it is the canonical, unpadded base64url of exactly 32 bytes; else null. */
    private fun canonicalEd25519B64u(s: Any?): String? = if (Js.nonEmptyString(s) && Pca.decodeB64uStrict(s, 32) != null) s as String else null
}
