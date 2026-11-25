package net.atlasauth.pca.idjag

import java.net.URLEncoder
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.Jws
import net.atlasauth.pca.oidc.Oidc
import net.atlasauth.pca.oidc.OidcVerificationError
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Keys

/**
 * The error of ID-JAG verification. [code]: the OIDC codes (config, invalid_token, signature, issuer, audience, expired, issued_at,
 * not_before, nonce, azp, at_hash, c_hash, keys, claims) plus actor, scope and grant.
 */
class IdJagVerificationError(val code: String, message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** The single-use check of an ID-JAG's jti: return `true` for a fresh one; anything else (or a throw) refuses the grant. */
fun interface JtiStore {
    fun consume(jti: String, expSec: Double): Any?
}

/**
 * An ID-JAG / OAuth Cross-App-Access bridge for Proof-Carrying Authority (draft-ietf-oauth-identity-assertion-authz-grant): verify an
 * ID-JAG (reusing the OIDC verifier for every crypto and registered-claim check), project it onto a PCA principal and a signed root
 * capability, and build the RFC 8693 token-exchange and RFC 7523 jwt-bearer requests of the flow. Options use the reference's names;
 * `key` / `fetch` take the same objects as [Oidc], `consumeJti` a [JtiStore].
 */
object IdJag {
    /** Upper bound on an accepted ID-JAG string (adversarial-size guard, checked before any parsing). */
    const val MAX_ID_JAG_CHARS = 16384
    const val IDJAG_AUTHORITY_CAVEAT = "idjag_authority"
    const val IDJAG_PROVENANCE_CAVEAT = "idjag_provenance"
    const val GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    const val GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    const val TOKEN_TYPE_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
    const val TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    const val TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    const val TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
    const val CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    private val systemClock: () -> Long = { System.currentTimeMillis() }

    private fun err(code: String, msg: String, cause: Throwable? = null): Nothing = throw IdJagVerificationError(code, msg, cause)

    // ---- verification ----

    /** Verify an ID-JAG and return the parsed grant; fails closed with an [IdJagVerificationError]. [clock]: verification time (epoch ms). */
    fun verifyIdJag(jwt: String?, opts: Map<String, Any?>?, clock: () -> Long = systemClock): Map<String, Any?> {
        if (jwt.isNullOrEmpty()) err("invalid_token", "verifyIdJag: jwt must be a non-empty string")
        if (jwt.length > MAX_ID_JAG_CHARS) err("invalid_token", "verifyIdJag: jwt exceeds the size limit")
        if (opts == null) err("config", "verifyIdJag: opts is required")
        if (!Js.nonEmptyString(opts["issuer"])) err("config", "verifyIdJag: opts.issuer is required")
        val audience = opts["audience"] as? String
        if (audience.isNullOrEmpty()) err("config", "verifyIdJag: opts.audience is required (ID-JAG is single-audience)")

        val strict = opts["strictDraft"] != false
        val store = opts["consumeJti"] as? JtiStore
        if (strict && store == null) err("config", "verifyIdJag: strictDraft requires opts.consumeJti (single-use store)")
        if (strict && !Js.nonEmptyString(opts["clientId"])) err("config", "verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)")

        val o = Js.obj("issuer" to opts["issuer"], "audience" to audience)
        for (k in listOf("nonce", "clockToleranceSec", "maxTokenAgeSec", "algorithms", "key", "jwksUri", "discover", "fetch")) if (opts[k] != null) o[k] = opts[k]
        val base = try {
            Oidc.verifyIdToken(jwt, o, clock)
        } catch (cause: OidcVerificationError) {
            err(cause.code, cause.message ?: "ID-JAG verification failed", cause)
        } catch (cause: RuntimeException) {
            err("invalid_token", "ID-JAG verification failed", cause)
        }

        // ID-JAG is SINGLE-AUDIENCE: the resource app must be the sole aud.
        val audList = base["aud"] as? List<*> ?: listOf(base["aud"])
        if (audList.size != 1 || audience != audList[0]) err("audience", "ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)")

        val canon = try {
            Jws.assertCanonicalCompactJws(jwt)
        } catch (cause: RuntimeException) {
            err("invalid_token", "ID-JAG payload could not be decoded", cause)
        }
        val raw = canon.payload
        val actor = asActor(raw["act"]) ?: err("actor", "ID-JAG is missing a well-formed \"act\" (agent) claim with a string \"sub\"")
        val scopes = parseScopes(raw["scope"], raw["scopes"]) ?: err("scope", "ID-JAG is missing the \"scope\" (or \"scopes\") claim")
        (opts["requiredScopes"] as? List<*>)?.let { req ->
            val have = scopes.toSet()
            for (r in req) if (r !in have) err("scope", "ID-JAG does not grant the required scope \"$r\"")
        }
        val jti = (raw["jti"] as? String)?.takeIf { it.isNotEmpty() }

        if (strict) {
            if (canon.header["typ"] != "oauth-id-jag+jwt") err("grant", "ID-JAG header typ must be \"oauth-id-jag+jwt\"")
            val cid = raw["client_id"]
            if (!Js.nonEmptyString(cid)) err("grant", "ID-JAG is missing \"client_id\"")
            if (cid != opts["clientId"]) err("grant", "ID-JAG client_id does not match the expected client")
            if (jti == null) err("grant", "ID-JAG is missing \"jti\"")
            val fresh = try { store!!.consume(jti, Js.num(base["exp"]) ?: Double.NaN) == true } catch (e: Exception) { false }
            if (!fresh) err("grant", "ID-JAG jti was already used or the single-use store failed")
        }

        val g = Js.obj(
            "iss" to base["iss"], "sub" to base["sub"], "actor" to actor, "agent" to actor["sub"], "audience" to audience,
            "scopes" to scopes, "iat" to base["iat"], "exp" to base["exp"],
        )
        if (jti != null) g["jti"] = jti
        if (base.containsKey("nonce")) g["nonce"] = base["nonce"]
        if (base.containsKey("cnf")) g["cnf"] = base["cnf"]
        g["oidcClaims"] = base
        return g
    }

    private fun asActor(v: Any?): Map<String, Any?>? {
        if (v !is Map<*, *>) return null
        val sub = v["sub"]
        if (!Js.nonEmptyString(sub)) return null
        return LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = x; out["sub"] = sub }
    }

    private fun strings(l: List<*>): List<Any?> = l.filter { Js.nonEmptyString(it) }

    /** s.split(/\s+/) without the empty entries: the JavaScript whitespace set separates. */
    private fun splitWords(s: String): List<Any?> {
        val out = ArrayList<Any?>()
        val cur = StringBuilder()
        for (c in s) {
            if (AttestUtil.isJsSpace(c.code)) {
                if (cur.isNotEmpty()) { out.add(cur.toString()); cur.setLength(0) }
            } else cur.append(c)
        }
        if (cur.isNotEmpty()) out.add(cur.toString())
        return out
    }

    /** The delegated authority from the scope (space-delimited string or array) / scopes claim. */
    private fun parseScopes(scope: Any?, scopes: Any?): List<Any?>? = when {
        scope is String -> splitWords(scope)
        scope is List<*> -> strings(scope)
        scopes is List<*> -> strings(scopes)
        else -> null
    }

    // ---- ID-JAG -> PCA principal / capability ----

    /** The PCA principal descriptor of a verified ID-JAG (delegates to the OIDC mapping over the grant's base claims). */
    @Suppress("UNCHECKED_CAST")
    fun idJagToPcaPrincipal(grant: Map<String, Any?>?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        requireNotNull(grant) { "idJagToPcaPrincipal: grant is required" }
        val claims = grant["oidcClaims"] as? Map<String, Any?> ?: throw IllegalArgumentException("idJagToPcaPrincipal: grant has no claims")
        return Oidc.oidcPrincipal(claims, opts)
    }

    /**
     * Project a verified ID-JAG onto a signed PCA ROOT capability (authority = the grant's scopes, holder = the agent key, subject =
     * the human, plus provenance). Options: principalSecret (the 32-byte Ed25519 seed, ByteArray), principalPublic (b64u, must be that
     * seed's public key: a mismatch is refused here rather than signed), holder (b64u), extraCaveats, suite (a [Keys.SuiteKey] signing the
     * root instead of the Ed25519 key). Returns {capability, principal, scopes}.
     */
    fun idJagToCapability(grant: Map<String, Any?>?, opts: Map<String, Any?>?): Map<String, Any?> {
        requireNotNull(grant) { "idJagToCapability: grant is required" }
        requireNotNull(opts) { "idJagToCapability: opts is required" }
        val secret = opts["principalSecret"] as? ByteArray ?: throw IllegalArgumentException("idJagToCapability: opts.principalSecret must be a byte array")
        require(Js.nonEmptyString(opts["principalPublic"])) { "idJagToCapability: opts.principalPublic is required" }
        require(Js.nonEmptyString(opts["holder"])) { "idJagToCapability: opts.holder (the agent key) is required" }

        val principal = idJagToPcaPrincipal(grant, mapOf("principalPublic" to opts["principalPublic"]))
        val authority = Js.obj("type" to IDJAG_AUTHORITY_CAVEAT, "scopes" to ArrayList(Js.list(grant["scopes"])), "aud" to grant["audience"])
        val provenance = Js.obj(
            "type" to IDJAG_PROVENANCE_CAVEAT, "iss" to grant["iss"], "sub" to grant["sub"], "agent" to grant["agent"],
            "aud" to grant["audience"], "iat" to grant["iat"], "exp" to grant["exp"],
        ).also { if (grant["jti"] != null) it["jti"] = grant["jti"] }
        val caveats = arrayListOf<Any?>(authority, provenance, principal["subjectCaveat"])
        opts["extraCaveats"]?.let { extra ->
            if (extra !is List<*>) throw IllegalArgumentException("idJagToCapability: opts.extraCaveats must be an array")
            caveats.addAll(extra)
        }
        val key = Keys.edFromSeed(secret)
        require(key.id() == opts["principalPublic"]) { "idJagToCapability: opts.principalSecret does not match opts.principalPublic" }
        val suite = opts["suite"] as? Keys.SuiteKey ?: Keys.ed25519(key)
        val capability = Issue.mintRoot(suite, opts["holder"] as String, null, caveats)
        return Js.obj("capability" to capability, "principal" to principal, "scopes" to ArrayList(Js.list(grant["scopes"])))
    }

    fun isIdJagAuthorityCaveat(cv: Any?): Boolean =
        cv is Map<*, *> && cv["type"] == IDJAG_AUTHORITY_CAVEAT && Js.allStrings(cv["scopes"]) && Js.nonEmptyString(cv["aud"])

    fun isIdJagProvenanceCaveat(cv: Any?): Boolean =
        cv is Map<*, *> && cv["type"] == IDJAG_PROVENANCE_CAVEAT && cv["iss"] is String && cv["sub"] is String && cv["agent"] is String &&
            cv["aud"] is String && Js.isNumber(cv["iat"]) && Js.isNumber(cv["exp"])

    private fun firstCaveat(cap: Any?, type: String): Any? {
        val cv = (cap as? Map<*, *>)?.get("caveats") ?: return null
        if (cv !is List<*>) throw IllegalStateException("cap?.caveats?.find is not a function") // optional chaining stops only at null / undefined
        return cv.firstOrNull { it is Map<*, *> && it["type"] == type }
    }

    /** The authority caveat of a root capability, or null when absent or malformed. */
    fun readIdJagAuthority(cap: Any?): Any? = firstCaveat(cap, IDJAG_AUTHORITY_CAVEAT)?.takeIf { isIdJagAuthorityCaveat(it) }

    /** The provenance caveat of a root capability, or null when absent or malformed. */
    fun readIdJagProvenance(cap: Any?): Any? = firstCaveat(cap, IDJAG_PROVENANCE_CAVEAT)?.takeIf { isIdJagProvenanceCaveat(it) }

    // ---- XAA flow: token-exchange and jwt-bearer request shapes ----

    /** application/x-www-form-urlencoded serialization (URLSearchParams): a lone surrogate becomes U+FFFD first. */
    private fun formEncode(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { sb.append(c).append(s[i + 1]); i += 2; continue }
            sb.append(if (Character.isSurrogate(c)) '�' else c)
            i++
        }
        return URLEncoder.encode(sb.toString(), "UTF-8")
    }

    private fun formRequest(url: String, params: Map<String, Any?>): Map<String, Any?> {
        val clean = Js.obj()
        for ((k, v) in params) if (Js.nonEmptyString(v)) clean[k] = v
        val body = clean.entries.joinToString("&") { formEncode(it.key) + "=" + formEncode(it.value as String) }
        return Js.obj(
            "url" to url, "method" to "POST",
            "headers" to Js.obj("content-type" to "application/x-www-form-urlencoded", "accept" to "application/json"),
            "params" to clean, "body" to body,
        )
    }

    /** A scope string or array as the space-delimited OAuth scope, or null when empty. */
    private fun scopeParam(scope: Any?): String? {
        val parts = when (scope) {
            null -> return null
            is List<*> -> strings(scope)
            is String -> splitWords(scope)
            else -> throw IllegalArgumentException("scopeParam: scope must be a string or an array")
        }
        return if (parts.isEmpty()) null else parts.joinToString(" ")
    }

    private fun putExtra(p: MutableMap<String, Any?>, extra: Any?) {
        if (extra is Map<*, *>) for ((k, v) in extra) p[k as String] = v
    }

    /** The RFC 8693 token-exchange request that OBTAINS an ID-JAG from the IdP (the first XAA leg). */
    fun tokenExchangeRequest(opts: Map<String, Any?>?): Map<String, Any?> {
        requireNotNull(opts) { "tokenExchangeRequest: opts is required" }
        require(Js.nonEmptyString(opts["tokenEndpoint"])) { "tokenExchangeRequest: opts.tokenEndpoint is required" }
        require(Js.nonEmptyString(opts["subjectToken"])) { "tokenExchangeRequest: opts.subjectToken is required" }
        val p = Js.obj(
            "grant_type" to GRANT_TYPE_TOKEN_EXCHANGE, "subject_token" to opts["subjectToken"],
            "subject_token_type" to (opts["subjectTokenType"] ?: TOKEN_TYPE_ID_TOKEN),
            "requested_token_type" to (opts["requestedTokenType"] ?: TOKEN_TYPE_ID_JAG),
        )
        if (opts["audience"] != null) p["audience"] = opts["audience"]
        if (opts["resource"] != null) p["resource"] = opts["resource"]
        scopeParam(opts["scope"])?.let { p["scope"] = it }
        if (Js.nonEmptyString(opts["actorToken"])) {
            p["actor_token"] = opts["actorToken"]
            p["actor_token_type"] = opts["actorTokenType"] ?: TOKEN_TYPE_JWT
        }
        if (opts["clientId"] != null) p["client_id"] = opts["clientId"]
        putExtra(p, opts["extra"])
        return formRequest(opts["tokenEndpoint"] as String, p)
    }

    /** The RFC 7523 jwt-bearer representation and request that REDEEMS an ID-JAG at the resource app's token endpoint (the second XAA leg). */
    fun jwtBearerAssertion(opts: Map<String, Any?>?): Map<String, Any?> {
        requireNotNull(opts) { "jwtBearerAssertion: opts is required" }
        require(Js.nonEmptyString(opts["tokenEndpoint"])) { "jwtBearerAssertion: opts.tokenEndpoint is required" }
        require(Js.nonEmptyString(opts["assertion"])) { "jwtBearerAssertion: opts.assertion is required" }
        val scope = scopeParam(opts["scope"])
        val p = Js.obj("grant_type" to GRANT_TYPE_JWT_BEARER, "assertion" to opts["assertion"])
        if (scope != null) p["scope"] = scope
        if (opts["clientId"] != null) p["client_id"] = opts["clientId"]
        if (Js.nonEmptyString(opts["clientAssertion"])) {
            p["client_assertion_type"] = CLIENT_ASSERTION_TYPE_JWT_BEARER
            p["client_assertion"] = opts["clientAssertion"]
        }
        putExtra(p, opts["extra"])
        val request = formRequest(opts["tokenEndpoint"] as String, p)
        return Js.obj("grantType" to GRANT_TYPE_JWT_BEARER, "assertion" to opts["assertion"]).also {
            if (scope != null) it["scope"] = scope
            it["request"] = request
        }
    }
}
