package net.atlasauth.pca.connectors

import net.atlasauth.pca.verifier.Json

import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.connect.JsText
import net.atlasauth.pca.connect.UrlBits
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.oauth.WhatwgUrl
import net.atlasauth.pca.verifier.Keys

/**
 * The authorization-request side of a connector: turn a declarative [ProviderManifest] into a correct OAuth 2.0 authorize URL (with PKCE
 * when the provider wants it), and describe how the resulting access token is presented on an outbound API call. Options arrive as a parsed-JSON
 * map with the reference's camelCase member names; a null member counts as unset.
 */
@Suppress("UNCHECKED_CAST")
object Authorize {
    private val PKCE_VERIFIER = Regex("[A-Za-z0-9._~-]{43,128}")
    private val VAR = Regex("\\{(\\w+)\\}")
    private val DNS_LABEL = Regex("[A-Za-z0-9][A-Za-z0-9-]{0,62}")
    private const val MIN_STATE_CHARS = 16
    private val RNG = SecureRandom()

    /** The PKCE values used for an authorize request; keep [verifier] to complete the code exchange. */
    class PkceResult internal constructor(val verifier: String, val challenge: String, val method: String) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["verifier"] = verifier
            m["challenge"] = challenge
            m["method"] = method
            return m
        }
    }

    /** A built authorize URL plus the state and (if used) PKCE values the caller must retain for the exchange. */
    class AuthorizeUrl internal constructor(val url: String, val state: String, /** Null when PKCE is not in effect. */ val pkce: PkceResult?) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["url"] = url
            m["state"] = state
            if (pkce != null) m["pkce"] = pkce.toMap()
            return m
        }
    }

    /** 32 bytes of CSPRNG entropy, base64url (unpadded). */
    internal fun randomToken(): String {
        val b = ByteArray(32)
        RNG.nextBytes(b)
        return Keys.b64u(b)
    }

    /** The S256 code challenge for a verifier: base64url(SHA-256(ASCII(verifier))), unpadded (RFC 7636 section 4.2); "plain" returns the verifier. */
    @JvmOverloads fun pkceChallenge(verifier: String, method: String? = "S256"): String {
        if ("plain" == method) return verifier
        return Keys.b64u(MessageDigest.getInstance("SHA-256").digest(Json.utf8(verifier)))
    }

    /** Substitute {var} placeholders in [url]. Throws [ConnectorError] when a used var is not supplied, or is not a single DNS label. */
    fun substituteVars(url: String, vars: Map<String, Any?>?): String {
        val sb = StringBuilder()
        var last = 0
        for (m in VAR.findAll(url)) {
            val name = m.groupValues[1]
            if (vars == null || !vars.containsKey(name)) throw ConnectorError("missing URL variable '{$name}'") // absent variables are an unsupplied variable
            val v = vars[name]
            // A variable is a DNS label (a shop, an account). Anything else could move the request to another host or path:
            // `evil.com/x?` in `https://{shop}.myshopify.com/...` sends the authorization code to evil.com.
            if (v !is String || !DNS_LABEL.matches(v)) {
                throw ConnectorError("URL variable '{$name}' must be a single DNS label (letters, digits and hyphens)")
            }
            sb.append(url, last, m.range.first).append(v)
            last = m.range.last + 1
        }
        sb.append(url, last, url.length)
        return sb.toString()
    }

    private fun str(v: Any?): String = if (v is String) v else Js.template(v)

    private fun encodeForm(params: List<Array<String>>): String {
        val sb = StringBuilder()
        for (kv in params) {
            if (sb.isNotEmpty()) sb.append('&')
            sb.append(JsText.encodeURIComponent(kv[0])).append('=').append(JsText.encodeURIComponent(kv[1]))
        }
        return sb.toString()
    }

    /**
     * Build the OAuth 2.0 authorization-request URL for [providerId]. Always emits response_type=code, client_id, redirect_uri, scope, and
     * state; adds code_challenge + code_challenge_method when PKCE is in effect, and merges the manifest's authParams then the caller's extraParams.
     * Scopes are joined with the manifest's scopeSeparator (default space). [registry] null means the default registry. Options:
     * clientId, redirectUri, scopes, state, pkce (true | false | {verifier, method}), vars, extraParams, allowUnlistedScopes, allowPlainPkce.
     */
    @JvmOverloads fun buildAuthorizeUrl(providerId: String, options: Map<String, Any?>, registry: ProviderRegistry? = null): AuthorizeUrl {
        val reg = registry ?: ProviderRegistry.defaultRegistry()
        val manifest = reg.require(providerId)

        val scopes: Any? = options["scopes"] ?: ArrayList<Any?>(manifest.defaultScopes)
        val separator = manifest.scopeSeparator ?: " "
        val state: Any? = options["state"] ?: randomToken()

        val clientId = options["clientId"]
        if (clientId !is String || clientId.isEmpty()) throw ConnectorError("buildAuthorizeUrl: clientId must be a non-empty string")
        checkRedirectUri(options["redirectUri"])
        if (state !is String || state.length < MIN_STATE_CHARS) {
            throw ConnectorError("buildAuthorizeUrl: state must be at least $MIN_STATE_CHARS characters (omit it to get a random one)")
        }
        checkScopes(manifest, scopes, options["allowUnlistedScopes"] == true)
        val extra = entriesOf(options["extraParams"])
        for (kv in extra) if (kv[0] in Manifest.RESERVED_AUTHORIZE_PARAMS) throw ConnectorError("buildAuthorizeUrl: extraParams may not set '${kv[0]}'")

        val scopeList = (scopes as List<*>).map { it as String }
        val params = ArrayList<Array<String>>()
        params.add(arrayOf("response_type", "code"))
        params.add(arrayOf("client_id", clientId))
        params.add(arrayOf("redirect_uri", str(options["redirectUri"])))
        if (scopeList.isNotEmpty()) params.add(arrayOf("scope", scopeList.joinToString(separator)))
        params.add(arrayOf("state", state))

        // PKCE: on when explicitly requested, when a verifier object is passed, or (unless disabled) when the manifest declares it.
        val pk = options["pkce"]
        val wantPkce = if (pk == false) false else if (pk != null) true else manifest.pkce == true
        var pkce: PkceResult? = null
        if (wantPkce) {
            val verifier: Any? = if (pk is Map<*, *>) pk["verifier"] else randomToken()
            val method: Any? = if (pk is Map<*, *>) (pk["method"] ?: "S256") else "S256"
            if (verifier !is String || !PKCE_VERIFIER.matches(verifier)) {
                throw ConnectorError("buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)")
            }
            if ("S256" != method && !("plain" == method && options["allowPlainPkce"] == true)) {
                throw ConnectorError("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')")
            }
            val challenge = pkceChallenge(verifier, method as String)
            params.add(arrayOf("code_challenge", challenge))
            params.add(arrayOf("code_challenge_method", method))
            pkce = PkceResult(verifier, challenge, method)
        }

        manifest.authParams?.let { for ((k, v) in it) params.add(arrayOf(k, v)) }
        for (kv in extra) params.add(arrayOf(kv[0] as String, str(kv[1])))

        val varsO = options["vars"]
        val base = substituteVars(manifest.authorizeUrl, if (varsO is Map<*, *>) varsO as Map<String, Any?> else null)
        val url = base + (if (base.contains("?")) "&" else "?") + encodeForm(params)
        return AuthorizeUrl(url, state, pkce)
    }

    /** `Object.entries(v)` of a parsed-JSON value: an object's members, an array's indexed items, a string's characters; nothing for a scalar. */
    private fun entriesOf(v: Any?): List<Array<Any?>> {
        val out = ArrayList<Array<Any?>>()
        if (v is Map<*, *>) {
            for ((k, x) in v) out.add(arrayOf(k, x))
        } else if (v is List<*>) {
            for (i in v.indices) out.add(arrayOf(i.toString(), v[i]))
        } else if (v is String) {
            // one entry per UTF-16 code unit, as Object.entries on a string
            for (i in v.indices) out.add(arrayOf(i.toString(), v[i].toString()))
        }
        return out
    }

    private fun checkRedirectUri(uriO: Any?) {
        val uri = str(uriO)
        val u = WhatwgUrl.parse(uri) ?: throw ConnectorError("buildAuthorizeUrl: redirectUri must be an absolute URL")
        if (UrlBits.hasFragment(uri)) throw ConnectorError("buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)")
        if (UrlBits.hasCredentials(uri)) throw ConnectorError("buildAuthorizeUrl: redirectUri must not carry credentials")
        val local = u.host == "localhost" || u.host == "127.0.0.1" || u.host == "[::1]"
        if (u.protocol != "https:" && !(u.protocol == "http:" && local)) throw ConnectorError("buildAuthorizeUrl: redirectUri must be https (http only for localhost)")
    }

    /** Every scope must be one token the manifest lists: a scope containing the separator would smuggle in another one. */
    private fun checkScopes(manifest: ProviderManifest, scopes: Any?, allowUnlisted: Boolean) {
        if (scopes !is List<*>) throw ConnectorError("buildAuthorizeUrl: scopes must be a list")
        val sep = manifest.scopeSeparator ?: " "
        val seen = HashSet<String>()
        for (o in scopes) {
            if (o !is String || o.isEmpty() || JsText.hasSpaceOrComma(o) || o.contains(sep)) {
                throw ConnectorError("buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator")
            }
            if (!seen.add(o)) throw ConnectorError("buildAuthorizeUrl: scope '$o' is listed twice")
            if (!allowUnlisted && manifest.scopesAvailable.isNotEmpty() && o !in manifest.scopesAvailable) {
                throw ConnectorError("buildAuthorizeUrl: scope '$o' is not offered by provider '${manifest.id}'")
            }
        }
    }

    /** Describe how [accessToken] is attached to a provider API call, per the manifest's tokenPlacement: `{kind, name, value}`. */
    fun applyAccessToken(manifest: ProviderManifest, accessToken: Any?): Map<String, Any?> {
        // A control character or space in a token would end the header value (response splitting) or add a header.
        if (accessToken !is String || accessToken.isEmpty() || hasNonPrintable(accessToken)) {
            throw ConnectorError("applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces")
        }
        val out = LinkedHashMap<String, Any?>()
        when (manifest.tokenPlacement) {
            "bearer" -> {
                out["kind"] = "header"
                out["name"] = "Authorization"
                out["value"] = "Bearer $accessToken"
            }
            "header" -> {
                out["kind"] = "header"
                out["name"] = manifest.headerName ?: throw ConnectorError("manifest '${manifest.id}' is header-placed but has no headerName")
                out["value"] = accessToken
            }
            "query" -> {
                out["kind"] = "query"
                out["name"] = manifest.queryParam ?: throw ConnectorError("manifest '${manifest.id}' is query-placed but has no queryParam")
                out["value"] = accessToken
            }
            else -> throw ConnectorError("manifest '${manifest.id}' has an unknown tokenPlacement")
        }
        return out
    }

    private fun hasNonPrintable(s: String): Boolean = s.any { it.code < 0x21 || it.code > 0x7e }
}
