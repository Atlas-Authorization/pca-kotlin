package net.atlasauth.pca.connect

import net.atlasauth.pca.connect.VaultError.RefreshFailedError
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json

/** The token-refresh side of the outbound vault: one refresh-token grant against a provider's token endpoint. */
object Refresh {
    /** Per-provider OAuth token-endpoint configuration used to refresh an access token. */
    class ProviderConfig @JvmOverloads constructor(var tokenEndpoint: String? = null, var clientId: String? = null) {
        /** Null for public clients / PKCE. */
        var clientSecret: String? = null

        /** Null = unset. When true a narrowed `scope` is sent on refresh. */
        var supportsScopeNarrowing: Boolean? = null

        /** Extra static form parameters (null = none). */
        var extraParams: Map<String, String>? = null

        /** The config as the reference's plain object. */
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["tokenEndpoint"] = tokenEndpoint
            m["clientId"] = clientId
            if (clientSecret != null) m["clientSecret"] = clientSecret
            if (supportsScopeNarrowing != null) m["supportsScopeNarrowing"] = supportsScopeNarrowing
            if (extraParams != null) m["extraParams"] = LinkedHashMap<String, Any?>(extraParams!!)
            return m
        }
    }

    /** A minimal structural view of an HTTP response. */
    interface VaultHttpResponse {
        fun ok(): Boolean
        fun status(): Int

        /** The parsed JSON body (Map, List, String, Boolean, Json.Num, null); throws when it does not parse. */
        fun json(): Any?
        fun text(): String
    }

    class VaultHttpRequest(val method: String, val headers: Map<String, String>, val body: String)

    /** The injectable transport. In production wrap OkHttp; in tests pass a scripted one. */
    fun interface VaultFetch {
        fun call(url: String, init: VaultHttpRequest): VaultHttpResponse
    }

    /** The fields [refreshConnection] hands back for the vault to apply. */
    class Refreshed {
        var accessToken: String = ""
        var refreshToken: String? = null
        var expiresAt: Double = 0.0
        var scopes: List<String> = ArrayList()
    }

    /** What [refreshConnection] needs. */
    class Args {
        lateinit var connection: StoredConnection

        /** Null when the provider has no configuration. */
        var config: ProviderConfig? = null
        var refreshToken: String = ""
        var requested: List<String> = ArrayList()

        /** Null when no transport is configured. */
        var fetch: VaultFetch? = null
        var now: Double = 0.0
        var defaultTokenLifetimeMs: Double = 0.0
    }

    private class TokenResponse {
        var accessToken: String = ""
        var expiresInSecs: Double? = null
        var refreshToken: String? = null
        var scopes: List<String>? = null
    }

    private fun parseTokenResponse(body: Any?, provider: String): TokenResponse {
        if (body !is Map<*, *>) throw RefreshFailedError(provider, "token endpoint returned a non-object body")
        val at = body["access_token"]
        if (at !is String || at.isEmpty()) throw RefreshFailedError(provider, "token endpoint response has no access_token")
        val out = TokenResponse()
        out.accessToken = at
        val ei = Js.num(body["expires_in"])
        if (ei != null && !ei.isNaN() && !ei.isInfinite() && ei > 0) out.expiresInSecs = ei
        val rt = body["refresh_token"]
        if (rt is String && rt.isNotEmpty()) out.refreshToken = rt
        val scope = body["scope"]
        if (scope is String && JsText.trim(scope).isNotEmpty()) out.scopes = JsText.splitRuns(JsText.trim(scope), false)
        return out
    }

    /**
     * Epoch-ms expiry claimed by a JWT access token (decodeJwt semantics: three dot-separated parts, a non-empty payload that is a JSON
     * object); null for an opaque token or a non-finite / non-number `exp`.
     */
    fun jwtExpiryMs(accessToken: String): Double? = try {
        val parts = accessToken.split('.')
        if (parts.size != 3 || parts[1].isEmpty()) null
        else {
            val raw = JsText.b64uDecode(parts[1])
            val payload = Json.parseLenient(String(raw, Charsets.UTF_8))
            if (payload !is Map<*, *>) null
            else {
                val exp = Js.num(payload["exp"])
                if (exp != null && !exp.isNaN() && !exp.isInfinite()) exp * 1000 else null
            }
        }
    } catch (e: RuntimeException) {
        null
    }

    /**
     * Refresh [Args.connection]'s access token at its provider's token endpoint with the stored refresh token. When the provider supports
     * scope narrowing the requested scopes are sent so the new token is no wider. Returns the fields to apply; throws
     * [RefreshFailedError] on any transport or parse failure.
     */
    fun refreshConnection(args: Args): Refreshed {
        val provider = args.connection.provider
        val secrets = ArrayList<String?>()
        secrets.add(args.refreshToken)
        secrets.add(args.connection.accessToken)
        val config = args.config
        if (config != null) {
            secrets.add(config.clientSecret)
            config.extraParams?.let { secrets.addAll(it.values) }
        }
        if (config == null) throw RefreshFailedError(provider, "no provider token-endpoint config")
        val fetch = args.fetch ?: throw RefreshFailedError(provider, "no fetch transport configured")

        val params = LinkedHashMap<String, String>()
        params["grant_type"] = "refresh_token"
        params["refresh_token"] = args.refreshToken
        params["client_id"] = config.clientId!!
        if (config.clientSecret != null) params["client_secret"] = config.clientSecret!!
        config.extraParams?.let { params.putAll(it) }
        val narrow = config.supportsScopeNarrowing == true && args.requested.isNotEmpty()
        if (narrow) params["scope"] = args.requested.joinToString(" ")

        val headers = LinkedHashMap<String, String>()
        headers["content-type"] = "application/x-www-form-urlencoded"
        headers["accept"] = "application/json"
        val res: VaultHttpResponse = try {
            fetch.call(config.tokenEndpoint!!, VaultHttpRequest("POST", headers, JsText.formEncode(params)))
        } catch (e: Exception) {
            throw RefreshFailedError(provider, "transport error: " + JsText.redact(JsText.errText(e), secrets))
        }
        if (!res.ok()) {
            val detail: String = try {
                val t = res.text()
                JsText.redact(if (t.length > 256) t.substring(0, 256) else t, secrets)
            } catch (e: Exception) {
                "<unreadable body>"
            }
            throw RefreshFailedError(provider, "token endpoint " + res.status() + ": " + detail, res.status())
        }
        val json: Any? = try {
            res.json()
        } catch (e: Exception) {
            // the parser's message quotes the start of the body, which may hold a token: say nothing of it
            throw RefreshFailedError(provider, "unparseable JSON body")
        }
        val parsed = parseTokenResponse(json, provider)

        val out = Refreshed()
        out.accessToken = parsed.accessToken
        val secs = parsed.expiresInSecs
        if (secs != null) out.expiresAt = args.now + secs * 1000
        else out.expiresAt = jwtExpiryMs(parsed.accessToken) ?: (args.now + args.defaultTokenLifetimeMs)
        out.scopes = parsed.scopes ?: if (narrow) ArrayList(args.requested) else ArrayList(args.connection.scopes)
        out.refreshToken = parsed.refreshToken ?: args.refreshToken
        return out
    }
}
