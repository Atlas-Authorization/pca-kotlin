package net.atlasauth.pca.connectors

import net.atlasauth.pca.verifier.Json

import net.atlasauth.pca.connect.JsText
import net.atlasauth.pca.connect.Refresh.ProviderConfig
import net.atlasauth.pca.connect.Refresh.VaultFetch
import net.atlasauth.pca.connect.Refresh.VaultHttpRequest
import net.atlasauth.pca.connect.Refresh.VaultHttpResponse
import net.atlasauth.pca.connect.StoredConnection
import net.atlasauth.pca.connect.TokenVault
import net.atlasauth.pca.jose.Js
import org.bouncycastle.util.encoders.Base64

/**
 * The token side of a connector: exchange an authorization code (or a refresh token) at a provider's token endpoint and FEED the connection vault,
 * so every stored connection is bound to a PCA capability. A connection minted here is unusable until a verified Proof-Carrying Action proves
 * authority over the provider and that the requested scopes are inside what the capability grants. The vault's own auto-refresh is wired from the
 * same manifests via [manifestToProviderConfig] / [buildVaultProviders]. Calls are synchronous.
 */
object Exchange {
    /** Default access-token lifetime assumed when the provider returns no expires_in. */
    private const val DEFAULT_TOKEN_LIFETIME_MS = 3_600_000.0

    /** How a minted connection is stored and bound to a PCA capability in the vault. */
    class ConnectionBinding {
        lateinit var vault: TokenVault

        /** b64u public key of the agent: the capability chain's LEAF holder this connection belongs to. */
        var agentId: String? = null

        /** Null = the vault's default connection id. */
        var connectionId: String? = null

        /** b64u public key the capability chain must be rooted at. */
        var principal: String? = null

        /** Scopes the capability must cover (null = the requested scopes: least privilege). */
        var authorityScopes: List<String>? = null

        /** When set, the PCActn's signed aud must equal it. */
        var audience: String? = null
    }

    class ExchangeCodeArgs {
        var providerId: String? = null
        var clientId: String? = null

        /** Null for a public client. */
        var clientSecret: String? = null

        /** The authorization code returned to the redirect URI. */
        var code: String? = null
        var redirectUri: String? = null

        /** The PKCE code_verifier used for the authorize request (required when the provider uses PKCE). */
        var codeVerifier: String? = null

        /** Scopes requested (null = the manifest's defaultScopes). */
        var scopes: List<String>? = null
        var fetch: VaultFetch? = null
        lateinit var bind: ConnectionBinding

        /** Clock, epoch ms (null = now). */
        var now: Double? = null

        /** Null = the default registry. */
        var registry: ProviderRegistry? = null
        var vars: Map<String, Any?>? = null
        var extraParams: Map<String, String>? = null
    }

    class RefreshArgs {
        var providerId: String? = null
        var clientId: String? = null
        var clientSecret: String? = null

        /** The refresh token to present (the vault does not expose stored refresh tokens without a PCActn). */
        var refreshToken: String? = null
        var scopes: List<String>? = null
        var fetch: VaultFetch? = null
        lateinit var bind: ConnectionBinding
        var now: Double? = null
        var registry: ProviderRegistry? = null
        var vars: Map<String, Any?>? = null
        var extraParams: Map<String, String>? = null
    }

    /** Per-provider client credentials used to derive a vault [ProviderConfig]. */
    class ProviderCredentials @JvmOverloads constructor(
        var clientId: String? = null,
        var clientSecret: String? = null,
        /** {var} substitutions for the refresh token endpoint. */
        var vars: Map<String, Any?>? = null,
    )

    /** The fields of a token-endpoint success response this package consumes. */
    private class ParsedToken {
        var accessToken: String = ""
        var expiresInSecs: Double? = null
        var refreshToken: String? = null
        var scopes: List<String>? = null
    }

    private fun checkExtraParams(extra: Map<String, String>?, what: String) {
        if (extra != null) for (k in extra.keys) if (k in Manifest.RESERVED_TOKEN_PARAMS) throw ConnectorError("$what: extraParams may not set '$k'")
    }

    /** Standard base64 (padded) of clientId:clientSecret, for HTTP Basic client authentication (RFC 6749 section 2.3.1). */
    internal fun basicAuthHeader(clientId: String, clientSecret: String): String =
        "Basic " + Base64.toBase64String(Json.utf8("$clientId:$clientSecret"))

    /** Parse an OAuth token-endpoint JSON body. Fails closed: a missing or empty access_token is a hard error. */
    private fun parseTokenResponse(body: Any?, provider: String): ParsedToken {
        if (body !is Map<*, *>) throw ConnectorError("[$provider] token endpoint returned a non-object body")
        val at = body["access_token"]
        if (at !is String || at.isEmpty()) throw ConnectorError("[$provider] token endpoint response has no access_token")
        val out = ParsedToken()
        out.accessToken = at
        val ei = Js.num(body["expires_in"])
        if (ei != null && !ei.isNaN() && !ei.isInfinite() && ei > 0) out.expiresInSecs = ei
        val rt = body["refresh_token"]
        if (rt is String && rt.isNotEmpty()) out.refreshToken = rt
        val scope = body["scope"]
        if (scope is String && JsText.trim(scope).isNotEmpty()) out.scopes = JsText.splitRuns(JsText.trim(scope), true)
        return out
    }

    /** POST a form to a token endpoint via the injectable transport and parse the response (fail-closed). */
    private fun postToken(manifest: ProviderManifest, tokenEndpoint: String, params: Map<String, String>, clientSecret: String?, fetchImpl: VaultFetch?): ParsedToken {
        val headers = LinkedHashMap<String, String>()
        headers["content-type"] = "application/x-www-form-urlencoded"
        headers["accept"] = "application/json"
        val body = LinkedHashMap<String, String>(params)
        if ("basic" == manifest.clientAuth) {
            // Client credentials move to the Authorization header; they must not also appear in the body.
            if (clientSecret == null) throw ConnectorError("[${manifest.id}] clientAuth 'basic' requires a clientSecret")
            val clientId = body["client_id"] ?: throw ConnectorError("[${manifest.id}] missing client_id for basic auth")
            headers["authorization"] = basicAuthHeader(clientId, clientSecret)
            body.remove("client_id")
            body.remove("client_secret")
        }

        if (fetchImpl == null) throw ConnectorError("[${manifest.id}] no fetch transport configured")
        val secrets = listOf(clientSecret, params["code"], params["code_verifier"], params["refresh_token"], headers["authorization"])
        val res: VaultHttpResponse = try {
            fetchImpl.call(tokenEndpoint, VaultHttpRequest("POST", headers, JsText.formEncode(body)))
        } catch (e: Exception) {
            throw ConnectorError("[${manifest.id}] token transport error: " + JsText.redact(JsText.errText(e), secrets))
        }
        if (!res.ok()) {
            val detail: String = try {
                val t = res.text()
                JsText.redact(if (t.length > 256) t.substring(0, 256) else t, secrets)
            } catch (e: Exception) {
                "<unreadable body>"
            }
            throw ConnectorError("[${manifest.id}] token endpoint ${res.status()}: $detail")
        }
        val json: Any? = try {
            res.json()
        } catch (e: Exception) {
            // the parser's message quotes the start of the body, which may hold a token
            throw ConnectorError("[${manifest.id}] unparseable token JSON")
        }
        return parseTokenResponse(json, manifest.id)
    }

    /** Store the token result in the vault, bound to the PCA capability authority. */
    private fun storeConnection(manifest: ProviderManifest, parsed: ParsedToken, requested: List<String>, bind: ConnectionBinding, now: Double, priorRefreshToken: String?): StoredConnection {
        val secs = parsed.expiresInSecs
        val expiresAt = if (secs != null) now + secs * 1000 else now + DEFAULT_TOKEN_LIFETIME_MS
        // Scopes the stored token actually carries: the provider's echo wins; else the requested set.
        val granted = parsed.scopes ?: requested
        // Token rotation: keep the prior refresh token unless the provider issued a new one.
        val refreshToken = parsed.refreshToken ?: priorRefreshToken
        val a = TokenVault.PutConnectionArgs()
        a.agentId = bind.agentId
        a.provider = manifest.id
        a.accessToken = parsed.accessToken
        a.expiresAt = expiresAt
        a.scopes = granted
        a.principal = bind.principal
        a.authorityScopes = bind.authorityScopes ?: requested
        a.audience = bind.audience
        a.connectionId = bind.connectionId
        a.refreshToken = refreshToken
        return bind.vault.putConnection(a)
    }

    private fun orUndefined(s: String?): String = s ?: "undefined"

    /**
     * Exchange an authorization code for tokens and store a capability-bound connection in the vault. The requested scopes become the connection's
     * least-privilege authority; the connection is unusable until a verified PCActn proves a capability covering them.
     */
    fun exchangeCode(args: ExchangeCodeArgs): StoredConnection {
        val registry = args.registry ?: ProviderRegistry.defaultRegistry()
        val manifest = registry.require(args.providerId!!)
        val now = args.now ?: System.currentTimeMillis().toDouble()
        val requested = args.scopes ?: manifest.defaultScopes

        val code = args.code
        if (code == null || code.isEmpty()) throw ConnectorError("[${manifest.id}] an authorization code is required")
        checkExtraParams(args.extraParams, "[${manifest.id}] exchangeCode")
        if (manifest.pkce == true && args.codeVerifier == null) {
            throw ConnectorError("[${manifest.id}] provider uses PKCE; a codeVerifier is required to exchange the code")
        }

        val params = LinkedHashMap<String, String>()
        params["grant_type"] = "authorization_code"
        params["code"] = code
        params["redirect_uri"] = orUndefined(args.redirectUri)
        params["client_id"] = orUndefined(args.clientId)
        args.clientSecret?.let { params["client_secret"] = it }
        args.codeVerifier?.let { params["code_verifier"] = it }
        args.extraParams?.let { params.putAll(it) }
        val tokenEndpoint = Authorize.substituteVars(manifest.tokenUrl, args.vars)
        val parsed = postToken(manifest, tokenEndpoint, params, args.clientSecret, args.fetch)
        return storeConnection(manifest, parsed, requested, args.bind, now, null)
    }

    /**
     * Refresh an access token at the provider's refresh endpoint and re-store the capability-bound connection. Throws when the manifest declares
     * `refresh.mode == "none"`. Scope narrowing is sent only when the manifest opts in. The authority binding is preserved from `bind`.
     */
    fun refresh(args: RefreshArgs): StoredConnection {
        val registry = args.registry ?: ProviderRegistry.defaultRegistry()
        val manifest = registry.require(args.providerId!!)
        if ("none" == manifest.refresh.mode) throw ConnectorError("[${manifest.id}] provider does not support token refresh")
        val now = args.now ?: System.currentTimeMillis().toDouble()
        val requested = args.scopes ?: manifest.defaultScopes
        val rt = args.refreshToken
        if (rt == null || rt.isEmpty()) throw ConnectorError("[${manifest.id}] a refresh token is required")
        checkExtraParams(args.extraParams, "[${manifest.id}] refresh")

        val params = LinkedHashMap<String, String>()
        params["grant_type"] = "refresh_token"
        params["refresh_token"] = rt
        params["client_id"] = orUndefined(args.clientId)
        args.clientSecret?.let { params["client_secret"] = it }
        manifest.refresh.extraParams?.let { params.putAll(it) }
        args.extraParams?.let { params.putAll(it) }
        if (manifest.refresh.supportsScopeNarrowing == true && requested.isNotEmpty()) {
            params["scope"] = requested.joinToString(manifest.scopeSeparator ?: " ")
        }
        val tokenEndpoint = Authorize.substituteVars(manifest.refresh.tokenEndpoint ?: manifest.tokenUrl, args.vars)
        val parsed = postToken(manifest, tokenEndpoint, params, args.clientSecret, args.fetch)
        return storeConnection(manifest, parsed, requested, args.bind, now, rt)
    }

    /**
     * Derive the connection vault's [ProviderConfig] (used for its OWN auto-refresh) from a manifest + credentials: the manifest's token
     * endpoint, scope-narrowing flag and extra params flow straight into the vault. Throws when the manifest does not support refresh.
     */
    fun manifestToProviderConfig(manifest: ProviderManifest, creds: ProviderCredentials): ProviderConfig {
        if ("none" == manifest.refresh.mode) {
            throw ConnectorError("[${manifest.id}] provider does not support token refresh; no ProviderConfig")
        }
        val config = ProviderConfig(
            Authorize.substituteVars(manifest.refresh.tokenEndpoint ?: manifest.tokenUrl, creds.vars), orUndefined(creds.clientId),
        )
        if (creds.clientSecret != null) config.clientSecret = creds.clientSecret
        if (manifest.refresh.supportsScopeNarrowing != null) config.supportsScopeNarrowing = manifest.refresh.supportsScopeNarrowing
        manifest.refresh.extraParams?.let { config.extraParams = LinkedHashMap(it) }
        return config
    }

    /**
     * Build the vault's `providers` map (provider id to [ProviderConfig]) from a set of configured providers, skipping any whose manifest
     * cannot refresh. [registry] null means the default registry.
     */
    @JvmOverloads fun buildVaultProviders(credsById: Map<String, ProviderCredentials>, registry: ProviderRegistry? = null): Map<String, ProviderConfig> {
        val reg = registry ?: ProviderRegistry.defaultRegistry()
        val out = LinkedHashMap<String, ProviderConfig>()
        for ((id, creds) in credsById) {
            val manifest = reg.require(id)
            if ("none" == manifest.refresh.mode) continue
            out[id] = manifestToProviderConfig(manifest, creds)
        }
        return out
    }
}
