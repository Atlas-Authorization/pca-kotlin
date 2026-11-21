package net.atlasauth.pca.connect

import net.atlasauth.pca.verifier.Json

import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.ConcurrentHashMap
import net.atlasauth.pca.connect.Proxy.ProxyFetch
import net.atlasauth.pca.connect.Proxy.ProxyRequest
import net.atlasauth.pca.connect.Proxy.ProxyResponse
import net.atlasauth.pca.connect.Refresh.ProviderConfig
import net.atlasauth.pca.connect.Refresh.VaultFetch
import net.atlasauth.pca.connect.VaultError.BearerReleaseDisabledError
import net.atlasauth.pca.connect.VaultError.ExpiredNoRefreshError
import net.atlasauth.pca.connect.VaultError.NotAuthorizedError
import net.atlasauth.pca.connect.VaultError.ProxyFailedError
import net.atlasauth.pca.connect.VaultError.RequestMismatchError
import net.atlasauth.pca.connect.VaultError.ScopeExceededError
import net.atlasauth.pca.connect.VaultError.StoreError
import net.atlasauth.pca.connect.VaultError.UnconfirmedActionError
import net.atlasauth.pca.connect.VaultError.UnknownActionError
import net.atlasauth.pca.connect.VaultError.UnknownConnectionError
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaCore

/**
 * An outbound connection/token vault for PCA agents. It holds an agent's third-party OAuth tokens and releases a FRESH access token only when
 * a verified Proof-Carrying Action proves least-privilege authority over the requested provider + scopes, or (proxy mode) makes the outbound
 * call itself so the agent never holds the credential. PCActns are parsed JSON trees (Json.parse); calls are synchronous.
 */
@Suppress("UNCHECKED_CAST")
class TokenVault(o: Options) {
    /** The pinned definition of one action: where the scopes a credential may carry come from. */
    class VaultAction {
        /** The verb a PCActn must carry for this action. */
        var verb: String? = null

        /** Digest of the definition this mapping was written for (informational). */
        var defDigest: String? = null

        /** True iff the definition carries a valid signed confirmation. Unconfirmed: nothing is released. */
        var confirmed: Boolean = false
        var provider: String? = null

        /** The minimum scopes the action needs (release is exactly these, and they must be inside the grant and the stored connection). */
        var scopesMin: List<String>? = ArrayList()

        /** Proxy mode: map the outbound request back to the action's parameters ([Proxy.httpExtractor]); null when none. */
        var extract: ((ProxyRequest) -> Map<String, Any?>)? = null
    }

    fun interface Actions { fun resolve(verb: String): VaultAction? }

    /** Revocation source: true refuses the action; a throw refuses it too (fail closed). */
    fun interface IsRevoked { fun test(pcActn: Map<String, Any?>): Boolean }

    class Receipts {
        var secretKey: net.atlasauth.pca.verifier.Keys.EdKey? = null

        /** Receives every signed receipt; null = none. A failing sink never fails the call. */
        var sink: ((Map<String, Any?>) -> Unit)? = null
    }

    /** Vault options; unset members keep the reference defaults. */
    class Options {
        var store: ConnectionStore? = null
        var providers: MutableMap<String, ProviderConfig> = LinkedHashMap()
        var fetch: VaultFetch? = null

        /** Clock, epoch ms. */
        var now: () -> Long = { System.currentTimeMillis() }

        /** This vault's resource-server id, compared to each PCActn's signed aud. Null accepts any audience. A connection's own audience overrides it. */
        var audience: String? = null

        /** Verifier-side issuer to pq_pk pins (b64u). */
        var pqPins: Map<String, String>? = null

        /** The Merkle plan roots the principal authorized; required unless [insecureSkipPlanRootCheck]. */
        var authorizedPlanRoots: List<String>? = null
        var insecureSkipPlanRootCheck: Boolean = false
        var expiryLeewayMs: Double = 30_000.0
        var defaultConnectionId: String = "default"
        var requireActionBinding: Boolean = true
        var resourceFor: (String, String) -> String = { provider, _ -> "oauth:$provider" }

        /** The action.verb a PCActn must carry; null skips the verb check. */
        var useVerb: String? = "use_connection"
        var defaultTokenLifetimeMs: Double = 300_000.0

        /** One-time-use store for presented actions (a captured action cannot be replayed to the vault). */
        var replay: Authorize.StateStore? = null
        var isRevoked: IsRevoked? = null

        /** Production profile (default on): requires an encrypting store, replay, isRevoked and an audience. */
        var strict: Boolean = true
        var actions: Actions? = null

        /** DOCUMENTED INSECURE opt-in: without it getConnectionToken throws bearer_release_disabled. */
        var insecureBearerRelease: Boolean = false
        var proxyFetch: ProxyFetch? = null
        var proxyHeaders: List<String> = Proxy.DEFAULT_PROXY_HEADERS
        var maxProxyResponseBytes: Long = 4L * 1024 * 1024
        var receipts: Receipts? = null
    }

    class ConnectionToken {
        var provider: String = ""
        var connectionId: String = ""
        var accessToken: String = ""
        var scopes: List<String> = ArrayList()
        var expiresAt: Double = 0.0

        /** True when the token was just refreshed at the provider. */
        var refreshed: Boolean = false

        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["provider"] = provider
            m["connectionId"] = connectionId
            m["accessToken"] = accessToken
            m["scopes"] = ArrayList<Any?>(scopes)
            m["expiresAt"] = Js.jsNum(expiresAt)
            m["refreshed"] = refreshed
            return m
        }
    }

    class GetConnectionTokenArgs @JvmOverloads constructor(
        var provider: String,
        var connectionId: String? = null,
        /** Null = default to the connection's bound authority scopes (or the action's scopes_min). */
        var scopes: List<String>? = null,
    )

    class ProxyCallArgs @JvmOverloads constructor(var provider: String, var connectionId: String? = null, var scopes: List<String>? = null)

    class ProxyResult {
        var response: ProxyResponse = ProxyResponse()

        /** Present when the vault was constructed with receipts, else null. */
        var receipt: Map<String, Any?>? = null
    }

    class PutConnectionArgs {
        var agentId: String? = null
        var provider: String? = null
        var connectionId: String? = null
        var accessToken: String? = null
        var refreshToken: String? = null
        var expiresAt: Double = 0.0
        var scopes: List<String>? = null

        /** The binding: principal, optional scopes (default: [scopes]) and optional audience. */
        var principal: String? = null
        var authorityScopes: List<String>? = null
        var audience: String? = null
    }

    private val store: ConnectionStore
    private val providers: Map<String, ProviderConfig> = o.providers
    private val fetchImpl: VaultFetch? = o.fetch
    private val now: () -> Long = o.now
    private val audience: String? = o.audience
    private val expiryLeewayMs: Double = o.expiryLeewayMs
    private val pqPins: Map<String, Any?>? = o.pqPins?.let { LinkedHashMap<String, Any?>(it) }
    private val authorizedPlanRoots: List<String>? = o.authorizedPlanRoots
    private val insecureSkipPlanRootCheck: Boolean = o.insecureSkipPlanRootCheck
    private val defaultConnectionId: String = o.defaultConnectionId
    private val requireActionBinding: Boolean = o.requireActionBinding
    private val resourceFor: (String, String) -> String = o.resourceFor
    private val useVerb: String? = o.useVerb
    private val defaultTokenLifetimeMs: Double = o.defaultTokenLifetimeMs
    private val replay: Authorize.StateStore? = o.replay
    private val isRevoked: IsRevoked? = o.isRevoked
    private val actions: Actions? = o.actions
    private val insecureBearerRelease: Boolean = o.insecureBearerRelease
    private val proxyFetch: ProxyFetch? = o.proxyFetch
    private val proxyHeaders: List<String> = o.proxyHeaders.map { it.lowercase(Locale.ROOT) }
    private val maxProxyResponseBytes: Long = o.maxProxyResponseBytes
    private val receipts: Receipts? = o.receipts

    /** In-flight refreshes by connection, so two callers never spend one single-use refresh token twice. */
    private val inflight = ConcurrentHashMap<String, CompletableFuture<Refresh.Refreshed>>()

    init {
        val st = o.store
        if (o.strict) {
            val missing = ArrayList<String>()
            if (st == null || !st.encrypted()) missing.add("an encrypting store")
            if (o.replay == null) missing.add("replay")
            if (o.isRevoked == null) missing.add("isRevoked")
            if (o.audience == null || o.audience!!.isEmpty()) missing.add("audience")
            if (missing.isNotEmpty()) throw IllegalArgumentException("TokenVault strict mode requires " + missing.joinToString(", "))
        } else if (st == null) {
            throw IllegalArgumentException("TokenVault requires a store")
        }
        store = st!!
    }

    private fun nonEmpty(k: String, v: String?) {
        if (v == null || v.isEmpty()) throw IllegalArgumentException("putConnection: $k must be a non-empty string")
    }

    /** Store (or replace) an agent's connection. The authority descriptor binds which capability may use it. */
    fun putConnection(args: PutConnectionArgs): StoredConnection {
        val connectionId = args.connectionId ?: defaultConnectionId
        nonEmpty("agentId", args.agentId)
        nonEmpty("provider", args.provider)
        nonEmpty("connectionId", connectionId)
        nonEmpty("accessToken", args.accessToken)
        nonEmpty("principal", args.principal)
        if (args.expiresAt.isNaN() || args.expiresAt.isInfinite()) throw IllegalArgumentException("putConnection: expiresAt must be a finite number")
        if (args.refreshToken != null && args.refreshToken!!.isEmpty()) throw IllegalArgumentException("putConnection: refreshToken must be a non-empty string when given")
        val scopes = args.scopes ?: throw IllegalArgumentException("putConnection: scopes must be a list of strings")
        val c = StoredConnection()
        c.agentId = args.agentId!!
        c.provider = args.provider!!
        c.connectionId = connectionId
        c.accessToken = args.accessToken!!
        c.expiresAt = args.expiresAt
        c.scopes = ArrayList(scopes)
        c.authority.provider = args.provider
        c.authority.principal = args.principal
        c.authority.scopes = ArrayList(args.authorityScopes ?: scopes)
        c.authority.audience = args.audience
        c.createdAt = now().toDouble()
        c.useCount = 0
        c.refreshToken = args.refreshToken
        storeSet(c)
        return c
    }

    /**
     * Resolve a FRESH access token iff (a) [pcActn] verifies against the connection's bound principal and (b) the capability chain's grant
     * covers the requested provider + scopes. Refreshes a stale token when a refresh token is present. INSECURE BY NATURE: the caller receives a
     * bearer credential, so this is disabled unless the vault was built with `insecureBearerRelease`; prefer [proxyCall].
     */
    fun getConnectionToken(pcActn: Map<String, Any?>, args: GetConnectionTokenArgs): ConnectionToken {
        if (!insecureBearerRelease) throw BearerReleaseDisabledError()
        val a = authorize(pcActn, args.provider, args.connectionId, args.scopes, false, null)
        val f = freshToken(a)
        val done = recordUse(a, f.token)
        issueReceipt(pcActn, a, "bearer", null, null, "released", done.scopes)
        val out = ConnectionToken()
        out.provider = a.provider
        out.connectionId = a.connectionId
        out.accessToken = done.accessToken
        out.scopes = ArrayList(done.scopes)
        val exp = Js.num(pcActn["exp"])
        out.expiresAt = if (a.action != null && exp != null && !exp.isNaN() && !exp.isInfinite()) Math.min(done.expiresAt, exp) else done.expiresAt
        out.refreshed = f.refreshed
        return out
    }

    /**
     * Proxy mode. The vault makes the outbound call itself: verify the PCActn and the pinned, CONFIRMED action; derive the scopes from the action;
     * map [request] back to the action's parameters and require paramsDigest to equal the PCActn's signed params_digest; spend the action
     * (replay guard); attach the token; make the call without following redirects; sign a receipt linking the release to the effect.
     */
    fun proxyCall(pcActn: Map<String, Any?>, request: ProxyRequest, args: ProxyCallArgs): ProxyResult {
        if (actions == null) throw IllegalArgumentException("proxyCall requires the vault to be constructed with `actions`")
        val pf = proxyFetch ?: throw IllegalArgumentException("proxyCall requires the vault to be constructed with `proxyFetch`")
        val sendHeaders = Proxy.checkProxyHeaders(request.headers, proxyHeaders) // before anything is spent
        val a = authorize(pcActn, args.provider, args.connectionId, args.scopes, true, request)
        val f = freshToken(a)
        val done = recordUse(a, f.token)
        val headers = LinkedHashMap<String, String>(sendHeaders)
        headers["authorization"] = "Bearer " + done.accessToken
        val reqDigest = Proxy.outboundRequestDigest(request.method, request.url, sendHeaders, request.body)
        val response: ProxyResponse
        try {
            response = pf.call(request.method!!, request.url!!, headers, request.body)
        } catch (e: Exception) {
            issueReceipt(pcActn, a, "proxy", reqDigest, null, "failed", done.scopes)
            throw ProxyFailedError("the outbound call failed before a response")
        }
        val rb = response.body
        val size = if (rb == null) Long.MAX_VALUE else Json.utf8(rb).size.toLong()
        val receipt = issueReceipt(pcActn, a, "proxy", reqDigest, response.status, "executed", done.scopes)
        if (size > maxProxyResponseBytes) throw ProxyFailedError("the response is larger than maxProxyResponseBytes (the call was made and the action is spent)")
        // the credential must never travel back: a response header or body that echoes it is redacted
        val body = (rb ?: "").replace(done.accessToken, "[redacted]")
        val rh = LinkedHashMap<String, String>()
        response.headers?.let { hs ->
            for ((k, v) in hs) if (k.lowercase(Locale.ROOT) != "set-cookie") rh[k] = v.toString().replace(done.accessToken, "[redacted]")
        }
        val r = ProxyResult()
        r.response = ProxyResponse(response.status, rh, body)
        r.receipt = receipt
        return r
    }

    private class Authz(
        val agentId: String,
        val provider: String,
        val connectionId: String,
        val connection: StoredConnection,
        val requested: List<String>,
        val now: Long,
        val action: VaultAction?,
    )

    private fun authorize(pcActn: Map<String, Any?>, provider: String, connIdArg: String?, scopesArg: List<String>?, needAction: Boolean, request: ProxyRequest?): Authz {
        val connectionId = connIdArg ?: defaultConnectionId

        val chainO = pcActn["cap_chain"]
        if (chainO !is List<*> || chainO.isEmpty()) throw NotAuthorizedError("PCActn has no capability chain")
        val chain = chainO as List<Any?>
        val leafO = chain[chain.size - 1]
        val rootO = chain[0]
        if (leafO == null || rootO == null) throw NotAuthorizedError("PCActn capability chain is malformed")
        // a hop that is not an object has no holder (undefined): the connection lookup then names agent 'undefined', as the reference's does
        // (and a holder of another type is named by its text form)
        val agentId: String = if (leafO is Map<*, *> && leafO.containsKey("holder")) net.atlasauth.pca.jose.Js.template(leafO["holder"]) else "undefined"

        // 1. Resolve the connection: it carries the trust anchor (bound principal), so it is looked up before verification is anchored.
        val connection = storeGet(ConnectionStore.Key(agentId, provider, connectionId)) ?: throw UnknownConnectionError(agentId, provider, connectionId)

        val root = rootO as? Map<String, Any?> ?: throw NotAuthorizedError("PCActn capability chain is malformed")

        // 2. Anchor + verify. The chain must be rooted at the connection's bound principal, else a self-minted chain would verify against itself.
        if (connection.authority.principal != root["issuer"]) throw NotAuthorizedError("capability chain is not rooted at the connection's bound principal")
        val nowMs = now()
        val aud = connection.authority.audience ?: audience
        // The root comes from the presented artifact, so a non-ed25519 root verifies ONLY under a pin for its issuer (grantFromArtifact).
        // A null audience is the deliberate opt-out ("accept any"), reported as not enforced.
        val co = PcaCore.Options(root)
        co.grantFromArtifact = true
        co.pqPins = pqPins
        co.audience = if (aud == null) Pca.Audience.Any else Pca.Audience.Of(aud)
        co.nowEpoch = nowMs
        co.authorizedPlanRoots = authorizedPlanRoots
        co.insecureSkipPlanRootCheck = insecureSkipPlanRootCheck
        val verdict = PcaCore.verify(pcActn, co)
        if (!verdict.allow) {
            val checks = LinkedHashMap<String, Boolean>()
            for ((k, v) in verdict.checks) checks[k] = PcaCore.FAIL != v
            val why = verdict.reason
            throw NotAuthorizedError("PCActn verification failed: " + (if (why == null || why.isEmpty()) "rejected" else why), checks)
        }

        // 2b. Revocation. No source configured means no check (opt in; strict makes it mandatory).
        val rev = isRevoked
        if (rev != null) {
            val revoked = try {
                rev.test(pcActn)
            } catch (e: Exception) {
                throw NotAuthorizedError("revocation source unavailable")
            }
            if (revoked) throw NotAuthorizedError("the capability chain is revoked")
        }

        val actionO = pcActn["action"]
        val pAction: Map<String, Any?> = if (actionO is Map<*, *>) actionO as Map<String, Any?> else emptyMap()

        // 3. Bind the action.
        var action: VaultAction? = null
        val acts = actions
        if (acts != null) {
            val verbO = pAction["verb"]
            val verb = if (verbO is String) verbO else verbO.toString()
            try {
                action = acts.resolve(verb)
            } catch (e: VaultError) {
                throw e
            } catch (e: Exception) {
                throw StoreError()
            }
            if (action == null || verb != action.verb) throw UnknownActionError(verb)
            if (!action.confirmed) throw UnconfirmedActionError(verb)
            if (provider != action.provider) throw NotAuthorizedError("the action '$verb' is not for provider '$provider'")
            val sm = action.scopesMin
            if (sm == null || sm.isEmpty()) throw NotAuthorizedError("the action '$verb' declares no upstream scopes (nothing to release)")
        } else if (needAction) {
            throw UnknownActionError(pAction["verb"].toString())
        } else if (requireActionBinding) {
            val expectedResource = resourceFor(provider, connectionId)
            if (expectedResource != pAction["resource"]) {
                throw NotAuthorizedError("PCActn action resource '${pAction["resource"]}' is not for this connection (expected '$expectedResource')")
            }
            if (useVerb != null && useVerb != pAction["verb"]) {
                throw NotAuthorizedError("PCActn action verb '${pAction["verb"]}' is not a connection-use verb (expected '$useVerb')")
            }
        }

        // 4. Authority coverage. null => the capability grants nothing for this provider.
        val granted = Authority.grantedOAuthScopes(chain, provider) ?: throw NotAuthorizedError("capability grants no authority for provider '$provider'")

        // 5. Least-privilege.
        val requested: List<String>
        if (action != null) {
            val min = ArrayList(action.scopesMin!!)
            requested = scopesArg ?: min
            val beyond = requested.filter { it !in min }
            if (beyond.isNotEmpty()) throw ScopeExceededError(provider, requested, min, beyond)
            val unheld = min.filter { it !in connection.scopes || it !in connection.authority.scopes }
            if (unheld.isNotEmpty()) throw ScopeExceededError(provider, min, connection.scopes, unheld)
            // a bare bearer token cannot be narrowed after issue: it may carry nothing beyond the action's scopes (use a connection per action)
            if (!needAction) {
                val extra = connection.scopes.filter { it !in min }
                if (extra.isNotEmpty()) throw ScopeExceededError(provider, min, connection.scopes, extra)
            }
            val ungranted = min.filter { it !in granted }
            if (ungranted.isNotEmpty()) throw ScopeExceededError(provider, min, ArrayList(granted), ungranted)
        } else {
            requested = scopesArg ?: connection.authority.scopes
        }
        val missing = requested.filter { it !in granted }
        if (missing.isNotEmpty()) throw ScopeExceededError(provider, requested, ArrayList(granted), missing)

        // 5a. Proxy mode: the outbound request must re-derive EXACTLY the params the PCActn signed.
        if (needAction && action != null) {
            val ex = action.extract
            if (request == null || ex == null) throw RequestMismatchError("the action has no request extractor: proxy mode cannot bind the outbound request")
            val params = try {
                ex(request)
            } catch (e: RequestMismatchError) {
                throw e
            } catch (e: RuntimeException) {
                throw RequestMismatchError("the outbound request could not be mapped to the action parameters")
            }
            val d = try {
                Pca.paramsDigest(params)
            } catch (e: RuntimeException) {
                throw RequestMismatchError("the outbound request parameters are not canonical")
            }
            if (d != pAction["params_digest"]) throw RequestMismatchError("the outbound request does not carry the parameters the PCActn signed")
        }

        // 5b. One-time use, last of the authorization checks so a refused request does not burn the action.
        val rp = replay
        if (rp != null) {
            val pa = pcActn["aud"]
            val rv = ReplayGuard.guard(rp, pcActn, pa as? String, nowMs)
            if (!rv.ok) throw NotAuthorizedError("replay guard refused the action: " + rv.reason)
        }
        return Authz(agentId, provider, connectionId, connection, requested, nowMs, action)
    }

    private class Fresh(val token: StoredConnection, val refreshed: Boolean)

    /** Step 6: refresh a stale token, else use it as is. A token whose expiry is not a finite number can never be shown fresh. */
    private fun freshToken(a: Authz): Fresh {
        val connection = a.connection
        if (connection.expiresAt.isNaN() || connection.expiresAt.isInfinite() || !a.now.toDouble().isFinite() || !expiryLeewayMs.isFinite() || connection.expiresAt - a.now <= expiryLeewayMs) {
            val rt = connection.refreshToken ?: throw ExpiredNoRefreshError(a.provider, a.connectionId)
            val flightKey = a.agentId + "\u0000" + a.provider + "\u0000" + a.connectionId
            val mine = CompletableFuture<Refresh.Refreshed>()
            val flight = inflight.putIfAbsent(flightKey, mine)
            val updated: Refresh.Refreshed
            if (flight == null) {
                try {
                    val ra = Refresh.Args()
                    ra.connection = connection
                    ra.config = providers[a.provider]
                    ra.refreshToken = rt
                    ra.requested = a.requested
                    ra.fetch = fetchImpl
                    ra.now = a.now.toDouble()
                    ra.defaultTokenLifetimeMs = defaultTokenLifetimeMs
                    updated = Refresh.refreshConnection(ra)
                    mine.complete(updated)
                } catch (e: RuntimeException) {
                    mine.completeExceptionally(e)
                    throw e
                } finally {
                    inflight.remove(flightKey, mine)
                }
            } else {
                try {
                    updated = flight.join()
                } catch (e: CompletionException) {
                    val cause = e.cause
                    if (cause is RuntimeException) throw cause
                    throw e
                }
            }
            val t = connection.copy()
            t.accessToken = updated.accessToken
            t.refreshToken = updated.refreshToken
            t.expiresAt = updated.expiresAt
            t.scopes = ArrayList(updated.scopes)
            return Fresh(t, true)
        }
        return Fresh(connection, false)
    }

    /** Step 7: record usage and persist. */
    private fun recordUse(a: Authz, token: StoredConnection): StoredConnection {
        val t = token.copy()
        t.lastUsedAt = a.now.toDouble()
        t.useCount = token.useCount + 1
        storeSet(t)
        return t
    }

    private fun issueReceipt(pcActn: Map<String, Any?>, a: Authz, mode: String, requestDigest: String?, httpStatus: Int?, outcome: String, scopes: List<String>): Map<String, Any?>? {
        val rc = receipts ?: return null
        val sorted = ArrayList(scopes)
        sorted.sort()
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Js.n(1)
        body["kind"] = "pca-release-receipt"
        body["action_digest"] = Proxy.receiptActionDigest(pcActn)
        body["provider"] = a.provider
        body["connection_id"] = a.connectionId
        body["mode"] = mode
        body["scopes_released"] = ArrayList<Any?>(sorted)
        body["request_digest"] = requestDigest
        body["http_status"] = if (httpStatus == null) null else Js.n(httpStatus.toLong())
        body["outcome"] = outcome
        body["ts"] = Js.n(a.now)
        val receipt = Proxy.signReleaseReceipt(body, rc.secretKey!!)
        try {
            rc.sink?.invoke(receipt)
        } catch (e: RuntimeException) {
            // a failing sink must not turn a made call into an error the caller retries; the receipt is still returned
        }
        return receipt
    }

    /** Remove a stored connection. */
    fun deleteConnection(agentId: String, provider: String, connectionId: String?) {
        try {
            store.delete(ConnectionStore.Key(agentId, provider, connectionId ?: defaultConnectionId))
        } catch (e: VaultError) {
            throw e
        } catch (e: Exception) {
            throw StoreError()
        }
    }

    // The store's own error text is never passed on: it can quote a connection string or a record.
    private fun storeGet(key: ConnectionStore.Key): StoredConnection? = try {
        store.get(key)
    } catch (e: VaultError) {
        throw e
    } catch (e: Exception) {
        throw StoreError()
    }

    private fun storeSet(c: StoredConnection) {
        try {
            store.set(c)
        } catch (e: VaultError) {
            throw e
        } catch (e: Exception) {
            throw StoreError()
        }
    }
}
