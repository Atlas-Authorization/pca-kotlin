package net.atlasauth.pca.connect

/** Base class for every typed refusal the outbound token vault raises. Branch on [code]; the codes are stable. */
open class VaultError internal constructor(
    /** One of not_authorized, scope_exceeded, expired_no_refresh, refresh_failed, unknown_connection, store_error, unknown_action, unconfirmed_action, request_mismatch, bearer_release_disabled, proxy_failed. */
    val code: String,
    /** The reference's error class name (e.g. NotAuthorizedError). */
    val errorName: String,
    message: String,
) : RuntimeException(message) {
    constructor(code: String, message: String) : this(code, "VaultError", message)

    /** The PCActn is not a valid, provider-bound authorization for this connection. */
    class NotAuthorizedError @JvmOverloads constructor(
        message: String,
        /** The verifier's per-check verdict map, when the refusal came from PCActn verification (else null). */
        val checks: Map<String, Boolean>? = null,
    ) : VaultError("not_authorized", "NotAuthorizedError", message)

    /** The requested scopes are not a subset of what the capability chain grants. */
    class ScopeExceededError(
        val provider: String,
        val requested: List<String>,
        val granted: List<String>,
        val missing: List<String>,
    ) : VaultError(
        "scope_exceeded", "ScopeExceededError",
        "requested scopes exceed the capability's grant for '$provider': not granted [" + missing.joinToString(", ") + "]",
    )

    /** The access token is stale and there is no refresh token. */
    class ExpiredNoRefreshError(val provider: String, val connectionId: String) : VaultError(
        "expired_no_refresh", "ExpiredNoRefreshError", "connection '$provider/$connectionId' token is expired and has no refresh token",
    )

    /** A refresh was attempted but the provider token endpoint call did not yield a usable token. */
    class RefreshFailedError @JvmOverloads constructor(
        val provider: String,
        detail: String,
        /** HTTP status when the failure was a non-2xx response, else null. */
        val status: Int? = null,
    ) : VaultError("refresh_failed", "RefreshFailedError", "refresh for '$provider' failed: $detail")

    /** No stored connection for this agent + provider + connectionId. */
    class UnknownConnectionError(val agentId: String, val provider: String, val connectionId: String) : VaultError(
        "unknown_connection", "UnknownConnectionError", "no connection for agent '$agentId' provider '$provider' id '$connectionId'",
    )

    /** The connection store or its encryption failed. The message never carries the underlying error text. */
    class StoreError @JvmOverloads constructor(message: String = "the connection store failed") : VaultError("store_error", "StoreError", message)

    /** The action definition for the PCActn's verb is unknown, so no scope can be derived. */
    class UnknownActionError(verb: String) : VaultError(
        "unknown_action", "UnknownActionError", "no pinned action definition for verb '$verb': refusing to release a credential",
    )

    /** The action definition has no valid signed confirmation: unconfirmed means maximally dangerous. */
    class UnconfirmedActionError(verb: String) : VaultError(
        "unconfirmed_action", "UnconfirmedActionError", "the definition of '$verb' has no valid signed confirmation: refusing to release a credential",
    )

    /** The outbound request does not re-derive the signed params digest. */
    class RequestMismatchError(message: String) : VaultError("request_mismatch", "RequestMismatchError", message)

    /** A bare bearer token was requested without the explicit insecure opt-in. */
    class BearerReleaseDisabledError : VaultError(
        "bearer_release_disabled", "BearerReleaseDisabledError",
        "this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)",
    )

    /** The proxied call failed after the action was spent. */
    class ProxyFailedError(message: String) : VaultError("proxy_failed", "ProxyFailedError", message)
}
