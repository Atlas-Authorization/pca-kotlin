package net.atlasauth.pca.connectors

/**
 * The declarative unit of the connector catalog: pure data (no secrets) naming a SaaS provider's OAuth 2.0 endpoints, the scopes it offers,
 * how its access token is presented, and how it refreshes. Build one only through [Manifest.assertManifest] (it validates).
 */
class ProviderManifest {
    /** The refresh contract: how a stale access token is renewed. */
    class RefreshSpec {
        /** "refresh_token" (standard refresh grant) or "none" (static / long-lived tokens). */
        var mode: String = ""

        /** Token endpoint for refresh (null = the manifest's tokenUrl). */
        var tokenEndpoint: String? = null

        /** Null = unset; true sends a narrowed scope on refresh. */
        var supportsScopeNarrowing: Boolean? = null

        /** Extra static form parameters (null = none). */
        var extraParams: Map<String, String>? = null
    }

    /** Stable, lowercase, globally-unique registry id. */
    var id: String = ""
    var displayName: String = ""

    /** May carry {var} placeholders (see [requiredVars]). */
    var authorizeUrl: String = ""
    var tokenUrl: String = ""
    var scopesAvailable: List<String> = ArrayList()
    var defaultScopes: List<String> = ArrayList()
    var refresh: RefreshSpec = RefreshSpec()

    /** "bearer", "header" or "query". */
    var tokenPlacement: String = ""

    /** Null = unset. */
    var pkce: Boolean? = null

    /** Scope delimiter in the authorize request (null = a space). */
    var scopeSeparator: String? = null
    var authParams: Map<String, String>? = null

    /** "post" (default when null) or "basic". */
    var clientAuth: String? = null
    var headerName: String? = null
    var queryParam: String? = null
    var requiredVars: List<String>? = null
    var docsUrl: String? = null

    /** The manifest as the reference's plain object: members that are unset are absent. */
    fun toMap(): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["mode"] = refresh.mode
        refresh.tokenEndpoint?.let { r["tokenEndpoint"] = it }
        refresh.supportsScopeNarrowing?.let { r["supportsScopeNarrowing"] = it }
        refresh.extraParams?.let { r["extraParams"] = LinkedHashMap<String, Any?>(it) }
        val m = LinkedHashMap<String, Any?>()
        m["id"] = id
        m["displayName"] = displayName
        m["authorizeUrl"] = authorizeUrl
        m["tokenUrl"] = tokenUrl
        m["scopesAvailable"] = ArrayList<Any?>(scopesAvailable)
        m["defaultScopes"] = ArrayList<Any?>(defaultScopes)
        m["refresh"] = r
        m["tokenPlacement"] = tokenPlacement
        pkce?.let { m["pkce"] = it }
        scopeSeparator?.let { m["scopeSeparator"] = it }
        authParams?.let { m["authParams"] = LinkedHashMap<String, Any?>(it) }
        clientAuth?.let { m["clientAuth"] = it }
        headerName?.let { m["headerName"] = it }
        queryParam?.let { m["queryParam"] = it }
        requiredVars?.let { m["requiredVars"] = ArrayList<Any?>(it) }
        docsUrl?.let { m["docsUrl"] = it }
        return m
    }
}
