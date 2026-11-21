package net.atlasauth.pca.connect

/**
 * The capability caveat that grants outbound OAuth authority. It is pure data inside the signed capability body, so it is
 * attenuable: a delegation hop may add a narrower `oauth_scope` for the same provider, which can only shrink the
 * effective grant (intersection), never widen it.
 */
object Authority {
    const val OAUTH_SCOPE_CAVEAT = "oauth_scope"

    /** An `oauth_scope` caveat granting [scopes] on [provider]; duplicate scopes are collapsed (first occurrence kept). */
    fun oauthScopeCaveat(provider: String, scopes: List<String>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["type"] = OAUTH_SCOPE_CAVEAT
        m["provider"] = provider
        m["scopes"] = ArrayList<Any?>(LinkedHashSet(scopes))
        return m
    }

    private fun isStringArray(v: Any?): Boolean = v is List<*> && v.all { it is String }

    fun isOAuthScopeCaveat(cv: Any?): Boolean {
        if (cv !is Map<*, *>) return false
        if (!cv.containsKey("type") || !cv.containsKey("provider") || !cv.containsKey("scopes")) return false
        return OAUTH_SCOPE_CAVEAT == cv["type"] && cv["provider"] is String && isStringArray(cv["scopes"])
    }

    /**
     * The effective OAuth scopes a verified capability chain grants for [provider]: the intersection of every `oauth_scope` caveat
     * naming it in the chain's leaf. Null when the chain grants nothing for the provider. Run the chain verification first.
     */
    fun grantedOAuthScopes(chain: Any?, provider: String): Set<String>? {
        if (chain !is List<*> || chain.isEmpty()) return null
        val leaf = chain[chain.size - 1] ?: throw NullPointerException("capability chain leaf is null") // the reference reads leaf.caveats and throws a TypeError
        if (leaf !is Map<*, *> || leaf["caveats"] !is List<*>) return null
        var effective: Set<String>? = null
        for (cv in leaf["caveats"] as List<*>) {
            if (!isOAuthScopeCaveat(cv) || provider != (cv as Map<*, *>)["provider"]) continue
            val here = LinkedHashSet<String>()
            for (s in cv["scopes"] as List<*>) here.add(s as String)
            val eff = effective
            effective = if (eff == null) here else eff.filterTo(LinkedHashSet()) { it in here }
        }
        return effective
    }
}
