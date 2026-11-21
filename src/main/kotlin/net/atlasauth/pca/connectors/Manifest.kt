package net.atlasauth.pca.connectors

import java.util.Locale
import net.atlasauth.pca.connect.JsText
import net.atlasauth.pca.connect.UrlBits
import net.atlasauth.pca.oauth.WhatwgUrl
import net.atlasauth.pca.verifier.Pca

/** Manifest validation: an untrusted value becomes a [ProviderManifest] only through [validateManifest] / [assertManifest]. */
object Manifest {
    /** OAuth request parameters a manifest or a caller must not set through authParams / extraParams: the request builders own them. */
    val RESERVED_AUTHORIZE_PARAMS: Set<String> = setOf("response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method")
    val RESERVED_TOKEN_PARAMS: Set<String> = setOf("grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token")

    private val ID_PATTERN = Regex("[a-z0-9][a-z0-9._-]*")
    private const val ID_SOURCE = "^[a-z0-9][a-z0-9._-]*$"
    private val HEADER_NAME = Regex("[A-Za-z0-9][A-Za-z0-9-]*")
    private val QUERY_NAME = Regex("[A-Za-z_][A-Za-z0-9_.-]*")
    private val FORBIDDEN_HEADERS = setOf("host", "content-length", "content-type", "transfer-encoding", "connection", "cookie", "set-cookie")
    private val VAR = Regex("\\{(\\w+)\\}")
    private val WHOLE_HOST_VAR = Regex("\\{\\w+\\}(:\\d+)?")
    private const val PLACEMENTS = "bearer | header | query"
    private const val REFRESH_MODES = "refresh_token | none"
    private const val CLIENT_AUTHS = "post | basic"

    /** The result of validating an untrusted manifest. */
    class ManifestValidation internal constructor(val ok: Boolean, val manifest: ProviderManifest?, val issues: List<String>)

    private fun isNonEmptyString(v: Any?): Boolean = v is String && v.isNotEmpty()

    private fun isStringArray(v: Any?): Boolean = v is List<*> && v.all { it is String }

    private fun isStringRecord(v: Any?): Boolean = v is Map<*, *> && v.values.all { it is String }

    private fun isHttpsUrl(v: Any?): Boolean {
        if (v !is String || !v.startsWith("https://")) return false
        // The host may carry {var} placeholders. Check the shape with them replaced by a label, and refuse credentials in the URL, a placeholder
        // that is the whole host (the caller would then choose where tokens go), and a fragment.
        val probe = VAR.replace(v, "x")
        val u = WhatwgUrl.parse(probe) ?: return false
        if (u.protocol != "https:" || UrlBits.hasCredentials(probe) || UrlBits.hasFragment(probe)) return false
        val rest = v.substring("https://".length)
        var e = rest.length
        for (i in rest.indices) {
            val c = rest[i]
            if (c == '/' || c == '?' || c == '#') { e = i; break }
        }
        return !WHOLE_HOST_VAR.matches(rest.substring(0, e))
    }

    private fun urlVars(url: String): List<String> = VAR.findAll(url).map { it.groupValues[1] }.toList()

    private fun strings(v: Any?): List<String> = (v as List<*>).map { it as String }

    private fun stringMap(v: Any?): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for ((k, x) in v as Map<*, *>) out[k as String] = x as String
        return out
    }

    /**
     * Structurally validate an untrusted value (a parsed JSON tree) as a [ProviderManifest]. Pure; collects every issue rather than failing
     * on the first. Enforces the catalog invariants: a well-formed id, HTTPS endpoints, string scope lists, defaultScopes inside scopesAvailable, a
     * known tokenPlacement / refresh.mode / clientAuth, a headerName / queryParam for the matching placement, and every {var} in the URLs declared
     * in requiredVars (and the reverse).
     */
    fun validateManifest(input: Any?): ManifestValidation {
        val issues = ArrayList<String>()
        if (input !is Map<*, *>) {
            issues.add("manifest must be an object")
            return ManifestValidation(false, null, issues)
        }
        val inp: Map<*, *> = input

        val id = inp["id"]
        if (!isNonEmptyString(id)) issues.add("id must be a non-empty string")
        else if (!ID_PATTERN.matches(id as String)) issues.add("id '$id' must be lowercase and match $ID_SOURCE")

        if (!isNonEmptyString(inp["displayName"])) issues.add("displayName must be a non-empty string")

        val authorizeUrl = inp["authorizeUrl"]
        if (!isHttpsUrl(authorizeUrl)) issues.add("authorizeUrl must be an https:// URL")
        val tokenUrl = inp["tokenUrl"]
        if (!isHttpsUrl(tokenUrl)) issues.add("tokenUrl must be an https:// URL")

        val scopesAvailable = inp["scopesAvailable"]
        if (!isStringArray(scopesAvailable)) issues.add("scopesAvailable must be an array of strings")
        val defaultScopes = inp["defaultScopes"]
        if (!isStringArray(defaultScopes)) issues.add("defaultScopes must be an array of strings")
        val listNames = arrayOf("scopesAvailable", "defaultScopes")
        val lists = arrayOf(scopesAvailable, defaultScopes)
        for (i in 0 until 2) {
            if (isStringArray(lists[i])) {
                val list = strings(lists[i])
                var bad = false
                for (s in list) if (s.isEmpty() || JsText.hasSpaceOrComma(s)) { bad = true; break }
                if (bad) issues.add(listNames[i] + " entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)")
                if (LinkedHashSet(list).size != list.size) issues.add(listNames[i] + " must not contain duplicates")
            }
        }
        if (isStringArray(scopesAvailable) && isStringArray(defaultScopes) && strings(scopesAvailable).isNotEmpty()) {
            val available = LinkedHashSet(strings(scopesAvailable))
            val missing = strings(defaultScopes).filter { it !in available }
            if (missing.isNotEmpty()) issues.add("defaultScopes must be a subset of scopesAvailable (unknown: " + missing.joinToString(", ") + ")")
        }

        val refresh = inp["refresh"]
        if (refresh !is Map<*, *>) {
            issues.add("refresh must be an object")
        } else {
            val mode = refresh["mode"]
            if (mode !is String || !(mode == "refresh_token" || mode == "none")) issues.add("refresh.mode must be one of $REFRESH_MODES")
            val te = refresh["tokenEndpoint"]
            if (refresh.containsKey("tokenEndpoint") && !isHttpsUrl(te)) issues.add("refresh.tokenEndpoint, when present, must be an https:// URL")
            if (refresh.containsKey("supportsScopeNarrowing") && refresh["supportsScopeNarrowing"] !is Boolean) issues.add("refresh.supportsScopeNarrowing must be a boolean")
            val ep = refresh["extraParams"]
            if (refresh.containsKey("extraParams") && !isStringRecord(ep)) issues.add("refresh.extraParams must be a string→string map")
            else if (isStringRecord(ep)) for (k in (ep as Map<*, *>).keys) if (k in RESERVED_TOKEN_PARAMS) issues.add("refresh.extraParams may not set '$k': the request builder owns it")
        }

        val tokenPlacement = inp["tokenPlacement"]
        if (tokenPlacement !is String || !(tokenPlacement == "bearer" || tokenPlacement == "header" || tokenPlacement == "query")) {
            issues.add("tokenPlacement must be one of $PLACEMENTS")
        } else if (tokenPlacement == "header" && !isNonEmptyString(inp["headerName"])) {
            issues.add("tokenPlacement 'header' requires a non-empty headerName")
        } else if (tokenPlacement == "query" && !isNonEmptyString(inp["queryParam"])) {
            issues.add("tokenPlacement 'query' requires a non-empty queryParam")
        }
        val headerName = inp["headerName"]
        if (headerName is String && (!HEADER_NAME.matches(headerName) || headerName.lowercase(Locale.ROOT) in FORBIDDEN_HEADERS)) {
            issues.add("headerName '$headerName' must be an HTTP token and not a protocol header")
        }
        val queryParam = inp["queryParam"]
        if (queryParam is String && !QUERY_NAME.matches(queryParam)) issues.add("queryParam '$queryParam' must be a plain parameter name")
        val sepRaw = inp["scopeSeparator"]
        if (sepRaw is String && sepRaw.isEmpty()) issues.add("scopeSeparator must not be empty")

        if (inp.containsKey("pkce") && inp["pkce"] !is Boolean) issues.add("pkce must be a boolean")
        if (inp.containsKey("scopeSeparator") && inp["scopeSeparator"] !is String) issues.add("scopeSeparator must be a string")
        val authParams = inp["authParams"]
        if (inp.containsKey("authParams") && !isStringRecord(authParams)) issues.add("authParams must be a string→string map")
        else if (isStringRecord(authParams)) for (k in (authParams as Map<*, *>).keys) if (k in RESERVED_AUTHORIZE_PARAMS) issues.add("authParams may not set '$k': the request builder owns it")
        val clientAuth = inp["clientAuth"]
        if (inp.containsKey("clientAuth") && !(clientAuth is String && (clientAuth == "post" || clientAuth == "basic"))) issues.add("clientAuth must be one of $CLIENT_AUTHS")

        val requiredVars = inp["requiredVars"]
        if (inp.containsKey("requiredVars") && !isStringArray(requiredVars)) issues.add("requiredVars must be an array of strings")
        // Every {var} that appears in a URL must be declared, and vice versa, so substitution can never silently leave a placeholder in a live request.
        if (isHttpsUrl(authorizeUrl) && isHttpsUrl(tokenUrl)) {
            val declared = LinkedHashSet<String>(if (isStringArray(requiredVars)) strings(requiredVars) else emptyList())
            val used = LinkedHashSet<String>(urlVars(authorizeUrl as String))
            used.addAll(urlVars(tokenUrl as String))
            for (v in used) if (v !in declared) issues.add("url uses '{$v}' but requiredVars does not declare it")
            for (v in declared) if (v !in used) issues.add("requiredVars declares '$v' but no URL uses '{$v}'")
        }

        if (inp.containsKey("docsUrl") && inp["docsUrl"] !is String) issues.add("docsUrl must be a string")

        if (issues.isNotEmpty()) return ManifestValidation(false, null, issues)
        return ManifestValidation(true, freezeManifest(inp), emptyList())
    }

    /** Build a [ProviderManifest] from an already-validated record, copying only known fields. */
    private fun freezeManifest(inp: Map<*, *>): ProviderManifest {
        val m = ProviderManifest()
        val rf: Map<*, *> = inp["refresh"] as? Map<*, *> ?: LinkedHashMap<Any?, Any?>()
        m.refresh.mode = if ("none" == rf["mode"]) "none" else "refresh_token"
        (rf["tokenEndpoint"] as? String)?.let { m.refresh.tokenEndpoint = it }
        (rf["supportsScopeNarrowing"] as? Boolean)?.let { m.refresh.supportsScopeNarrowing = it }
        if (isStringRecord(rf["extraParams"])) m.refresh.extraParams = stringMap(rf["extraParams"])

        m.id = inp["id"] as? String ?: ""
        m.displayName = inp["displayName"] as? String ?: ""
        m.authorizeUrl = inp["authorizeUrl"] as? String ?: ""
        m.tokenUrl = inp["tokenUrl"] as? String ?: ""
        m.scopesAvailable = if (isStringArray(inp["scopesAvailable"])) strings(inp["scopesAvailable"]) else ArrayList()
        m.defaultScopes = if (isStringArray(inp["defaultScopes"])) strings(inp["defaultScopes"]) else ArrayList()
        val tp = inp["tokenPlacement"]
        m.tokenPlacement = if ("header" == tp) "header" else if ("query" == tp) "query" else "bearer"
        (inp["pkce"] as? Boolean)?.let { m.pkce = it }
        (inp["scopeSeparator"] as? String)?.let { m.scopeSeparator = it }
        if (isStringRecord(inp["authParams"])) m.authParams = stringMap(inp["authParams"])
        val ca = inp["clientAuth"]
        if ("post" == ca || "basic" == ca) m.clientAuth = ca as String
        (inp["headerName"] as? String)?.let { m.headerName = it }
        (inp["queryParam"] as? String)?.let { m.queryParam = it }
        if (isStringArray(inp["requiredVars"])) m.requiredVars = strings(inp["requiredVars"])
        (inp["docsUrl"] as? String)?.let { m.docsUrl = it }
        return m
    }

    /** Validate [input], returning the manifest or throwing [ConnectorError.ManifestValidationError]. */
    fun assertManifest(input: Any?): ProviderManifest {
        val r = validateManifest(input)
        if (!r.ok) throw ConnectorError.ManifestValidationError(r.issues)
        return r.manifest!!
    }

    /** A digest of a manifest (SHA-256 over canonical JSON). Pin the digest of a manifest you reviewed: a registry given it refuses a manifest that has since changed. */
    fun manifestDigest(manifest: ProviderManifest): String = Pca.hashCanonical(manifest.toMap())
}
