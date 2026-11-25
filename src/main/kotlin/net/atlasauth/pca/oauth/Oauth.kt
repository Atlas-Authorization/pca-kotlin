package net.atlasauth.pca.oauth

import java.nio.charset.StandardCharsets
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.A2a
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.PcaGrant

/**
 * OAuth 2.1 / MCP-authorization interop bridge for Proof-Carrying Authority: RFC 9728 protected resource metadata, the MCP 401
 * challenge (RFC 6750 + RFC 7235), RFC 8707 resource indicators, the `pca_grant` authorization-details type (RFC 9396) and the OAuth
 * scopes derived from a confirmed action. Pure: no I/O. Documents are maps (member names as on the wire), options use the reference's
 * camelCase names. A refusal throws IllegalArgumentException.
 */
object Oauth {
    const val WELL_KNOWN_OAUTH_PRM = "/.well-known/oauth-protected-resource"
    const val WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration"
    private const val DEFAULT_PCA_HINT = "send PCA-Action: <base64url PCActn> or JSON body {pcactn}"
    private const val PCA_NEED_MAX_ENCODED = 2048

    private fun bad(msg: String): Nothing = throw IllegalArgumentException(msg)

    // ---- RFC 9728 ----

    /** RFC 9728 section 1.2: the reason [resource] is not an https URL without a fragment; null when valid. */
    fun resourceIdentifierProblem(resource: Any?): String? {
        if (resource !is String || resource.isEmpty()) return "resource identifier must be a non-empty string"
        val u = WhatwgUrl.parse(resource) ?: return "resource identifier is not an absolute URL"
        if (u.protocol != "https:") return "resource identifier must use the https scheme"
        if (resource.indexOf('#') >= 0) return "resource identifier must not contain a fragment"
        return null
    }

    /** RFC 9728 section 3.1: the well-known path for a resource identifier. Throws on an invalid identifier. */
    fun prmPathForResource(resource: String): String {
        resourceIdentifierProblem(resource)?.let { bad("prmPathForResource: $it") }
        val u = WhatwgUrl.parse(resource)!!
        return WELL_KNOWN_OAUTH_PRM + (if (u.pathname == "/") "" else u.pathname) + u.search
    }

    /** The absolute metadata URL for a resource identifier. */
    fun prmUrlForResource(resource: String): String {
        val u = WhatwgUrl.parse(resource) ?: bad("prmUrlForResource: not an absolute URL")
        return u.origin() + prmPathForResource(resource)
    }

    private fun Map<String, Any?>.or(k: String, dflt: Any?): Any? = this[k] ?: dflt

    private fun copy(o: Any?): List<Any?> = ArrayList(Js.list(o))

    /** The PCA discovery document the PRM embeds (audience, suites, versions, header, checks, endpoints, roots, metadata). */
    private fun buildDiscoveryDocument(o: Map<String, Any?>): Map<String, Any?> {
        val aud = o["audience"]
        if (!Js.nonEmptyString(aud)) bad("buildDiscoveryDocument: audience is required")
        return Js.obj(
            "audience" to aud,
            "pca_versions" to o.or("pcaVersions", listOf(Js.n(2))),
            "signature_suites" to o.or("signatureSuites", listOf("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")),
            "action_header" to o.or("actionHeader", "PCA-Action"),
            "required_checks" to o.or("requiredChecks", listOf("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")),
        ).also { d ->
            if (Js.truthy(o["endpoints"])) d["endpoints"] = o["endpoints"]
            if (Js.truthy(o["trustedRoots"])) d["trusted_roots"] = o["trustedRoots"]
            if (Js.truthy(o["metadata"])) d["metadata"] = o["metadata"]
        }
    }

    /** RFC 9728: the Protected Resource Metadata document with the PCA extension block. Throws on an empty or (strict) invalid resource. */
    fun protectedResourceMetadata(opts: Map<String, Any?>): Map<String, Any?> {
        val resource = opts["resource"] as? String
        if (resource.isNullOrEmpty()) bad("protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required")
        if (opts["strict"] != false) resourceIdentifierProblem(resource)?.let { bad("protectedResourceMetadata: $it") }
        val dopts = Js.obj("audience" to resource)
        for (k in listOf("signatureSuites", "pcaVersions", "actionHeader", "requiredChecks", "endpoints", "trustedRoots", "metadata")) dopts[k] = opts[k]
        val discovery = buildDiscoveryDocument(dopts)
        val endpoint = opts["pcaConfigurationEndpoint"] ?: resource.substringBefore('?').trimEnd('/') + WELL_KNOWN_PCA_PATH
        return Js.obj(
            "resource" to resource,
            "bearer_methods_supported" to opts.or("bearerMethodsSupported", listOf("header")),
            "pca_action_header" to discovery["action_header"],
            "pca_signature_suites" to copy(discovery["signature_suites"]),
            "pca_versions" to copy(discovery["pca_versions"]),
            "pca_configuration_endpoint" to endpoint,
            "pca" to discovery,
        ).also { doc ->
            if (Js.truthy(opts["authorizationServers"])) doc["authorization_servers"] = copy(opts["authorizationServers"])
            if (Js.truthy(opts["resourceDocumentation"])) doc["resource_documentation"] = opts["resourceDocumentation"]
            if (Js.truthy(opts["scopesSupported"])) doc["scopes_supported"] = copy(opts["scopesSupported"])
            if (Js.truthy(opts["resourceName"])) doc["resource_name"] = opts["resourceName"]
            if (Js.truthy(opts["resourceSigningAlgValuesSupported"])) doc["resource_signing_alg_values_supported"] = copy(opts["resourceSigningAlgValuesSupported"])
            if (Js.truthy(opts["authorizationDetailsTypesSupported"])) doc["authorization_details_types_supported"] = copy(opts["authorizationDetailsTypesSupported"])
        }
    }

    /** Validate and narrow an untrusted value into a protected-resource-metadata document. Throws on anything malformed. */
    fun parseProtectedResourceMetadata(value: Any?, parseOpts: Map<String, Any?>? = null): Map<String, Any?> {
        val p = "parseProtectedResourceMetadata: "
        val po = parseOpts ?: emptyMap()
        if (!Js.isObjectLike(value)) bad(p + "not an object")
        val resource = Js.get(value, "resource")
        if (!Js.nonEmptyString(resource)) bad(p + "missing `resource`")
        val bearer = Js.get(value, "bearer_methods_supported")
        if (!Js.allStrings(bearer)) bad(p + "bearer_methods_supported must be a string[]")
        val header = Js.get(value, "pca_action_header")
        if (!Js.nonEmptyString(header)) bad(p + "missing pca_action_header")
        val suites = Js.get(value, "pca_signature_suites")
        if (!Js.allStrings(suites)) bad(p + "pca_signature_suites must be a string[]")
        val versions = Js.get(value, "pca_versions")
        if (!Js.allNumbers(versions)) bad(p + "pca_versions must be a number[]")
        val pca = Js.get(value, "pca")
        if (!Js.isObjectLike(pca)) bad(p + "missing embedded `pca` discovery document")
        val audience = Js.get(pca, "audience")
        if (!Js.nonEmptyString(audience)) bad(p + "embedded pca.audience is required")
        val expected = po["expectedResource"]
        if (expected != null) {
            if (resource != expected) bad(p + "`resource` does not match the expected resource identifier")
            if (audience != expected) bad(p + "embedded pca.audience does not match the expected resource identifier")
        }
        if (po["strict"] != false) {
            if (expected == null) bad(p + "expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip")
            resourceIdentifierProblem(resource)?.let { bad(p + it) }
            if (Js.list(bearer).any { it != "header" && it != "body" && it != "query" }) bad(p + "bearer_methods_supported has a value outside header/body/query")
        }
        val doc = Js.obj(
            "resource" to resource, "bearer_methods_supported" to bearer, "pca_action_header" to header,
            "pca_signature_suites" to suites, "pca_versions" to versions, "pca" to pca,
        )
        for (k in listOf("pca_configuration_endpoint", "authorization_servers", "resource_documentation", "scopes_supported", "resource_name", "resource_signing_alg_values_supported")) {
            val v = Js.get(value, k)
            if (if (k.endsWith("_endpoint") || k == "resource_documentation" || k == "resource_name") v is String else Js.allStrings(v)) doc[k] = v
        }
        return doc
    }

    // ---- RFC 6750 / MCP challenge ----

    /** A value for a quoted auth-param: a quote, backslash or control character would allow header injection. */
    private fun quotedParam(v: String): String {
        if (v.any { it == '"' || it == '\\' || it <= '\u001f' || it == '\u007f' }) bad("pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline")
        return v
    }

    private fun str(o: Any?): String = o as? String ?: bad("pca-oauth: option must be a string")

    /** The auth-param that carries the encoded need in a `WWW-Authenticate` challenge. */
    const val PCA_NEED_PARAM = "pca_need"
    const val PCA_NEED_DOMAIN = "atlas-pca/need/v1"

    /** The outcome of [validatePcaNeed] / [decodePcaNeed]: `ok` with the [need], else a typed [code]. */
    class NeedResult internal constructor(val ok: Boolean, val need: Map<String, Any?>?, val code: String?)

    /** Validate a decoded need. Unknown members are refused: an unreviewed field must not ride along. */
    fun validatePcaNeed(x: Any?): NeedResult {
        val code = A2a.needError(x)
        @Suppress("UNCHECKED_CAST")
        return if (code == null) NeedResult(true, x as Map<String, Any?>, null) else NeedResult(false, null, code)
    }

    /** Decode a `pca_need` value. Never throws; every failure is a typed code and the caller falls back to plain scope step-up. */
    fun decodePcaNeed(value: Any?): NeedResult {
        if (value !is String || value.isEmpty()) return NeedResult(false, null, "bad_base64")
        if (value.length > PCA_NEED_MAX_ENCODED) return NeedResult(false, null, "too_long")
        val bytes = net.atlasauth.pca.verifier.Pca.decodeB64uStrict(value, -1) ?: return NeedResult(false, null, "bad_base64")
        val text = try {
            Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            return NeedResult(false, null, "bad_utf8")
        }
        val parsed = try { Json.parse(text) } catch (e: RuntimeException) { return NeedResult(false, null, "bad_json") }
        return validatePcaNeed(parsed)
    }

    /** The content address an approval flow cites for a need (domain-separated, over the canonical form). */
    fun pcaNeedDigest(need: Any?): String =
        net.atlasauth.pca.verifier.Pca.hashCanonical(linkedMapOf<String, Any?>("d" to PCA_NEED_DOMAIN, "need" to need))

    /** Encode a need as the unpadded base64url of its strict-canonical JSON. Throws on a malformed need or an over-long value. */
    fun encodePcaNeed(need: Any?): String {
        A2a.needError(need)?.let { bad("encodePcaNeed: malformed need ($it)") }
        val enc = Keys.b64u(Json.canonicalizeStrict(need).toByteArray(Charsets.UTF_8))
        if (enc.length > PCA_NEED_MAX_ENCODED) bad("encodePcaNeed: the need is too large for a header")
        return enc
    }

    /** The WWW-Authenticate value of an MCP 401: Bearer resource_metadata (+ error, scope, pca_need) and by default a PCA challenge. */
    fun wwwAuthenticate(prmUrl: String?, opts: Map<String, Any?>? = null): String {
        if (prmUrl.isNullOrEmpty()) bad("wwwAuthenticate: prmUrl is required")
        val o = opts ?: emptyMap()
        val bearer = arrayListOf("resource_metadata=\"" + quotedParam(prmUrl) + "\"")
        if (Js.truthy(o["error"])) bearer.add("error=\"" + quotedParam(str(o["error"])) + "\"")
        if (Js.truthy(o["errorDescription"])) bearer.add("error_description=\"" + quotedParam(str(o["errorDescription"])) + "\"")
        if (Js.truthy(o["scope"])) bearer.add("scope=\"" + quotedParam(str(o["scope"])) + "\"")
        if (Js.truthy(o["pcaNeed"])) bearer.add("pca_need=\"" + quotedParam(encodePcaNeed(o["pcaNeed"])) + "\"")
        val challenges = arrayListOf("Bearer " + bearer.joinToString(", "))
        if (Js.truthy(o["pcaChallenge"])) {
            val c = str(o["pcaChallenge"])
            if (c.any { it <= '\u0008' || it in '\u000a'..'\u001f' || it == '\u007f' }) bad("pca-oauth: pcaChallenge may not contain control characters or newlines")
            challenges.add(c)
        } else if (Js.truthy(o.or("includePca", true))) {
            val hint = o.or("hint", DEFAULT_PCA_HINT)
            var pca = "PCA realm=\"" + quotedParam(str(o.or("realm", "pca"))) + "\""
            if (Js.truthy(hint)) pca += ", hint=\"" + quotedParam(str(hint)) + "\""
            challenges.add(pca)
        }
        return challenges.joinToString(", ")
    }

    // ---- RFC 8707 ----

    private fun ok(matched: String) = Js.obj("ok" to true, "matched" to matched)
    private fun fail(reason: String) = Js.obj("ok" to false, "reason" to reason)
    private fun valuesOf(v: Any?): List<Any?> = v as? List<Any?> ?: listOf(v)

    /** RFC 8707: does an incoming resource indicator (one value or several) include this RS's audience? */
    fun checkResourceIndicator(resourceParam: Any?, expectedAudience: String?): Map<String, Any?> {
        if (expectedAudience.isNullOrEmpty()) bad("checkResourceIndicator: expectedAudience is required")
        if (resourceParam == null) return fail("no resource indicator presented")
        val values = valuesOf(resourceParam)
        if (values.isEmpty()) return fail("empty resource indicator")
        for (r in values) if (r is String && r.isNotEmpty() && r == expectedAudience) return ok(r)
        return fail("resource indicator " + Js.stringify(values) + " does not match audience " + Js.stringify(expectedAudience))
    }

    /** A token's aud must be, or contain, exactly this resource identifier (exact string equality; fail closed). */
    fun checkTokenAudience(aud: Any?, expectedResource: String?): Map<String, Any?> {
        if (expectedResource.isNullOrEmpty()) bad("checkTokenAudience: expectedResource is required")
        if (aud == null) return fail("token has no audience")
        val values = valuesOf(aud)
        if (values.isEmpty()) return fail("token has an empty audience")
        if (values.any { it == expectedResource }) return ok(expectedResource)
        return fail("token audience " + Js.stringify(aud) + " does not include resource " + Js.stringify(expectedResource))
    }

    // ---- glue ----

    /** The path and body to serve the PRM document: {path, body, rfcPath}. */
    fun oauthDiscoveryHandler(opts: Map<String, Any?>): Map<String, Any?> {
        val body = protectedResourceMetadata(opts)
        val resource = opts["resource"] as String
        val path = if (resourceIdentifierProblem(resource) == null) prmPathForResource(resource) else WELL_KNOWN_OAUTH_PRM
        return Js.obj("path" to path, "body" to body, "rfcPath" to path)
    }

    /** The complete MCP/OAuth 401: status, the WWW-Authenticate header and a small JSON body. */
    fun mcpUnauthorized(prmUrl: String?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val o = opts ?: emptyMap()
        val body = Js.obj("error" to o.or("error", "invalid_request"), "resource_metadata" to prmUrl)
        if (Js.truthy(o["errorDescription"])) body["error_description"] = o["errorDescription"]
        return Js.obj("status" to Js.n(401), "headers" to Js.obj("WWW-Authenticate" to wwwAuthenticate(prmUrl, o)), "body" to body)
    }

    /** Upgrade a deny result's challenge so it also carries the MCP resource_metadata pointer; other fields are kept. */
    fun upgradeUnauthorizedChallenge(result: Map<String, Any?>, prmUrl: String?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>(opts ?: emptyMap())
        val existing = result["wwwAuthenticate"]
        if (Js.truthy(existing)) o["pcaChallenge"] = existing
        return LinkedHashMap(result).also { it["wwwAuthenticate"] = wwwAuthenticate(prmUrl, o) }
    }

    // ---- pca_grant (RFC 9396) ----

    private fun idList(o: Any?): List<String> = Js.list(o).map { it as? String ?: bad("chainIds must be strings") }

    /** A validated pca_grant detail for the chain. Throws on anything the profile would refuse. */
    fun buildPcaGrantDetail(o: Map<String, Any?>): Map<String, Any?> {
        val ids = idList(o["chainIds"])
        val d = Js.obj("type" to PcaGrant.TYPE, "chain_digest" to PcaGrant.chainDigest(ids), "chain_len" to Js.n(ids.size.toLong()))
        if (o["chainRef"] != null) d["chain_ref"] = o["chainRef"]
        if (o["bundleRevision"] != null) d["bundle_revision"] = o["bundleRevision"]
        if (o["locations"] != null) d["locations"] = copy(o["locations"])
        PcaGrant.validate(d)?.let { bad("buildPcaGrantDetail: refused ($it)") }
        return d
    }

    /** The form-encoded value of the authorization_details request parameter (encodeURIComponent of the JSON). */
    fun pcaGrantRequestParam(details: List<Any?>): String {
        val json = Js.stringify(details)
        if (Json.hasLoneSurrogate(json)) bad("pcaGrantRequestParam: URI malformed")
        val sb = StringBuilder()
        for (b in Json.utf8(json)) {
            val c = b.toInt() and 0xff
            if (c in 'A'.code..'Z'.code || c in 'a'.code..'z'.code || c in '0'.code..'9'.code || "-_.!~*'()".indexOf(c.toChar()) >= 0) sb.append(c.toChar())
            else sb.append('%').append(String.format("%02X", c))
        }
        return sb.toString()
    }

    /**
     * Gate an OAuth access token carrying pca_grant details: allow only for well-formed details naming a prefix of the presented chain
     * and this resource, with a verified per-action proof. Returns {allow:true, detail} or {allow:false, status, error, code}.
     */
    fun authorizePcaGrantToken(o: Map<String, Any?>): Map<String, Any?> {
        val parsed = PcaGrant.parse(o["authorizationDetails"])
        parsed.code?.let { return denied(401, "invalid_token", it) }
        val r = PcaGrant.check(parsed.details, o["resource"] as? String ?: "\u0000no-resource", idList(o["chainIds"]), o["proofVerified"] == true)
        val code = r.code ?: return Js.obj("allow" to true, "detail" to parsed.details[r.index])
        val loc = code == "wrong_location"
        return denied(if (loc) 403 else 401, if (loc) "insufficient_scope" else "invalid_token", code)
    }

    private fun denied(status: Int, error: String, code: String) = Js.obj("allow" to false, "status" to Js.n(status.toLong()), "error" to error, "code" to code)

    // ---- scopes derived from the confirmed action ----

    private val SCOPE_TOKEN = Regex("^[\\x21\\x23-\\x5b\\x5d-\\x7e]+$")

    /** The scope (and RFC 8707 resource) an OAuth client should request for one action; an unconfirmed or mismatched action yields a refusal. */
    fun oauthScopeForAction(action: Any?, o: Map<String, Any?>): Map<String, Any?> {
        val scopes = deriveActionScopes(action, o["provider"] as? String, o["granted"])
        if (scopes is String) return Js.obj("ok" to false, "code" to scopes)
        @Suppress("UNCHECKED_CAST") val list = scopes as List<String>
        return Js.obj("ok" to true, "scope" to list.joinToString(" "), "scopes" to ArrayList<Any?>(list)).also { if (o["resource"] != null) it["resource"] = o["resource"] }
    }

    /** The refusal code (a String), or the sorted scopes (a List). */
    private fun deriveActionScopes(action: Any?, provider: String?, granted: Any?): Any {
        if (action == null || !Js.isObjectLike(action)) return "unknown_action"
        if (Js.get(action, "confirmed") != true) return "unconfirmed"
        val up = Js.get(action, "upstream")
        if (provider != null && provider != Js.get(up, "provider")) return "provider_mismatch"
        val min = Js.get(up, "scopes_min") as? List<*>
        if (min.isNullOrEmpty()) return "no_scopes"
        if (min.any { it !is String || it.length > 256 || !SCOPE_TOKEN.matches(it) }) return "bad_scope"
        val sorted = min.map { it as String }.toSortedSet().toList()
        if (granted != null && sorted.any { it !in (granted as List<*>) }) return "exceeds_grant"
        return sorted
    }
}
