package net.atlasauth.pca.verifier

/**
 * The resource server's discovery document (`/.well-known/pca-configuration`): the audience a PCActn must name, the accepted wire
 * versions and signature suites, the header the PCActn rides in, and the optional intent block. [parse] narrows an UNTRUSTED value and
 * throws [IllegalArgumentException] on anything malformed (fail closed).
 */
object Discovery {
    const val WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration"

    private val INTENT_MEMBERS = listOf("versions", "actions_uri", "schema_keys", "question_relay", "tiers", "evidence_uri")

    private fun bad(m: String): Nothing = throw IllegalArgumentException("parseDiscoveryDocument: $m")

    private fun isNumber(v: Any?): Boolean = v !is Boolean && IntentJs.num(v) != null

    /** Validate an `intent` discovery block (fail closed on anything malformed). */
    @JvmStatic
    fun parseDiscoveryIntent(v: Any?): Map<String, Any?> {
        if (v !is Map<*, *>) bad("intent must be an object")
        for (k in v.keys) if (k !in INTENT_MEMBERS) bad("intent has unknown member '$k'")
        val versions = v["versions"] as? List<*>
        if (versions == null || versions.isEmpty() || !versions.all { IntentJs.num(it) == 1.0 || IntentJs.num(it) == 2.0 }) bad("intent.versions must list 1 and/or 2")
        val out = linkedMapOf<String, Any?>("versions" to ArrayList<Any?>(versions))
        for (k in listOf("actions_uri", "evidence_uri")) {
            if (v.containsKey(k)) {
                val x = v[k]
                if (x !is String || x.isEmpty()) bad("intent.$k must be a non-empty string")
                out[k] = x
            }
        }
        if (v.containsKey("schema_keys")) {
            val sk = v["schema_keys"] as? List<*> ?: bad("intent.schema_keys must be an array")
            out["schema_keys"] = sk.map { e ->
                if (e !is Map<*, *> || e["kid"] !is String || e["alg"] !is String || e["pk"] !is String || (e.containsKey("pq_pk") && e["pq_pk"] !is String)) {
                    bad("intent.schema_keys entries are {kid, alg, pk, pq_pk?}")
                }
                val m = linkedMapOf<String, Any?>("kid" to e["kid"], "alg" to e["alg"], "pk" to e["pk"])
                if (e.containsKey("pq_pk")) m["pq_pk"] = e["pq_pk"]
                m
            }
        }
        if (v.containsKey("question_relay")) {
            val q = v["question_relay"]
            if (q !is Boolean) bad("intent.question_relay must be a boolean")
            out["question_relay"] = q
        }
        if (v.containsKey("tiers")) {
            val t = v["tiers"] as? Map<*, *> ?: bad("intent.tiers must be an object")
            if (!t.values.all { n -> val d = IntentJs.num(n); n !is Boolean && d != null && d == Math.rint(d) && d >= 0 && d <= 4 && !(d == 0.0 && 1.0 / d < 0) }) bad("intent.tiers values must be integers 0..4")
            out["tiers"] = LinkedHashMap<Any?, Any?>(t)
        }
        return out
    }

    private fun strings(v: Any?): Boolean = v is List<*> && v.all { it is String }

    /** Validate and narrow an untrusted value into a discovery document. Throws on anything malformed. */
    @JvmStatic
    fun parseDiscoveryDocument(value: Any?): Map<String, Any?> {
        if (value !is Map<*, *>) bad("not an object")
        val aud = value["audience"]
        if (aud !is String || aud.isEmpty()) bad("missing audience")
        val versions = value["pca_versions"]
        if (versions !is List<*> || !versions.all { isNumber(it) }) bad("pca_versions must be a number[]")
        val suites = value["signature_suites"]
        if (!strings(suites)) bad("signature_suites must be a string[]")
        val header = value["action_header"]
        if (header !is String || header.isEmpty()) bad("missing action_header")
        val doc = linkedMapOf<String, Any?>("audience" to aud, "pca_versions" to versions, "signature_suites" to suites, "action_header" to header)
        if (strings(value["required_checks"])) doc["required_checks"] = value["required_checks"]
        if (value["endpoints"] is Map<*, *> || value["endpoints"] is List<*>) doc["endpoints"] = value["endpoints"] // any non-null object, as the reference does
        if (strings(value["trusted_roots"])) doc["trusted_roots"] = value["trusted_roots"]
        if (value["metadata"] is Map<*, *> || value["metadata"] is List<*>) doc["metadata"] = value["metadata"]
        if (value.containsKey("intent")) doc["intent"] = parseDiscoveryIntent(value["intent"])
        if (value.containsKey("obligations_supported")) {
            val o = value["obligations_supported"]
            if (!strings(o)) bad("obligations_supported must be a string[]")
            doc["obligations_supported"] = ArrayList<Any?>(o as List<*>)
        }
        return doc
    }

    /** The HTTP seam of [fetchDiscovery]: one GET in, the status and body out. */
    fun interface Fetch {
        fun get(url: String, headers: Map<String, String>): Pair<Int, String>
    }

    private val DEFAULT_FETCH = Fetch { url, headers -> SimpleHttp.request("GET", url, headers, null) }

    /**
     * Fetch and parse a resource server's discovery document. [baseUrl] is the server origin (for example `https://api.acme.com`); the
     * well-known path is appended. Throws on a non-2xx response or a malformed document.
     */
    @JvmStatic
    @JvmOverloads
    fun fetchDiscovery(baseUrl: String, fetch: Fetch? = null): Map<String, Any?> {
        val url = baseUrl.trimEnd('/') + WELL_KNOWN_PCA_PATH
        val (status, body) = (fetch ?: DEFAULT_FETCH).get(url, linkedMapOf("accept" to "application/json"))
        check(status in 200..299) { "fetchDiscovery: $url returned $status" }
        return parseDiscoveryDocument(Json.parseLenient(body))
    }

    /**
     * Build a well-formed discovery document from options (`audience`, `signatureSuites`, `pcaVersions`, `actionHeader`, `requiredChecks`,
     * `endpoints`, `trustedRoots`, `metadata`, `intent`, `obligationsSupported`). Throws on an empty audience.
     */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun buildDiscoveryDocument(opts: Map<String, Any?>): Map<String, Any?> {
        val aud = opts["audience"]
        if (aud !is String || aud.isEmpty()) throw IllegalArgumentException("buildDiscoveryDocument: audience is required")
        val d = LinkedHashMap<String, Any?>()
        d["audience"] = aud
        d["pca_versions"] = opts["pcaVersions"] ?: arrayListOf<Any?>(StoreJs.num(2L))
        d["signature_suites"] = opts["signatureSuites"] ?: arrayListOf<Any?>("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")
        d["action_header"] = opts["actionHeader"] ?: "PCA-Action"
        d["required_checks"] = opts["requiredChecks"]
            ?: arrayListOf<Any?>("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")
        if (opts["endpoints"] != null) d["endpoints"] = opts["endpoints"]
        if (opts["trustedRoots"] != null) d["trusted_roots"] = opts["trustedRoots"]
        if (opts["metadata"] != null) d["metadata"] = opts["metadata"]
        if (opts["intent"] != null) d["intent"] = parseDiscoveryIntent(opts["intent"])
        if (opts["obligationsSupported"] != null) d["obligations_supported"] = ArrayList<Any?>(opts["obligationsSupported"] as List<Any?>)
        return d
    }

    /** True iff this server (per its discovery document) accepts a given signature suite. */
    @JvmStatic
    fun acceptsSuite(doc: Map<String, Any?>, suite: String): Boolean = (doc["signature_suites"] as? List<*>)?.contains(suite) == true
}
