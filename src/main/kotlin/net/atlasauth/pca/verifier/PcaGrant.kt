package net.atlasauth.pca.verifier

/**
 * The `pca_grant` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check. The type is a
 * pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Everything here is total.
 */
object PcaGrant {
    const val TYPE = "pca_grant"
    const val DOMAIN = "atlas-pca/pca-grant-chain/v1"

    private val MEMBERS = setOf("type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations")
    private val REFUSED = setOf("actions", "datatypes", "identifier", "privileges")

    /** `parse`: [code] is null on success and [details] holds the `pca_grant` entries. `check`: [code] null means allow at [index]. */
    class Result(val code: String?, val details: List<Map<String, Any?>> = emptyList(), val index: Int = -1)

    /** https://, printable ASCII without '#' or '\', at most 2048 characters, non-empty authority (to the first '/' or '?') without '@'. */
    @JvmStatic
    fun isHttpsUrl(o: Any?): Boolean {
        if (o !is String || o.length > 2048 || !o.startsWith("https://")) return false
        for (c in o) if (c.code < 0x21 || c.code > 0x7e || c == '#' || c == '\\') return false
        val rest = o.substring(8)
        val cut = rest.indexOfFirst { it == '/' || it == '?' }
        val authority = if (cut < 0) rest else rest.substring(0, cut)
        return authority.isNotEmpty() && !authority.contains('@')
    }

    @JvmStatic
    fun chainDigest(ids: List<String>): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to DOMAIN, "ids" to ids))

    /** null when accepted, else the refusal code. */
    @JvmStatic
    fun validate(x: Any?): String? {
        val m = K3Sig.map(x) ?: return "bad_entry"
        if (m["type"] != TYPE) return "bad_type"
        for (k in m.keys) {
            if (k in REFUSED) return "refused_member"
            if (k !in MEMBERS) return "unknown_member"
        }
        val d = m["chain_digest"]
        if (d !is String || Pca.decodeB64uStrict(d, 32) == null) return "bad_chain_digest"
        val n = m["chain_len"]
        if (!IntentJs.isSafeInteger(n) || IntentJs.lng(n) < 1 || IntentJs.lng(n) > 16) return "bad_chain_len"
        if (m.containsKey("chain_ref") && !isHttpsUrl(m["chain_ref"])) return "bad_chain_ref"
        if (m.containsKey("bundle_revision") && !K3Sig.isSafeInt(m["bundle_revision"])) return "bad_bundle_revision"
        if (m.containsKey("locations")) {
            val l = K3Sig.list(m["locations"])
            if (l == null || l.isEmpty() || l.size > 8 || !l.all { isHttpsUrl(it) }) return "bad_locations"
        }
        return null
    }

    @JvmStatic
    fun parse(arr: Any?): Result {
        val l = K3Sig.list(arr) ?: return Result("not_an_array")
        if (l.size > 16) return Result("too_many_details")
        val out = ArrayList<Map<String, Any?>>()
        for (e in l) {
            val m = K3Sig.map(e)
            if (m == null || m["type"] !is String) return Result("bad_entry")
            if (m["type"] != TYPE) continue
            val code = validate(m)
            if (code != null) return Result(code)
            out.add(m)
        }
        return Result(null, out)
    }

    /** Allow only with a verified per-action proof and a detail naming a prefix of the presented chain (and this resource). */
    @JvmStatic
    fun check(details: List<Map<String, Any?>>, resource: String, chainIds: List<String>, proofVerified: Boolean): Result {
        if (details.isEmpty()) return Result("no_detail")
        if (!proofVerified) return Result("proof_required")
        var reason = "chain_mismatch"
        for ((i, d) in details.withIndex()) {
            val n = IntentJs.lng(d["chain_len"]).toInt()
            if (chainIds.size < n || chainDigest(chainIds.subList(0, n)) != d["chain_digest"]) continue
            val loc = K3Sig.list(d["locations"])
            if (loc != null && !loc.contains(resource)) {
                reason = "wrong_location"
                continue
            }
            return Result(null, index = i)
        }
        return Result(reason)
    }
}
