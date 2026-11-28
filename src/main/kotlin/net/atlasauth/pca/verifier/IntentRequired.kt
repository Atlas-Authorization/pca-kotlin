package net.atlasauth.pca.verifier

import net.atlasauth.pca.compliance.ComplianceJs

/**
 * Lazy elicitation on the wire (Intent Layer v2, the `intent_required` artifact): when the cell of an attempted action is uncertain the site answers HTTP 403
 * with `WWW-Authenticate: PCA error="intent_required", session=..., question=...` and an RFC 9457 problem body whose `pca` member is a SITE-SIGNED
 * `pca-intent-required` v1 object (the session, the map and schema digests, the PCActn and action digests, the cell as coordinates, the question id, the friction
 * tier and an expiry). The other outcomes are terminal: `schema-violation`, `ceiling` and `intent-denied`.
 */
@Suppress("UNCHECKED_CAST")
object IntentRequired {
    const val PROBLEM_BASE = "https://atlasauth.net/pca/problems/"
    val INTENT_PROBLEM_KINDS: List<String> = listOf("intent-required", "intent-denied", "schema-violation", "ceiling")
    const val INTENT_REQUIRED_DOMAIN = SignersMore.INTENT_REQUIRED_DOMAIN
    const val INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"
    val FRICTIONS: List<String> = listOf("tap", "hold", "typed", "device")

    private val TITLES = mapOf(
        "intent-required" to "Principal confirmation required for this action",
        "intent-denied" to "The principal does not intend this action",
        "schema-violation" to "The action does not conform to the site action schema",
        "ceiling" to "The action is outside a ceiling the principal cannot widen",
    )
    private val ERRORS = mapOf("intent-required" to "intent_required", "intent-denied" to "intent_denied", "schema-violation" to "schema_violation", "ceiling" to "ceiling")
    private val BODY_KEYS = listOf("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig")
    private val QUESTION_ID_RE = Regex("[A-Za-z0-9_-]{1,64}")
    private val J = ComplianceJs

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = LinkedHashMap<String, Any?>().also { for ((k, v) in kv) it[k] = v }

    private fun suiteErr(alg: Any?, present: Boolean): String? = IntentJs.suiteError(alg, present)

    /** The action digest a JIT consent is bound to: `H({d, action})` over the PCActn's signed `{verb, resource, params_digest, reversibility_class}`. */
    @JvmStatic fun intentActionDigest(action: Any?): String {
        if (action == null) throw IllegalArgumentException("Cannot read properties of null (reading 'verb')")
        fun m(k: String): Any? = if (action is Map<*, *> && action.containsKey(k)) action[k] else J.UNDEF
        for (k in listOf("verb", "resource", "params_digest", "reversibility_class")) if (m(k) === J.UNDEF) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        return Pca.hashCanonical(obj("d" to INTENT_ACTION_DOMAIN, "action" to obj("verb" to m("verb"), "resource" to m("resource"), "params_digest" to m("params_digest"), "reversibility_class" to m("reversibility_class"))))
    }

    /** The reason a cell's coordinates are malformed, else null: 1..64 dimensions, each an index range `[lo, hi]` or a distinct value set. */
    @JvmStatic fun cellCoordsError(c: Any?): String? = SignersMore.cellCoordsError(c)

    /** The reason a `pca-intent-required` body is malformed, else null. `signed` false checks the unsigned body a signer pre-checks (it must not carry `sig`). */
    @JvmStatic @JvmOverloads
    fun intentRequiredShapeError(b: Any?, signed: Boolean = true): String? {
        if (b !is Map<*, *>) return "not an object"
        for (k in IntentJs.jsKeys(b)) if (k !in BODY_KEYS) return "unknown member '$k'"
        if (IntentJs.num(b["v"]) != 1.0 || b["kind"] != "pca-intent-required") return "not a pca-intent-required v1"
        for (k in listOf("session", "map_digest", "schema", "pcactn_digest", "action_digest")) if (!IntentJs.b32(b[k])) return "$k must be canonical base64url (32 bytes)"
        val cell = b["cell"]
        if (cell !is Map<*, *> || cell.size != 2 || !cell.containsKey("coords") || !cell.containsKey("verb") || cell["verb"] !is String || (cell["verb"] as String).isEmpty()) return "cell must be {verb, coords}"
        val ce = SignersMore.cellCoordsError(cell["coords"])
        if (ce != null) return ce
        if (b["reason"] != "uncertain") return "reason must be 'uncertain'"
        val q = b["question_id"]
        if (q !is String || !QUESTION_ID_RE.matches(q)) return "question_id must match [A-Za-z0-9_-]{1,64}"
        if (b["friction"] !in FRICTIONS) return "unknown friction tier"
        if (b["delivered_to"] != "wallet" && b["delivered_to"] != "agent") return "delivered_to must be 'wallet' or 'agent'"
        if (!IntentJs.isNonNeg(b["expires_at"])) return "expires_at must be a non-negative safe integer"
        if (signed) {
            val s = b["sig"]
            if (s is Map<*, *>) {
                suiteErr(s["alg"], s.containsKey("alg"))?.let { return "sig.alg: $it" }
                if (s.containsKey("pq_value") && s["pq_value"] !is String) return "sig.pq_value must be a string"
            }
            if (s !is Map<*, *> || s.keys.any { it !in listOf("alg", "kid", "value", "pq_value") } || Pq.resolveSigAlg(s["alg"], s.containsKey("alg")) == null || s["kid"] !is String || s["value"] !is String) {
                return "sig must be {alg, kid, value, pq_value?}"
            }
        } else if (b.containsKey("sig")) return "an unsigned body must not carry sig"
        return null
    }

    /** The site's signed `pca-intent-required` body (`sig = {alg, kid, value, pq_value?}`), pinned by the discovery key entry `kid`. Throws on a malformed unsigned body. */
    @JvmStatic fun signIntentRequired(body: Map<String, Any?>, kid: String, site: Keys.SuiteKey): Map<String, Any?> {
        val bad = intentRequiredShapeError(body, false)
        if (bad != null) throw IllegalArgumentException("signIntentRequired: $bad")
        return SignersMore.signIntentRequired(body, kid, site)
    }

    private fun failV(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    private fun pinned(keys: List<*>, kid: Any?): Map<String, Any?>? {
        for (k in keys) if (k is Map<*, *> && ZkJs.strictEq(ZkJs.get(k, "kid"), kid)) return k as Map<String, Any?>
        return null
    }

    /**
     * Verify a site-signed body against the site's discovery keys (the keys of the action schema). The clock is REQUIRED: a `now` that is not a safe integer is refused,
     * never coerced, so expiry can never be skipped. Never throws: `{ok: true}` or `{ok: false, reason}`.
     */
    @JvmStatic fun verifyIntentRequired(b: Any?, keys: Any?, now: Any?): Map<String, Any?> = try {
        verify(b, keys, now)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        failV("malformed intent_required: ${e.message ?: "invalid"}")
    }

    private fun verify(b: Any?, keys: Any?, now: Any?): Map<String, Any?> {
        if (!IntentJs.isSafeInteger(now)) return failV("the verifier clock is not a safe integer (fail closed)")
        val e = intentRequiredShapeError(b)
        if (e != null) return failV(e)
        val s = b as Map<String, Any?>
        val sig = s["sig"] as Map<String, Any?>
        if (keys !is List<*>) return failV("the site keys must be an array")
        val key = pinned(keys, sig["kid"]) ?: return failV("no site key with kid '${sig["kid"]}'")
        val kse = suiteErr(key["alg"], key.containsKey("alg"))
        if (kse != null) return failV("site key: $kse")
        if (Pq.resolveSigAlg(key["alg"], key.containsKey("alg"))?.alg != Pq.resolveSigAlg(sig["alg"], sig.containsKey("alg"))?.alg) return failV("sig.alg does not match the pinned key suite")
        val pk = key["pk"]
        val pins = if (key.containsKey("pq_pk") && pk is String) linkedMapOf<String, Any?>(pk to key["pq_pk"]) else null
        val body = LinkedHashMap(s)
        body.remove("sig")
        if (!IntentJs.verifyPinnedSuite(key["alg"], key.containsKey("alg"), pk as? String, key["pq_pk"], IntentJs.message(INTENT_REQUIRED_DOMAIN, body), sig["value"], sig["pq_value"], pins)) return failV("site signature invalid")
        if (!(IntentJs.num(now)!! <= IntentJs.num(s["expires_at"])!!)) return failV("the question has expired")
        return linkedMapOf("ok" to true)
    }

    /** [verifyIntentRequired] with the clock REQUIRED: a missing or non-integer `now` is a denial, so expiry can never be skipped. */
    @JvmStatic fun verifyIntentRequiredAt(b: Any?, keys: Any?, now: Any?): Map<String, Any?> =
        if (!IntentJs.isSafeInteger(now)) failV("the verifier clock is not a safe integer (fail closed)") else verifyIntentRequired(b, keys, now)

    /**
     * The RFC 9457 response for an Intent Layer outcome: status 403, the `WWW-Authenticate` challenge and the problem body (`pca` carries the signed body for
     * `intent-required`, which needs it). An unknown kind answers with the reference's `error="undefined"` and no title. `detail` is carried when given.
     */
    @JvmStatic @JvmOverloads
    fun intentProblem(kind: Any?, detail: Any? = ZkJs.UNDEF, body: Any? = null): Map<String, Any?> {
        val params = ArrayList<String>()
        val kindName = kind as? String
        params.add("error=\"${(if (kindName == null) null else ERRORS[kindName]) ?: "undefined"}\"")
        if (kind == "intent-required") {
            if (!ZkJs.truthy(body)) throw IllegalArgumentException("intentProblem: intent-required needs the signed body")
            params.add("session=\"${ZkJs.string(ZkJs.get(body, "session"))}\"")
            params.add("question=\"${ZkJs.string(ZkJs.get(body, "question_id"))}\"")
        }
        val out = LinkedHashMap<String, Any?>()
        out["type"] = PROBLEM_BASE + ZkJs.string(kind)
        val title = if (kindName == null) null else TITLES[kindName]
        if (title != null) out["title"] = title
        out["status"] = Json.Num("403")
        if (detail !== ZkJs.UNDEF) out["detail"] = detail
        if (ZkJs.truthy(body)) out["pca"] = body
        return obj("status" to Json.Num("403"), "headers" to obj("WWW-Authenticate" to "PCA ${params.joinToString(", ")}", "Content-Type" to "application/problem+json"), "body" to out)
    }
}
