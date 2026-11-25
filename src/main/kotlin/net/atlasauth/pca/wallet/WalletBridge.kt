package net.atlasauth.pca.wallet

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.OracleFacts
import net.atlasauth.pca.verifier.Pq
import net.atlasauth.pca.verifier.SignersMore

/** The core rule the wallet needs: verification of a site-signed `pca-intent-required` body against the site's discovery keys. */
@Suppress("UNCHECKED_CAST")
internal object WalletBridge {
    private val BODY_KEYS = listOf("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig")
    private val QID = Regex("[A-Za-z0-9_-]{1,64}")

    private fun signedShapeError(bO: Any?): String? {
        if (bO !is Map<*, *>) return "not an object"
        for (k in bO.keys) if (k !in BODY_KEYS) return "unknown member '$k'"
        if (!OracleFacts.isOne(bO["v"]) || "pca-intent-required" != bO["kind"]) return "not a pca-intent-required v1"
        for (k in listOf("session", "map_digest", "schema", "pcactn_digest", "action_digest")) if (!IntentJs.b32(bO[k])) return "$k must be canonical base64url (32 bytes)"
        val cell = bO["cell"]
        if (cell !is Map<*, *> || cell.size != 2 || !cell.containsKey("coords") || cell["verb"] !is String || (cell["verb"] as String).isEmpty()) return "cell must be {verb, coords}"
        val ce = SignersMore.cellCoordsError(cell["coords"])
        if (ce != null) return ce
        if ("uncertain" != bO["reason"]) return "reason must be 'uncertain'"
        if (bO["question_id"] !is String || !QID.matches(bO["question_id"] as String)) return "question_id must match [A-Za-z0-9_-]{1,64}"
        if (bO["friction"] !in listOf("tap", "hold", "typed", "device")) return "unknown friction tier"
        if ("wallet" != bO["delivered_to"] && "agent" != bO["delivered_to"]) return "delivered_to must be 'wallet' or 'agent'"
        if (!IntentJs.isNonNeg(bO["expires_at"])) return "expires_at must be a non-negative safe integer"
        val s = bO["sig"]
        if (s is Map<*, *>) {
            val se = IntentJs.suiteError(s["alg"], s.containsKey("alg"))
            if (se != null) return "sig.alg: $se"
            if (s.containsKey("pq_value") && s["pq_value"] != null && s["pq_value"] !is String) return "sig.pq_value must be a string"
        }
        var okSig = s is Map<*, *>
        if (s is Map<*, *>) {
            for (k in s.keys) if (k !in listOf("alg", "kid", "value", "pq_value")) okSig = false
            if (Pq.resolveSigAlg(s["alg"], s.containsKey("alg")) == null || s["kid"] !is String || s["value"] !is String) okSig = false
        }
        if (!okSig) return "sig must be {alg, kid, value, pq_value?}"
        return null
    }

    /** Verify a site-signed intent_required body against the site's discovery keys at [now]: null when valid, else the reason. */
    fun verifyIntentRequired(b: Any?, keys: Any?, now: Any?): String? {
        try {
            if (!IntentJs.isSafeInteger(now)) return "the verifier clock is not a safe integer (fail closed)"
            val e = signedShapeError(b)
            if (e != null) return e
            val s = b as Map<String, Any?>
            val sig = s["sig"] as Map<String, Any?>
            if (keys !is List<*>) return "the site keys must be an array"
            var key: Map<String, Any?>? = null
            for (k in keys) if (k is Map<*, *> && sig["kid"] == k["kid"]) { key = k as Map<String, Any?>; break }
            if (key == null) return "no site key with kid '${sig["kid"]}'"
            val kse = IntentJs.suiteError(key["alg"], key.containsKey("alg"))
            if (kse != null) return "site key: $kse"
            val ka = IntentJs.suiteOf(key)
            val sa = IntentJs.suiteOf(sig)
            if (ka == null || ka != sa) return "sig.alg does not match the pinned key suite"
            val pk = key["pk"] as String?
            val pin = if (key.containsKey("pq_pk") && key["pq_pk"] != null) IntentJs.pin(pk as String, key["pq_pk"]) else null
            val body = LinkedHashMap(s)
            body.remove("sig")
            val msg = IntentJs.message(SignersMore.INTENT_REQUIRED_DOMAIN, body)
            if (!IntentJs.verifyPinnedSuite(ka, true, pk, key["pq_pk"], msg, sig["value"], sig["pq_value"], pin)) return "site signature invalid"
            if (!(IntentJs.num(now)!! <= IntentJs.num(s["expires_at"])!!)) return "the question has expired"
            return null
        } catch (err: RuntimeException) {
            return "malformed intent_required: " + err.message
        }
    }
}
