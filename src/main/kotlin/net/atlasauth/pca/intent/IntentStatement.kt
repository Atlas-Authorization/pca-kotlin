package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Intent capture and commitment: the principal's own words plus their structured reading, with provenance pointers, signed by the
 * principal (Ed25519; a PQ-suite artifact verifies only under a PQ key the verifier pins). [intentRef] is the content address a
 * grant binds to through the intent goal string.
 */
@Suppress("UNCHECKED_CAST")
object IntentStatement {
    const val INTENT_SIG_DOMAIN = "atlas-pca/intent/v1\u0000"
    const val INTENT_REF_DOMAIN = "atlas-pca/intent-ref/v1"
    const val INTENT_GOAL_PREFIX = "pca-intent:v1:"
    @JvmField val INTENT_SOURCE_KINDS: List<String> = listOf("conversation", "ticket", "document", "form", "other")

    private val BODY_KEYS = listOf("v", "principal", "text", "slots", "sources", "created_at", "nonce")

    private fun statementBody(s: Map<*, *>): Map<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) if (s.containsKey(k)) b[k] = s[k]
        return IntentJs.normalize(b) as Map<String, Any?>
    }

    /** Content address of a statement: suite fields and signatures excluded. */
    @JvmStatic
    fun intentRef(s: Any?): String = Pca.hashCanonical(linkedMapOf("d" to INTENT_REF_DOMAIN, "s" to statementBody(s as Map<*, *>)))

    /** The first shape problem of a statement, or null. */
    internal fun statementShapeError(so: Any?): String? {
        if (so !is Map<*, *>) return "intent statement is not an object"
        val v = IntentKit.num(so["v"])
        if (v == null || v != 1.0) return "unsupported intent statement version"
        if (Pca.decodeB64uStrict(so["principal"], 32) == null) return "principal is not canonical base64url (32 bytes)"
        val text = so["text"]
        if (text !is String || text.isEmpty()) return "text must be a non-empty string"
        if (so["slots"] !is Map<*, *>) return "slots must be an object"
        val sources = so["sources"]
        if (sources !is List<*>) return "sources must be an array"
        for (i in sources.indices) {
            val src = sources[i]
            val kind = if (src is Map<*, *>) src["kind"] else null
            if (src !is Map<*, *> || kind !is String || kind !in INTENT_SOURCE_KINDS) return "sources[$i] has an unknown kind"
            if (src.containsKey("uri") && src["uri"] !is String) return "sources[$i].uri must be a string"
            if (Pca.decodeB64uStrict(src["digest"], 32) == null) return "sources[$i].digest is not canonical base64url (32 bytes)"
        }
        val ca = so["created_at"]
        if (!IntentKit.isInt(ca) || IntentKit.num(ca)!! < 0) return "created_at must be a non-negative safe integer (epoch ms)"
        val nonce = so["nonce"]
        if (nonce !is String || nonce.isEmpty()) return "nonce must be a non-empty string"
        return null
    }

    /** Sign a statement as its principal with the principal's Ed25519 seed (principal defaults to the key's identity; must match when given). */
    @JvmStatic
    fun signIntent(s: Map<String, Any?>, principalSeed: ByteArray): MutableMap<String, Any?> = signIntent(s, Keys.ed25519(Keys.edFromSeed(principalSeed)))

    /** Sign under any registry suite (ML-DSA, hybrid, ...): alg and pq_pk are signed into the statement. */
    @JvmStatic
    fun signIntent(s: Map<String, Any?>, suiteKey: Keys.SuiteKey): MutableMap<String, Any?> {
        val principal = suiteKey.ed?.id() ?: throw IllegalArgumentException("signIntentStatement: signer needs an Ed25519 identity key")
        if (s.containsKey("principal") && principal != s["principal"]) throw IllegalArgumentException("signIntentStatement: principal key mismatch")
        val withP = LinkedHashMap(s)
        withP["principal"] = principal
        val body = statementBody(withP)
        val bad = statementShapeError(body)
        if (bad != null) throw IllegalArgumentException("signIntentStatement: $bad")
        return IntentKit.signSuite(body, suiteKey) { b -> IntentKit.message(INTENT_SIG_DOMAIN, b) }
    }

    private fun verdict(reason: String?): MutableMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["ok"] = reason == null
        if (reason != null) r["reason"] = reason
        return r
    }

    /** {ok: true} or {ok: false, reason}. [pqPins] maps a principal to the PQ key the verifier pins for it. Never throws. */
    @JvmStatic
    @JvmOverloads
    fun verifyIntent(so: Any?, expectedSigner: String? = null, pqPins: Map<String, Any?>? = null): MutableMap<String, Any?> {
        try {
            val bad = statementShapeError(so)
            if (bad != null) return verdict(bad)
            val st = so as Map<*, *>
            if (expectedSigner != null && expectedSigner != st["principal"]) return verdict("principal mismatch")
            val algPresent = st.containsKey("alg")
            val suite = IntentKit.suiteName(st["alg"], algPresent) ?: return verdict("unknown signature suite")
            if (suite == "ed25519" && (st.containsKey("pq_pk") || st.containsKey("pq_sig"))) return verdict("an ed25519 artifact must not carry pq_pk / pq_sig")
            val body = IntentKit.bindSuiteFields(statementBody(st), st["alg"], algPresent, st["pq_pk"], st.containsKey("pq_pk"))
            val msg = IntentKit.message(INTENT_SIG_DOMAIN, body)
            if (!IntentKit.verifyPinnedSuite(st["alg"], algPresent, st["principal"] as String, st["pq_pk"], msg, st["sig"], st["pq_sig"], pqPins)) return verdict("bad signature")
            return verdict(null)
        } catch (e: RuntimeException) {
            return verdict("malformed intent statement: " + e.message)
        }
    }

    /** The goal string that binds a grant to an intent statement (and optionally an Intent Map). */
    @JvmStatic
    @JvmOverloads
    fun intentGoal(ref: String, mapDigest: String? = null): String = INTENT_GOAL_PREFIX + ref + (if (mapDigest != null && mapDigest.isNotEmpty()) ":$mapDigest" else "")

    /** Parse an intent goal string: {intentRef, mapDigest?}, or null when it is not one. */
    @JvmStatic
    fun parseIntentGoal(goal: Any?): Map<String, Any?>? {
        if (goal !is String || !goal.startsWith(INTENT_GOAL_PREFIX)) return null
        val parts = goal.substring(INTENT_GOAL_PREFIX.length).split(":")
        val ref = parts[0]
        val map = if (parts.size > 1) parts[1] else null
        if (ref.isEmpty() || parts.size > 2) return null
        val r = LinkedHashMap<String, Any?>()
        r["intentRef"] = ref
        if (map != null && map.isNotEmpty()) r["mapDigest"] = map
        return r
    }
}
