package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * A signed runtime observation against an Intent Map: y = 0 says the outcome should NOT have been allowed (a divergence), y = 1 confirms it.
 * Signed by whoever observed it (Ed25519; a PQ-suite artifact verifies only under a PQ key the verifier pins).
 */
@Suppress("UNCHECKED_CAST")
object IntentObservation {
    const val INTENT_OBS_SIG_DOMAIN = "atlas-pca/intent-obs/v1\u0000"
    @JvmField val INTENT_OBSERVATION_SOURCES: List<String> = listOf("runtime", "witness", "elicitation", "import")
    private val BODY_KEYS = listOf("v", "map_digest", "verb", "values", "y", "source", "observed_at", "pcactn_digest", "signer")

    private fun obsBody(o: Map<*, *>): Map<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) if (o.containsKey(k)) b[k] = o[k]
        return IntentJs.normalize(b) as Map<String, Any?>
    }

    private fun isNum(o: Any?, v: Double): Boolean {
        val d = IntentKit.num(o)
        return d != null && d == v
    }

    /** The first shape problem of an observation, or null. */
    internal fun obsShapeError(oo: Any?): String? {
        if (oo !is Map<*, *> || !isNum(oo["v"], 1.0)) return "not an intent observation v1"
        if (Pca.decodeB64uStrict(oo["map_digest"], 32) == null) return "map_digest is not canonical base64url (32 bytes)"
        val verb = oo["verb"]
        if (verb !is String || verb.isEmpty()) return "verb must be a non-empty string"
        val values = oo["values"]
        var ok = values is Map<*, *>
        if (ok) {
            for (x in (values as Map<*, *>).values) {
                val d = IntentKit.num(x)
                if (x !is String && !(d != null && !d.isNaN() && !d.isInfinite())) ok = false
            }
        }
        if (!ok) return "values must map paths to numbers or strings"
        if (!isNum(oo["y"], 0.0) && !isNum(oo["y"], 1.0)) return "y must be 0 or 1"
        val source = oo["source"]
        if (source !is String || source !in INTENT_OBSERVATION_SOURCES) return "unknown observation source"
        if (!IntentKit.isInt(oo["observed_at"]) || IntentKit.num(oo["observed_at"])!! < 0) return "observed_at must be a non-negative safe integer"
        if (oo.containsKey("pcactn_digest") && Pca.decodeB64uStrict(oo["pcactn_digest"], 32) == null) return "pcactn_digest is not canonical base64url (32 bytes)"
        if (Pca.decodeB64uStrict(oo["signer"], 32) == null) return "signer is not canonical base64url (32 bytes)"
        return null
    }

    /** Sign an observation ({map_digest, verb, values, y, source, observed_at, pcactn_digest?}) as the holder of an Ed25519 seed. */
    @JvmStatic
    fun signIntentObservation(o: Map<String, Any?>, signerSeed: ByteArray): MutableMap<String, Any?> = signIntentObservation(o, Keys.ed25519(Keys.edFromSeed(signerSeed)))

    /** Sign under any registry suite (ML-DSA, hybrid, ...): alg and pq_pk are signed into the observation. */
    @JvmStatic
    fun signIntentObservation(o: Map<String, Any?>, key: Keys.SuiteKey): MutableMap<String, Any?> {
        val ed = key.ed ?: throw IllegalArgumentException("signIntentObservation: signer needs an Ed25519 identity key")
        val inp = LinkedHashMap(o)
        inp["v"] = 1L
        inp["signer"] = ed.id()
        val body = obsBody(inp)
        val bad = obsShapeError(body)
        if (bad != null) throw IllegalArgumentException("signIntentObservation: $bad")
        return IntentKit.signSuite(body, key) { b -> IntentKit.message(INTENT_OBS_SIG_DOMAIN, b) }
    }

    private fun verdict(reason: String?): MutableMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["ok"] = reason == null
        if (reason != null) r["reason"] = reason
        return r
    }

    /** {ok: true} or {ok: false, reason}. Never throws. */
    @JvmStatic
    @JvmOverloads
    fun verifyIntentObservation(oo: Any?, expectedSigner: String? = null, pqPins: Map<String, Any?>? = null): MutableMap<String, Any?> {
        try {
            val bad = obsShapeError(oo)
            if (bad != null) return verdict(bad)
            val ob = oo as Map<*, *>
            if (expectedSigner != null && expectedSigner != ob["signer"]) return verdict("signer mismatch")
            val algPresent = ob.containsKey("alg")
            val suite = IntentKit.suiteName(ob["alg"], algPresent) ?: return verdict("unknown signature suite")
            if (suite == "ed25519" && (ob.containsKey("pq_pk") || ob.containsKey("pq_sig"))) return verdict("an ed25519 artifact must not carry pq_pk / pq_sig")
            val body = IntentKit.bindSuiteFields(obsBody(ob), ob["alg"], algPresent, ob["pq_pk"], ob.containsKey("pq_pk"))
            val msg = IntentKit.message(INTENT_OBS_SIG_DOMAIN, body)
            if (!IntentKit.verifyPinnedSuite(ob["alg"], algPresent, ob["signer"] as String, ob["pq_pk"], msg, ob["sig"], ob["pq_sig"], pqPins)) return verdict("bad signature")
            return verdict(null)
        } catch (e: RuntimeException) {
            return verdict("malformed intent observation: " + e.message)
        }
    }
}
