package net.atlasauth.pca.attesteat

import net.atlasauth.pca.verifier.Json

import java.security.MessageDigest
import net.atlasauth.pca.verifier.Pca

/**
 * EAT evidence for blueprint admission: turns an EAT (RFC 9711) into admission evidence for ONE instance key. The token's signature,
 * issuer, freshness (the server-issued nonce) and RATS appraisal must all pass and its `cnf.jkt` must be the RFC 7638 thumbprint of the
 * instance key, so evidence for one instance cannot admit another. The identity returned is the measured identity the verifier
 * established, never a field the instance supplies separately.
 */
object AttestEatAdmission {
    /** RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url. */
    fun ed25519Jkt(holderPubB64u: String): String {
        val canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"$holderPubB64u\"}"
        return Pca.b64(MessageDigest.getInstance("SHA-256").digest(Json.utf8(canonical)))
    }

    private fun rank(tier: Any?): Int = when (tier) {
        "rejected", "contraindicated" -> 0
        "warning" -> 1
        "affirming" -> 2
        "affirming-hw-rooted" -> 3
        else -> -1
    }

    private fun result(ok: Boolean, bound: Boolean, reason: String?, identity: Map<String, Any?>?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        m["bound"] = bound
        if (identity != null) m["identity"] = identity
        if (reason != null) m["reason"] = reason
        return m
    }

    /**
     * [o]: the [AttestEat.verifyFreshAttestedEAT] options (verifyKey, amd?, now?, maxAgeMs?, ...) plus nonce, instanceKey, policy and
     * `minTier` (`affirming` default, or `affirming-hw-rooted`). Result {ok, bound, identity?, reason?}; anything unverifiable is
     * `ok: false`. (Any unexpected failure reports the reason `TypeError`, the reference's error name.)
     */
    fun eatAdmissionEvidence(eat: Any?, o: Map<String, Any?>): Map<String, Any?> {
        try {
            // An unknown tier has no rank: refuse it before verification instead of admitting any tier.
            if (o.containsKey("minTier") && "affirming" != o["minTier"] && "affirming-hw-rooted" != o["minTier"]) return result(false, false, "invalid minTier", null)
            val rest = LinkedHashMap<String, Any?>(o)
            rest.remove("instanceKey")
            rest.remove("minTier")
            val ik = o["instanceKey"]
            rest["channelBinding"] = linkedMapOf<String, Any?>("jkt" to ed25519Jkt(if (ik is String) ik else ik.toString()))
            val v = AttestEat.verifyFreshAttestedEAT(eat, rest)
            if (v["ok"] != true || v["tier"] == null) {
                val rs = v["reasons"] as List<*>
                return result(false, false, if (rs.isEmpty()) "EAT rejected" else rs[rs.size - 1].toString(), null)
            }
            val minTier: Any? = if (o.containsKey("minTier")) o["minTier"] else "affirming"
            if (!(rank(v["tier"]) >= rank(minTier))) return result(false, true, "appraisal tier ${v["tier"]} is below the minimum", null)
            val claims = v["claims"]
            val m = if (claims is Map<*, *>) AttestEat.rec(claims["measured"]) else null
            if (m == null) return result(true, true, null, null)
            val id = LinkedHashMap<String, Any?>()
            for (k in listOf("runtime_measurement", "model_id", "weights_digest", "operator")) id[k] = m[k]
            return result(true, true, null, id)
        } catch (e: RuntimeException) {
            return result(false, false, "TypeError", null)
        }
    }
}
