package net.atlasauth.pca.connect

import net.atlasauth.pca.events.Events
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json

/**
 * One-time-use guard for a signature-verified PCActn (the vault's replay check): the nonce is consumed once under a key that binds the
 * audience, the grant and the leaf holder. Run it only AFTER the PCActn verified, last of the authorization checks. Never throws: a store
 * failure is a denial. Check order follows the formally verified replay decision (no store call before every pre-check passed).
 */
object ReplayGuard {
    internal const val MAX_LIFETIME_MS = 3_600_000L
    internal const val MAX_SKEW_MS = 60_000L
    internal const val MAX_REPLAY_COMPONENT_LEN = 512
    internal const val MAX_AUD_LEN = 256
    internal const val MAX_NONCE_LEN = 128
    internal const val MAX_SAFE = 9007199254740991L

    /** The guard's verdict: [ok], else a denial [code] (malformed, audience, not_yet_valid, expired, replay, store_unavailable) and a reason. */
    class Verdict internal constructor(val ok: Boolean, val code: String?, val reason: String?)

    private fun deny(code: String, reason: String) = Verdict(false, code, reason)

    private fun u8len(s: String): Int = Json.utf8(s).size

    private fun safeNonNegInt(o: Any?): Boolean {
        if (!Json.isSafeInt(o)) return false
        if (o is Json.Num && o.raw.startsWith("-")) return false // -0 is not a counter / time
        return Json.asLong(o) >= 0
    }

    private fun wellFormed(s: String): Boolean = s.isNotEmpty() && !Json.hasLoneSurrogate(s) && u8len(s) <= MAX_REPLAY_COMPONENT_LEN

    /** Decide whether [p] (a parsed PCActn) may be accepted once, for the verifier audience [aud] at [now] (epoch ms). */
    fun guard(store: Authorize.StateStore, p: Any?, aud: String?, now: Long): Verdict {
        val objectOk = p is Map<*, *>
        val pm: Map<*, *>? = p as? Map<*, *>
        val chain = pm?.get("cap_chain")
        val leaf = if (chain is List<*> && chain.isNotEmpty()) chain[chain.size - 1] else null
        val leafOk = leaf is Map<*, *> && leaf["holder"] is String && pm != null && pm["grant_ref"] is String
        val componentsOk = leafOk && wellFormed(pm!!["grant_ref"] as String) && wellFormed((leaf as Map<*, *>)["holder"] as String)
        val hasNonce = pm != null && pm.containsKey("nonce")
        val nonce = if (hasNonce) pm!!["nonce"] else null
        val nonceOk = hasNonce && nonce is String && nonce.isNotEmpty() && u8len(nonce) <= MAX_NONCE_LEN && !Json.hasLoneSurrogate(nonce)

        val nowOk = now >= -MAX_SAFE && now <= MAX_SAFE
        val verifierAudOk = aud != null && aud.isNotEmpty() && u8len(aud) <= MAX_AUD_LEN && !Json.hasLoneSurrogate(aud)
        val audMatches = pm != null && pm["aud"] is String && pm["aud"] == aud
        val iatOk = pm != null && safeNonNegInt(pm["iat"])
        val expOk = pm != null && safeNonNegInt(pm["exp"])
        val iat = if (iatOk) Json.asLong(pm!!["iat"]) else 0L
        val exp = if (expOk) Json.asLong(pm!!["exp"]) else 0L
        val counterOk = pm != null && safeNonNegInt(pm["counter"])
        val windowOk = iatOk && expOk && exp > iat && exp - iat <= MAX_LIFETIME_MS

        // formally verified Pre
        if (!nowOk || !verifierAudOk || !objectOk) {
            return deny("malformed", if (!nowOk) "verifier clock is not an integer epoch-ms" else if (!verifierAudOk) "verifier audience is invalid" else "not a PCActn")
        }
        if (!audMatches) return deny("audience", "the PCActn is for another audience")
        if (!windowOk) return deny("malformed", "iat / exp are not a valid bounded window")
        if (iat > now + MAX_SKEW_MS) return deny("not_yet_valid", "iat is in the future beyond the clock-skew allowance")
        if (now > exp) return deny("expired", "the PCActn has expired")
        if (!leafOk) return deny("malformed", "no leaf holder / grant")
        if (!componentsOk) return deny("malformed", "grant / holder is not a bounded string")
        if (!counterOk) return deny("malformed", "counter is not a non-negative safe integer")
        // the retention horizon must be representable
        if (exp + MAX_SKEW_MS > MAX_SAFE) return deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)")
        val retainUntil = exp + MAX_SKEW_MS
        // nonce stage (a nonce is required: requireNonce is on)
        if (!hasNonce || !nonceOk) return deny("malformed", if (hasNonce) "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" else "a nonce is required")
        try {
            val key = Events.replayKey("pca-nonce/v1", aud, pm!!["grant_ref"] as String, (leaf as Map<*, *>)["holder"] as String, nonce as String)
            if (!store.consumeOnce(key, retainUntil, now)) return deny("replay", "nonce already consumed")
        } catch (e: RuntimeException) {
            return deny("store_unavailable", "replay store failed closed: " + (e.message ?: "error"))
        }
        return Verdict(true, null, null)
    }
}
