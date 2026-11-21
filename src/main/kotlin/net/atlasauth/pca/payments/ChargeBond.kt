package net.atlasauth.pca.payments

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Optimistic
import net.atlasauth.pca.verifier.Pca

/**
 * The opening half of the optimistic fast path for a charge: a bonded claim over the PCActn digest, signed by the agent-leaf key, that the
 * verifier side checks with [Optimistic.claimCheck]. Kept here because the core verifier only carries the checking half.
 */
object ChargeBond {
    private const val IRREVERSIBLE = "irreversible"

    /** The window [openOptimistic] uses when none is requested. */
    const val DEFAULT_WINDOW_MS = 300_000.0

    /** Options of [openOptimistic]; null members take the defaults (window policy default, server time = now, issued_at = server time). */
    class OpenOptions(val bondRef: String, val claimedR: Double) {
        var challengeWindowMs: Double? = null
        var issuedAt: Double? = null
        var serverNow: Double? = null
        var windowPolicy: Optimistic.ChallengeWindowPolicy? = null
        var defaultWindowMs: Double = DEFAULT_WINDOW_MS
    }

    /** The reason a claim's (issued_at, window) is not acceptable against server time and policy, or null when it is. */
    @JvmStatic
    fun validateWindow(issuedAt: Double, windowMs: Double, serverNow: Double, p: Optimistic.ChallengeWindowPolicy): String? {
        if (serverNow.isNaN() || serverNow.isInfinite()) return "server time is not finite"
        if (issuedAt.isNaN() || issuedAt.isInfinite() || windowMs.isNaN() || windowMs.isInfinite()) return "malformed challenge window"
        if (!(Math.abs(issuedAt - serverNow) <= p.maxSkewMs)) return "issued_at is outside the allowed skew of server time"
        if (!(windowMs >= p.minWindowMs)) return "challenge window is below the minimum"
        if (!(windowMs <= p.maxWindowMs)) return "challenge window exceeds the maximum"
        return null
    }

    private fun num(d: Double): Json.Num = Json.Num(if (d == 0.0) "0" else Json.esNumber(d))

    private fun finiteOr(d: Double?, fallback: Double): Double = if (d != null && !d.isNaN() && !d.isInfinite()) d else fallback

    /**
     * Opens a bonded optimistic claim for [pcactn], signed by the agent-leaf key. REFUSES (throws) an irreversible action, a non-finite
     * `claimedR` and a window outside the policy.
     */
    @JvmStatic
    fun openOptimistic(pcactn: Map<String, Any?>?, o: OpenOptions, signer: Keys.EdKey): Map<String, Any?> {
        val action = pcactn?.get("action")
        val rc = if (action is Map<*, *>) action["reversibility_class"] else null
        if (rc == IRREVERSIBLE) throw IllegalArgumentException("openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)")
        if (o.claimedR.isNaN() || o.claimedR.isInfinite()) throw IllegalArgumentException("openOptimistic: claimedR must be finite")
        val policy = o.windowPolicy ?: Optimistic.DEFAULT_POLICY
        val serverNow = finiteOr(o.serverNow, System.currentTimeMillis().toDouble())
        val issuedAt = finiteOr(o.issuedAt, serverNow)
        val windowMs = o.challengeWindowMs ?: o.defaultWindowMs
        val bad = validateWindow(issuedAt, windowMs, serverNow, policy)
        if (bad != null) throw IllegalArgumentException("openOptimistic: $bad")
        val body = LinkedHashMap<String, Any?>()
        body["pcactn_digest"] = Pca.hashCanonical(pcactn)
        body["bond_ref"] = o.bondRef
        body["claimed_r"] = num(o.claimedR)
        body["reversibility_class"] = rc as? String ?: "unknown"
        body["issued_at"] = num(issuedAt)
        body["challenge_window_ms"] = num(windowMs)
        val msg = Pca.concat(Json.utf8(Optimistic.CLAIM_DOMAIN), Json.canonicalize(body).toByteArray(Charsets.UTF_8))
        val claim = LinkedHashMap<String, Any?>(body)
        claim["sig"] = Keys.b64u(signer.sign(msg))
        return claim
    }
}
