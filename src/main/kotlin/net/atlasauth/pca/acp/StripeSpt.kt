package net.atlasauth.pca.acp

import java.util.Locale
import net.atlasauth.pca.acp.AcpJs.def
import net.atlasauth.pca.acp.AcpJs.get
import net.atlasauth.pca.acp.AcpJs.isInt
import net.atlasauth.pca.acp.AcpJs.isObj
import net.atlasauth.pca.jose.Js

/**
 * Stripe Shared Payment Granted Tokens: reads and checks the `shared_payment.granted_token` object and relates it to a PCA delegated
 * payment token. No I/O; whether Stripe accepts a token is Stripe's decision, these checks only refuse what PCA authority forbids.
 */
object StripeSpt {
    const val STRIPE_SPT_OBJECT = "shared_payment.granted_token"
    private val REASONS = listOf("consumed", "expired", "resolved", "revoked")
    private val SPT_ID = Regex("spt_[A-Za-z0-9_]+")
    private val CURRENCY = Regex("[a-z]{3}")
    private val CURRENCY_ANY_CASE = Regex("[A-Za-z]{3}")

    private fun isCurrency(v: Any?): Boolean = AcpJs.matches(CURRENCY, v)

    /** Problems with a Shared Payment Granted Token object (empty = well formed). */
    @JvmStatic
    fun stripeSptProblems(t: Any?): List<String> {
        val p = ArrayList<String>()
        if (!isObj(t)) { p.add("the token must be an object"); return p }
        if (STRIPE_SPT_OBJECT != get(t, "object")) p.add("object must be \"$STRIPE_SPT_OBJECT\"")
        if (!AcpJs.matches(SPT_ID, get(t, "id"))) p.add("id must be an spt_ identifier")
        if (!isInt(get(t, "created"))) p.add("created must be an integer timestamp")
        if (get(t, "livemode") !is Boolean) p.add("livemode must be a boolean")
        val da = get(t, "deactivated_at")
        if (!(def(t, "deactivated_at") && da == null) && !isInt(da)) p.add("deactivated_at must be null or an integer timestamp")
        val dr = get(t, "deactivated_reason")
        if (!(def(t, "deactivated_reason") && dr == null) && !(dr is String && REASONS.contains(dr))) {
            p.add("deactivated_reason must be null or one of consumed, expired, resolved, revoked")
        }
        val u = get(t, "usage_limits")
        if (!isObj(u)) p.add("usage_limits is required")
        else {
            if (!isCurrency(get(u, "currency"))) p.add("usage_limits.currency must be a lowercase three-letter code")
            val max = get(u, "max_amount")
            if (!isInt(max) || Js.num(max)!! < 0) p.add("usage_limits.max_amount must be a non-negative integer in minor units")
            if (get(u, "expires_at") != null && !isInt(get(u, "expires_at"))) p.add("usage_limits.expires_at must be an integer timestamp")
        }
        val ud = get(t, "usage_details")
        if (ud != null) {
            val c = if (isObj(ud)) get(ud, "amount_captured") else null
            if (!isObj(c) || !isInt(get(c, "value")) || Js.num(get(c, "value"))!! < 0 || !isCurrency(get(c, "currency"))) {
                p.add("usage_details.amount_captured needs a non-negative integer value and a lowercase currency")
            }
        }
        for (k in listOf("payment_method_details", "agent_details", "shared_metadata")) {
            if (get(t, k) != null && !isObj(get(t, k))) p.add("$k must be null or an object")
        }
        val pm = get(t, "payment_method_details")
        if (isObj(pm) && get(pm, "type") !is String) p.add("payment_method_details.type must be a string")
        return p
    }

    /** Parse a Shared Payment Granted Token; throws IllegalArgumentException listing every problem. */
    @JvmStatic
    fun parseStripeSpt(t: Any?): Map<String, Any?> {
        val problems = stripeSptProblems(t)
        if (problems.isNotEmpty()) throw IllegalArgumentException("stripe spt: " + problems.joinToString("; "))
        return AcpJs.map(t)
    }

    private fun ok(): Map<String, Any?> = linkedMapOf("ok" to true)

    private fun no(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    /**
     * Can this token still be used for this capture? [use] = `{now (epoch seconds), amount (minor units), currency, livemode? (default true)}`.
     * Refuses a malformed or deactivated or expired token, the wrong mode, another currency, a non-integer amount and one above
     * max_amount minus what was already captured. Returns `{ok}` or `{ok:false, reason}`.
     */
    @JvmStatic
    fun stripeSptUsable(t: Any?, use: Map<String, Any?>): Map<String, Any?> {
        val problems = stripeSptProblems(t)
        if (problems.isNotEmpty()) return no("malformed token: " + problems[0])
        val spt = AcpJs.map(t)
        val now = use["now"]
        val amount = use["amount"]
        if (!isInt(now) || !isInt(amount) || Js.num(amount)!! <= 0) return no("now and amount must be integers and the amount positive")
        val live = use["livemode"] ?: true
        if (live != spt["livemode"]) return no("the token is in the wrong mode")
        if (spt["deactivated_reason"] != null) return no("the token is deactivated (${spt["deactivated_reason"]})")
        if (spt["deactivated_at"] != null && Js.num(spt["deactivated_at"])!! <= Js.num(now)!!) return no("the token is deactivated")
        val lim = AcpJs.map(spt["usage_limits"])
        val exp = lim["expires_at"]
        if (Js.isNumber(exp) && Js.num(now)!! >= Js.num(exp)!!) return no("the token has expired")
        val cur = use["currency"] as? String ?: throw IllegalArgumentException("use.currency must be a string")
        if (lim["currency"] != cur.lowercase(Locale.ROOT)) return no("the capture currency differs from the token currency")
        val captured = if (spt["usage_details"] == null) null else AcpJs.map(AcpJs.map(spt["usage_details"])["amount_captured"])
        if (captured != null && captured["currency"] != lim["currency"]) return no("the captured amount is in another currency")
        val remaining = AcpJs.lng(lim["max_amount"]) - (if (captured != null) AcpJs.lng(captured["value"]) else 0L)
        if (Js.num(amount)!! > remaining) return no("the amount ${AcpJs.str(amount)} exceeds the remaining $remaining")
        return ok()
    }

    /**
     * The `usage_limits` to request for a PCA authority `{maxAmount, currency, expiresAtMs?}`: lowercase currency, integer minor units,
     * expiry in whole seconds (rounded down). Throws IllegalArgumentException for an invalid authority.
     */
    @JvmStatic
    fun stripeUsageLimitsFor(authority: Map<String, Any?>): Map<String, Any?> {
        val max = authority["maxAmount"]
        if (!(AcpJs.isSafeInteger(max) && Js.num(max)!! > 0)) throw IllegalArgumentException("stripe spt: maxAmount must be a positive integer in minor units")
        val cur = authority["currency"]
        if (cur !is String || !CURRENCY_ANY_CASE.matches(cur)) throw IllegalArgumentException("stripe spt: currency must be a three-letter code")
        val hasExp = def(authority, "expiresAtMs")
        val e = Js.num(authority["expiresAtMs"])
        if (hasExp && !(e != null && !e.isNaN() && !e.isInfinite() && e > 0)) throw IllegalArgumentException("stripe spt: expiresAtMs must be a positive epoch-ms time")
        val out = LinkedHashMap<String, Any?>()
        out["currency"] = cur.lowercase(Locale.ROOT)
        out["max_amount"] = max
        if (hasExp) out["expires_at"] = AcpJs.num(Math.floor(e!! / 1000).toLong())
        return out
    }

    /**
     * A Shared Payment Token may be no wider than the delegated payment token it serves: same currency, max_amount not above the delegated
     * amount, and an expiry present and not after the delegated token's. [claims] = `{amount, currency, exp (epoch ms)}`.
     */
    @JvmStatic
    fun stripeSptWithinClaims(t: Any?, claims: Map<String, Any?>): Map<String, Any?> {
        val problems = stripeSptProblems(t)
        if (problems.isNotEmpty()) return no("malformed token: " + problems[0])
        val lim = AcpJs.map(AcpJs.map(t)["usage_limits"])
        val cur = claims["currency"] as? String ?: throw IllegalArgumentException("claims.currency must be a string")
        if (lim["currency"] != cur.lowercase(Locale.ROOT)) return no("the token currency differs from the delegated currency")
        if (!(AcpJs.dblField(claims, "amount").isFinite() && AcpJs.dbl(lim["max_amount"]) <= AcpJs.dblField(claims, "amount"))) {
            return no("max_amount ${AcpJs.str(lim["max_amount"])} exceeds the delegated amount ${AcpJs.str(claims["amount"])}")
        }
        if (!Js.isNumber(lim["expires_at"])) return no("the token has no expiry")
        if (!(AcpJs.dblField(claims, "exp").isFinite() && AcpJs.dbl(lim["expires_at"]) * 1000 <= AcpJs.dblField(claims, "exp"))) return no("the token outlives the delegated payment token")
        return ok()
    }
}
