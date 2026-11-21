package net.atlasauth.pca.payments

import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import net.atlasauth.pca.payments.PayJs.copy
import net.atlasauth.pca.payments.PayJs.get
import net.atlasauth.pca.payments.PayJs.has
import net.atlasauth.pca.payments.PayJs.jn
import net.atlasauth.pca.payments.PayJs.map
import net.atlasauth.pca.payments.PayJs.num
import net.atlasauth.pca.payments.PayJs.str
import net.atlasauth.pca.verifier.Json

/**
 * Spend rails: a virtual card (or any instrument) whose limits mirror the grant, the real-time authorization callback that answers from
 * [Payments.authorizeCharge], settlement reconciliation, the Shared Payment Token limits and the Stripe Issuing adapter (the reference's rails,
 * spt-limits and rails-stripe modules). A rail answer is only ever "approve" when the PCA decision is `auto`; a step-up, a deny, an unknown
 * card, a timeout or an exception all decline.
 */
@Suppress("UNCHECKED_CAST")
object Rails {
    const val STRIPE_WEBHOOK_TOLERANCE_SEC = 300
    const val STRIPE_API_VERSION = "2025-03-31.basil"

    /** Action-kit convention: a custom trait `mcc.c5734` on the verb says the verb may spend in MCC 5734. */
    @JvmField val MCC_TRAIT_RE = Regex("^mcc\\.c(\\d{4})$")

    // ---- Shared Payment Token limits ----

    /**
     * The `usage_limits` of a Stripe Shared Payment Token that fit what the mandate lets an agent spend WITHOUT a human co-sign: at most the
     * auto-approve threshold, at most the remaining autonomous budget, in the mandate currency, expiring with the mandate period. Throws when no
     * autonomous capacity is left or the mandate has ended at [now].
     */
    @JvmStatic
    fun sharedPaymentTokenLimits(mandate: Map<String, Any?>, now: Double): Map<String, Any?> {
        if (now.isNaN() || now.isInfinite()) throw IllegalArgumentException("sharedPaymentTokenLimits: now must be an epoch-ms time")
        val t = mandate["terms"]
        val budget = Math.floor(num(get(get(mandate, "budget"), "B")) ?: Double.NaN)
        val thr = num(get(t, "autoApproveThreshold"))
        val max = if (thr == null) Double.NaN else Math.min(thr, budget)
        if (!PayJs.isSafeInteger(max) || max <= 0) throw IllegalArgumentException("sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed")
        val periodEnd: Double? = if (has(t, "periodEnd")) (num(get(t, "periodEnd")) ?: Double.NaN) else null
        if (periodEnd != null && !periodEnd.isFinite()) throw IllegalArgumentException("sharedPaymentTokenLimits: periodEnd must be an epoch-ms time")
        if (periodEnd != null && !(now < periodEnd)) throw IllegalArgumentException("sharedPaymentTokenLimits: the mandate period has ended")
        val out = map("currency" to (get(t, "currency") as String).lowercase(Locale.ROOT), "max_amount" to jn(max))
        if (periodEnd != null) out["expires_at"] = jn(Math.floor(periodEnd / 1000))
        return out
    }

    // ---- rail limits ----

    /** The MCC codes named by `mcc.cNNNN` traits, sorted and de-duplicated. */
    @JvmStatic
    fun categoriesFromTraits(traits: List<*>): List<Any?> {
        val out = java.util.TreeSet<String>()
        for (t in traits) {
            if (t !is String) continue
            val m = MCC_TRAIT_RE.matchEntire(t)
            if (m != null) out.add(m.groupValues[1])
        }
        return ArrayList<Any?>(out)
    }

    private fun sortStrings(l: MutableList<Any?>) = l.sortWith(Comparator { a, b -> (a as String).compareTo(b as String) })

    /**
     * The limits an instrument for this mandate may carry. [opts]: actionTraits (list of strings) and allowAnyCategory (boolean). No autonomous
     * capacity left throws; an empty category intersection throws; with no category control the call is refused unless allowAnyCategory.
     */
    @JvmStatic
    fun railLimits(mandate: Map<String, Any?>, now: Double, opts: Map<String, Any?>?): Map<String, Any?> {
        val spt = sharedPaymentTokenLimits(mandate, now)
        val total = Math.floor(num(get(get(mandate, "budget"), "B"))!!)
        val fromMandate = ArrayList(get(mandate["terms"], "categories") as List<Any?>)
        val at = opts?.get("actionTraits")
        val fromTraits = categoriesFromTraits(if (at == null) ArrayList<Any?>() else at as List<*>)
        val categories: MutableList<Any?>
        if (fromMandate.isNotEmpty() && fromTraits.isNotEmpty()) {
            categories = ArrayList()
            for (c in fromMandate) if (fromTraits.contains(c)) categories.add(c)
            sortStrings(categories)
            if (categories.isEmpty()) throw IllegalArgumentException("railLimits: the action traits and the mandate categories do not intersect; nothing may be spent")
        } else {
            categories = ArrayList(if (fromMandate.isNotEmpty()) fromMandate else fromTraits)
            sortStrings(categories)
        }
        if (categories.isEmpty() && opts?.get("allowAnyCategory") != true) {
            throw IllegalArgumentException("railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category")
        }
        val out = map(
            "currency" to (get(mandate["terms"], "currency") as String).uppercase(Locale.ROOT), "perAuthorizationMax" to spt["max_amount"],
            "totalMax" to jn(total), "categories" to categories, "merchants" to ArrayList(get(mandate["terms"], "merchants") as List<Any?>),
        )
        if (spt.containsKey("expires_at")) out["expiresAt"] = jn(num(spt["expires_at"])!! * 1000)
        return out
    }

    // ---- the real-time authorization callback ----

    /** The instrument a rail request is for. [grant] is the one the caller verified or loaded from its own store; [budgetKey] null = the grant hash. */
    class InstrumentBinding(val mandate: Map<String, Any?>, val grant: Any?, val budgetKey: String?)

    /** A step-up cannot wait at a card terminal: it is declined, and this hook may notify the principal. */
    fun interface StepUpHook {
        @Throws(Exception::class)
        fun onStepUp(authorization: Map<String, Any?>, decision: Map<String, Any?>)
    }

    /** Options of [createRailAuthorizer]. */
    class RailAuthorizerOptions(var instruments: (String) -> InstrumentBinding?, var store: ChargeBudgetStore?) {
        var decider: Payments.Decider? = null

        /** Answer by this many ms or decline (default 1500). */
        var latencyBudgetMs: Double = 1500.0
        var now: () -> Long = { System.currentTimeMillis() }
        var onStepUp: StepUpHook? = null
    }

    private fun decline(vararg reasons: String): Map<String, Any?> = map("approved" to false, "reasons" to ArrayList<Any?>(reasons.toList()))

    private fun nonEmptyStr(o: Any?): Boolean = o is String && o.isNotEmpty()

    private fun decideRail(opts: RailAuthorizerOptions, a: Map<String, Any?>?): Map<String, Any?> {
        if (a == null || a["id"] !is String || a["instrumentId"] !is String || (a["id"] as String).isEmpty()) return decline("malformed_authorization")
        if (!PayJs.isSafeInteger(a["amount"]) || num(a["amount"])!! <= 0) return decline("amount_not_positive_minor_units")
        if (!nonEmptyStr(a["currency"])) return decline("currency_missing")
        if (!nonEmptyStr(a["merchantId"])) return decline("merchant_unknown")
        val inst = opts.instruments(a["instrumentId"] as String) ?: return decline("instrument_unknown")
        val charge = map("merchant" to a["merchantId"], "amount" to a["amount"], "currency" to (a["currency"] as String).uppercase(Locale.ROOT))
        if (has(a, "mcc")) charge["category"] = a["mcc"]
        charge["now"] = jn(opts.now().toDouble())
        val d = Payments.authorizeChargeAtomic(inst.mandate, charge, inst.grant, opts.store, inst.budgetKey, opts.decider)
        val outcome = d["outcome"]
        if (outcome == "auto") return map("approved" to true, "reasons" to ArrayList<Any?>(), "decision" to d)
        val dr = d["reasons"] as? List<Any?> ?: ArrayList()
        if (outcome == "step_up") {
            try {
                opts.onStepUp?.onStepUp(a, d)
            } catch (e: Exception) {
                // a failing notifier must not change the answer
            }
            val r = ArrayList<Any?>()
            r.add("step_up_required")
            r.addAll(dr)
            return map("approved" to false, "reasons" to r, "decision" to d)
        }
        val r = ArrayList<Any?>(dr)
        if (r.isEmpty()) r.add("denied")
        return map("approved" to false, "reasons" to r, "decision" to d)
    }

    private val POOL = Executors.newCachedThreadPool(ThreadFactory { r -> Thread(r, "pca-rail-authorizer").also { it.isDaemon = true } })

    /** The single code path from a rail request to a PCA decision. Total: every failure (including a timeout) is a decline. Blocks the caller. */
    @JvmStatic
    fun createRailAuthorizer(opts: RailAuthorizerOptions): (Map<String, Any?>?) -> Map<String, Any?> {
        val budgetMs = opts.latencyBudgetMs
        if (budgetMs.isNaN() || budgetMs.isInfinite() || budgetMs <= 0) throw IllegalArgumentException("createRailAuthorizer: latencyBudgetMs must be positive")
        return { a ->
            val f = POOL.submit(Callable { try { decideRail(opts, a) } catch (t: Throwable) { decline("authorizer_error") } })
            try {
                // shortcut: a decision that finishes after the timeout may still have debited the budget with no approval sent (under-spend, the safe direction)
                f.get(Math.ceil(budgetMs).toLong(), TimeUnit.MILLISECONDS)
            } catch (e: TimeoutException) {
                f.cancel(true)
                decline("latency_budget_exceeded")
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                decline("authorizer_error")
            } catch (e: ExecutionException) {
                decline("authorizer_error")
            }
        }
    }

    // ---- settlement ----

    /**
     * Compare what settled with what PCA approved. `{ok: true}` only on an exact fit; any excess, a different merchant or currency, or a second
     * capture is `{ok: false, reasons, action: "freeze_grant"}`. No classifier; the caller applies the action.
     */
    @JvmStatic
    fun reconcileSettlement(approved: Map<String, Any?>, s: Map<String, Any?>): Map<String, Any?> {
        val reasons = ArrayList<Any?>()
        if (s["authorizationId"] != approved["id"]) reasons.add("authorization_id_mismatch")
        if (gt(s["amount"], approved["amount"])) reasons.add("settled_more_than_approved")
        if ((s["currency"] as String).uppercase(Locale.ROOT) != (approved["currency"] as String).uppercase(Locale.ROOT)) reasons.add("currency_mismatch")
        if (s["merchantId"] != approved["merchantId"]) reasons.add("merchant_mismatch")
        if (gt(s["captures"], Json.Num("1"))) reasons.add("second_capture")
        return if (reasons.isEmpty()) map("ok" to true) else map("ok" to false, "reasons" to reasons, "action" to "freeze_grant")
    }

    private fun gt(a: Any?, b: Any?): Boolean = PayJs.toNumber(a) > PayJs.toNumber(b)

    // ---- Stripe Issuing ----

    /**
     * The form parameters for `POST /v1/issuing/cards` (virtual, active) that carry the rail limits. Throws if an MCC has no Stripe category name.
     * [categoryNames] maps MCC to the Stripe name; [metadata] may be null.
     */
    @JvmStatic
    fun stripeCardParams(limits: Map<String, Any?>, categoryNames: Map<String, String>, cardholder: String, metadata: Map<String, String>?): Map<String, String> {
        val p = LinkedHashMap<String, String>()
        p["cardholder"] = cardholder
        p["type"] = "virtual"
        p["status"] = "active"
        p["currency"] = (limits["currency"] as String).lowercase(Locale.ROOT)
        p["spending_controls[spending_limits][0][amount]"] = str(limits["perAuthorizationMax"])
        p["spending_controls[spending_limits][0][interval]"] = "per_authorization"
        p["spending_controls[spending_limits][1][amount]"] = str(limits["totalMax"])
        p["spending_controls[spending_limits][1][interval]"] = "all_time"
        val cats = limits["categories"] as List<Any?>
        for (i in cats.indices) {
            val mcc = cats[i] as String
            val name = categoryNames[mcc] ?: throw IllegalArgumentException("stripeCardParams: no Stripe category name for MCC $mcc")
            p["spending_controls[allowed_categories][$i]"] = name
        }
        if (metadata != null) for ((k, v) in metadata) p["metadata[$k]"] = v
        return p
    }

    private val T_RE = Regex("[0-9]{1,12}")
    private val HEX64 = Regex("[0-9a-f]{64}")

    private fun hmac(secret: String, payload: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(Json.utf8(secret), "HmacSHA256"))
        return mac.doFinal(Json.utf8(payload))
    }

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder()
        for (x in b) sb.append(Character.forDigit((x.toInt() shr 4) and 15, 16)).append(Character.forDigit(x.toInt() and 15, 16))
        return sb.toString()
    }

    private fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    /** Verify a `Stripe-Signature` header over the RAW body. Total; false on anything malformed, stale (beyond tolerance) or mismatched. */
    @JvmStatic
    @JvmOverloads
    fun verifyStripeSignature(rawBody: String?, header: String?, secret: String?, nowSec: Double, toleranceSec: Double = STRIPE_WEBHOOK_TOLERANCE_SEC.toDouble()): Boolean {
        try {
            if (rawBody == null || header == null || secret == null || secret.isEmpty() || !(toleranceSec.isFinite() && toleranceSec > 0)) return false
            var t: String? = null
            val v1 = ArrayList<String>()
            for (part in header.split(",")) {
                val i = part.indexOf('=')
                if (i < 0) continue
                val k = PayJs.jsTrim(part.substring(0, i))
                val v = PayJs.jsTrim(part.substring(i + 1))
                if (k == "t") t = v else if (k == "v1") v1.add(v)
            }
            if (t == null || !T_RE.matches(t) || v1.isEmpty()) return false
            if (!(Math.abs(nowSec - t.toDouble()) <= toleranceSec)) return false
            val want = hmac(secret, "$t.$rawBody")
            var ok = false
            for (sig in v1) if (HEX64.matches(sig) && MessageDigest.isEqual(unhex(sig), want)) ok = true
            return ok
        } catch (e: Exception) {
            return false
        }
    }

    /** The header Stripe would send (tests and local tooling): `t=<tSec>,v1=<hex hmac>`. */
    @JvmStatic
    fun signStripePayload(rawBody: String, secret: String, tSec: Long): String = "t=$tSec,v1=" + hex(hmac(secret, "$tSec.$rawBody"))

    private fun obj(v: Any?): Map<String, Any?>? = if (v is Map<*, *>) copy(v) else null

    /** Normalise an `issuing_authorization.request` event; null when it is not a well-formed request with a pending amount. */
    @JvmStatic
    fun stripeAuthorizationFromEvent(event: Any?): Map<String, Any?>? {
        val e = obj(event)
        if (e == null || e["type"] != "issuing_authorization.request") return null
        val a = obj(get(obj(e["data"]), "object"))
        val pending = obj(get(a, "pending_request"))
        val card = obj(get(a, "card"))
        val merchant = obj(get(a, "merchant_data"))
        if (a == null || pending == null || a["id"] !is String || card == null || card["id"] !is String) return null
        val amount = pending["amount"]
        val currency = pending["currency"]
        if (num(amount) == null || currency !is String) return null
        val out = map("id" to a["id"], "instrumentId" to card["id"], "amount" to amount, "currency" to currency)
        val nid = get(merchant, "network_id")
        if (nid is String && nid.isNotEmpty()) out["merchantId"] = nid
        val cc = get(merchant, "category_code")
        if (cc is String) out["mcc"] = cc
        return out
    }

    /** Normalise an `issuing_transaction.created` capture into a settlement (a capture amount is negative in Stripe's ledger); null otherwise. */
    @JvmStatic
    fun stripeSettlementFromTransaction(txn: Any?): Map<String, Any?>? {
        val t = obj(txn)
        val m = obj(get(t, "merchant_data"))
        if (t == null || t["type"] != "capture" || t["authorization"] !is String || num(t["amount"]) == null || t["currency"] !is String) return null
        val out = map("authorizationId" to t["authorization"], "amount" to jn(-num(t["amount"])!!), "currency" to t["currency"])
        if (get(m, "network_id") is String) out["merchantId"] = get(m, "network_id")
        out["captures"] = Json.Num("1")
        return out
    }

    /** Options of [stripeIssuingWebhook]. [secret] is the endpoint's signing secret; [authorize] is normally what [createRailAuthorizer] returned. */
    class StripeWebhookOptions(var secret: String?, var authorize: (Map<String, Any?>) -> Map<String, Any?>) {
        var stripeVersion: String = STRIPE_API_VERSION
        var nowSec: () -> Double = { Math.floor(System.currentTimeMillis() / 1000.0) }
        var toleranceSec: Double = STRIPE_WEBHOOK_TOLERANCE_SEC.toDouble()
    }

    private fun reply(status: Int, body: String, version: String): Map<String, Any?> =
        map("status" to jn(status.toDouble()), "headers" to map("Stripe-Version" to version, "Content-Type" to "application/json"), "body" to body)

    /**
     * The handler body for the `issuing_authorization.request` endpoint: a bad signature is 400 (nothing is decided), a request event gets 200
     * `{approved}` from the PCA decision, any other event type gets 200 `{}`. `amount` is never sent. Returns `{status, headers, body}`.
     */
    @JvmStatic
    fun stripeIssuingWebhook(opts: StripeWebhookOptions, rawBody: String?, signature: String?): Map<String, Any?> {
        val version = opts.stripeVersion
        if (!verifyStripeSignature(rawBody, signature, opts.secret, opts.nowSec(), opts.toleranceSec)) return reply(400, "{\"error\":\"bad_signature\"}", version)
        val event = try { Json.parseLenient(rawBody) } catch (e: RuntimeException) { return reply(400, "{\"error\":\"bad_json\"}", version) }
        val ev = obj(event)
        if (ev == null || ev["type"] != "issuing_authorization.request") return reply(200, "{}", version)
        val auth = stripeAuthorizationFromEvent(event) ?: return reply(200, "{\"approved\":false}", version)
        val v = opts.authorize(auth)
        return reply(200, if (v["approved"] == true) "{\"approved\":true}" else "{\"approved\":false}", version)
    }
}
