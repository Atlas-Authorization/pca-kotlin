package net.atlasauth.pca.ap2

import java.math.BigInteger
import java.util.Locale

/**
 * Settlement backends: the rails PCA's governance feeds. STRUCTURAL ONLY, no network.
 *
 * A backend turns a payment mandate that has ALREADY been verified into the rail's wire shape. Amounts are the mandate's
 * integer minor units; nothing here accepts a decimal. Mandates are parsed JSON (Map, List, String, Boolean, Json.Num, null).
 */
@Suppress("UNCHECKED_CAST")
object Settlement {
    /** Context the caller supplies for building a rail-specific settlement payload (every field optional). */
    class SettlementContext {
        /** Protected resource URL (x402). */
        var resourceUrl: String? = null

        /** Payee address / account (x402 `payTo`, Stripe `on_behalf_of`). */
        var payTo: String? = null

        /** Rail network, e.g. an x402 chain id like `base-sepolia`. */
        var network: String? = null

        /** x402 `asset`: the token contract address. Defaults to the mandate's currency code (a placeholder; supply the address). */
        var asset: String? = null

        /** x402: decimals of the asset (a number), used to convert the mandate amount to atomic units. Default 6 (USDC). */
        var decimals: Any? = null

        /** x402 `maxTimeoutSeconds` (a number): how long the payer has to complete payment. Default 60. */
        var maxTimeoutSeconds: Any? = null

        companion object {
            /** A context from its JSON object form (members named as in the TypeScript option bag). */
            @JvmStatic
            fun fromMap(m: Map<String, Any?>?): SettlementContext? {
                if (m == null) return null
                val c = SettlementContext()
                c.resourceUrl = m["resourceUrl"] as String?
                c.payTo = m["payTo"] as String?
                c.network = m["network"] as String?
                c.asset = m["asset"] as String?
                c.decimals = m["decimals"]
                c.maxTimeoutSeconds = m["maxTimeoutSeconds"]
                return c
            }
        }
    }

    /**
     * Convert integer minor units to an integer string of atomic units. Scales by `10^(decimals - exponent)` exactly, so no
     * float is involved; when the asset has fewer decimals than the currency the division must be exact. Throws otherwise
     * (fail closed). [amount] is `{amount, currency}`; [decimals] a number.
     */
    @JvmStatic
    fun toAtomicUnits(amount: Map<String, Any?>, decimals: Any?): String {
        val d = Ap2Js.num(decimals)
        if (!Ap2Js.isFinite(decimals) || d == null || d != Math.rint(d) || d < 0 || d > 18) {
            throw IllegalArgumentException("x402: decimals must be an integer in 0..18, got " + Ap2Js.str(decimals))
        }
        val dec = d.toInt()
        val a = amount["amount"]
        val av = Ap2Js.num(a)
        if (!Ap2Js.isSafeInteger(a) || av == null || av < 0 || Ap2Js.isNegZero(av)) {
            throw IllegalArgumentException("x402: amount " + Ap2Js.str(a) + " cannot be expressed in atomic units with " + dec + " decimals")
        }
        val exp = Mandates.currencyExponent(amount["currency"])
        val minor = BigInteger.valueOf(av.toLong())
        if (dec >= exp) return minor.multiply(BigInteger.TEN.pow(dec - exp)).toString()
        val div = BigInteger.TEN.pow(exp - dec)
        if (minor.mod(div).signum() != 0) {
            throw IllegalArgumentException("x402: amount " + Ap2Js.str(a) + " cannot be expressed in atomic units with " + dec + " decimals")
        }
        return minor.divide(div).toString()
    }

    /** A settlement rail: turns a (presumed-verified) closed Payment Mandate into the rail's wire shape. Pure; no network. */
    interface SettlementBackend {
        fun rail(): String

        /** The instruction `{rail, amount, merchant?, payload}`. */
        fun settle(payment: Map<String, Any?>, ctx: SettlementContext?): Map<String, Any?>
    }

    private fun or(v: Any?, dflt: Any?): Any? = v ?: dflt

    /**
     * Coinbase x402 adapter: the HTTP 402 `Payment Required` challenge (`accepts`) plus the `X-PAYMENT` request
     * header (standard base64 of the JSON payment payload). The payload is a placeholder envelope, not a signed authorization:
     * the real rail settles on-chain.
     */
    @JvmField
    val x402Settlement: SettlementBackend = object : SettlementBackend {
        override fun rail(): String = "x402"

        override fun settle(payment: Map<String, Any?>, ctx: SettlementContext?): Map<String, Any?> {
            val network = or(ctx?.network, "base-sepolia")
            val amt = payment["payment_amount"]
            val payeeId = Ap2Js.get(payment["payee"], "id")
            val requirement = Ap2Js.m(
                "scheme" to "exact",
                "network" to network,
                // x402 v1: maxAmountRequired is a string in ATOMIC token units, not a decimal amount.
                "maxAmountRequired" to toAtomicUnits(Ap2Js.obj(amt), or(ctx?.decimals, Ap2Js.n(6L))),
                "resource" to or(ctx?.resourceUrl, ""),
                "description" to "AP2 payment mandate " + Ap2Js.str(Ap2Js.getU(payment, "transaction_id")),
                "payTo" to or(ctx?.payTo, payeeId),
                "asset" to or(ctx?.asset, Ap2Js.get(amt, "currency")),
                "mimeType" to "application/json",
                "maxTimeoutSeconds" to or(ctx?.maxTimeoutSeconds, Ap2Js.n(60L)),
            )
            val xPayment = Ap2Js.b64std(
                Ap2Js.utf8(
                    Ap2Js.json(
                        Ap2Js.m(
                            "x402Version" to Ap2Js.n(1L),
                            "scheme" to "exact",
                            "network" to network,
                            "payload" to Ap2Js.m("transactionId" to payment["transaction_id"], "amount" to Ap2Js.get(amt, "amount"), "currency" to Ap2Js.get(amt, "currency")),
                        ),
                    ),
                ),
            )
            return Ap2Js.m(
                "rail" to "x402",
                "amount" to amt,
                "merchant" to payeeId,
                "payload" to Ap2Js.m(
                    "httpStatus" to Ap2Js.n(402L), "x402Version" to Ap2Js.n(1L), "error" to "X-PAYMENT header is required",
                    "accepts" to Ap2Js.l(requirement), "header" to Ap2Js.m("X-PAYMENT" to xPayment),
                ),
            )
        }
    }

    /**
     * Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a bounded amount. The
     * mandate amount is already in minor units, which is what Stripe takes. The token is the mandate's payment instrument id,
     * never a raw PAN.
     */
    @JvmField
    val stripeSptSettlement: SettlementBackend = object : SettlementBackend {
        override fun rail(): String = "stripe-spt"

        override fun settle(payment: Map<String, Any?>, ctx: SettlementContext?): Map<String, Any?> {
            val inst = payment["payment_instrument"]
            if ("shared_payment_token" != Ap2Js.get(inst, "type")) {
                throw Ap2Error("stripe-spt: the payment instrument must be of type shared_payment_token, got " + Ap2Js.str(Ap2Js.getU(inst, "type")))
            }
            val amt = payment["payment_amount"]
            val payload = Ap2Js.m(
                "shared_payment_token" to Ap2Js.get(inst, "id"),
                "amount" to Ap2Js.get(amt, "amount"),
                "currency" to Ap2Js.str(Ap2Js.get(amt, "currency")).lowercase(Locale.ROOT),
            )
            val payTo = ctx?.payTo
            if (payTo != null && payTo.isNotEmpty()) payload["on_behalf_of"] = payTo
            return Ap2Js.m("rail" to "stripe-spt", "amount" to amt, "merchant" to Ap2Js.get(payment["payee"], "id"), "payload" to payload)
        }
    }
}
