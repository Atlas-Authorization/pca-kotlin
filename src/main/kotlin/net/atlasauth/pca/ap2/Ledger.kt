package net.atlasauth.pca.ap2

import net.atlasauth.pca.ap2.Chain.PurchaseResult
import net.atlasauth.pca.ap2.Chain.VerifyPurchaseOptions

/**
 * Durable, serialised purchase state for open mandates, and [redeemPurchase]: `verifyPurchase` plus single use and
 * server-owned cumulative state.
 */
@Suppress("UNCHECKED_CAST")
object Ledger {
    /**
     * Durable, serialised purchase state for open mandates. `reserve` is ONE atomic step: it refuses a transaction id that
     * was already reserved under this open mandate ([REPLAYED]), otherwise records it with its amount and returns the
     * usage context of every EARLIER reservation (so two concurrent purchases see each other and cannot share one budget).
     * Back it with a unique key on (openMandateHash, transactionId) and a serialised sum (a row lock or one conditional write).
     * `release` undoes a reservation whose purchase then failed verification.
     */
    interface PurchaseLedger {
        /** A usage context map ([Constraints.context]) or [REPLAYED]. */
        fun reserve(openMandateHash: String, transactionId: String, amountMinor: Double): Any?

        fun release(openMandateHash: String, transactionId: String)

        companion object {
            /** The [reserve] answer for a transaction id that was already reserved. */
            const val REPLAYED = "replayed"
        }
    }

    private fun withContext(o: VerifyPurchaseOptions, ctx: Map<String, Any?>?): VerifyPurchaseOptions {
        val c = VerifyPurchaseOptions()
        c.resolveIssuerKey = o.resolveIssuerKey
        c.resolveMerchantKey = o.resolveMerchantKey
        c.checkout = o.checkout
        c.payment = o.payment
        c.context = ctx
        c.now = o.now
        c.clockSkewSeconds = o.clockSkewSeconds
        return c
    }

    /**
     * `verifyPurchase` plus single use and server-owned cumulative state. The usage context comes from [ledger], never
     * from the caller (the `context` of [o] is ignored), and the purchase's transaction id can be redeemed once. A
     * missing or failing ledger denies (`ledger_required`, `ledger_unavailable`, `replayed`).
     */
    @JvmStatic
    fun redeemPurchase(checkoutToken: String, paymentToken: String, o: VerifyPurchaseOptions, ledger: PurchaseLedger?): PurchaseResult {
        if (ledger == null) return PurchaseResult.fail("ledger_required")
        // A zero context is the most permissive one for budget and recurrence, so a failure here is final.
        val first = Chain.verifyPurchase(checkoutToken, paymentToken, withContext(o, Constraints.context(0.0, 0.0, null)))
        if (!first.ok) return first
        val pay = first.payment ?: return PurchaseResult.fail("ledger_unavailable")
        val openHash = pay.openHash ?: return PurchaseResult.fail("ledger_unavailable")
        val closed = pay.closed ?: return PurchaseResult.fail("ledger_unavailable")
        val txId = closed["transaction_id"] as? String ?: return PurchaseResult.fail("ledger_unavailable")
        val amount = Ap2Js.num(Ap2Js.get(closed["payment_amount"], "amount")) ?: Double.NaN
        val ctx: Any? = try {
            ledger.reserve(openHash, txId, amount)
        } catch (e: Exception) {
            return PurchaseResult.fail("ledger_unavailable")
        }
        if (PurchaseLedger.REPLAYED == ctx) return PurchaseResult.fail("replayed")
        val fin = Chain.verifyPurchase(checkoutToken, paymentToken, withContext(o, ctx as? Map<String, Any?>))
        if (!fin.ok) {
            try {
                ledger.release(openHash, txId)
            } catch (e: Exception) {
                // the reservation stays: a failed release only ever over-counts spend
            }
        }
        return fin
    }
}
