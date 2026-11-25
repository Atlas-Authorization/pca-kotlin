package net.atlasauth.pca.verifier

/**
 * A finite, fail-closed insurance capital pool (packages/pca/src/bond-settlement.ts `InsuranceCapitalPool`). Premiums are credited;
 * victim payouts are debited and REFUSED when they exceed the free capital (scarce collateral). `initial + premiumsIn - payoutsOut ==
 * balance` always, so a payout never silently overdraws. Pure accounting; the real custody ledger is the deployment's.
 *
 * A premium is priced by the caller (a coverage quote `{premium, declined, ...}`); [collectPremium] credits a priced quote that is not
 * declined.
 */
class InsuranceCapitalPool(private val initial: Double = 0.0) {
    private var premiumsIn = 0.0
    private var payoutsOut = 0.0

    init {
        if (initial.isNaN() || initial.isInfinite() || initial < 0) throw IllegalStateException("InsuranceCapitalPool: initial capital must be a non-negative finite number")
    }

    @Synchronized
    fun balance(): Double = initial + premiumsIn - payoutsOut

    @Synchronized
    fun premiumsIn(): Double = premiumsIn

    @Synchronized
    fun payoutsOut(): Double = payoutsOut

    /** `{initial, premiumsIn, payoutsOut, balance}` (the conservation invariant always holds over these). */
    @Synchronized
    fun state(): Map<String, Any?> = linkedMapOf(
        "initial" to StoreJs.num(initial), "premiumsIn" to StoreJs.num(premiumsIn), "payoutsOut" to StoreJs.num(payoutsOut), "balance" to StoreJs.num(balance()),
    )

    /** Credit a priced coverage quote (`{premium, declined}`) unless it is declined; returns `{pricing, state}`. */
    @Synchronized
    fun collectPremium(pricing: Map<String, Any?>): Map<String, Any?> {
        val premium = StoreJs.dbl(pricing["premium"]) ?: Double.NaN
        if (pricing["declined"] != true && premium > 0) {
            if (premium.isNaN() || premium.isInfinite() || premium < 0) throw IllegalStateException("collectPremium: priced premium is not a non-negative finite number")
            premiumsIn += premium
        }
        return linkedMapOf("pricing" to pricing, "state" to state())
    }

    /** True iff the pool currently holds at least [amount] of free capital. */
    @Synchronized
    fun canCover(amount: Double): Boolean = !amount.isNaN() && !amount.isInfinite() && amount >= 0 && balance() >= amount

    /** Pay [amount] of victim compensation; REFUSED (throws) when non-positive, non-finite or above the free capital. Returns the post-payout state. */
    @Synchronized
    fun payClaim(amount: Double): Map<String, Any?> {
        if (amount.isNaN() || amount.isInfinite() || amount <= 0) throw IllegalStateException("payClaim: amount must be a positive finite number")
        if (!(balance().isFinite() && amount <= balance())) throw IllegalStateException("payClaim: insufficient pool capital (need ${AttestUtil.jsNumString(amount)}, have ${AttestUtil.jsNumString(balance())})")
        payoutsOut += amount
        return state()
    }
}
