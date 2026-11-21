package net.atlasauth.pca.payments

/** Why a mandate was refused before any decision: verified_grant_required, mandate_grant_mismatch or mandate_terms_mismatch. */
class MandateGrantError(val code: String, message: String) : RuntimeException(message)

/** The cumulative-budget store is missing, malformed or kept changing. */
class ChargeStoreError(message: String) : RuntimeException(message)

/**
 * Durable cumulative-budget state with an atomic compare-and-set. `version` is opaque to the caller: [compareAndSet] succeeds only when the
 * stored version still equals `expected` (null = no record yet) and returns false otherwise.
 */
interface ChargeBudgetStore {
    /** A stored budget and its version. */
    class Record(val budget: Any?, val version: Any?)

    /** The record under [key], or null when there is none. */
    fun get(key: String): Record?

    fun compareAndSet(key: String, expected: Any?, budget: Map<String, Any?>): Boolean
}

/** Single-process reference store; production needs a durable store with a conditional write. */
class MemoryChargeBudgetStore : ChargeBudgetStore {
    private val m = HashMap<String, ChargeBudgetStore.Record>()

    @Synchronized override fun get(key: String): ChargeBudgetStore.Record? = m[key]

    @Synchronized override fun compareAndSet(key: String, expected: Any?, budget: Map<String, Any?>): Boolean {
        val have = m[key]?.version
        if ((if (have == null) null else PayJs.num(have)) != (if (expected == null) null else PayJs.num(expected))) return false
        m[key] = ChargeBudgetStore.Record(budget, PayJs.jn((if (expected == null) 0.0 else PayJs.num(expected) ?: Double.NaN) + 1))
        return true
    }
}
