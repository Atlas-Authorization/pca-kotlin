package net.atlasauth.pca.verifier

/**
 * The state-store and authorizer constructors of the reference's `server/authorize` and `server/require-pca`.
 *
 * Every Kotlin [Authorize.StateStore] is claim-based (one atomic operation per counter), so the reference's non-atomic read-then-write
 * store has no counterpart here: [memoryPcaStore] and [atomicMemoryPcaStore] are both the process-scoped [Authorize.MemoryStateStore], and
 * [isAtomicPcaStateStore] is true for every store.
 */

/** A process-scoped replay, pin and budget store (tests, one worker). */
fun memoryPcaStore(): Authorize.MemoryStateStore = Authorize.MemoryStateStore()

/** The atomic in-memory store (the same as [memoryPcaStore]: claims are atomic). */
fun atomicMemoryPcaStore(): Authorize.MemoryStateStore = Authorize.MemoryStateStore()

/** True when [store] claims counters atomically (every [Authorize.StateStore] does). */
fun isAtomicPcaStateStore(store: Any?): Boolean = store is Authorize.StateStore

/**
 * A replay, pin and budget store over any [AtomicKv] (for example `openDurableState(...)`: crash-safe and multi-process-safe on one host,
 * so `scope` is `shared`). [prefix] namespaces the keys.
 */
@JvmOverloads
fun durablePcaStateStore(kv: AtomicKv, prefix: String = "pca-state:", scope: String = Authorize.SCOPE_SHARED): KvStateStore = KvStateStore(kv, prefix, scope)

/** [Authorize.StateStore], [Authorize.LastStore] and [Authorize.BudgetStore] over an [AtomicKv]: every operation is ONE `update` of the backend. */
class KvStateStore @JvmOverloads constructor(
    private val kv: AtomicKv,
    private val prefix: String = "pca-state:",
    override val scope: String = Authorize.SCOPE_SHARED,
) : Authorize.StateStore, Authorize.LastStore, Authorize.BudgetStore {
    init {
        require(scope == Authorize.SCOPE_PROCESS || scope == Authorize.SCOPE_SHARED) { "scope is process or shared" }
    }

    private fun lastKey(k: String) = prefix + "last:" + k

    override fun last(key: String): Long? = kv.get(lastKey(key))?.let { IntentJs.lng(it) }

    override fun claim(key: String, counter: Long): Authorize.ClaimResult {
        var res = Authorize.ClaimResult(false, null)
        kv.update(lastKey(key)) { prev ->
            val p = prev?.let { IntentJs.lng(it) }
            if (p != null && counter <= p) {
                res = Authorize.ClaimResult(false, p)
                null
            } else {
                res = Authorize.ClaimResult(true)
                counter
            }
        }
        return res
    }

    override fun consumeOnce(key: String, retainUntil: Long, now: Long): Boolean {
        require(key.isNotEmpty() && retainUntil >= now) { "consumeOnce needs a key and a retention horizon not before now" }
        var first = false
        kv.update(prefix + "once:" + key) { prev ->
            val p = prev?.let { IntentJs.lng(it) }
            first = p == null || p < now // a record is live while retainUntil >= now
            if (first || p!! < retainUntil) retainUntil else null // never shorten a live horizon
        }
        return first
    }

    private fun budgetKey(k: String) = prefix + "budget:" + k

    private fun decode(o: Any?): Risk.Budget? {
        val m = o as? Map<*, *> ?: return null
        return Risk.Budget(IntentJs.num(m["B"])!!, IntentJs.num(m["tau"])!!, IntentJs.num(m["asOf"]))
    }

    private fun encode(b: Risk.Budget): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("B" to b.B, "tau" to b.tau)
        if (b.asOf != null) m["asOf"] = b.asOf
        return m
    }

    override fun budget(key: String): Risk.Budget? = decode(kv.get(budgetKey(key)))

    override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean {
        var done = false
        kv.update(budgetKey(key)) { prev ->
            done = decode(prev) == old
            if (done) encode(new) else null
        }
        return done
    }
}

/**
 * An authorizer built once from the shared options and called per operation (the reference's `createAuthorizer`). The configuration is
 * checked on every call: a missing component is a 403 `authorize_config` refusal naming it (fail closed), never a signature-only verdict.
 */
class Authorizer internal constructor(
    val options: Authorize.AuthorizeOptions,
    val audience: String?,
    val resolveGrant: ((String) -> Map<String, Any?>?)?,
) {
    /** Authorize one [operation] for [pcactn] (a parsed object or its encoded form); see [Authorize.AuthorizeOptions.run] for the per-call inputs. */
    @JvmOverloads
    fun authorize(
        pcactn: Any?, operation: Authorize.Operation?, now: Long? = null, intentPolicy: Pca.IntentPolicy? = null,
        intentV2: ((Map<String, Any?>) -> IntentV2.Context?)? = null, escalationAnswer: Any? = null, freshAt: FreshAt.Policy? = null,
        freshAtHeader: String? = null, workflowCall: Authorize.WorkflowStep? = null, provenance: Any? = null, provenanceHeader: String? = null,
        passport: Any? = null, forbidCertificate: Any? = null,
    ): Authorize.Result = options.run(
        pcactn, operation, audience, resolveGrant, now, intentPolicy, intentV2, escalationAnswer, options.k1, freshAt, freshAtHeader,
        workflowCall, provenance, provenanceHeader, passport, forbidCertificate,
    )
}

/** Build an authorizer once and call it per operation. */
fun createAuthorizer(options: Authorize.AuthorizeOptions, audience: String?, resolveGrant: ((String) -> Map<String, Any?>?)?): Authorizer = Authorizer(options, audience, resolveGrant)
