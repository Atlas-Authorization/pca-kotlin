package net.atlasauth.pca.verifier

/** The typed failure of the aggregate budget ledger: `not_durable`, `scope_unbound`, `store_missing`, `store_corrupt`, `invalid`, `conflict_exhausted`. */
class BudgetLedgerError(val code: String, message: String) : RuntimeException("$code: $message")

/**
 * The persistence contract of a durable aggregate budget (no overspend at principal, org and fleet scope), given a ledger that is
 * linearizable per key and durable. A reservation counts as soon as it is made; the ledger refuses a reservation whose post-value
 * would pass the accumulator's `domain_max` inside the same atomic step that records it.
 *
 * Two phases: `reserve` (counted at once), then `start` (recorded BEFORE the effect runs), then `commit` (the effect happened) or
 * `release` (it did not). `expire` frees only a reservation that was never started. A committed event is never released and a
 * released one is never committed. Each operation is atomic per key; the same reservation again is a replay that changes nothing;
 * acknowledged writes survive a crash; [durable] is true only for a store that does. Events are the JSON objects
 * `{id, verb, resource, params, t, status, exp?, started?, rel?}`.
 */
interface BudgetLedger {
    /** A reservation request. `accumulators` are the declarations of THIS key (each `domain_max` is the cap). */
    class ReserveRequest {
        /** {id, verb, resource, params, t}. */
        var event: Map<String, Any?>? = null
        var accumulators: List<Map<String, Any?>>? = null

        /** An action schema (or null). */
        var schema: Any? = null

        /** Refuse (`conflict`) unless the key is at this version. */
        var expectedVersion: Long? = null
        var expiresAt: Long? = null
    }

    /** `reserved` (+post), `replayed` (+status), `over_cap` (+acc, post, cap), `conflict`, `id_conflict`. */
    class ReserveOutcome(
        val outcome: String, val version: Long, val post: Map<String, Long>?, val status: String?,
        val acc: String?, val postValue: Long?, val cap: Double?,
    ) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["outcome"] = outcome
            m["version"] = StoreJs.num(version)
            if (post != null) m["post"] = post.entries.associateTo(LinkedHashMap<String, Any?>()) { it.key to StoreJs.num(it.value) }
            if (status != null) m["status"] = status
            if (acc != null) {
                m["acc"] = acc
                m["post"] = StoreJs.num(postValue!!)
                m["cap"] = StoreJs.num(cap!!)
            }
            return m
        }
    }

    /** `settled`, `replayed`, `unknown` or `refused` (+status of the entry). */
    class SettleOutcome(val outcome: String, val version: Long, val status: String?) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["outcome"] = outcome
            m["version"] = StoreJs.num(version)
            if (status != null) m["status"] = status
            return m
        }
    }

    /** The result of [expire]: the released ids and the version afterwards. */
    class Expired(val released: List<String>, val version: Long) {
        fun toJson(): Map<String, Any?> = linkedMapOf("released" to ArrayList<Any?>(released), "version" to StoreJs.num(version))
    }

    /** A copy of a key's events and its version. */
    class Snapshot(val version: Long, val events: List<Map<String, Any?>>) {
        fun toJson(): Map<String, Any?> = linkedMapOf("version" to StoreJs.num(version), "events" to ArrayList<Any?>(events))
    }

    /** True ONLY when acknowledged writes survive a restart or crash. Non-session scopes refuse a ledger that does not say so. */
    fun durable(): Boolean

    fun snapshot(key: String): Snapshot

    fun reserve(key: String, req: ReserveRequest): ReserveOutcome

    /** The effect is about to run: mark the reservation non-expirable. `refused` once released; `replayed` when already started or committed. */
    fun start(key: String, id: String): SettleOutcome

    fun commit(key: String, id: String): SettleOutcome

    /** `evidence` (a signed release) may be null. */
    fun release(key: String, id: String, evidence: Map<String, Any?>?): SettleOutcome

    /** Release every open, never-started reservation whose `exp` is at or before `now`. */
    fun expire(key: String, now: Long): Expired
}

/** One key's reservations and the pure transitions over them; every reference budget store is these plus a per-key lock. */
class BudgetDoc {
    var ver = 0L
    val events = ArrayList<MutableMap<String, Any?>>()

    fun encode(): Map<String, Any?> = linkedMapOf("v" to StoreJs.num(1L), "ver" to StoreJs.num(ver), "events" to events.map { StoreJs.deepCopy(it) })

    private fun find(id: String): MutableMap<String, Any?>? = events.firstOrNull { id == it["id"] }

    fun reserveInDoc(req: BudgetLedger.ReserveRequest?): BudgetLedger.ReserveOutcome {
        val e = req?.event
        if (e == null || !idOk(e["id"]) || e["verb"] !is String || e["resource"] !is String || !IntentJs.isInt(e["t"]) ||
            !(e["params"] is Map<*, *> || e["params"] is List<*>)
        ) throw IllegalArgumentException("reserve: a malformed event")
        val accumulators = req.accumulators ?: throw IllegalArgumentException("reserve: accumulators must be an array")
        val expectedVersion = req.expectedVersion
        if (expectedVersion != null && expectedVersion < 0) throw IllegalArgumentException("reserve: expectedVersion must be a non-negative safe integer")
        val id = e["id"] as String
        val prior = find(id)
        if (prior != null) {
            return if (sameEvent(prior, e)) BudgetLedger.ReserveOutcome("replayed", ver, null, prior["status"] as String?, null, null, null)
            else BudgetLedger.ReserveOutcome("id_conflict", ver, null, null, null, null, null)
        }
        if (expectedVersion != null && expectedVersion != ver) return BudgetLedger.ReserveOutcome("conflict", ver, null, null, null, null, null)
        val post = LinkedHashMap<String, Long>()
        for (a in accumulators) {
            if (a["domain_max"] == null) throw IllegalArgumentException("reserve: accumulator ${a["id"]} has no domain_max (the cap)")
            if (!IntentAcc.accSelects(a, e["verb"] as String, req.schema)) continue
            val p = try {
                IntentHistory.accPost(a, events, e["verb"] as String, StoreJs.map(e["params"]) ?: LinkedHashMap(), e["t"], req.schema)
            } catch (x: RuntimeException) { // the reference throws where history is unreadable
                throw BudgetLedgerError("store_corrupt", "unreadable history")
            }
            val cap = StoreJs.dbl(a["domain_max"])!!
            if (!(p.toDouble() <= cap)) return BudgetLedger.ReserveOutcome("over_cap", ver, null, null, a["id"] as String, p, cap)
            post[a["id"] as String] = p
        }
        val entry = LinkedHashMap<String, Any?>()
        entry["id"] = id
        entry["verb"] = e["verb"]
        entry["resource"] = e["resource"]
        entry["params"] = StoreJs.deepCopy(e["params"])
        entry["t"] = e["t"]
        entry["status"] = "reserved"
        if (req.expiresAt != null) entry["exp"] = StoreJs.num(req.expiresAt!!)
        events.add(entry)
        ver += 1
        return BudgetLedger.ReserveOutcome("reserved", ver, post, null, null, null, null)
    }

    fun startInDoc(id: String): BudgetLedger.SettleOutcome {
        val e = find(id) ?: return BudgetLedger.SettleOutcome("unknown", ver, null)
        if (e["status"] == "released") return BudgetLedger.SettleOutcome("refused", ver, "released")
        if (e.containsKey("started") || e["status"] == "committed") return BudgetLedger.SettleOutcome("replayed", ver, null)
        e["started"] = true
        ver += 1
        return BudgetLedger.SettleOutcome("settled", ver, null)
    }

    fun commitInDoc(id: String): BudgetLedger.SettleOutcome {
        val e = find(id) ?: return BudgetLedger.SettleOutcome("unknown", ver, null)
        if (e["status"] == "committed") return BudgetLedger.SettleOutcome("replayed", ver, null)
        if (e["status"] != "reserved") return BudgetLedger.SettleOutcome("refused", ver, e["status"] as String?)
        e["status"] = "committed"
        ver += 1
        return BudgetLedger.SettleOutcome("settled", ver, null)
    }

    fun releaseInDoc(key: String, id: String, evidence: Map<String, Any?>?): BudgetLedger.SettleOutcome {
        val e = find(id) ?: return BudgetLedger.SettleOutcome("unknown", ver, null)
        if (e["status"] == "released") return BudgetLedger.SettleOutcome("replayed", ver, null)
        if (e["status"] != "reserved") return BudgetLedger.SettleOutcome("refused", ver, e["status"] as String?)
        if (evidence != null && (key != evidence["key"] || id != evidence["id"])) throw IllegalArgumentException("release: the evidence is for another reservation")
        e["status"] = "released"
        if (evidence != null) e["rel"] = StoreJs.deepCopy(evidence)
        ver += 1
        return BudgetLedger.SettleOutcome("settled", ver, null)
    }

    fun expireInDoc(now: Long): BudgetLedger.Expired {
        if (now < -9007199254740991L || now > 9007199254740991L) throw IllegalArgumentException("expire: now must be a safe integer")
        val released = ArrayList<String>()
        for (e in events) {
            val exp = if (e.containsKey("exp")) StoreJs.dbl(e["exp"]) else null
            if (e["status"] == "reserved" && !e.containsKey("started") && exp != null && exp <= now) {
                e["status"] = "released"
                e["rel"] = linkedMapOf("reason" to "expired", "at" to StoreJs.num(now))
                released.add(e["id"] as String)
            }
        }
        if (released.isNotEmpty()) ver += 1
        return BudgetLedger.Expired(released, ver)
    }

    companion object {
        fun empty() = BudgetDoc()

        const val ID_MAX = 256

        /** A non-empty string of at most 256 characters without control characters. */
        fun idOk(s: Any?): Boolean = s is String && s.isNotEmpty() && s.length <= ID_MAX && s.none { it.code <= 0x1f }

        /** Decode a stored document (null = empty); fails closed with `store_corrupt`. The result shares nothing with `raw`. */
        fun decode(raw: Any?): BudgetDoc {
            if (raw == null) return empty()
            val m = StoreJs.map(raw)
            if (m == null || !IntentJs.isInt(m["v"]) || IntentJs.lng(m["v"]) != 1L || !IntentJs.isInt(m["ver"]) || m["events"] !is List<*>) {
                throw BudgetLedgerError("store_corrupt", "budget document has the wrong shape")
            }
            val d = empty()
            d.ver = IntentJs.lng(m["ver"])
            for (e in m["events"] as List<*>) {
                val em = StoreJs.map(e)
                if (em == null || em["id"] !is String) throw BudgetLedgerError("store_corrupt", "budget document has the wrong shape")
                d.events.add(StoreJs.map(StoreJs.deepCopy(em))!!)
            }
            return d
        }

        private fun sameEvent(a: Map<String, Any?>, b: Map<String, Any?>): Boolean = Pca.hashCanonical(core(a)) == Pca.hashCanonical(core(b))

        private fun core(e: Map<String, Any?>): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            for (k in listOf("id", "verb", "resource", "params", "t")) if (e.containsKey(k)) m[k] = e[k]
            return m
        }
    }
}

/**
 * The reference [BudgetLedger]: one document per key in an [AtomicKv], so every operation is one atomic read-modify-write. `durable`
 * is declared by the caller because a kv cannot tell: pass true only for a persistent one ([JdbcAtomicKv]); over [MemoryAtomicKv] it
 * must be false. LIMIT: one document per key, rewritten per write; a production ledger is a database row-per-event with a unique
 * index on (key, id) and a version column (reuse [BudgetDoc] inside its transaction).
 */
class KvBudgetLedger(private val kv: AtomicKv, private val durable: Boolean) : BudgetLedger {
    override fun durable(): Boolean = durable

    private fun k(key: String): String {
        if (!BudgetDoc.idOk(key)) throw IllegalArgumentException("a ledger key is a non-empty string without control characters")
        return PREFIX + key
    }

    private fun <T> txn(key: String, fn: (BudgetDoc) -> T, writes: (T) -> Boolean): T {
        var out: Any? = null
        kv.update(k(key)) { prev ->
            val d = BudgetDoc.decode(prev)
            val r = fn(d)
            out = r
            if (writes(r)) d.encode() else null
        }
        @Suppress("UNCHECKED_CAST")
        return out as T
    }

    override fun snapshot(key: String): BudgetLedger.Snapshot {
        val d = BudgetDoc.decode(kv.get(k(key)))
        return BudgetLedger.Snapshot(d.ver, d.events.map { StoreJs.map(StoreJs.deepCopy(it))!! })
    }

    override fun reserve(key: String, req: BudgetLedger.ReserveRequest) = txn(key, { it.reserveInDoc(req) }) { it.outcome == "reserved" }

    override fun start(key: String, id: String) = txn(key, { it.startInDoc(id) }) { it.outcome == "settled" }

    override fun commit(key: String, id: String) = txn(key, { it.commitInDoc(id) }) { it.outcome == "settled" }

    override fun release(key: String, id: String, evidence: Map<String, Any?>?) = txn(key, { it.releaseInDoc(key, id, evidence) }) { it.outcome == "settled" }

    override fun expire(key: String, now: Long) = txn(key, { it.expireInDoc(now) }) { it.released.isNotEmpty() }

    companion object {
        const val PREFIX = "pca-budget-ledger/v1/"
    }
}
