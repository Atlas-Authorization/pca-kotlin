package net.atlasauth.pca.verifier

/** The typed failure of every store-backed bond operation. [code] is stable; the message is for humans. */
class BondStoreError(val code: String, message: String, cause: Throwable? = null) : RuntimeException("$code: $message", cause)

/**
 * The persistence contract for bond settlement. INTERNAL ACCOUNTING ONLY: nothing here moves money; balances are numbers a store
 * keeps for the deployment's own books. [commit] applies a plan ALL OR NOTHING: the compare-and-swap on the bond's phase, every
 * balance movement, the new phase and the signed record become visible together; committing the same transition twice is idempotent
 * (the stored record, nothing moved).
 *
 * A plan is the JSON object `{claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?},
 * moves: [{account, op, amount}], record}`; a bond row is `{claimId, amount, depositor, status, window?, records}`.
 */
interface BondStore {
    /** What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark. */
    class Snapshot(
        /** The bond row (a copy), or null. */
        val bond: Map<String, Any?>?,
        /** `account -> balance` for the accounts asked for. */
        val balances: Map<String, Double>,
        val openCount: Long,
        val openSum: Double,
        val highWater: Double,
    ) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            if (bond != null) m["bond"] = bond
            m["balances"] = balances.map { (k, v) -> arrayListOf<Any?>(k, StoreJs.num(v)) }
            m["openTotals"] = linkedMapOf<String, Any?>("count" to StoreJs.num(openCount), "sum" to StoreJs.num(openSum))
            m["highWater"] = StoreJs.num(highWater)
            return m
        }
    }

    /** `committed` / `replayed` (with `record`) or `conflict` (with `reason` and `current`, the bond's phase). */
    class CommitOutcome(val outcome: String, val record: Map<String, Any?>?, val reason: String?, val current: String?) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["outcome"] = outcome
            if (record != null) m["record"] = record
            if (reason != null) m["reason"] = reason
            if (current != null) m["current"] = current
            return m
        }
    }

    /** A consistent snapshot for planning (`depositor` may be null). May be stale by commit time; commit re-checks everything. */
    fun read(claimId: String, depositor: String?): Snapshot

    /**
     * Apply `plan` atomically and record `observedAt` in the time high-water mark. An open plan on an absent bond checks the caps and
     * the balance and creates it; the same bond again is `replayed`, anything else `conflict`. Any other plan needs the bond in phase
     * `expect`; if it is already in `next` via the same settlement it is `replayed`, else `conflict`; an overdraft is a `conflict`.
     * Never throws for a refused plan, only when the store itself fails.
     */
    fun commit(plan: Map<String, Any?>, observedAt: Double): CommitOutcome

    /** Atomically credit `account` with `amount` (a positive finite number). Returns the new balance. */
    fun deposit(account: String, amount: Double): Double
}

/** The state a reference bond store keeps, and the pure transition over it ([commitBondPlan]); every reference store is this plus a lock. */
@Suppress("UNCHECKED_CAST")
class BondDoc {
    val balances = LinkedHashMap<String, Double>()
    val bonds = LinkedHashMap<String, MutableMap<String, Any?>>()
    var highWater = 0.0

    /** The snapshot a scope reads from a document. */
    fun snapshot(claimId: String, depositor: String?): BondStore.Snapshot {
        val bond = bonds[claimId]
        var count = 0L
        var sum = 0.0
        val bal = LinkedHashMap<String, Double>()
        if (depositor != null) {
            for (b in bonds.values) {
                if (b["status"] == "open" && depositor == b["depositor"]) {
                    count += 1
                    sum += StoreJs.dbl(b["amount"])!!
                }
            }
            bal[depositor] = balances[depositor] ?: 0.0
        }
        return BondStore.Snapshot(if (bond == null) null else StoreJs.deepCopy(bond) as Map<String, Any?>, bal, count, sum, highWater)
    }

    /** The stored form `{v:1, balances:[[a,n]..], bonds:[..], highWater}`. */
    fun encode(): Map<String, Any?> = linkedMapOf(
        "v" to StoreJs.num(1L),
        "balances" to balances.map { (k, v) -> arrayListOf<Any?>(k, StoreJs.num(v)) },
        "bonds" to bonds.values.map { StoreJs.deepCopy(it) },
        "highWater" to StoreJs.num(highWater),
    )

    companion object {
        fun empty() = BondDoc()

        private const val MAX_SAFE_MICROS = 1e15

        /** Integer micro-units of `x` when it is a micro-grid amount below 1e15 micros, else null. */
        internal fun toMicros(x: Double): Long? {
            if (x.isNaN() || x.isInfinite() || x < 0) return null
            val scaled = x * 1_000_000
            if (scaled > MAX_SAFE_MICROS) return null
            val r = Math.floor(scaled + 0.5) // JavaScript Math.round
            if (r / 1_000_000 != x && Math.abs(scaled - r) > 1e-3) return null
            return r.toLong()
        }

        /** a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain float otherwise. */
        fun exactAdd(a: Double, b: Double, sign: Int): Double {
            val ma = toMicros(a)
            val mb = toMicros(b)
            if (ma == null || mb == null) return a + sign * b
            return (if (sign == 1) ma + mb else ma - mb).toDouble() / 1_000_000
        }

        /** Apply moves in order over a balance reader; throws IllegalStateException (the reference's Error) on an invalid amount or an overdraft. */
        fun applyBondMoves(balanceOf: (String) -> Double, moves: List<*>): Map<String, Double> {
            val out = LinkedHashMap<String, Double>()
            val bal = { a: String -> out[a] ?: balanceOf(a) }
            for (mo in moves) {
                val m = StoreJs.map(mo)!!
                val amount = StoreJs.dbl(m["amount"])
                val op = m["op"]
                if (amount == null || amount.isNaN() || amount.isInfinite() || amount < 0) throw IllegalStateException("$op: invalid amount")
                val account = m["account"] as String
                val debit = op == "debit"
                if (!bal(account).isFinite()) throw IllegalStateException("$op: balance of $account is not finite")
                if (debit && !(bal(account) >= amount)) throw IllegalStateException("debit: insufficient balance for $account")
                out[account] = exactAdd(bal(account), amount, if (debit) -1 else 1)
            }
            return out
        }

        /** Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored). */
        fun sameSettlement(a: Map<String, Any?>, b: Map<String, Any?>): Boolean =
            a["claimId"] == b["claimId"] && a["action"] == b["action"] && sameNum(a["amount"], b["amount"]) && a["from"] == b["from"] &&
                a["to"] == b["to"] && a["evidenceDigest"] == b["evidenceDigest"] && StoreJs.hashLenient(a["split"]) == StoreJs.hashLenient(b["split"])

        private fun sameNum(a: Any?, b: Any?): Boolean {
            val x = StoreJs.dbl(a)
            val y = StoreJs.dbl(b)
            return if (x == null || y == null) a == null && b == null else x == y
        }

        private fun sameWindow(a: Map<String, Any?>?, b: Map<String, Any?>?): Boolean {
            if (a == null || b == null) return a == null && b == null
            return sameNum(a["windowMs"], b["windowMs"]) && a["claimDigest"] == b["claimDigest"] // registeredAt is the first call's
        }

        private fun status(bond: Map<String, Any?>?): String = if (bond == null) "none" else bond["status"] as String

        private fun records(bond: Map<String, Any?>): MutableList<Any?> = bond["records"] as MutableList<Any?>

        /** Apply `plan` to `doc` following the [BondStore.commit] rules. Mutates `doc` ONLY on `committed` (the moves are checked on an overlay first). */
        fun commitBondPlan(doc: BondDoc, plan: Map<String, Any?>, observedAt: Double): BondStore.CommitOutcome {
            val claimId = plan["claimId"] as String
            val bond = doc.bonds[claimId]
            val open = StoreJs.map(plan["open"])
            val record = StoreJs.map(plan["record"])
            if (plan["expect"] == "none") {
                if (open == null || plan["next"] != "open") return BondStore.CommitOutcome("conflict", null, "malformed open plan", status(bond))
                if (bond != null) {
                    val recs = records(bond)
                    val same = bond["depositor"] == open["depositor"] && sameNum(bond["amount"], open["amount"]) &&
                        sameWindow(StoreJs.map(bond["window"]), StoreJs.map(open["window"])) && recs.isNotEmpty() && sameSettlement(StoreJs.map(recs[0])!!, record!!)
                    return if (same) BondStore.CommitOutcome("replayed", StoreJs.map(recs[0]), null, null)
                    else BondStore.CommitOutcome("conflict", null, "bond $claimId already exists", status(bond))
                }
                var count = 0L
                var sum = 0.0
                for (b in doc.bonds.values) {
                    if (b["status"] == "open" && b["depositor"] == open["depositor"]) {
                        count += 1
                        sum += StoreJs.dbl(b["amount"])!!
                    }
                }
                if (!(count + 1 <= StoreJs.dbl(open["maxOpenClaims"])!!)) return BondStore.CommitOutcome("conflict", null, "depositor open-claim cap reached", "none")
                if (!((sum + StoreJs.dbl(open["amount"])!!).isFinite() && sum + StoreJs.dbl(open["amount"])!! <= StoreJs.dbl(open["maxOpenAmount"])!!)) {
                    return BondStore.CommitOutcome("conflict", null, "depositor aggregate open-bond cap exceeded", "none")
                }
            } else if (bond == null) {
                return BondStore.CommitOutcome("conflict", null, "no bond for $claimId", "none")
            } else if (bond["status"] != plan["expect"]) {
                val recs = records(bond)
                val last = if (recs.isEmpty()) null else StoreJs.map(recs[recs.size - 1])
                return if (bond["status"] == plan["next"] && last != null && sameSettlement(last, record!!)) BondStore.CommitOutcome("replayed", last, null, null)
                else BondStore.CommitOutcome("conflict", null, "bond $claimId is already ${bond["status"]}", status(bond))
            }
            val next = try {
                applyBondMoves({ a -> doc.balances[a] ?: 0.0 }, plan["moves"] as List<*>)
            } catch (e: IllegalStateException) {
                return BondStore.CommitOutcome("conflict", null, e.message, status(bond))
            }
            doc.balances.putAll(next)
            if (open != null) {
                val row = LinkedHashMap<String, Any?>()
                row["claimId"] = claimId
                row["amount"] = open["amount"]
                row["depositor"] = open["depositor"]
                row["status"] = "open"
                if (StoreJs.map(open["window"]) != null) row["window"] = StoreJs.deepCopy(open["window"])
                row["records"] = arrayListOf(StoreJs.deepCopy(record))
                doc.bonds[claimId] = row
            } else {
                bond!!["status"] = plan["next"]
                records(bond).add(StoreJs.deepCopy(record))
            }
            val obs = if (observedAt.isNaN() || observedAt.isInfinite()) 0.0 else observedAt
            doc.highWater = Math.max(doc.highWater, obs)
            return BondStore.CommitOutcome("committed", record, null, null)
        }

        private fun bad(why: String) = BondStoreError("store_corrupt", why)

        /** Decode a stored document (null = empty); fails closed with `store_corrupt`. The result shares nothing with `raw`. */
        fun decode(raw: Any?): BondDoc {
            if (raw == null) return empty()
            val m = StoreJs.map(raw)
            if (m == null || !IntentJs.isInt(m["v"]) || IntentJs.lng(m["v"]) != 1L || m["balances"] !is List<*> || m["bonds"] !is List<*> || StoreJs.dbl(m["highWater"]) == null) {
                throw bad("bond document has the wrong shape")
            }
            val d = empty()
            val hw = StoreJs.dbl(m["highWater"])!!
            if (hw.isNaN() || hw.isInfinite() || hw < 0) throw bad("highWater is not a non-negative number")
            d.highWater = hw
            for (e in m["balances"] as List<*>) {
                if (e !is List<*> || e.size != 2 || e[0] !is String) throw bad("malformed balance entry")
                val v = StoreJs.dbl(e[1])
                if (v == null || v.isNaN() || v.isInfinite() || v < 0) throw bad("malformed balance entry")
                d.balances[e[0] as String] = v
            }
            for (bo in m["bonds"] as List<*>) {
                val b = StoreJs.map(bo)
                if (b == null || b["claimId"] !is String || b["depositor"] !is String || StoreJs.dbl(b["amount"]) == null || !IntentJs.isFinite(b["amount"]) ||
                    !(b["status"] == "open" || b["status"] == "released" || b["status"] == "slashed") ||
                    b["records"] !is List<*> || (b["records"] as List<*>).isEmpty()
                ) throw bad("malformed bond row")
                if (d.bonds.containsKey(b["claimId"])) throw bad("duplicate bond row")
                d.bonds[b["claimId"] as String] = StoreJs.map(StoreJs.deepCopy(b))!!
            }
            return d
        }
    }
}

/**
 * The reference [BondStore]: the whole book is one document in an [AtomicKv], so every transition is a single atomic read-modify-write.
 * Over [JdbcAtomicKv] it is durable and multi-process safe; over [MemoryAtomicKv] it is the in-process variant (tests only). LIMIT: one
 * document rewritten on every commit; a production deployment implements [BondStore] over a database transaction.
 */
class KvBondStore @JvmOverloads constructor(private val kv: AtomicKv, private val key: String = DOC_KEY) : BondStore {
    override fun read(claimId: String, depositor: String?): BondStore.Snapshot = BondDoc.decode(kv.get(key)).snapshot(claimId, depositor)

    override fun commit(plan: Map<String, Any?>, observedAt: Double): BondStore.CommitOutcome {
        var out: BondStore.CommitOutcome? = null
        kv.update(key) { prev ->
            val doc = BondDoc.decode(prev)
            val o = BondDoc.commitBondPlan(doc, plan, observedAt)
            out = o
            if (o.outcome == "committed") doc.encode() else null // null: leave the key untouched
        }
        return out!!
    }

    override fun deposit(account: String, amount: Double): Double {
        if (account.isEmpty()) throw IllegalArgumentException("deposit: account is required")
        if (amount.isNaN() || amount.isInfinite() || amount <= 0) throw IllegalArgumentException("deposit: amount must be a positive finite number")
        var balance = 0.0
        kv.update(key) { prev ->
            val doc = BondDoc.decode(prev)
            val mv = listOf(linkedMapOf<String, Any?>("account" to account, "op" to "credit", "amount" to StoreJs.num(amount)))
            balance = BondDoc.applyBondMoves({ a -> doc.balances[a] ?: 0.0 }, mv)[account]!!
            doc.balances[account] = balance
            doc.encode()
        }
        return balance
    }

    companion object {
        const val DOC_KEY = "pca-bond-store/v1"
    }
}
