package net.atlasauth.pca.verifier

/** The typed failure of every store-backed ledger operation. [code] is stable (`store_missing`, `rollback`, ...); the message is for humans. */
class LedgerStoreError(val code: String, message: String, cause: Throwable? = null) : RuntimeException("$code: $message", cause)

/**
 * The persistence contract of a transparency log (the durable side of a stored ledger). Implement it over a database (an append-only
 * table with a unique index on the position gives `append` for free) or use [KvLedgerStore].
 *
 * `append` and `appendCheckpoint` are compare-and-swap on the current length: they succeed only at the exact position the caller saw,
 * all entries of a batch or none, so two writers can never assign one index twice and a log never has holes. Committing the same
 * batch again at the same position is a replay (idempotent, nothing written). Acknowledged writes survive a crash or restart; a write
 * in flight at the crash is applied entirely or not at all.
 */
interface LedgerStore {
    /** The result of [append]: `appended`, `replayed` (the same batch was already there) or `conflict`; `size` is the log length after. */
    class AppendOutcome(val outcome: String, val size: Long) {
        fun toJson(): Map<String, Any?> = linkedMapOf("outcome" to outcome, "size" to StoreJs.num(size))
    }

    /** The result of [appendCheckpoint]; `reason` only on a conflict. */
    class CheckpointOutcome(val outcome: String, val count: Long, val reason: String?) {
        fun toJson(): Map<String, Any?> {
            val m = linkedMapOf<String, Any?>("outcome" to outcome, "count" to StoreJs.num(count))
            if (reason != null) m["reason"] = reason
            return m
        }
    }

    /** Current number of entries. */
    fun size(): Long

    /** Commits `[from, to)`. Throws IllegalArgumentException (the reference's RangeError) when the range is not inside the log. */
    fun read(from: Long, to: Long): List<String>

    /**
     * Atomically append `commits` iff the log has exactly `expectedSize` entries (all or none). A batch that is already stored at
     * `expectedSize` is `replayed`. Every commit must be a non-empty string (IllegalArgumentException otherwise).
     */
    fun append(expectedSize: Long, commits: List<String>): AppendOutcome

    /** Number of checkpoints. */
    fun checkpointCount(): Long

    /** Checkpoints `[from, count)` in order (copies). */
    fun checkpoints(from: Long): List<Map<String, Any?>>

    /**
     * Atomically append a checkpoint `{sth, proof?}` iff exactly `expectedCount` exist. A store also enforces what needs no
     * cryptography: the checkpoint's size is within the log and not below the previous checkpoint's (equal only with the same root).
     * The same checkpoint at the same position is `replayed`.
     */
    fun appendCheckpoint(expectedCount: Long, cp: Map<String, Any?>?): CheckpointOutcome
}

/**
 * The pure transition functions of a ledger store: every reference store is these plus a lock. A document is the commits and the
 * checkpoints; [appendToLedgerDoc] and [checkpointToLedgerDoc] mutate it ONLY when they report `appended`.
 */
class LedgerDoc {
    val commits = ArrayList<String>()
    val checkpoints = ArrayList<MutableMap<String, Any?>>()

    /** The JSON form `{v:1, commits, checkpoints}`. */
    fun toJson(): Map<String, Any?> =
        linkedMapOf("v" to StoreJs.num(1L), "commits" to ArrayList<Any?>(commits), "checkpoints" to checkpoints.map { StoreJs.deepCopy(it) })

    companion object {
        fun empty() = LedgerDoc()

        private fun isCommit(c: Any?) = c is String && c.isNotEmpty()

        /** Decode a stored document (null = empty). Fails closed with `store_corrupt`; the result shares nothing with `raw`. */
        fun decode(raw: Any?): LedgerDoc {
            if (raw == null) return empty()
            val m = StoreJs.map(raw)
            if (m == null || !IntentJs.isInt(m["v"]) || IntentJs.lng(m["v"]) != 1L || m["commits"] !is List<*> || m["checkpoints"] !is List<*>) {
                throw LedgerStoreError("store_corrupt", "ledger document has the wrong shape")
            }
            val d = LedgerDoc()
            for (c in m["commits"] as List<*>) {
                if (!isCommit(c)) throw LedgerStoreError("store_corrupt", "ledger document has the wrong shape")
                d.commits.add(c as String)
            }
            for (c in m["checkpoints"] as List<*>) {
                val cm = StoreJs.map(c)
                if (cm == null || StoreJs.map(cm["sth"]) == null) throw LedgerStoreError("store_corrupt", "malformed checkpoint entry")
                d.checkpoints.add(StoreJs.map(StoreJs.deepCopy(cm))!!)
            }
            return d
        }

        private fun checkSafe(v: Long, what: String) {
            if (v < 0 || v > 9007199254740991L) throw IllegalArgumentException(what)
        }

        fun appendToLedgerDoc(doc: LedgerDoc, expectedSize: Long, commits: List<String>?): LedgerStore.AppendOutcome {
            checkSafe(expectedSize, "append: expectedSize must be a non-negative safe integer")
            if (commits.isNullOrEmpty()) throw IllegalArgumentException("append: commits must be a non-empty array of non-empty strings")
            for (c in commits) if (!isCommit(c)) throw IllegalArgumentException("append: commits must be a non-empty array of non-empty strings")
            val size = doc.commits.size.toLong()
            if (expectedSize < size) {
                var same = true
                for (i in commits.indices) {
                    val at = expectedSize + i
                    if (at >= size || doc.commits[at.toInt()] != commits[i]) { same = false; break }
                }
                return LedgerStore.AppendOutcome(if (same) "replayed" else "conflict", size)
            }
            if (expectedSize > size) return LedgerStore.AppendOutcome("conflict", size)
            doc.commits.addAll(commits)
            return LedgerStore.AppendOutcome("appended", doc.commits.size.toLong())
        }

        fun checkpointToLedgerDoc(doc: LedgerDoc, expectedCount: Long, cp: Map<String, Any?>?): LedgerStore.CheckpointOutcome {
            checkSafe(expectedCount, "appendCheckpoint: expectedCount must be a non-negative safe integer")
            val count = doc.checkpoints.size.toLong()
            if (expectedCount < count) {
                return if (StoreJs.jsonEq(doc.checkpoints[expectedCount.toInt()], cp)) LedgerStore.CheckpointOutcome("replayed", count, null)
                else LedgerStore.CheckpointOutcome("conflict", count, "another checkpoint holds that position")
            }
            if (expectedCount > count) return LedgerStore.CheckpointOutcome("conflict", count, "the checkpoint position is ahead of the log")
            val sth = if (cp == null) null else StoreJs.map(cp["sth"])
            if (sth == null || !IntentJs.isInt(sth["size"]) || IntentJs.lng(sth["size"]) < 0 || sth["root"] !is String) {
                return LedgerStore.CheckpointOutcome("conflict", count, "malformed checkpoint")
            }
            val size = IntentJs.lng(sth["size"])
            if (size > doc.commits.size) return LedgerStore.CheckpointOutcome("conflict", count, "the checkpoint is beyond the end of the log")
            val last = if (count == 0L) null else StoreJs.map(doc.checkpoints[count.toInt() - 1]["sth"])
            if (last != null) {
                val ls = StoreJs.dbl(last["size"]) // a stored size that is no number compares false both ways, as in the reference
                if (ls != null && (size < ls || (size.toDouble() == ls && sth["root"] != last["root"]))) {
                    return LedgerStore.CheckpointOutcome("conflict", count, "the checkpoint does not extend the previous one")
                }
            }
            doc.checkpoints.add(StoreJs.map(StoreJs.deepCopy(cp))!!)
            return LedgerStore.CheckpointOutcome("appended", doc.checkpoints.size.toLong(), null)
        }
    }
}

/**
 * The reference [LedgerStore]: the whole log is one document in an [AtomicKv], so every write is one atomic read-modify-write. Over
 * [JdbcAtomicKv] it is durable and safe across processes; over [MemoryAtomicKv] it is the in-process variant (tests only).
 * LIMIT: the document is rewritten on every write; a production log lives in a database with a unique index on the position.
 */
class KvLedgerStore @JvmOverloads constructor(private val kv: AtomicKv, private val key: String = DOC_KEY) : LedgerStore {
    private fun doc() = LedgerDoc.decode(kv.get(key))

    override fun size(): Long = doc().commits.size.toLong()

    override fun read(from: Long, to: Long): List<String> {
        val d = doc()
        if (from < 0 || from > to || to > d.commits.size) throw IllegalArgumentException("read: range is not inside the log")
        return ArrayList(d.commits.subList(from.toInt(), to.toInt()))
    }

    override fun append(expectedSize: Long, commits: List<String>): LedgerStore.AppendOutcome {
        var out: LedgerStore.AppendOutcome? = null
        kv.update(key) { prev ->
            val d = LedgerDoc.decode(prev)
            val o = LedgerDoc.appendToLedgerDoc(d, expectedSize, commits)
            out = o
            if (o.outcome == "appended") d.toJson() else null
        }
        return out!!
    }

    override fun checkpointCount(): Long = doc().checkpoints.size.toLong()

    override fun checkpoints(from: Long): List<Map<String, Any?>> {
        val d = doc()
        if (from < 0 || from > d.checkpoints.size) throw IllegalArgumentException("checkpoints: from is not inside the list")
        return d.checkpoints.subList(from.toInt(), d.checkpoints.size).map { StoreJs.map(StoreJs.deepCopy(it))!! }
    }

    override fun appendCheckpoint(expectedCount: Long, cp: Map<String, Any?>?): LedgerStore.CheckpointOutcome {
        var out: LedgerStore.CheckpointOutcome? = null
        kv.update(key) { prev ->
            val d = LedgerDoc.decode(prev)
            val o = LedgerDoc.checkpointToLedgerDoc(d, expectedCount, cp)
            out = o
            if (o.outcome == "appended") d.toJson() else null
        }
        return out!!
    }

    companion object {
        const val DOC_KEY = "pca-ledger-store/v1"
    }
}
