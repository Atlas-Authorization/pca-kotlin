package net.atlasauth.pca.verifier

/** What a failed undo-ledger operation says: [code] is one of `not_durable`, `store_missing`, `store_corrupt`, `invalid`, `conflict_exhausted`, `signer_missing`, `config`. */
class UndoError(val code: String, message: String) : RuntimeException("$code: $message")

/** Which undo records to list: the [state], and optionally those whose window ended by a time, of one grant or one bond. */
class UndoQuery @JvmOverloads constructor(
    val state: String,
    /** Only records whose window ended at or before this time (the finalize sweep). */
    val windowEndedBy: Long? = null,
    val grantRef: String? = null,
    val bondRef: String? = null,
    val limit: Int? = null,
)

/**
 * The persistence contract of the undo ledger. Implement it over a database (a row per record with a unique id and a version
 * column: `UPDATE ... WHERE id = ? AND ver = ?`) or use [KvUndoStore].
 */
interface UndoStore {
    /** True ONLY when acknowledged writes survive a restart or crash. The coordinator refuses a store that does not say so. */
    val durable: Boolean

    fun get(id: String): Map<String, Any?>?

    /** Atomically insert if no record with this id exists (returns null); otherwise return the stored one unchanged. */
    fun create(rec: Map<String, Any?>): Map<String, Any?>?

    /** Atomically replace the record iff its stored `ver` is [expectedVer]. */
    fun replace(id: String, expectedVer: Long, next: Map<String, Any?>): Boolean

    fun list(q: UndoQuery): List<Map<String, Any?>>
}

/** True when [s] is an [UndoStore]. */
fun isUndoStore(s: Any?): Boolean = s is UndoStore

private object UndoStoreSupport {
    fun matches(r: Map<String, Any?>, q: UndoQuery): Boolean =
        r["state"] == q.state && (q.windowEndedBy == null || IntentJs.lng(r["window_end"]) <= q.windowEndedBy) &&
            (q.grantRef == null || r["grant_ref"] == q.grantRef) && (q.bondRef == null || r["bond_ref"] == q.bondRef)

    fun copy(r: Map<String, Any?>): Map<String, Any?> = Pca.asMap(MemoryAtomicKv.copyTree(r))

    fun idOk(id: Any?): Boolean = Undo.idOk(id)

    @Suppress("UNCHECKED_CAST")
    fun decode(raw: Any?): Map<String, Any?>? {
        if (raw == null) return null
        val m = raw as? Map<String, Any?>
        if (m == null || IntentJs.num(m["v"]) != 1.0 || !idOk(m["id"]) || m["state"] !in Undo.STATES || !IntentJs.isSafeInteger(m["ver"]) || m["receipts"] !is List<*>) {
            throw UndoError("store_corrupt", "an undo record has the wrong shape")
        }
        return m
    }

    fun requireId(id: Any?) {
        if (!idOk(id)) throw UndoError("invalid", "an undo record id is a non-empty string without control characters")
    }
}

/**
 * The reference [UndoStore] over any [AtomicKv] that can list its keys (one document per record, every write one atomic
 * read-modify-write). [durable] is declared by the caller because a kv cannot tell: true only over a persistent kv ([JdbcAtomicKv]),
 * false over an in-memory one. `list` scans every key (fine for one host's backlog); a database store indexes (state, window_end).
 */
class KvUndoStore(private val kv: AtomicKv, override val durable: Boolean) : UndoStore {
    private fun k(id: String): String {
        UndoStoreSupport.requireId(id)
        return PREFIX + id
    }

    override fun get(id: String): Map<String, Any?>? = UndoStoreSupport.decode(kv.get(k(id)))?.let { UndoStoreSupport.copy(it) }

    override fun create(rec: Map<String, Any?>): Map<String, Any?>? {
        var existing: Map<String, Any?>? = null
        kv.update(k(rec["id"] as? String ?: "")) { prev ->
            existing = UndoStoreSupport.decode(prev)
            if (existing != null) null else UndoStoreSupport.copy(rec)
        }
        return existing?.let { UndoStoreSupport.copy(it) }
    }

    override fun replace(id: String, expectedVer: Long, next: Map<String, Any?>): Boolean {
        if (next["id"] != id) throw UndoError("invalid", "replace: the record id cannot change")
        var done = false
        kv.update(k(id)) { prev ->
            val cur = UndoStoreSupport.decode(prev)
            done = cur != null && IntentJs.lng(cur["ver"]) == expectedVer
            if (done) UndoStoreSupport.copy(next) else null
        }
        return done
    }

    override fun list(q: UndoQuery): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        for (key in kv.keys().filter { it.startsWith(PREFIX) }.sorted()) {
            val r = UndoStoreSupport.decode(kv.get(key))
            if (r != null && UndoStoreSupport.matches(r, q)) out.add(UndoStoreSupport.copy(r))
            if (q.limit != null && out.size >= q.limit) break
        }
        return out
    }

    private companion object {
        const val PREFIX = "pca-undo/v1/"
    }
}

/**
 * A process-memory [UndoStore]: [durable] is false, so the coordinator refuses it unless the caller says, for a test, that it accepts
 * losing every open window on restart. Never use it in production.
 */
class MemoryUndoStore : UndoStore {
    override val durable: Boolean = false
    private val m = HashMap<String, Map<String, Any?>>()

    @Synchronized
    override fun get(id: String): Map<String, Any?>? = m[id]?.let { UndoStoreSupport.copy(it) }

    @Synchronized
    override fun create(rec: Map<String, Any?>): Map<String, Any?>? {
        UndoStoreSupport.requireId(rec["id"])
        val id = rec["id"] as String
        val cur = m[id]
        if (cur != null) return UndoStoreSupport.copy(cur)
        m[id] = UndoStoreSupport.copy(rec)
        return null
    }

    @Synchronized
    override fun replace(id: String, expectedVer: Long, next: Map<String, Any?>): Boolean {
        if (next["id"] != id) throw UndoError("invalid", "replace: the record id cannot change")
        val cur = m[id] ?: return false
        if (IntentJs.lng(cur["ver"]) != expectedVer) return false
        m[id] = UndoStoreSupport.copy(next)
        return true
    }

    @Synchronized
    override fun list(q: UndoQuery): List<Map<String, Any?>> {
        val out = m.values.filter { UndoStoreSupport.matches(it, q) }.sortedBy { it["id"] as String }
        return (if (q.limit != null) out.take(q.limit) else out).map { UndoStoreSupport.copy(it) }
    }
}
