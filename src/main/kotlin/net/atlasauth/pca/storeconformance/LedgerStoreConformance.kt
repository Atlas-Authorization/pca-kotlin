package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.storeconformance.Suite.Check
import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.KvLedgerStore
import net.atlasauth.pca.verifier.LedgerDoc
import net.atlasauth.pca.verifier.LedgerStore
import net.atlasauth.pca.verifier.MemoryAtomicKv
import net.atlasauth.pca.verifier.StoreJs

/**
 * Conformance for transparency-log stores ([LedgerStore]). A ledger store is the durable side of a tamper-evident log: what it must
 * get right is atomic compare-and-swap on the length (one winner per position, all of a batch or none, no holes), idempotent retries,
 * the cryptography-free checkpoint rules, and durability of acknowledged writes. Each check is one such claim, driven against YOUR
 * store through an [Adapter]; a violation throws with the exact mismatch.
 */
@Suppress("UNCHECKED_CAST")
object LedgerStoreConformance {
    /** One isolated backend plus the means to reconnect to it. */
    class Handle(
        val store: LedgerStore,
        private val reopenFn: () -> LedgerStore,
        private val crashFn: (() -> LedgerStore)?,
        private val closer: (() -> Unit)?,
    ) : Suite.Handle {
        /** Another client on the SAME backend (the first stays usable). */
        fun reopen(): LedgerStore = reopenFn()

        /** Kill the backend abruptly (no flush), then return a client on whatever survived. */
        fun crash(): LedgerStore = crashFn!!()

        override fun canCrash(): Boolean = crashFn != null

        override fun close() { closer?.invoke() }
    }

    /** The adapter a store author implements. */
    interface Adapter {
        fun name(): String

        /** Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported. */
        fun durable(): Boolean = true

        /** A fresh, empty, isolated backend. Called once per check. */
        fun create(): Handle
    }

    // ---- fixtures ----

    private fun cm(i: Int): String = "commit-" + i + "-" + "x".repeat(30)

    private fun cp(size: Long, root: String = "root-$size", prev: String = ""): MutableMap<String, Any?> {
        val sth = linkedMapOf<String, Any?>(
            "instance_id" to "i", "principal" to "p", "size" to StoreJs.num(size), "root" to root, "prev_root" to prev,
            "timestamp" to StoreJs.num(1L), "guardian" to "g", "sig" to "s",
        )
        return linkedMapOf("sth" to sth)
    }

    private fun range(a: Int, b: Int): List<String> = (a until b).map { cm(it) }

    private fun all(s: LedgerStore): List<String> = s.read(0, s.size())

    private fun outcome(o: String, size: Long) = LedgerStore.AppendOutcome(o, size).toJson()

    private fun cpOutcome(o: String, count: Long) = LedgerStore.CheckpointOutcome(o, count, null).toJson()

    private fun sizes(cps: List<Map<String, Any?>>): List<Any?> = cps.map { StoreJs.map(it["sth"])!!["size"] }

    /** A writer that retries until its commit is in, the way a real client does. */
    private fun appendRetrying(s: LedgerStore, commit: String): Long {
        while (true) {
            val size = s.size()
            val r = s.append(size, listOf(commit))
            if (r.outcome == "appended" || r.outcome == "replayed") return size
        }
    }

    // ---- the checks ----

    val CHECKS: List<Check<Handle>> = listOf(
        Check<Handle>("empty-store-is-empty", "a new store has no entries and no checkpoints, and reads of the empty range succeed") { h ->
            val s = h.store
            Suite.eq(0, s.size())
            Suite.eq(listOf<Any?>(), s.read(0, 0))
            Suite.eq(0, s.checkpointCount())
            Suite.eq(listOf<Any?>(), s.checkpoints(0))
        },
        Check<Handle>("append-assigns-the-next-position", "an append at the current length adds its commits in order at exactly those positions") { h ->
            val s = h.store
            Suite.eq(outcome("appended", 1), s.append(0, listOf(cm(0))).toJson())
            Suite.eq(outcome("appended", 3), s.append(1, listOf(cm(1), cm(2))).toJson())
            Suite.eq(range(0, 3), s.read(0, 3))
            Suite.eq(range(1, 3), s.read(1, 3))
            Suite.eq(listOf<Any?>(), s.read(3, 3))
        },
        Check<Handle>("append-at-another-position-conflicts-without-trace", "an append whose expected length is not the current length conflicts, reports the real length, and writes nothing") { h ->
            val s = h.store
            s.append(0, range(0, 3))
            Suite.eq(outcome("conflict", 3), s.append(5, listOf(cm(9))).toJson())
            Suite.eq(outcome("conflict", 3), s.append(2, listOf(cm(9))).toJson())
            Suite.eq(range(0, 3), all(s))
        },
        Check<Handle>("append-retry-is-a-replay", "repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts") { h ->
            val s = h.store
            s.append(0, range(0, 3))
            Suite.eq(outcome("replayed", 3), s.append(0, range(0, 3)).toJson())
            Suite.eq(outcome("replayed", 3), s.append(1, range(1, 3)).toJson())
            Suite.eq(outcome("conflict", 3), s.append(0, listOf(cm(0), "other")).toJson())
            Suite.eq(outcome("conflict", 3), s.append(2, listOf(cm(2), cm(3))).toJson())
            Suite.eq(range(0, 3), all(s))
        },
        Check<Handle>("invalid-input-is-refused", "empty batches, empty or non-string commits and a bad expected length throw and write nothing") { h ->
            val s = h.store
            s.append(0, listOf(cm(0)))
            val bads = listOf<List<String?>>(listOf(), listOf(""), listOf(cm(1), null), listOf(null))
            for (bad in bads) Suite.rejects(IllegalArgumentException::class.java, { s.append(1, bad as List<String>) }, "append of $bad")
            for (bad in longArrayOf(-1, Long.MAX_VALUE, 9007199254740992L)) {
                Suite.rejects(IllegalArgumentException::class.java, { s.append(bad, listOf(cm(1))) }, "append at $bad")
            }
            Suite.eq(listOf(cm(0)), all(s))
            for (r in listOf(longArrayOf(-1, 1), longArrayOf(1, 0), longArrayOf(0, 2))) {
                Suite.rejects(IllegalArgumentException::class.java, { s.read(r[0], r[1]) }, "read ${r.toList()}")
            }
        },
        Check<Handle>("commit-strings-are-stored-exactly", "unicode, quotes, separators and long commits come back byte for byte") { h ->
            val s = h.store
            val odd = listOf("a\"b\\c", "gränt-🔒-\t-\u0001", "x".repeat(5000), "__proto__", " leading and trailing ")
            s.append(0, odd)
            Suite.eq(odd, all(s))
        },
        Check<Handle>("racing-appends-at-one-position-have-one-winner", "clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch") { h ->
            val clients = listOf(h.store, h.reopen(), h.reopen(), h.reopen())
            val r = Suite.parallel((0 until 8).map { n -> { clients[n % 4].append(0, listOf(cm(100 + n))) } })
            Suite.eq(1, r.count { it.outcome == "appended" })
            Suite.eq(7, r.count { it.outcome == "conflict" })
            val log = all(h.store)
            Suite.eq(1, log.size)
            Suite.ok(range(100, 108).contains(log[0]), "the log holds a winner's commit")
        },
        Check<Handle>("racing-writers-with-retry-fill-every-position-once", "sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once") { h ->
            val clients = listOf(h.store, h.reopen(), h.reopen())
            val idx = Suite.parallel((0 until 16).map { n -> { appendRetrying(clients[n % 3], cm(200 + n)) } })
            Suite.eq(16, idx.toSet().size)
            Suite.eq((0L until 16L).toList(), idx.sorted())
            val log = all(h.store)
            Suite.eq(range(200, 216).toSortedSet().toList(), log.toSortedSet().toList())
            Suite.eq(16, log.size)
            for (i in 0 until 16) Suite.eq(cm(200 + i), log[idx[i].toInt()])
        },
        Check<Handle>("a-batch-is-all-or-nothing", "a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit") { h ->
            val s = h.store
            s.append(0, range(0, 2))
            Suite.eq("conflict", s.append(5, range(10, 14)).outcome)
            Suite.eq(range(0, 2), all(s))
            Suite.eq(outcome("appended", 6), s.append(2, range(10, 14)).toJson())
            Suite.eq(range(0, 2) + range(10, 14), all(s))
        },
        Check<Handle>("checkpoints-append-by-count-and-replay", "a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts") { h ->
            val s = h.store
            s.append(0, range(0, 6))
            Suite.eq(cpOutcome("appended", 1), s.appendCheckpoint(0, cp(2)).toJson())
            Suite.eq(cpOutcome("replayed", 1), s.appendCheckpoint(0, cp(2)).toJson())
            Suite.eq("conflict", s.appendCheckpoint(0, cp(3)).outcome)
            Suite.eq("conflict", s.appendCheckpoint(2, cp(3)).outcome)
            Suite.eq(cpOutcome("appended", 2), s.appendCheckpoint(1, cp(5, "root-5", "root-2")).toJson())
            Suite.eq(listOf(2, 5), sizes(s.checkpoints(0)))
            Suite.eq(listOf(5), sizes(s.checkpoints(1)))
            Suite.eq(2, s.checkpointCount())
        },
        Check<Handle>("checkpoints-stay-inside-the-log-and-never-go-back", "a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused") { h ->
            val s = h.store
            s.append(0, range(0, 4))
            Suite.eq("conflict", s.appendCheckpoint(0, cp(5)).outcome)
            Suite.eq("appended", s.appendCheckpoint(0, cp(3)).outcome)
            Suite.eq("conflict", s.appendCheckpoint(1, cp(2)).outcome)
            Suite.eq("conflict", s.appendCheckpoint(1, cp(3, "other-root", "")).outcome)
            Suite.eq("appended", s.appendCheckpoint(1, cp(3)).outcome) // equal size, same root: allowed
            Suite.eq("conflict", s.appendCheckpoint(2, null).outcome)
            Suite.eq(2, s.checkpointCount())
        },
        Check<Handle>("racing-checkpoints-have-one-winner", "checkpoints racing for one position: exactly one lands") { h ->
            h.store.append(0, range(0, 6))
            val other = h.reopen()
            val who = listOf(h.store, other, h.store, other)
            val r = Suite.parallel((0 until 4).map { n -> { who[n].appendCheckpoint(0, cp(2L + n)) } })
            Suite.eq(1, r.count { it.outcome == "appended" })
            Suite.eq(1, h.store.checkpointCount())
        },
        Check<Handle>("reads-are-snapshots", "mutating what a read returned cannot change the store") { h ->
            val s = h.store
            s.append(0, range(0, 3))
            s.appendCheckpoint(0, cp(2))
            try { (s.read(0, 3) as MutableList<String>)[0] = "mutated" } catch (ignored: UnsupportedOperationException) { /* an unmodifiable copy is as good */ }
            val c = s.checkpoints(0)
            (StoreJs.map(c[0]["sth"]))!!["size"] = StoreJs.num(99L)
            Suite.eq(range(0, 3), all(s))
            Suite.eq(2, StoreJs.map(s.checkpoints(0)[0]["sth"])!!["size"])
        },
        Check<Handle>("state-survives-reopen", "every acknowledged append and checkpoint is visible to a new client after the backend restarts", "durable") { h ->
            h.store.append(0, range(0, 5))
            h.store.appendCheckpoint(0, cp(3))
            h.store.append(5, range(5, 7))
            val back = h.reopen()
            Suite.eq(range(0, 7), all(back))
            Suite.eq(listOf(cp(3)), back.checkpoints(0))
            Suite.eq(outcome("appended", 8), back.append(7, listOf(cm(7))).toJson())
        },
        Check<Handle>("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch", "crash") { h ->
            h.store.append(0, range(0, 3))
            h.store.appendCheckpoint(0, cp(2))
            val inflight = Thread { try { h.store.append(3, range(3, 7)) } catch (ignored: RuntimeException) { /* killed in flight */ } }
            inflight.start()
            val back = h.crash()
            inflight.join()
            val log = all(back)
            Suite.ok(log.size == 3 || log.size == 7, "log has ${log.size} entries") // the batch of four is whole or absent
            Suite.eq(range(0, log.size), log)
            Suite.eq(listOf(cp(2)), back.checkpoints(0))
            Suite.eq(outcome(if (log.size == 3) "appended" else "replayed", 7), back.append(3, range(3, 7)).toJson())
            Suite.eq(range(0, 7), all(back))
        },
    )

    /** Run the suite against [adapter] (only the named checks when [only] is non-null). */
    @JvmOverloads
    fun run(adapter: Adapter, only: Collection<String>? = null): Suite.Report =
        Suite.run("ledger store", adapter.name(), adapter.durable(), { adapter.create() }, CHECKS, only)

    // ---- reference adapters: GOOD ones must pass, BAD ones are positive controls the suite MUST flag ----

    /** An adapter over any [AtomicKv]: [backend] opens one isolated backend and returns a supplier of clients on it. */
    fun kvAdapter(name: String, durable: Boolean, backend: () -> (() -> AtomicKv), crashable: Boolean): Adapter = object : Adapter {
        override fun name() = name

        override fun durable() = durable

        override fun create(): Handle {
            val clients = backend()
            val open: () -> LedgerStore = { KvLedgerStore(clients()) }
            return Handle(open(), open, if (crashable) open else null, null)
        }
    }

    /** GOOD, in process: the reference store over a [MemoryAtomicKv]. Not durable (declared). */
    fun memoryAdapter(): Adapter = kvAdapter("KvLedgerStore over MemoryAtomicKv", false, { val kv = MemoryAtomicKv(); { kv } }, false)

    /** The mistakes a bad store makes. */
    enum class Defect(val label: String) {
        NO_CAS("BAD no compare-and-swap (appends at the tail whatever the caller saw)"),
        PARTIAL_BATCH("BAD partial batch (a conflicting batch leaves its first commit behind)"),
        LOST_UPDATE("BAD lost update (read, pause, write)"),
        AMNESIA("BAD amnesia (claims durability, forgets on reopen)"),
        CHECKPOINT_REGRESS("BAD checkpoint regression (accepts a checkpoint below the previous one)"),
        NO_REPLAY("BAD no idempotence (a retried batch conflicts)"),
    }

    /** A store with one switchable defect, for the positive controls (each reproduces a real mistake). */
    private class Defective(private val defect: Defect) : LedgerStore {
        private val lock = Any()

        @Volatile private var doc = LedgerDoc.empty()

        fun forget() { doc = LedgerDoc.empty() }

        override fun size(): Long = doc.commits.size.toLong()

        override fun read(from: Long, to: Long): List<String> {
            val d = doc
            if (from < 0 || from > to || to > d.commits.size) throw IllegalArgumentException("read")
            return ArrayList(d.commits.subList(from.toInt(), to.toInt()))
        }

        override fun append(expectedSize: Long, commits: List<String>): LedgerStore.AppendOutcome {
            if (expectedSize < 0 || commits.isEmpty()) throw IllegalArgumentException("append")
            for (c in commits) if ((c as String?).isNullOrEmpty()) throw IllegalArgumentException("append")
            if (defect == Defect.LOST_UPDATE) {
                val work = LedgerDoc.decode(doc.toJson())
                try { Thread.sleep(2) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
                val out = LedgerDoc.appendToLedgerDoc(work, expectedSize, commits)
                if (out.outcome == "appended") doc = work
                return out
            }
            synchronized(lock) {
                val d = doc
                if (defect == Defect.NO_CAS) {
                    d.commits.addAll(commits)
                    return LedgerStore.AppendOutcome("appended", d.commits.size.toLong())
                }
                if (defect == Defect.PARTIAL_BATCH && expectedSize != d.commits.size.toLong()) {
                    d.commits.add(commits[0])
                    return LedgerStore.AppendOutcome("conflict", d.commits.size.toLong())
                }
                val out = LedgerDoc.appendToLedgerDoc(d, expectedSize, commits)
                if (defect == Defect.NO_REPLAY && out.outcome == "replayed") return LedgerStore.AppendOutcome("conflict", out.size)
                return out
            }
        }

        override fun checkpointCount(): Long = doc.checkpoints.size.toLong()

        override fun checkpoints(from: Long): List<Map<String, Any?>> =
            doc.checkpoints.subList(from.toInt(), doc.checkpoints.size).map { StoreJs.map(StoreJs.deepCopy(it))!! }

        override fun appendCheckpoint(expectedCount: Long, cp: Map<String, Any?>?): LedgerStore.CheckpointOutcome = synchronized(lock) {
            val d = doc
            val sth = if (cp == null) null else StoreJs.map(cp["sth"])
            if (defect == Defect.CHECKPOINT_REGRESS && expectedCount == d.checkpoints.size.toLong() && sth != null) {
                d.checkpoints.add(StoreJs.map(StoreJs.deepCopy(cp))!!)
                return@synchronized LedgerStore.CheckpointOutcome("appended", d.checkpoints.size.toLong(), null)
            }
            LedgerDoc.checkpointToLedgerDoc(d, expectedCount, cp)
        }
    }

    /** A bad adapter: one store object shared by every client (a reopen on AMNESIA clears it). */
    fun defectiveAdapter(defect: Defect): Adapter = object : Adapter {
        override fun name() = defect.label

        override fun create(): Handle {
            val d = Defective(defect)
            val again: () -> LedgerStore = { if (defect == Defect.AMNESIA) d.forget(); d }
            return Handle(d, again, again, null)
        }
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    fun referenceAdapters(): Map<String, () -> Adapter> {
        val m = LinkedHashMap<String, () -> Adapter>()
        m["ledger-memory"] = { memoryAdapter() }
        for (d in Defect.values()) m["bad-ledger-" + d.name.lowercase().replace('_', '-')] = { defectiveAdapter(d) }
        return m
    }
}
