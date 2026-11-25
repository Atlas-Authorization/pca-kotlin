package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.storeconformance.Suite.Check
import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.BudgetDoc
import net.atlasauth.pca.verifier.BudgetLedger
import net.atlasauth.pca.verifier.KvBudgetLedger
import net.atlasauth.pca.verifier.MemoryAtomicKv
import net.atlasauth.pca.verifier.StoreJs

/**
 * Conformance for aggregate budget ledgers ([BudgetLedger]): no overspend at principal, org and fleet scope given a ledger that is
 * linearizable per key and durable. Each check is one claim (the cap holds under racing reservations, a reservation counts at once,
 * a release frees budget only for a real reservation, a committed event is never released, expiry frees only what never started, a
 * crash can only over-restrict), driven against YOUR ledger through an [Adapter].
 */
@Suppress("UNCHECKED_CAST")
object BudgetLedgerConformance {
    /** One isolated backend plus the means to reconnect to it. */
    class Handle(
        val ledger: BudgetLedger,
        private val reopenFn: () -> BudgetLedger,
        private val crashFn: (() -> BudgetLedger)?,
        private val closer: (() -> Unit)?,
    ) : Suite.Handle {
        /** Set by the runner: the adapter's declared durability, so a check can compare it with the ledger's own claim. */
        var adapterDurable = true

        /** Another client on the SAME backend (the first stays usable). */
        fun reopen(): BudgetLedger = reopenFn()

        /** Kill the backend abruptly, then return a client on whatever survived. */
        fun crash(): BudgetLedger = crashFn!!()

        override fun canCrash(): Boolean = crashFn != null

        override fun close() { closer?.invoke() }
    }

    /** The adapter a ledger author implements. */
    interface Adapter {
        fun name(): String

        /** Default true. Declare false ONLY for an in-process ledger; its `durable()` must then be false too, and the durability checks are skipped. */
        fun durable(): Boolean = true

        fun create(): Handle
    }

    // ---- fixtures ----

    private const val CAP = 200L
    private const val K = "principal/alice"
    private const val K2 = "principal/bob"

    private fun spend(over: Map<String, Any?> = emptyMap()): MutableMap<String, Any?> {
        val a = linkedMapOf<String, Any?>(
            "id" to "spend", "agg" to "sum", "val" to "action.params.amount", "sel" to mapOf("verbs" to listOf("pay")),
            "win" to mapOf("kind" to "task"), "key" to null, "domain_max" to StoreJs.num(CAP), "holder" to mapOf("kind" to "site_local"), "scope" to "principal",
        )
        a.putAll(over)
        return a
    }

    private fun ev(id: String, amount: Any?, t: Long = 1000): MutableMap<String, Any?> = linkedMapOf(
        "id" to id, "verb" to "pay", "resource" to "r",
        "params" to linkedMapOf("amount" to (if (amount is Number) StoreJs.num(amount.toDouble()) else amount)),
        "t" to StoreJs.num(t),
    )

    private fun req(event: Map<String, Any?>, accs: List<Map<String, Any?>>): BudgetLedger.ReserveRequest {
        val r = BudgetLedger.ReserveRequest()
        r.event = event
        r.accumulators = accs
        return r
    }

    private fun req(id: String, amount: Double, expectedVersion: Long? = null, expiresAt: Long? = null): BudgetLedger.ReserveRequest {
        val r = req(ev(id, amount), listOf(spend()))
        r.expectedVersion = expectedVersion
        r.expiresAt = expiresAt
        return r
    }

    private fun reservedTotal(l: BudgetLedger, key: String): Double =
        l.snapshot(key).events.filter { it["status"] != "released" }.sumOf { StoreJs.dbl(StoreJs.map(it["params"])!!["amount"])!! }

    private fun statuses(l: BudgetLedger, key: String): List<Any?> = l.snapshot(key).events.map { it["status"] }

    private fun mkEvidence(id: String): MutableMap<String, Any?> = linkedMapOf(
        "v" to StoreJs.num(1L), "key" to K, "id" to id, "reason" to "effect_failed", "at" to StoreJs.num(5L), "signer" to "s", "sig" to "x",
    )

    private fun count(r: List<BudgetLedger.ReserveOutcome>, outcome: String): Int = r.count { it.outcome == outcome }

    /** The outcome name, or the entry's status when the settlement was refused. */
    private fun refusedStatus(o: BudgetLedger.SettleOutcome): String? = if (o.outcome == "refused") o.status else o.outcome

    private fun reserves(clients: List<BudgetLedger>, n: Int, req: (Int) -> BudgetLedger.ReserveRequest): List<() -> BudgetLedger.ReserveOutcome> =
        (0 until n).map { k -> { clients[k % clients.size].reserve(K, req(k)) } }

    // ---- the checks ----

    val CHECKS: List<Check<Handle>> = listOf(
        Check<Handle>("empty-key-is-empty", "a key nobody reserved on has version 0 and no events") { h ->
            Suite.eq(linkedMapOf<String, Any?>("version" to 0, "events" to listOf<Any?>()), h.ledger.snapshot(K).toJson())
        },
        Check<Handle>("reservation-counts-at-once-and-cap-is-inclusive", "a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted") { h ->
            val l = h.ledger
            val a = l.reserve(K, req("a", 150.0))
            Suite.eq("reserved", a.outcome)
            Suite.eq(mapOf("spend" to 150), a.toJson()["post"])
            val b = l.reserve(K, req("b", 51.0))
            Suite.eq(listOf("over_cap", "spend", 201, CAP), listOf(b.outcome, b.acc.toString(), b.postValue, b.cap))
            Suite.eq("reserved", l.reserve(K, req("c", 50.0)).outcome)
            Suite.eq(CAP, reservedTotal(l, K))
        },
        Check<Handle>("a-refusal-writes-nothing", "an over-cap reservation leaves no event and does not move the version") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 150.0))
            val before = l.snapshot(K).toJson()
            Suite.eq("over_cap", l.reserve(K, req("b", 60.0)).outcome)
            Suite.eq(before, l.snapshot(K).toJson())
        },
        Check<Handle>("reserve-retry-is-a-replay", "the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts") { h ->
            val l = h.ledger
            val first = l.reserve(K, req("a", 150.0))
            Suite.eq(BudgetLedger.ReserveOutcome("replayed", first.version, null, "reserved", null, null, null).toJson(), l.reserve(K, req("a", 150.0)).toJson())
            Suite.eq("id_conflict", l.reserve(K, req("a", 10.0)).outcome)
            Suite.eq(150, reservedTotal(l, K))
            Suite.eq("reserved", l.reserve(K, req("b", 50.0)).outcome)
        },
        Check<Handle>("expected-version-is-compare-and-swap", "a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version") { h ->
            val l = h.ledger
            Suite.eq("reserved", l.reserve(K, req("a", 10.0, 0L, null)).outcome)
            Suite.eq(BudgetLedger.ReserveOutcome("conflict", 1, null, null, null, null, null).toJson(), l.reserve(K, req("b", 10.0, 0L, null)).toJson())
            Suite.eq(1, l.snapshot(K).events.size)
            Suite.eq("reserved", l.reserve(K, req("b", 10.0, 1L, null)).outcome)
            Suite.eq("replayed", l.reserve(K, req("a", 10.0, 0L, null)).outcome)
        },
        Check<Handle>("racing-reserves-never-pass-the-cap", "forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice") { h ->
            val clients = listOf(h.ledger, h.reopen(), h.reopen(), h.reopen())
            val rs = Suite.parallel(reserves(clients, 40) { i -> req("r$i", 30.0) })
            Suite.eq(6, count(rs, "reserved"))
            Suite.eq(34, count(rs, "over_cap"))
            Suite.eq(180, reservedTotal(h.ledger, K))
            Suite.eq(6, h.ledger.snapshot(K).events.map { it["id"] }.toSet().size)
        },
        Check<Handle>("racing-reserves-at-one-version-have-one-winner", "clients reserving with the same expected version: exactly one lands, the others conflict") { h ->
            val clients = listOf(h.ledger, h.reopen(), h.reopen())
            val rs = Suite.parallel(reserves(clients, 9) { i -> req("v$i", 1.0, 0L, null) })
            Suite.eq(1, count(rs, "reserved"))
            Suite.eq(8, count(rs, "conflict"))
            Suite.eq(1, h.ledger.snapshot(K).events.size)
        },
        Check<Handle>("racing-writers-with-retry-fill-the-cap-exactly", "twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused") { h ->
            val clients = listOf(h.ledger, h.reopen(), h.reopen())
            val tasks = (0 until 20).map { n ->
                {
                    val c = clients[n % 3]
                    var outcome = "conflict"
                    while (outcome == "conflict") outcome = c.reserve(K, req("w$n", 10.0, c.snapshot(K).version, null)).outcome
                    outcome
                }
            }
            for (o in Suite.parallel(tasks)) Suite.eq("reserved", o)
            Suite.eq(CAP, reservedTotal(h.ledger, K))
            Suite.eq("over_cap", h.ledger.reserve(K, req("extra", 1.0)).outcome)
        },
        Check<Handle>("settle-rules", "commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 10.0))
            l.reserve(K, req("b", 10.0))
            Suite.eq("unknown", l.commit(K, "ghost").outcome)
            Suite.eq("unknown", l.release(K, "ghost", null).outcome)
            Suite.eq("settled", l.commit(K, "a").outcome)
            Suite.eq("replayed", l.commit(K, "a").outcome)
            Suite.eq("committed", refusedStatus(l.release(K, "a", null)))
            Suite.eq("settled", l.release(K, "b", null).outcome)
            Suite.eq("replayed", l.release(K, "b", null).outcome)
            Suite.eq("released", refusedStatus(l.commit(K, "b")))
            Suite.eq(listOf("committed", "released"), statuses(l, K))
        },
        Check<Handle>("release-frees-budget-and-commit-keeps-it", "a released reservation no longer counts; a committed one still does; an open one keeps counting until settled") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 100.0))
            l.reserve(K, req("b", 100.0))
            Suite.eq("over_cap", l.reserve(K, req("c", 1.0)).outcome)
            l.release(K, "a", null)
            l.commit(K, "b")
            Suite.eq("reserved", l.reserve(K, req("d", 100.0)).outcome)
            Suite.eq("over_cap", l.reserve(K, req("e", 1.0)).outcome)
        },
        Check<Handle>("release-without-reserve-credits-nothing", "releasing an id that was never reserved does not create headroom, now or after the id is reserved later") { h ->
            val l = h.ledger
            Suite.eq("unknown", l.release(K, "ghost", null).outcome)
            Suite.eq("over_cap", l.reserve(K, req("a", 201.0)).outcome)
            Suite.eq("reserved", l.reserve(K, req("ghost", 200.0)).outcome)
            Suite.eq("over_cap", l.reserve(K, req("b", 1.0)).outcome)
        },
        Check<Handle>("a-late-commit-cannot-overspend", "after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 200.0))
            l.release(K, "a", null)
            l.reserve(K, req("b", 200.0))
            Suite.eq("refused", l.commit(K, "a").outcome)
            l.commit(K, "b")
            Suite.eq(1, l.snapshot(K).events.count { it["status"] == "committed" })
        },
        Check<Handle>("expiry-releases-only-open-reservations-past-their-deadline", "expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 40.0, null, 500L))
            l.reserve(K, req("b", 40.0, null, 500L))
            l.reserve(K, req("c", 40.0))
            l.reserve(K, req("d", 40.0, null, 500L))
            l.commit(K, "b")
            l.start(K, "d")
            Suite.eq(listOf<Any?>(), l.expire(K, 499).released)
            Suite.eq(listOf("a"), l.expire(K, 500).released)
            Suite.eq(listOf<Any?>(), l.expire(K, 10_000).released)
            Suite.eq(120, reservedTotal(l, K))
            Suite.eq("refused", l.commit(K, "a").outcome)
            Suite.eq("refused", l.start(K, "a").outcome)
        },
        Check<Handle>("start-rules", "start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 10.0, null, 5L))
            l.reserve(K, req("b", 10.0))
            l.reserve(K, req("c", 10.0))
            val v = l.snapshot(K).version
            Suite.eq("unknown", l.start(K, "ghost").outcome)
            Suite.eq(v, l.snapshot(K).version)
            Suite.eq("settled", l.start(K, "a").outcome)
            Suite.eq("replayed", l.start(K, "a").outcome)
            Suite.eq(listOf<Any?>(), l.expire(K, 100).released)
            Suite.eq("settled", l.commit(K, "a").outcome)
            Suite.eq("replayed", l.start(K, "a").outcome)
            l.start(K, "b")
            Suite.eq("settled", l.release(K, "b", null).outcome)
            Suite.eq("released", refusedStatus(l.start(K, "b")))
            for (e in l.snapshot(K).events) if (e["id"] == "c") Suite.ok(!e.containsKey("started"), "an unstarted reservation has no started flag")
        },
        Check<Handle>("keys-are-independent", "two keys have their own caps, versions and events") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 200.0))
            Suite.eq("reserved", l.reserve(K2, req("a", 200.0)).outcome)
            Suite.eq("over_cap", l.reserve(K, req("b", 1.0)).outcome)
            Suite.eq(listOf("a"), l.snapshot(K2).events.map { it["id"] })
            Suite.eq(1, l.snapshot(K2).version)
        },
        Check<Handle>("windows-reset-the-count", "a period window counts only the events of the period of the new event") { h ->
            val l = h.ledger
            val win = linkedMapOf<String, Any?>("kind" to "period", "ms" to StoreJs.num(1000L), "t0" to StoreJs.num(0L))
            val w = listOf(spend(mapOf("win" to win)))
            Suite.eq("reserved", l.reserve(K, req(ev("a", 200, 100), w)).outcome)
            Suite.eq("over_cap", l.reserve(K, req(ev("b", 1, 900), w)).outcome)
            Suite.eq("reserved", l.reserve(K, req(ev("c", 200, 1100), w)).outcome)
        },
        Check<Handle>("release-evidence-is-stored-and-bound", "evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 10.0))
            Suite.rejects(IllegalArgumentException::class.java, { l.release(K, "a", mkEvidence("other")) }, "evidence for another reservation")
            Suite.eq("reserved", l.snapshot(K).events[0]["status"])
            Suite.eq("settled", l.release(K, "a", mkEvidence("a")).outcome)
            Suite.eq(mkEvidence("a"), l.snapshot(K).events[0]["rel"])
        },
        Check<Handle>("invalid-input-is-refused", "a malformed event or request throws and writes nothing") { h ->
            val l = h.ledger
            val badT = ev("x", 1.0)
            badT["t"] = StoreJs.num(0.5)
            val badVerb = ev("x", 1.0)
            badVerb["verb"] = 7
            for (bad in listOf(ev("", 1.0), badT, badVerb)) {
                Suite.rejects(IllegalArgumentException::class.java, { l.reserve(K, req(bad, listOf(spend()))) }, "reserve of $bad")
            }
            Suite.rejects(IllegalArgumentException::class.java, { l.reserve(K, req("x", 1.0, -1L, null)) }, "negative expected version")
            val noCap = spend()
            noCap["domain_max"] = null
            Suite.rejects(IllegalArgumentException::class.java, { l.reserve(K, req(ev("x", 1.0), listOf(noCap))) }, "accumulator without a cap")
            Suite.eq(linkedMapOf<String, Any?>("version" to 0, "events" to listOf<Any?>()), l.snapshot(K).toJson())
        },
        Check<Handle>("snapshots-are-copies", "mutating what a snapshot returned cannot change the ledger") { h ->
            val l = h.ledger
            l.reserve(K, req("a", 10.0))
            (l.snapshot(K).events[0] as MutableMap<String, Any?>)["status"] = "released"
            Suite.eq("reserved", l.snapshot(K).events[0]["status"])
        },
        Check<Handle>("durable-claim-matches-the-adapter", "a ledger says durable exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal") { h ->
            Suite.ok(h.ledger.durable() == h.adapterDurable, "ledger.durable()=${h.ledger.durable()} but the adapter declares durable=${h.adapterDurable}")
        },
        Check<Handle>("state-survives-reopen", "every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds", "durable") { h ->
            h.ledger.reserve(K, req("a", 150.0))
            h.ledger.reserve(K, req("b", 50.0))
            h.ledger.commit(K, "a")
            h.ledger.release(K, "b", null)
            val back = h.reopen()
            Suite.eq(listOf(listOf("a", "committed"), listOf("b", "released")), back.snapshot(K).events.map { listOf(it["id"], it["status"]) })
            Suite.eq("over_cap", back.reserve(K, req("c", 51.0)).outcome)
            Suite.eq("reserved", back.reserve(K, req("c", 50.0)).outcome)
        },
        Check<Handle>("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap", "crash") { h ->
            h.ledger.reserve(K, req("a", 200.0))
            val inflight = Thread { try { h.ledger.reserve(K, req("b", 0.0)) } catch (ignored: RuntimeException) { /* killed in flight */ } }
            inflight.start()
            val back = h.crash()
            inflight.join()
            Suite.eq("over_cap", back.reserve(K, req("c", 1.0)).outcome)
            Suite.eq("a", back.snapshot(K).events[0]["id"])
        },
    )

    /** Run the suite against [adapter] (only the named checks when [only] is non-null). */
    @JvmOverloads
    fun run(adapter: Adapter, only: Collection<String>? = null): Suite.Report =
        Suite.run("budget ledger", adapter.name(), adapter.durable(), { adapter.create().also { it.adapterDurable = adapter.durable() } }, CHECKS, only)

    // ---- reference adapters ----

    /** An adapter over any [AtomicKv]: [backend] opens one isolated backend and returns a supplier of clients on it. */
    fun kvAdapter(name: String, durable: Boolean, backend: () -> (() -> AtomicKv), crashable: Boolean): Adapter = object : Adapter {
        override fun name() = name

        override fun durable() = durable

        override fun create(): Handle {
            val clients = backend()
            val open: () -> BudgetLedger = { KvBudgetLedger(clients(), durable) }
            return Handle(open(), open, if (crashable) open else null, null)
        }
    }

    /** GOOD, in process: the reference ledger over a [MemoryAtomicKv]. Not durable (declared, and the ledger says so too). */
    fun memoryAdapter(): Adapter = kvAdapter("KvBudgetLedger over MemoryAtomicKv", false, { val kv = MemoryAtomicKv(); { kv } }, false)

    /** The mistakes a bad ledger makes. */
    enum class Defect(val label: String) {
        NO_CAP("BAD no cap check (records every reservation)"),
        NO_CAS("BAD no compare-and-swap (ignores expectedVersion)"),
        LOST_UPDATE("BAD lost update (read, pause, write)"),
        AMNESIA("BAD amnesia (claims durability, forgets on reopen)"),
        RELEASE_UNRESERVED("BAD release without reserve (credits budget for an unknown id)"),
        RELEASE_COMMITTED("BAD release of a committed event (frees spent budget)"),
        LATE_COMMIT("BAD late commit (a released reservation can be committed again)"),
        NO_REPLAY("BAD no idempotence (a retried reservation counts twice)"),
        SHARED_KEYS("BAD one state for every key (keys leak into each other)"),
        EXPIRE_COMMITTED("BAD expiry releases committed events"),
        EXPIRE_STARTED("BAD expiry releases started reservations (an effect that ran stops counting)"),
        VOLATILE_CLAIMS_DURABLE("BAD in-process ledger that claims durable: true"),
    }

    private class Defective(private val defect: Defect) : BudgetLedger {
        private val lock = Any()

        @Volatile private var docs = HashMap<String, BudgetDoc>()

        fun forget() { docs = HashMap() }

        private fun doc(key: String): BudgetDoc = docs.getOrPut(if (defect == Defect.SHARED_KEYS) "*" else key) { BudgetDoc.empty() }

        override fun durable() = true // every defective ledger claims durability (VOLATILE_CLAIMS_DURABLE is the lie the check catches)

        override fun snapshot(key: String): BudgetLedger.Snapshot = synchronized(lock) {
            val d = doc(key)
            BudgetLedger.Snapshot(d.ver, d.events.map { StoreJs.map(StoreJs.deepCopy(it))!! })
        }

        override fun reserve(key: String, req: BudgetLedger.ReserveRequest): BudgetLedger.ReserveOutcome {
            var rr = req
            if (defect == Defect.NO_CAS) { rr = copy(req); rr.expectedVersion = null }
            if (defect == Defect.NO_CAP) {
                rr = copy(rr)
                rr.accumulators = req.accumulators!!.map { a -> LinkedHashMap(a).also { it["domain_max"] = StoreJs.num(9007199254740991L) } }
            }
            if (defect == Defect.LOST_UPDATE) {
                val work = BudgetDoc.decode(doc(key).encode())
                try { Thread.sleep(2) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
                val out = work.reserveInDoc(rr)
                if (out.outcome == "reserved") docs[key] = work
                return out
            }
            synchronized(lock) {
                val d = doc(key)
                if (defect == Defect.NO_REPLAY) {
                    for (e in d.events) {
                        if (e["id"] == req.event!!["id"]) {
                            val dup = StoreJs.map(StoreJs.deepCopy(e))!!
                            dup["id"] = req.event!!["id"].toString() + "#dup"
                            d.events.add(dup)
                            d.ver += 1
                            return BudgetLedger.ReserveOutcome("reserved", d.ver, LinkedHashMap(), null, null, null, null)
                        }
                    }
                }
                return d.reserveInDoc(rr)
            }
        }

        private fun copy(r: BudgetLedger.ReserveRequest): BudgetLedger.ReserveRequest {
            val c = BudgetLedger.ReserveRequest()
            c.event = r.event
            c.accumulators = r.accumulators
            c.schema = r.schema
            c.expectedVersion = r.expectedVersion
            c.expiresAt = r.expiresAt
            return c
        }

        private fun find(d: BudgetDoc, id: String): MutableMap<String, Any?>? = d.events.firstOrNull { id == it["id"] }

        override fun start(key: String, id: String) = synchronized(lock) { doc(key).startInDoc(id) }

        override fun commit(key: String, id: String): BudgetLedger.SettleOutcome = synchronized(lock) {
            val d = doc(key)
            if (defect == Defect.LATE_COMMIT) {
                val e = find(d, id)
                if (e != null && e["status"] == "released") {
                    e["status"] = "committed"
                    d.ver += 1
                    return@synchronized BudgetLedger.SettleOutcome("settled", d.ver, null)
                }
            }
            d.commitInDoc(id)
        }

        override fun release(key: String, id: String, evidence: Map<String, Any?>?): BudgetLedger.SettleOutcome = synchronized(lock) {
            val d = doc(key)
            val e = find(d, id)
            if (defect == Defect.RELEASE_UNRESERVED && e == null) {
                val ghost = ev(id, 0.0, 0)
                StoreJs.map(ghost["params"])!!["amount"] = StoreJs.num(-CAP)
                ghost["status"] = "committed"
                d.events.add(ghost)
                d.ver += 1
                return@synchronized BudgetLedger.SettleOutcome("settled", d.ver, null)
            }
            if (defect == Defect.RELEASE_COMMITTED && e != null && e["status"] == "committed") {
                e["status"] = "released"
                d.ver += 1
                return@synchronized BudgetLedger.SettleOutcome("settled", d.ver, null)
            }
            d.releaseInDoc(key, id, evidence)
        }

        override fun expire(key: String, now: Long): BudgetLedger.Expired = synchronized(lock) {
            val d = doc(key)
            if (defect == Defect.EXPIRE_COMMITTED || defect == Defect.EXPIRE_STARTED) {
                val released = ArrayList<String>()
                for (e in d.events) {
                    val exp = if (e.containsKey("exp")) StoreJs.dbl(e["exp"]) else null
                    val hit = exp != null && exp <= now && (if (defect == Defect.EXPIRE_COMMITTED) e["status"] != "released" else e["status"] == "reserved")
                    if (hit) { e["status"] = "released"; released.add(e["id"] as String) }
                }
                if (released.isNotEmpty()) d.ver += 1
                return@synchronized BudgetLedger.Expired(released, d.ver)
            }
            d.expireInDoc(now)
        }
    }

    /** A bad adapter: one ledger object shared by every client (a reopen on AMNESIA clears it). */
    fun defectiveAdapter(defect: Defect): Adapter = object : Adapter {
        override fun name() = defect.label

        override fun durable() = defect != Defect.VOLATILE_CLAIMS_DURABLE

        override fun create(): Handle {
            val d = Defective(defect)
            val again: () -> BudgetLedger = { if (defect == Defect.AMNESIA) d.forget(); d }
            return Handle(d, again, again, null)
        }
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    fun referenceAdapters(): Map<String, () -> Adapter> {
        val m = LinkedHashMap<String, () -> Adapter>()
        m["budget-memory"] = { memoryAdapter() }
        for (d in Defect.values()) m["bad-budget-" + d.name.lowercase().replace('_', '-')] = { defectiveAdapter(d) }
        return m
    }
}
