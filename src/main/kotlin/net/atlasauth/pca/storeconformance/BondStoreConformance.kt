package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.storeconformance.Suite.Check
import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.BondDoc
import net.atlasauth.pca.verifier.BondStore
import net.atlasauth.pca.verifier.KvBondStore
import net.atlasauth.pca.verifier.MemoryAtomicKv
import net.atlasauth.pca.verifier.StoreJs

/**
 * Conformance for bond-settlement stores ([BondStore]). A bond store keeps INTERNAL ACCOUNTING for the optimistic path (escrow,
 * depositors, challengers, treasury); no money moves. What it must get right is atomicity and idempotence: a transition (open,
 * release, slash) applies in full or not at all, a retry of a committed transition returns the stored record and moves nothing, two
 * racing transitions on one bond have exactly one winner, and an acknowledged commit survives a restart or a crash. Each check is
 * one such claim, driven against YOUR store through an [Adapter].
 */
@Suppress("UNCHECKED_CAST")
object BondStoreConformance {
    /** One isolated backend plus the means to reconnect to it. */
    class Handle(
        val store: BondStore,
        private val reopenFn: () -> BondStore,
        private val crashFn: (() -> BondStore)?,
        private val closer: (() -> Unit)?,
    ) : Suite.Handle {
        /** Another client on the SAME backend. After a restart this is how state is read back. */
        fun reopen(): BondStore = reopenFn()

        /** Kill the backend abruptly, then return a client on whatever survived. */
        fun crash(): BondStore = crashFn!!()

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

    // ---- plan builders (the store never verifies signatures; records are opaque to it) ----

    private fun num(v: Double) = StoreJs.num(v)

    internal fun rec(claimId: String, action: String, amount: Double, from: String, to: String, evidenceDigest: String, split: Map<String, Any?>?): MutableMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["claimId"] = claimId
        r["action"] = action
        r["amount"] = num(amount)
        r["from"] = from
        r["to"] = to
        r["at"] = num(1.0)
        r["evidenceDigest"] = evidenceDigest
        if (split != null) r["split"] = split
        r["sig"] = "sig"
        return r
    }

    internal fun move(account: String, op: String, amount: Double): MutableMap<String, Any?> =
        linkedMapOf("account" to account, "op" to op, "amount" to num(amount))

    internal fun openPlan(id: String, dep: String, amount: Double, maxOpenClaims: Double = 100.0, maxOpenAmount: Double = 1e9): MutableMap<String, Any?> {
        val open = linkedMapOf<String, Any?>("amount" to num(amount), "depositor" to dep, "maxOpenClaims" to num(maxOpenClaims), "maxOpenAmount" to num(maxOpenAmount))
        return linkedMapOf(
            "claimId" to id, "expect" to "none", "next" to "open", "open" to open,
            "moves" to arrayListOf<Any?>(move(dep, "debit", amount), move("escrow", "credit", amount)),
            "record" to rec(id, "open", amount, dep, "escrow", "", null),
        )
    }

    internal fun releasePlan(id: String, dep: String, amount: Double): MutableMap<String, Any?> = linkedMapOf(
        "claimId" to id, "expect" to "open", "next" to "released",
        "moves" to arrayListOf<Any?>(move("escrow", "debit", amount), move(dep, "credit", amount)),
        "record" to rec(id, "release", amount, "escrow", dep, "", null),
    )

    internal fun slashPlan(id: String, amount: Double, evidence: String = "ev"): MutableMap<String, Any?> {
        val split = linkedMapOf<String, Any?>(
            "amount" to num(amount), "challengerReward" to num(amount / 2), "victimCompensation" to num(0.0), "treasuryRemainder" to num(amount / 2),
            "challengerAccount" to "chal", "victimAccount" to "pool", "treasuryAccount" to "treasury",
        )
        return linkedMapOf(
            "claimId" to id, "expect" to "open", "next" to "slashed",
            "moves" to arrayListOf<Any?>(move("escrow", "debit", amount), move("chal", "credit", amount / 2), move("treasury", "credit", amount / 2)),
            "record" to rec(id, "slash", amount, "escrow", "treasury", evidence, split),
        )
    }

    private fun record(plan: Map<String, Any?>): Map<String, Any?> = plan["record"] as Map<String, Any?>

    private fun committed(plan: Map<String, Any?>) = BondStore.CommitOutcome("committed", record(plan), null, null).toJson()

    private fun replayed(plan: Map<String, Any?>) = BondStore.CommitOutcome("replayed", record(plan), null, null).toJson()

    private fun commit(s: BondStore, plan: Map<String, Any?>, at: Double) = s.commit(plan, at)

    private fun bal(s: BondStore, vararg accounts: String): List<Any?> = accounts.map { s.read("", it).balances[it] }

    private fun status(s: BondStore, id: String): String = (s.read(id, null).bond?.get("status") as String?) ?: "none"

    private val ACCOUNTS = arrayOf("alice", "bob", "escrow", "chal", "treasury")

    private fun total(s: BondStore): Double = bal(s, *ACCOUNTS).sumOf { it as Double }

    private fun outcomes(r: List<BondStore.CommitOutcome>): List<String> = r.map { it.outcome }.sorted()

    private fun count(r: List<BondStore.CommitOutcome>, outcome: String): Int = r.count { it.outcome == outcome }

    private fun records(s: BondStore, id: String): List<Any?> = s.read(id, null).bond!!["records"] as List<Any?>

    // ---- the checks ----

    val CHECKS: List<Check<Handle>> = listOf(
        Check<Handle>("empty-store-reads-empty", "an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0") { h ->
            val want = linkedMapOf<String, Any?>("balances" to listOf(listOf("alice", 0)), "openTotals" to mapOf("count" to 0, "sum" to 0), "highWater" to 0)
            Suite.eq(want, h.store.read("nope", "alice").toJson())
        },
        Check<Handle>("deposit-validates-and-accumulates", "deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit") { h ->
            val s = h.store
            Suite.eq(2.5, s.deposit("alice", 2.5))
            Suite.eq(3.0, s.deposit("alice", 0.5))
            for (bad in doubleArrayOf(0.0, -1.0, Double.NaN, Double.POSITIVE_INFINITY)) Suite.rejects({ s.deposit("alice", bad) }, "deposit of $bad")
            Suite.rejects({ s.deposit("", 1.0) }, "deposit to an unnamed account")
            Suite.eq(listOf(3), bal(s, "alice"))
        },
        Check<Handle>("open-is-atomic-and-recorded", "an open moves the collateral, stores the row with its record, and raises the high-water mark, all together") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            val plan = openPlan("b1", "alice", 60.0)
            Suite.eq(committed(plan), commit(s, plan, 500.0).toJson())
            val bond = linkedMapOf<String, Any?>("claimId" to "b1", "amount" to 60, "depositor" to "alice", "status" to "open", "records" to listOf(record(plan)))
            val want = linkedMapOf<String, Any?>(
                "bond" to bond, "balances" to listOf(listOf("alice", 40)), "openTotals" to mapOf("count" to 1, "sum" to 60), "highWater" to 500,
            )
            Suite.eq(want, s.read("b1", "alice").toJson())
            Suite.eq(listOf(60), bal(s, "escrow"))
        },
        Check<Handle>("open-overdraft-refused-without-trace", "an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched") { h ->
            val s = h.store
            s.deposit("alice", 10.0)
            Suite.eq("conflict", commit(s, openPlan("b1", "alice", 60.0), 900.0).outcome)
            val want = linkedMapOf<String, Any?>("balances" to listOf(listOf("alice", 10)), "openTotals" to mapOf("count" to 0, "sum" to 0), "highWater" to 0)
            Suite.eq(want, s.read("b1", "alice").toJson())
            Suite.eq(listOf(0), bal(s, "escrow"))
        },
        Check<Handle>("open-retry-is-replayed-and-different-terms-conflict", "committing the same open again returns the stored record and moves nothing; other terms for that bond conflict") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            val plan = openPlan("b1", "alice", 60.0)
            commit(s, plan, 1.0)
            Suite.eq(replayed(plan), commit(s, plan, 2.0).toJson())
            Suite.eq("conflict", commit(s, openPlan("b1", "alice", 61.0), 3.0).outcome)
            Suite.eq("conflict", commit(s, openPlan("b1", "bob", 60.0), 3.0).outcome)
            Suite.eq(listOf(40, 60), bal(s, "alice", "escrow"))
            Suite.eq(1, records(s, "b1").size)
        },
        Check<Handle>("open-caps-are-rechecked-at-commit", "the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            Suite.eq("committed", commit(s, openPlan("c1", "alice", 30.0, 2.0, 50.0), 1.0).outcome)
            Suite.eq("conflict", commit(s, openPlan("c2", "alice", 21.0, 2.0, 50.0), 1.0).outcome) // 30 + 21 > 50
            Suite.eq("committed", commit(s, openPlan("c3", "alice", 20.0, 2.0, 50.0), 1.0).outcome)
            Suite.eq("conflict", commit(s, openPlan("c4", "alice", 1.0, 2.0, 50.0), 1.0).outcome) // third open claim
            Suite.eq(listOf(50, 50), bal(s, "alice", "escrow"))
        },
        Check<Handle>("settle-applies-every-move-once", "a release and a slash apply all their balance moves, store the record, and conserve the total") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            commit(s, openPlan("r", "alice", 20.0), 1.0)
            commit(s, openPlan("s", "alice", 40.0), 1.0)
            val rel = releasePlan("r", "alice", 20.0)
            val sl = slashPlan("s", 40.0)
            Suite.eq(committed(rel), commit(s, rel, 2.0).toJson())
            Suite.eq(committed(sl), commit(s, sl, 3.0).toJson())
            Suite.eq(listOf(60, 0, 20, 20), bal(s, "alice", "escrow", "chal", "treasury"))
            Suite.eq(100, total(s))
            Suite.eq(listOf("released", "slashed"), listOf(status(s, "r"), status(s, "s")))
            Suite.eq(listOf(record(openPlan("s", "alice", 40.0)), record(sl)), records(s, "s"))
        },
        Check<Handle>("settle-needs-the-expected-phase", "settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            Suite.eq("conflict", commit(s, releasePlan("ghost", "alice", 5.0), 9.0).outcome)
            commit(s, openPlan("b", "alice", 20.0), 10.0)
            commit(s, releasePlan("b", "alice", 20.0), 11.0)
            val before = bal(s, "alice", "escrow", "treasury", "chal") + s.read("b", null).highWater
            Suite.eq("conflict", commit(s, slashPlan("b", 20.0), 99.0).outcome)
            val after = bal(s, "alice", "escrow", "treasury", "chal") + s.read("b", null).highWater
            Suite.eq(before, after)
            Suite.eq("released", status(s, "b"))
        },
        Check<Handle>("settle-overdraw-refused-without-trace", "a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            commit(s, openPlan("b", "alice", 20.0), 1.0)
            val greedy = slashPlan("b", 20.0)
            greedy["moves"] = arrayListOf<Any?>(move("escrow", "debit", 21.0), move("treasury", "credit", 21.0))
            Suite.eq("conflict", commit(s, greedy, 5.0).outcome)
            Suite.eq(listOf(20, 0), bal(s, "escrow", "treasury"))
            Suite.eq("open", status(s, "b"))
        },
        Check<Handle>("settle-retry-returns-the-stored-record", "the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            commit(s, openPlan("b", "alice", 40.0), 1.0)
            val sl = slashPlan("b", 40.0, "ev-1")
            commit(s, sl, 2.0)
            val again = slashPlan("b", 40.0, "ev-1")
            val other = LinkedHashMap(record(sl))
            other["at"] = num(77.0)
            other["sig"] = "other"
            again["record"] = other
            Suite.eq(replayed(sl), commit(s, again, 3.0).toJson())
            Suite.eq("conflict", commit(s, slashPlan("b", 40.0, "ev-2"), 3.0).outcome)
            Suite.eq("conflict", commit(s, releasePlan("b", "alice", 40.0), 3.0).outcome)
            Suite.eq(listOf(60, 0, 20, 20), bal(s, "alice", "escrow", "chal", "treasury"))
            Suite.eq(2, records(s, "b").size)
        },
        Check<Handle>("racing-identical-settles-commit-once", "eight clients racing the same release: one commits, seven are replays, funds move once") { h ->
            h.store.deposit("alice", 100.0)
            commit(h.store, openPlan("b", "alice", 40.0), 1.0)
            val clients = listOf(h.store, h.reopen(), h.reopen(), h.reopen())
            val tasks = (0 until 8).map { n -> { clients[n % clients.size].commit(releasePlan("b", "alice", 40.0), (10 + n).toDouble()) } }
            Suite.eq(listOf("committed") + List(7) { "replayed" }, outcomes(Suite.parallel(tasks)))
            Suite.eq(listOf(100, 0), bal(h.store, "alice", "escrow"))
            Suite.eq(2, records(h.store, "b").size)
        },
        Check<Handle>("racing-conflicting-settles-have-one-winner", "a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved") { h ->
            h.store.deposit("alice", 100.0)
            commit(h.store, openPlan("b", "alice", 40.0), 1.0)
            val other = h.reopen()
            val r = Suite.parallel(listOf(
                { h.store.commit(releasePlan("b", "alice", 40.0), 5.0) }, { other.commit(slashPlan("b", 40.0), 5.0) },
                { h.store.commit(slashPlan("b", 40.0), 5.0) }, { other.commit(releasePlan("b", "alice", 40.0), 5.0) },
            ))
            Suite.eq(1, count(r, "committed"))
            Suite.eq(3, count(r, "conflict") + count(r, "replayed"))
            val st = status(h.store, "b")
            Suite.eq(if (st == "released") listOf(100, 0, 0, 0) else listOf(60, 0, 20, 20), bal(h.store, "alice", "escrow", "chal", "treasury"))
            Suite.eq(100, total(h.store))
        },
        Check<Handle>("racing-opens-for-the-same-bond-commit-once", "concurrent identical opens collect the collateral once; a differing open loses") { h ->
            h.store.deposit("alice", 100.0)
            val other = h.reopen()
            val r = Suite.parallel(listOf(
                { h.store.commit(openPlan("b", "alice", 60.0), 1.0) }, { other.commit(openPlan("b", "alice", 60.0), 1.0) },
                { h.store.commit(openPlan("b", "alice", 60.0), 1.0) }, { other.commit(openPlan("b", "alice", 50.0), 1.0) },
            ))
            Suite.eq(1, count(r, "committed"))
            Suite.eq(if (r[3].outcome == "committed") listOf(50, 50) else listOf(40, 60), bal(h.store, "alice", "escrow"))
            Suite.eq(100, total(h.store))
        },
        Check<Handle>("racing-opens-cannot-overdraw", "concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited") { h ->
            h.store.deposit("alice", 100.0)
            val other = h.reopen()
            val tasks = (0 until 6).map { n -> { (if (n % 2 == 1) h.store else other).commit(openPlan("b$n", "alice", 40.0), 1.0) } }
            Suite.eq(2, count(Suite.parallel(tasks), "committed"))
            Suite.eq(listOf(20, 80), bal(h.store, "alice", "escrow"))
        },
        Check<Handle>("concurrent-deposits-lose-nothing", "sixteen racing deposits add up exactly") { h ->
            val other = h.reopen()
            Suite.parallel((0 until 16).map { n -> { (if (n % 2 == 1) h.store else other).deposit("alice", 1.0) } })
            Suite.eq(listOf(16), bal(h.store, "alice"))
        },
        Check<Handle>("time-high-water-only-moves-forward", "the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            commit(s, openPlan("a", "alice", 10.0), 100.0)
            commit(s, openPlan("b", "alice", 10.0), 40.0)
            Suite.eq(100, s.read("", null).highWater)
            commit(s, openPlan("c", "alice", 10.0), Double.NaN)
            Suite.eq(100, s.read("", null).highWater)
            commit(s, openPlan("d", "alice", 10.0), 101.0)
            Suite.eq(101, s.read("", null).highWater)
        },
        Check<Handle>("reads-are-snapshots", "mutating a returned snapshot cannot change the store") { h ->
            val s = h.store
            s.deposit("alice", 100.0)
            commit(s, openPlan("b", "alice", 10.0), 1.0)
            val snap = s.read("b", "alice")
            val bond = snap.bond as MutableMap<String, Any?>
            bond["amount"] = num(999.0)
            (bond["records"] as MutableList<Any?>).clear()
            (snap.balances as MutableMap<String, Double>)["alice"] = 12345.0
            val again = s.read("b", "alice")
            Suite.eq(10, again.bond!!["amount"])
            Suite.eq(1, (again.bond!!["records"] as List<*>).size)
            Suite.eq(listOf(listOf("alice", 90)), again.toJson()["balances"])
        },
        Check<Handle>("hostile-names-are-plain-keys", "claim and account names such as __proto__, constructor and toString behave like any other name") { h ->
            val s = h.store
            for (n in listOf("__proto__", "constructor", "toString", "hasOwnProperty")) {
                s.deposit(n, 50.0)
                Suite.eq("committed", commit(s, openPlan(n, n, 20.0), 1.0).outcome, n)
                Suite.eq(listOf(30), bal(s, n), n)
                Suite.eq("open", status(s, n), n)
            }
            Suite.eq("none", status(s, "valueOf"))
            Suite.eq(listOf(0), bal(s, "valueOf"))
        },
        Check<Handle>("state-survives-reopen", "every acknowledged commit and deposit is visible to a new client after the backend restarts", "durable") { h ->
            h.store.deposit("alice", 100.0)
            commit(h.store, openPlan("a", "alice", 40.0), 7.0)
            commit(h.store, openPlan("b", "alice", 20.0), 8.0)
            val sl = slashPlan("b", 20.0)
            commit(h.store, sl, 9.0)
            val back = h.reopen()
            val bond = linkedMapOf<String, Any?>(
                "claimId" to "b", "amount" to 20, "depositor" to "alice", "status" to "slashed",
                "records" to listOf(record(openPlan("b", "alice", 20.0)), record(sl)),
            )
            val want = linkedMapOf<String, Any?>(
                "bond" to bond, "balances" to listOf(listOf("alice", 40)), "openTotals" to mapOf("count" to 1, "sum" to 40), "highWater" to 9,
            )
            Suite.eq(want, back.read("b", "alice").toJson())
            Suite.eq(listOf(40, 10, 10), bal(back, "escrow", "chal", "treasury"))
            Suite.eq("replayed", commit(back, sl, 10.0).outcome)
        },
        Check<Handle>("acknowledged-commits-survive-a-crash", "after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all", "crash") { h ->
            h.store.deposit("alice", 100.0)
            commit(h.store, openPlan("a", "alice", 40.0), 1.0)
            commit(h.store, openPlan("b", "alice", 30.0), 2.0)
            val inflight = Thread { try { h.store.commit(slashPlan("b", 30.0), 3.0) } catch (ignored: RuntimeException) { /* killed in flight */ } }
            inflight.start()
            val back = h.crash()
            inflight.join()
            Suite.eq("open", status(back, "a"))
            val st = status(back, "b")
            Suite.ok(st == "open" || st == "slashed", "bond b is $st")
            Suite.eq(if (st == "slashed") listOf(30, 40, 15, 15) else listOf(30, 70, 0, 0), bal(back, "alice", "escrow", "chal", "treasury"))
            Suite.eq(100, total(back))
            Suite.eq(if (st == "slashed") "replayed" else "committed", commit(back, slashPlan("b", 30.0), 4.0).outcome)
            Suite.eq(listOf(30, 40, 15, 15), bal(back, "alice", "escrow", "chal", "treasury"))
        },
    )

    /** Run the suite against [adapter] (only the named checks when [only] is non-null). */
    @JvmOverloads
    fun run(adapter: Adapter, only: Collection<String>? = null): Suite.Report =
        Suite.run("bond store", adapter.name(), adapter.durable(), { adapter.create() }, CHECKS, only)

    // ---- reference adapters ----

    /** An adapter over any [AtomicKv]: [backend] opens one isolated backend and returns a supplier of clients on it. */
    fun kvAdapter(name: String, durable: Boolean, backend: () -> (() -> AtomicKv), crashable: Boolean): Adapter = object : Adapter {
        override fun name() = name

        override fun durable() = durable

        override fun create(): Handle {
            val clients = backend()
            val open: () -> BondStore = { KvBondStore(clients()) }
            return Handle(open(), open, if (crashable) open else null, null)
        }
    }

    /** GOOD, in process: the reference store over a [MemoryAtomicKv]. Not durable (declared). */
    fun memoryAdapter(): Adapter = kvAdapter("KvBondStore over MemoryAtomicKv", false, { val kv = MemoryAtomicKv(); { kv } }, false)

    /** The mistakes a bad store makes. */
    enum class Defect(val label: String) {
        NON_ATOMIC("BAD non-atomic (moves land before the phase check)"),
        NO_REPLAY("BAD no idempotence (a retried transition conflicts)"),
        LOST_UPDATE("BAD lost update (read, pause, write)"),
        AMNESIA("BAD amnesia (claims durability, forgets on reopen)"),
        CLOCK_REWIND("BAD clock rewind (high-water mark follows the last call)"),
    }

    private class Defective(private val defect: Defect) : BondStore {
        private val lock = Any()

        @Volatile private var doc = BondDoc.empty()

        fun forget() { doc = BondDoc.empty() }

        override fun read(claimId: String, depositor: String?): BondStore.Snapshot = doc.snapshot(claimId, depositor)

        override fun deposit(account: String, amount: Double): Double {
            if (!(amount > 0) || amount.isInfinite() || account.isEmpty()) throw IllegalArgumentException("deposit")
            if (defect == Defect.LOST_UPDATE) {
                val base = BondDoc.decode(doc.encode())
                try { Thread.sleep(2) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
                val v = (base.balances[account] ?: 0.0) + amount
                base.balances[account] = v
                doc = base
                return v
            }
            synchronized(lock) {
                val v = (doc.balances[account] ?: 0.0) + amount
                doc.balances[account] = v
                return v
            }
        }

        override fun commit(plan: Map<String, Any?>, observedAt: Double): BondStore.CommitOutcome {
            if (defect == Defect.LOST_UPDATE) {
                val working = BondDoc.decode(doc.encode())
                try { Thread.sleep(2) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
                val out = BondDoc.commitBondPlan(working, plan, observedAt)
                if (out.outcome == "committed") doc = working
                return out
            }
            synchronized(lock) {
                val d = doc
                val claimId = plan["claimId"] as String
                if (defect == Defect.NON_ATOMIC) {
                    // applies the balance moves first, then checks the phase: a conflict leaves the money moved
                    for (mo in plan["moves"] as List<Any?>) {
                        val m = mo as Map<String, Any?>
                        val a = net.atlasauth.pca.doctor.Js.num(m["amount"])!!
                        val acct = m["account"] as String
                        d.balances[acct] = (d.balances[acct] ?: 0.0) + (if (m["op"] == "credit") a else -a)
                    }
                    val b = d.bonds[claimId]
                    val bad = if (plan["expect"] == "none") b != null else b == null || plan["expect"] != b["status"]
                    if (bad) return BondStore.CommitOutcome("conflict", null, "phase", if (b == null) "none" else b["status"] as String)
                    val open = plan["open"] as Map<String, Any?>?
                    if (open != null) {
                        d.bonds[claimId] = linkedMapOf(
                            "claimId" to claimId, "amount" to open["amount"], "depositor" to open["depositor"], "status" to "open",
                            "records" to arrayListOf(plan["record"]),
                        )
                    } else {
                        b!!["status"] = plan["next"]
                        (b["records"] as MutableList<Any?>).add(plan["record"])
                    }
                    d.highWater = Math.max(d.highWater, observedAt)
                    return BondStore.CommitOutcome("committed", plan["record"] as Map<String, Any?>, null, null)
                }
                val out = BondDoc.commitBondPlan(d, plan, observedAt)
                if (defect == Defect.NO_REPLAY && out.outcome == "replayed") return BondStore.CommitOutcome("conflict", null, "already applied", "open")
                if (defect == Defect.CLOCK_REWIND && out.outcome == "committed") d.highWater = observedAt
                return out
            }
        }
    }

    /** A bad adapter: one store object shared by every client (a reopen on AMNESIA clears it). */
    fun defectiveAdapter(defect: Defect): Adapter = object : Adapter {
        override fun name() = defect.label

        override fun create(): Handle {
            val d = Defective(defect)
            val again: () -> BondStore = { if (defect == Defect.AMNESIA) d.forget(); d }
            return Handle(d, again, again, null)
        }
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    fun referenceAdapters(): Map<String, () -> Adapter> {
        val m = LinkedHashMap<String, () -> Adapter>()
        m["bond-memory"] = { memoryAdapter() }
        for (d in Defect.values()) m["bad-bond-" + d.name.lowercase().replace('_', '-')] = { defectiveAdapter(d) }
        return m
    }
}
