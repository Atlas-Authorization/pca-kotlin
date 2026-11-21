package net.atlasauth.pca.verifier

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The store-conformance helper passes the shipped stores and fails racy, aliasing, non-atomic and loose-CAS ones. */
class StoreConformanceTest {
    private fun sqlite(path: String) = PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) }

    @Test
    fun theShippedStateStoresPass() {
        val mem = StoreConformance.runStateStore({ Authorize.MemoryStateStore() }, durable = false, shared = false, name = "memory")
        assertTrue(mem.render(), mem.ok)
        // claim-burst runs against ONE handle: the in-memory store must share its state across opens for the sequence checks
        val shared = Authorize.MemoryStateStore()
        val memShared = StoreConformance.runStateStore({ shared }, durable = false, shared = true, name = "memory (one instance)")
        assertTrue(memShared.render(), memShared.ok)
        val path = AuthorizeTestKit.tempDb()
        val jdbc = StoreConformance.runStateStore({ PcaJdbcStateStore(sqlite(path)) }, name = "jdbc")
        assertTrue(jdbc.render(), jdbc.ok)
        assertEquals(jdbc.render(), 6, jdbc.results.count { it.status == "pass" })
    }

    @Test
    fun theShippedOperationStoresPass() {
        val memory = Operations.MemoryStore()
        val mem = StoreConformance.runOperationStore({ memory }, durable = false, shared = true, name = "memory")
        assertTrue(mem.render(), mem.ok)
        val path = AuthorizeTestKit.tempDb()
        val jdbc = StoreConformance.runOperationStore({ Operations.jdbcStore(sqlite(path)) }, name = "jdbc")
        assertTrue(jdbc.render(), jdbc.ok)
        assertEquals(jdbc.render(), 6, jdbc.results.count { it.status == "pass" })
    }

    /**
     * The racers of a racy double meet between their read and their write: every racing caller reads, then waits until a partner on the
     * same key has read too (racers pair off in arrival order: the kit's retry race has two racers, its bursts sixteen, so a barrier of a
     * fixed size would not fit both), and only then do the two write, so a pair always loses an update whatever the scheduler or the
     * machine speed does (a wall-clock sleep let a late racer run alone and the race go unseen). Calls from the thread that built the
     * double are serial setup and never wait. A racer left without a partner for 30 s records [broken] and fails; the tests assert it is
     * null.
     */
    private class PairMeeting {
        private val owner = Thread.currentThread()
        private val lock = ReentrantLock()
        private val arrived = lock.newCondition()
        private val arrivals = HashMap<String, Int>()

        /** The first failure of a rendezvous; the tests assert it is null. */
        val broken = AtomicReference<Throwable?>(null)

        fun meet(key: String) {
            if (Thread.currentThread() === owner) return
            lock.lock()
            try {
                val ticket = (arrivals[key] ?: 0) + 1
                arrivals[key] = ticket
                val target = (ticket + 1) / 2 * 2
                if (ticket >= target) arrived.signalAll()
                var left = TimeUnit.SECONDS.toNanos(30)
                while ((arrivals[key] ?: 0) < target) {
                    if (left <= 0L) {
                        val e = AssertionError("no partner reached the rendezvous of $key")
                        broken.compareAndSet(null, e)
                        throw e
                    }
                    left = arrived.awaitNanos(left)
                }
            } finally {
                lock.unlock()
            }
        }
    }

    /** Check-then-set with a meeting in between: two claimers can both read "unconsumed". */
    private class RacyStateStore : Authorize.StateStore {
        private val m = ConcurrentHashMap<String, Long>()
        val meeting = PairMeeting()

        override fun claim(key: String, counter: Long): Authorize.ClaimResult {
            val prev = m[key]
            meeting.meet(key)
            if (prev != null && counter <= prev) return Authorize.ClaimResult(false, prev)
            m[key] = counter
            return Authorize.ClaimResult(true)
        }
    }

    /** Admits whatever it is asked. */
    private class AdmitAllStateStore : Authorize.StateStore {
        override fun claim(key: String, counter: Long): Authorize.ClaimResult = Authorize.ClaimResult(true)
    }

    @Test
    fun aRacyStateStoreIsCaught() {
        val racy = RacyStateStore()
        val r = StoreConformance.runStateStore({ racy }, durable = false, shared = false, name = "racy")
        assertNull("the racers failed to rendezvous", racy.meeting.broken.get())
        assertFalse(r.render(), r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "claim-burst" })
    }

    @Test
    fun aStoreThatAdmitsEverythingIsCaught() {
        val r = StoreConformance.runStateStore({ AdmitAllStateStore() }, durable = false, shared = false, name = "admit-all")
        assertFalse(r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "claim-sequence" })
    }

    /** Stores and returns the caller's own map; check-then-act without atomicity (the racers meet between the check and the act). */
    private class AliasingStore : Operations.Store {
        val m = ConcurrentHashMap<String, MutableMap<String, Any?>>()
        val meeting = PairMeeting()

        @Suppress("UNCHECKED_CAST")
        override fun create(record: Map<String, Any?>): Map<String, Any?>? {
            val cur = m[record["id"] as String]
            meeting.meet(record["id"] as String)
            if (cur != null) return cur
            m[record["id"] as String] = record as MutableMap<String, Any?>
            return null
        }

        override fun get(id: String): Map<String, Any?>? = m[id]

        @Suppress("UNCHECKED_CAST")
        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean {
            val matches = m[id]?.get("state") == from
            meeting.meet(id)
            if (!matches) return false
            m[id] = next as MutableMap<String, Any?>
            return true
        }
    }

    /** A transition that never compares the state. */
    private class LooseCasStore : Operations.Store {
        private val inner = Operations.MemoryStore()
        override fun create(record: Map<String, Any?>): Map<String, Any?>? = inner.create(record)
        override fun get(id: String): Map<String, Any?>? = inner.get(id)
        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean {
            inner.get(id) ?: return false
            return inner.transition(id, inner.get(id)!!["state"] as String, next)
        }
    }

    @Test
    fun anAliasingNonAtomicOperationStoreIsCaught() {
        val s = AliasingStore()
        val r = StoreConformance.runOperationStore({ s }, durable = false, shared = false, name = "aliasing")
        assertNull("the racers failed to rendezvous", s.meeting.broken.get())
        assertFalse(r.render(), r.ok)
        val failed = r.failures().map { it.test }
        assertTrue(r.render(), "copies" in failed && "create-race" in failed)
    }

    @Test
    fun aLooseCasOperationStoreIsCaught() {
        val s = LooseCasStore()
        val r = StoreConformance.runOperationStore({ s }, durable = false, shared = false, name = "loose cas")
        assertFalse(r.render(), r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "semantics" })
    }

    // ---- the trust-budget and kv-registry profiles (F11) ----

    @Test
    fun theShippedBudgetStoresPass() {
        val memory = Authorize.MemoryStateStore()
        val mem = StoreConformance.runBudgetStore({ memory }, durable = false, name = "memory")
        assertTrue(mem.render(), mem.ok)
        assertEquals(mem.render(), 4, mem.results.count { it.status == "pass" })
        val path = AuthorizeTestKit.tempDb()
        val jdbc = StoreConformance.runBudgetStore({ PcaJdbcStateStore(sqlite(path)) }, name = "jdbc")
        assertTrue(jdbc.render(), jdbc.ok)
        assertEquals(jdbc.render(), 5, jdbc.results.count { it.status == "pass" })
    }

    /** Stores whatever it is given: it never compares the budget the caller read. */
    private class BlindBudgetStore : Authorize.BudgetStore {
        private val m = ConcurrentHashMap<String, Risk.Budget>()
        override fun budget(key: String): Risk.Budget? = m[key]
        override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean {
            Thread.sleep(1)
            m[key] = new
            return true
        }
    }

    /** Holds no budget at all: every read is empty. */
    private class AmnesiacBudgetStore : Authorize.BudgetStore {
        override fun budget(key: String): Risk.Budget? = null
        override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean = old == null
    }

    @Test
    fun aBudgetStoreThatIgnoresTheOldBudgetIsCaught() {
        val blind = BlindBudgetStore()
        val r = StoreConformance.runBudgetStore({ blind }, durable = false, rounds = 2, name = "blind")
        assertFalse(r.render(), r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "budget-conflict" })
        assertTrue(r.render(), r.failures().any { it.test == "budget-burst" })
    }

    @Test
    fun aBudgetStoreThatKeepsNothingIsCaught() {
        val r = StoreConformance.runBudgetStore({ AmnesiacBudgetStore() }, durable = false, name = "amnesiac")
        assertFalse(r.render(), r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "budget-absent-then-set" })
    }

    private fun registryVectors() = Triple(ParityVectors.load("lease-vectors.json"), ParityVectors.load("break-glass-vectors.json"), ParityVectors.load("blueprint-vectors.json"))

    @Test
    fun theShippedKvStoresPassTheRegistryProfile() {
        val (lease, bg, bp) = registryVectors()
        val memory = MemoryAtomicKv()
        val mem = StoreConformance.runKvRegistries({ memory }, lease, bg, bp, shared = true, name = "memory kv")
        assertTrue(mem.render(), mem.ok)
        assertEquals(mem.render(), 4, mem.results.count { it.status == "pass" })
        val path = AuthorizeTestKit.tempDb()
        val jdbc = StoreConformance.runKvRegistries({ JdbcAtomicKv(sqlite(path)) }, lease, bg, bp, name = "jdbc kv")
        assertTrue(jdbc.render(), jdbc.ok)
    }

    /**
     * A read-modify-write whose racers rendezvous between the read and the write: every racing caller reads and computes from the same
     * previous value, waits at a barrier until all [racers] have done so, and only then do they write, so the lost update always happens
     * whatever the scheduler or the machine speed does (a wall-clock sleep let a late racer run alone and the race go unseen). Calls
     * from the thread that built the kv are serial setup and never wait; each serial call also installs a fresh barrier, so a race
     * starts with an unused rendezvous. A racer that cannot rendezvous (a missing or extra racer) fails loudly in [broken].
     */
    private class RacyKv(private val inner: AtomicKv, private val racers: Int) : AtomicKv {
        private val owner = Thread.currentThread()

        @Volatile
        private var round = CyclicBarrier(racers)

        /** The first failure of a rendezvous; the test asserts it is null. */
        val broken = AtomicReference<Throwable?>(null)

        override fun get(key: String): Any? = inner.get(key)

        override fun set(key: String, value: Any?) = inner.set(key, value)

        override fun update(key: String, fn: (Any?) -> Any?): Any? {
            val next = fn(inner.get(key))
            if (Thread.currentThread() === owner) round = CyclicBarrier(racers) else rendezvous(round)
            if (next != null) inner.set(key, next)
            return inner.get(key)
        }

        private fun rendezvous(barrier: CyclicBarrier) {
            try {
                barrier.await(30, TimeUnit.SECONDS)
            } catch (e: Exception) {
                broken.compareAndSet(null, e)
                throw AssertionError("racy kv: the $racers racers did not all reach the rendezvous (${e.javaClass.simpleName})", e)
            }
        }
    }

    /** A kv that keeps a private copy per handle: nothing is shared between registries. */
    private class PrivateKv : AtomicKv by MemoryAtomicKv()

    @Test
    fun aRacyKvIsCaughtByTheRegistryProfile() {
        val (lease, bg, bp) = registryVectors()
        val racers = 16
        val shared = RacyKv(MemoryAtomicKv(), racers)
        val r = StoreConformance.runKvRegistries({ shared }, lease, bg, bp, threads = racers, name = "racy kv")
        assertNull("the racers failed to rendezvous", shared.broken.get())
        assertFalse(r.render(), r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "break-glass-single-use-across-handles" })
    }

    @Test
    fun aKvThatSharesNothingIsCaughtByTheRegistryProfile() {
        val (lease, bg, bp) = registryVectors()
        val r = StoreConformance.runKvRegistries({ PrivateKv() }, lease, bg, bp, name = "private kv")
        assertFalse(r.render(), r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "lease-revocation-survives-reopen" })
        assertTrue(r.render(), r.failures().any { it.test == "break-glass-single-use-across-handles" })
        assertTrue(r.render(), r.failures().any { it.test == "blueprint-stale-epoch-is-refused" })
    }
}
