package net.atlasauth.pca.verifier

import java.util.concurrent.ConcurrentHashMap
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

    /** Check-then-set with a window in between: two claimers can both read "unconsumed". */
    private class RacyStateStore : Authorize.StateStore {
        private val m = ConcurrentHashMap<String, Long>()

        override fun claim(key: String, counter: Long): Authorize.ClaimResult {
            val prev = m[key]
            if (prev != null && counter <= prev) return Authorize.ClaimResult(false, prev)
            Thread.sleep(3)
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
        assertFalse(r.render(), r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "claim-burst" })
    }

    @Test
    fun aStoreThatAdmitsEverythingIsCaught() {
        val r = StoreConformance.runStateStore({ AdmitAllStateStore() }, durable = false, shared = false, name = "admit-all")
        assertFalse(r.ok)
        assertTrue(r.render(), r.failures().any { it.test == "claim-sequence" })
    }

    /** Stores and returns the caller's own map; check-then-act without atomicity. */
    private class AliasingStore : Operations.Store {
        val m = ConcurrentHashMap<String, MutableMap<String, Any?>>()

        @Suppress("UNCHECKED_CAST")
        override fun create(record: Map<String, Any?>): Map<String, Any?>? {
            val cur = m[record["id"] as String]
            if (cur != null) return cur
            Thread.sleep(3)
            m[record["id"] as String] = record as MutableMap<String, Any?>
            return null
        }

        override fun get(id: String): Map<String, Any?>? = m[id]

        @Suppress("UNCHECKED_CAST")
        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean {
            if (m[id]?.get("state") != from) return false
            Thread.sleep(3)
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

    /** A read-modify-write with a window between the read and the write: two writers can both act on the same previous value. */
    private class RacyKv(private val inner: AtomicKv) : AtomicKv {
        override fun get(key: String): Any? = inner.get(key)
        override fun set(key: String, value: Any?) = inner.set(key, value)
        override fun update(key: String, fn: (Any?) -> Any?): Any? {
            val next = fn(inner.get(key))
            Thread.sleep(3)
            if (next != null) inner.set(key, next)
            return inner.get(key)
        }
    }

    /** A kv that keeps a private copy per handle: nothing is shared between registries. */
    private class PrivateKv : AtomicKv by MemoryAtomicKv()

    @Test
    fun aRacyKvIsCaughtByTheRegistryProfile() {
        val (lease, bg, bp) = registryVectors()
        val shared = RacyKv(MemoryAtomicKv())
        val r = StoreConformance.runKvRegistries({ shared }, lease, bg, bp, name = "racy kv")
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
