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
        assertEquals(jdbc.render(), 5, jdbc.results.count { it.status == "pass" })
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
}
