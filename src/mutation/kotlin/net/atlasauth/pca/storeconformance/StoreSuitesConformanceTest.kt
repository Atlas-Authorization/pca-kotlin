package net.atlasauth.pca.storeconformance

import java.io.File
import java.nio.file.Files
import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.FileMeshWitnessStore
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.KvMeshWitnessStore
import net.atlasauth.pca.verifier.MemoryAtomicKv
import net.atlasauth.pca.verifier.MeshWitnessStore
import net.atlasauth.pca.verifier.StoreJs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Runs the bond, ledger, budget and mesh-witness conformance suites against the reference stores (memory, and a file for the witness)
 * and checks that each suite flags every bad store (a suite that passes a bad store is worthless). The durable SQLite variants of the
 * kv suites need a JDBC driver and are covered by the durable-kv tests of the verifier.
 */
@Suppress("UNCHECKED_CAST")
class StoreSuitesConformanceTest {
    private val dir: File = Files.createTempDirectory("pca-suites").toFile()
    private var n = 0

    private fun assertPasses(r: Suite.Report, minPassed: Int) {
        assertEquals(r.format(), "pass", r.status)
        assertTrue(r.format(), r.count("pass") >= minPassed)
    }

    @Test fun ledgerMemoryPasses() {
        val r = LedgerStoreConformance.run(LedgerStoreConformance.memoryAdapter())
        assertPasses(r, 13)
        assertEquals("skip", r.check("state-survives-reopen").status)
    }

    @Test fun ledgerBadStoresAreFlagged() {
        for ((name, make) in LedgerStoreConformance.referenceAdapters()) if (name.startsWith("bad-")) assertEquals(name, "fail", LedgerStoreConformance.run(make()).status)
    }

    @Test fun bondMemoryPasses() {
        val r = BondStoreConformance.run(BondStoreConformance.memoryAdapter())
        assertPasses(r, 18)
        assertEquals("skip", r.check("state-survives-reopen").status)
    }

    @Test fun bondBadStoresAreFlagged() {
        for ((name, make) in BondStoreConformance.referenceAdapters()) if (name.startsWith("bad-")) assertEquals(name, "fail", BondStoreConformance.run(make()).status)
    }

    @Test fun budgetMemoryPasses() {
        val r = BudgetLedgerConformance.run(BudgetLedgerConformance.memoryAdapter())
        assertPasses(r, 20)
        assertEquals("skip", r.check("state-survives-reopen").status)
    }

    @Test fun budgetBadLedgersAreFlagged() {
        for ((name, make) in BudgetLedgerConformance.referenceAdapters()) if (name.startsWith("bad-")) assertEquals(name, "fail", BudgetLedgerConformance.run(make()).status)
    }

    @Test fun meshWitnessMemoryPasses() = assertPasses(MeshWitnessStoreConformance.run(MeshWitnessStoreConformance.memoryAdapter()), 7)

    @Test fun meshWitnessBadStoresAreFlagged() {
        for ((name, make) in MeshWitnessStoreConformance.referenceAdapters()) if (name.startsWith("bad-")) assertEquals(name, "fail", MeshWitnessStoreConformance.run(make()).status)
    }

    @Test fun meshWitnessFileStorePasses() {
        val paths = HashMap<MeshWitnessStore, File>()
        val a = object : MeshWitnessStoreConformance.Adapter {
            override fun name() = "FileMeshWitnessStore"

            override fun make(): MeshWitnessStore {
                val p = synchronized(this@StoreSuitesConformanceTest) { File(dir, "w${n++}.json") }
                return FileMeshWitnessStore(p).also { paths[it] = p }
            }

            override fun canReopen() = true

            override fun reopen(previous: MeshWitnessStore): MeshWitnessStore = FileMeshWitnessStore(paths[previous]!!).also { paths[it] = paths[previous]!! }

            override fun canDamage() = true

            override fun damage(store: MeshWitnessStore) {
                val p = paths[store]!!
                val j = StoreJs.map(Json.parseLenient(p.readText(Charsets.UTF_8)))!!
                val head = StoreJs.map(StoreJs.map((StoreJs.map(j["state"])!!["seen"] as List<*>)[0])!!["head"])!!
                head["size"] = StoreJs.num(99L) // edit without fixing the digest
                p.writeText(Json.canonicalize(j), Charsets.UTF_8)
            }
        }
        assertPasses(MeshWitnessStoreConformance.run(a), 10)
    }

    @Test fun meshWitnessKvStorePasses() {
        val clients = HashMap<MeshWitnessStore, AtomicKv>()
        val a = object : MeshWitnessStoreConformance.Adapter {
            override fun name() = "KvMeshWitnessStore over MemoryAtomicKv"

            override fun make(): MeshWitnessStore {
                val kv = MemoryAtomicKv()
                return KvMeshWitnessStore(kv).also { clients[it] = kv }
            }

            override fun canReopen() = true

            override fun reopen(previous: MeshWitnessStore): MeshWitnessStore = KvMeshWitnessStore(clients[previous]!!).also { clients[it] = clients[previous]!! }

            override fun canDamage() = true

            override fun damage(store: MeshWitnessStore) {
                val kv = clients[store]!!
                val doc = StoreJs.map(StoreJs.deepCopy(kv.get(KvMeshWitnessStore.DOC_KEY)))!!
                StoreJs.map(StoreJs.map((StoreJs.map(doc["state"])!!["seen"] as List<*>)[0])!!["head"])!!["size"] = StoreJs.num(99L)
                kv.set(KvMeshWitnessStore.DOC_KEY, doc)
            }
        }
        assertPasses(MeshWitnessStoreConformance.run(a), 10)
    }

    @Test fun fileWitnessStoreRefusesJunk() {
        val p = File(dir, "junk.json")
        val s = FileMeshWitnessStore(p)
        assertNull(s.load())
        p.writeText("not json", Charsets.UTF_8)
        assertThrows(IllegalStateException::class.java) { s.load() }
        p.writeText("{\"v\":2,\"state\":{},\"digest\":\"x\"}", Charsets.UTF_8)
        assertThrows(IllegalStateException::class.java) { s.load() }
        p.writeText("{\"v\":1,\"state\":{},\"digest\":\"x\"}", Charsets.UTF_8)
        assertThrows(IllegalStateException::class.java) { s.load() }
        val st = linkedMapOf<String, Any?>("seen" to ArrayList<Any?>())
        s.save(st)
        assertEquals(Json.canonicalize(st), Json.canonicalize(s.load()))
    }
}
