package net.atlasauth.pca.verifier

import java.util.HashMap
import net.atlasauth.pca.storeconformance.Cli
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The pca-state profile: the in-memory reference store passes, a check-then-act store is caught, and the CLI runs the profile. */
class PcaStateConformanceTest {
    private fun adapter(label: String, store: Authorize.StateStore): PcaStateConformance.Adapter = object : PcaStateConformance.Adapter {
        override val name: String get() = label
        override fun open(): Authorize.StateStore = store
    }

    private fun status(r: StoreConformance.Report, test: String): String? = r.results.firstOrNull { it.test == test }?.status

    @Test
    fun theReferenceStorePasses() {
        val r = PcaStateConformance.run(adapter("memory", Authorize.MemoryStateStore()))
        assertTrue(r.render(), r.ok)
        assertEquals(r.render(), "pass", status(r, "one-instance"))
        assertEquals(r.render(), "pass", status(r, "retry-after-timeout"))
        assertEquals(r.render(), "skip", status(r, "instances"))
        assertEquals(r.render(), "skip", status(r, "processes"))
        assertEquals(r.render(), "skip", status(r, "crash-after-claim"))
    }

    /** A claim that reads, pauses and then writes: two copies of one proof are both admitted. */
    private class RacyStore : Authorize.StateStore {
        private val last = HashMap<String, Long>()
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? {
            val prev = synchronized(last) { last[key] }
            if (prev != null && counter <= prev) return Authorize.ClaimResult(false, prev)
            Thread.sleep(5)
            synchronized(last) { last[key] = counter }
            return Authorize.ClaimResult(true)
        }
    }

    @Test
    fun aCheckThenActStoreIsCaught() {
        val r = PcaStateConformance.run(adapter("racy", RacyStore()), PcaStateConformance.Options(rounds = 3))
        assertEquals(r.render(), "fail", status(r, "one-instance"))
        assertFalse(r.render(), r.ok)
    }

    @Test
    fun theCliRunsTheProfile() {
        val out = ArrayList<String>()
        val err = ArrayList<String>()
        val code = Cli.main(listOf("--adapter", "builtin:in-memory", "--profile", "pca-state", "--rounds", "3"), { out.add(it) }, { err.add(it) })
        assertEquals(out.joinToString("\n") + err.joinToString("\n"), 0, code)
        assertTrue(out.joinToString("\n").contains("one-instance"))
    }
}
