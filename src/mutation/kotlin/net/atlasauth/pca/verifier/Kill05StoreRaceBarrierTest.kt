package net.atlasauth.pca.verifier

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * StoreConformance.race releases its n threads together (CyclicBarrier): no thread calls the store before all n race threads
 * are alive. A store that, on the FIRST claim of each claim-burst round, counts the live threads running StoreConformance code
 * (the caller's thread excluded) therefore always sees all n with the barrier (the other claimers of the round wait until it has
 * counted, so none can exit first). Without it, the first thread claims while the
 * caller is still starting the rest (64 threads, 5 rounds), so the count comes up short and the store throws, which fails
 * claim-burst. The real code can never fail this test.
 */
class Kill05StoreRaceBarrierTest {
    private val n = 64

    private class Watching(val caller: Thread, val n: Int) : Authorize.StateStore {
        val inner = Authorize.MemoryStateStore()
        val firstOfRound = ConcurrentHashMap<String, Boolean>()

        private fun liveRaceThreads(): Int {
            var c = 0
            for ((t, frames) in Thread.getAllStackTraces()) {
                if (t === caller || !t.isAlive) continue
                for (f in frames) if (f.className.startsWith("net.atlasauth.pca.verifier.StoreConformance")) { c++; break }
            }
            return c
        }

        val counted = ConcurrentHashMap<String, CountDownLatch>()

        override fun claim(key: String, counter: Long): Authorize.ClaimResult? {
            if (key.startsWith("burst:")) {
                val round = "$key#$counter"
                val done = counted.computeIfAbsent(round) { CountDownLatch(1) }
                if (firstOfRound.putIfAbsent(round, true) == null) {
                    try {
                        val live = liveRaceThreads()
                        if (live < n) throw IllegalStateException("only $live of $n race threads were alive at the first claim")
                    } finally { done.countDown() }
                } else {
                    // no race thread may finish (and exit) before the first claimer has counted: an exited thread would be missed
                    done.await(30, TimeUnit.SECONDS)
                }
            }
            return synchronized(inner) { inner.claim(key, counter) }
        }
    }

    @Test fun claimBurstStartsOnlyOnceEveryRaceThreadIsAlive() {
        val store = Watching(Thread.currentThread(), n)
        val r = StoreConformance.runStateStore({ store }, durable = false, threads = n, rounds = 5, handles = 2)
        var burst: String? = null
        for (x in r.results) if (x.test == "claim-burst") burst = x.status
        assertEquals(r.render(), "pass", burst)
        assertTrue(r.render(), store.firstOfRound.size == 5)
    }
}
