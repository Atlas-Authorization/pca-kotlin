package net.atlasauth.pca.verifier

import java.io.File
import java.sql.Connection
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.input
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The replay stores: the monotone claim table, durability, and exactly one winner under concurrency. */
class AuthorizeStoreTest {
    private fun monotone(st: Authorize.StateStore) {
        assertEquals(Authorize.ClaimResult(true), st.claim("k", 5))
        assertEquals(Authorize.ClaimResult(false, 5), st.claim("k", 5))
        assertEquals(Authorize.ClaimResult(false, 5), st.claim("k", 4))
        assertEquals(Authorize.ClaimResult(true), st.claim("k", 6))
        assertEquals(Authorize.ClaimResult(true), st.claim("other", 0))
        assertEquals(Authorize.ClaimResult(false, 0), st.claim("other", 0))
        assertEquals(Authorize.ClaimResult(false, 6), st.claim("k", 6))
        assertEquals(Authorize.ClaimResult(true), st.claim("k", 9007199254740991L))
    }

    @Test
    fun memoryMonotone() = monotone(Authorize.MemoryStateStore())

    @Test
    fun jdbcMonotone() = monotone(AuthorizeTestKit.jdbcStore())

    @Test
    fun jdbcSurvivesReopen() {
        val path = AuthorizeTestKit.tempDb()
        assertTrue(AuthorizeTestKit.jdbcStore(path).claim("k", 1).ok)
        assertEquals(Authorize.ClaimResult(false, 1), AuthorizeTestKit.jdbcStore(path).claim("k", 1))
    }

    @Test
    fun jdbcCustomTableAndNoCreate() {
        val path = AuthorizeTestKit.tempDb()
        val st = PcaJdbcStateStore({ AuthorizeTestKit.sqlite(path) }, "replay_v2")
        assertTrue(st.claim("k", 1).ok)
        AuthorizeTestKit.sqlite(path).use { c ->
            c.createStatement().use { s -> s.executeQuery("SELECT key, last_counter FROM replay_v2").use { rs -> assertTrue(rs.next()); assertEquals(1L, rs.getLong(2)) } }
        }
        // no table and createTable = false: the claim throws (authorize denies)
        val missing = PcaJdbcStateStore({ AuthorizeTestKit.sqlite(AuthorizeTestKit.tempDb()) }, "absent", false)
        assertTrue(runCatching { missing.claim("k", 1) }.isFailure)
        assertTrue(runCatching { PcaJdbcStateStore({ AuthorizeTestKit.sqlite(path) }, "x; DROP TABLE y") }.isFailure)
    }

    @Test
    fun jdbcNonAutoCommitConnectionIsCommitted() {
        val path = AuthorizeTestKit.tempDb()
        val st = PcaJdbcStateStore({ AuthorizeTestKit.sqlite(path).also { it.autoCommit = false } })
        assertTrue(st.claim("k", 3).ok)
        assertEquals(Authorize.ClaimResult(false, 3), AuthorizeTestKit.jdbcStore(path).claim("k", 3))
    }

    private fun race(n: Int, fn: () -> Boolean): Int {
        val barrier = CyclicBarrier(n)
        val wins = AtomicInteger()
        val errors = AtomicInteger()
        val ts = (0 until n).map {
            Thread {
                try {
                    barrier.await()
                    if (fn()) wins.incrementAndGet()
                } catch (e: Exception) {
                    errors.incrementAndGet()
                }
            }
        }
        ts.forEach { it.start() }
        ts.forEach { it.join(60_000) }
        assertEquals(0, errors.get())
        return wins.get()
    }

    @Test
    fun concurrentClaimsMemory() {
        val st = Authorize.MemoryStateStore()
        assertEquals(1, race(16) { st.claim("k", 7).ok })
    }

    @Test
    fun concurrentClaimsJdbcSeveralConnections() {
        val path = AuthorizeTestKit.tempDb()
        val opened = AtomicInteger()
        val st = PcaJdbcStateStore({ opened.incrementAndGet(); AuthorizeTestKit.sqlite(path) }) // a fresh connection per claim
        assertEquals(1, race(16) { st.claim("k", 7).ok })
        assertTrue(opened.get() >= 17)
        // one store object per thread (its own connections) as well
        assertEquals(1, race(16) { AuthorizeTestKit.jdbcStore(path).claim("k", 8).ok })
    }

    @Test
    fun concurrentClaimsJdbcProcesses() {
        val path = AuthorizeTestKit.tempDb()
        AuthorizeTestKit.jdbcStore(path) // create the table first
        val java = File(System.getProperty("java.home"), "bin/java").path
        val cp = System.getProperty("java.class.path")
        val procs = (0 until 4).map {
            ProcessBuilder(java, "-cp", cp, AuthorizeClaimProcess::class.java.name, path, "k", "9").redirectErrorStream(true).start()
        }
        val outs = procs.map { p ->
            assertTrue(p.waitFor(120, TimeUnit.SECONDS))
            p.inputStream.bufferedReader().readText().trim().lines().last()
        }
        assertEquals(listOf("false", "false", "false", "true"), outs.sorted())
    }

    @Test
    fun concurrentAuthorizeSameProofOneWins() {
        val c = case("envelope-max-spend-within")
        val mem = Authorize.MemoryStateStore()
        assertEquals(1, race(8) { Authorize.authorize(pcactn(c), input(c, stateStore = mem)).allow })
        val jdbc = AuthorizeTestKit.jdbcStore()
        assertEquals(1, race(8) { Authorize.authorize(pcactn(c), input(c, stateStore = jdbc)).allow })
    }

    @Test
    fun deniedProofDoesNotConsumeTheCounter() {
        val c = case("denied-does-not-consume")
        val st = AuthorizeTestKit.jdbcStore()
        assertFalse(Authorize.authorize(pcactn(c, 0), input(c, 0, stateStore = st)).allow)
        assertTrue(Authorize.authorize(pcactn(c, 1), input(c, 1, stateStore = st)).allow)
    }
}

/** One claim in a separate JVM (the cross-process test): prints `true` or `false`. */
object AuthorizeClaimProcess {
    @JvmStatic
    fun main(args: Array<String>) {
        val st = PcaJdbcStateStore({ AuthorizeTestKit.sqlite(args[0]) as Connection }, createTable = false)
        println(st.claim(args[1], args[2].toLong()).ok)
    }
}
