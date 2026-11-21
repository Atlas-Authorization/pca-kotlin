package net.atlasauth.pca.verifier

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A DataSource-like object exposing one getter, for PcaJdbcStateStore.jdbcUrlOf. */
class Kill06DeadlineCOnlyUpper { fun getURL(): String = "jdbc:sqlite:upper" }
class Kill06DeadlineCOnlyJdbcUrl { fun getJdbcUrl(): String = "jdbc:sqlite:jdbc" }
class Kill06DeadlineCWrongType { fun getUrl(): Int = 7; fun getJdbcUrl(): String = "jdbc:sqlite:second" }
class Kill06DeadlineCNone { fun getOther(): String = "x" }

/**
 * Deadline tests: StoreConformance (race barrier and round loops), JdbcAtomicKv.update (retry loop), PcaJdbcStateStore
 * (jdbcUrlOf name loop, percentDecode cursor). Every block runs under [Deadline.within].
 */
class Kill06DeadlineCStoreTest {
    @Test fun stateStoreConformanceFinishesAndPasses() {
        val shared = Authorize.MemoryStateStore()
        var crashes = 0
        val report = Deadline.within {
            StoreConformance.runStateStore({ shared }, crash = { crashes++ }, threads = 6, rounds = 3, handles = 3, name = "k06")
        }
        assertTrue(report.render(), report.ok)
        assertEquals(report.render(), 6, report.results.count { it.status == "pass" })
        assertEquals(1, crashes)
        val local = Deadline.within { StoreConformance.runStateStore({ Authorize.MemoryStateStore() }, durable = false, shared = false, threads = 4, rounds = 2) }
        assertTrue(local.render(), local.ok)
        assertEquals(local.render(), 3, local.results.count { it.status == "skip" })
    }

    @Test fun operationStoreConformanceFinishesAndPasses() {
        val memory = Operations.MemoryStore()
        val report = Deadline.within { StoreConformance.runOperationStore({ memory }, threads = 6, rounds = 3, handles = 3, name = "k06") }
        assertTrue(report.render(), report.ok)
        assertEquals(report.render(), 6, report.results.count { it.status == "pass" })
        val local = Deadline.within { StoreConformance.runOperationStore({ Operations.MemoryStore() }, durable = false, shared = false, threads = 4, rounds = 2) }
        assertTrue(local.render(), local.ok)
    }

    @Test fun jdbcAtomicKvUpdateStoresRetriesAndReturns() {
        val path = AuthorizeTestKit.tempDb()
        val url = "jdbc:sqlite:$path"
        val kv = JdbcAtomicKv(PcaJdbcStateStore.sqliteConnections(url))
        val other = JdbcAtomicKv(PcaJdbcStateStore.sqliteConnections(url))
        Deadline.within {
            assertNull(kv.get("a"))
            assertEquals("one", kv.update("a") { "one" })
            assertEquals("one+", kv.update("a") { (it as String) + "+" })
            assertEquals("one+", kv.update("a") { null }) // null = leave alone, return the previous value
            kv.set("b", "bee")
            assertEquals("bee", kv.get("b"))
            // another writer wins the first attempt on an absent key: the insert is refused, the retry sees its value
            var calls = 0
            val r = kv.update("c") { p -> calls++; if (calls == 1) other.set("c", "first"); ((p ?: "none") as String) + "+" }
            assertEquals(2, calls)
            assertEquals("first+", r)
            assertEquals("first+", other.get("c"))
            // ... and on a present key: the compare-and-set misses, the retry succeeds
            calls = 0
            val r2 = kv.update("c") { p -> calls++; if (calls == 1) other.set("c", "again"); (p as String) + "!" }
            assertEquals(2, calls)
            assertEquals("again!", r2)
            // a writer that never lets go exhausts the attempts and fails closed instead of spinning
            val tiny = JdbcAtomicKv(PcaJdbcStateStore.sqliteConnections(url), maxAttempts = 3)
            var n = 0
            try {
                tiny.update("c") { p -> n++; other.set("c", "x$n"); (p as String) + "?" }
                throw AssertionError("expected give-up")
            } catch (e: IllegalStateException) {
                assertEquals(3, n)
            }
        }
    }

    @Test fun jdbcUrlOfTriesEachGetterName() {
        Deadline.within {
            assertEquals("jdbc:sqlite:upper", PcaJdbcStateStore.jdbcUrlOf(Kill06DeadlineCOnlyUpper()))
            assertEquals("jdbc:sqlite:jdbc", PcaJdbcStateStore.jdbcUrlOf(Kill06DeadlineCOnlyJdbcUrl()))
            assertEquals("jdbc:sqlite:second", PcaJdbcStateStore.jdbcUrlOf(Kill06DeadlineCWrongType()))
            assertNull(PcaJdbcStateStore.jdbcUrlOf(Kill06DeadlineCNone()))
        }
    }

    @Test fun percentDecodeAdvancesOverEveryByte() {
        val dir = Files.createTempDirectory("k06pd").toAbsolutePath()
        Deadline.within {
            fun file(tail: String) = PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file:$dir/$tail")
            assertEquals(dir.resolve("a b/c.db"), file("a%20b/c.db"))
            assertEquals(dir.resolve("A-é-%G1-100%.db"), file("%41-%C3%A9-%G1-100%.db"))
            assertEquals(dir.resolve("plain.db"), file("plain.db"))
            assertEquals(dir.resolve("x%4"), file("x%4"))
            assertEquals(dir.resolve("x%"), file("x%"))
            assertEquals(dir.resolve("a%a"), file("a%a"))
        }
    }
}
