package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Paths
import java.sql.DriverManager
import java.sql.SQLException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The SQLite file is created BEFORE the driver opens it (so xerial's create-then-delete open probe never runs), the URL forms
 * are parsed like the driver and SQLite read them, and an in-memory SQLite database is refused.
 */
class SqliteFileTest {
    private val dir = Files.createTempDirectory("pca-sqlite")

    @Test
    fun urlFormsNameTheDatabaseFile() {
        val a = dir.resolve("a.db")
        assertEquals(a.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:$a"))
        assertEquals(a.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:$a?journal_mode=WAL&busy_timeout=5"))
        assertEquals(Paths.get("rel.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:rel.db"))
        val spaced = dir.resolve("a b.db")
        val uri = spaced.toUri().toString() // file:///... with %20 (and /C:/ on Windows)
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:$uri"))
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:$uri?cache=shared"))
        val local = uri.replaceFirst("file:///", "file://localhost/")
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:$local"))
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:" + uri.replaceFirst("file:///", "file:/")))
    }

    @Test
    fun nothingToCreateForMemoryReadOnlyResourceRemoteOrOtherDatabases() {
        for (url in listOf(
            "jdbc:sqlite:", "jdbc:sqlite::memory:", "jdbc:sqlite:file::memory:?cache=shared", "jdbc:sqlite:file:x?mode=memory&cache=shared",
            "jdbc:sqlite:${dir.resolve("r.db")}?mode=ro", "jdbc:sqlite::resource:x.db", "jdbc:sqlite:file://remote/x.db",
            "jdbc:sqlite:file:", "jdbc:postgresql://h/db",
        )) assertNull(url, PcaJdbcStateStore.sqliteFile(url))
    }

    @Test
    fun ensureCreatesTheFileAndItsDirectoriesOnceAndKeepsAnExistingOne() {
        val f = dir.resolve("x").resolve("y").resolve("kv.db")
        assertEquals(f.toAbsolutePath(), PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:$f"))
        assertTrue(Files.isRegularFile(f))
        Files.write(f, byteArrayOf(1, 2, 3))
        PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:$f")
        assertEquals(3L, Files.size(f))
        assertNull(PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite::memory:"))
    }

    @Test
    fun theFactoryCreatesTheFileBeforeTheDriverOpensIt() {
        val f = dir.resolve("new").resolve("replay.db")
        val store = PcaJdbcStateStore(PcaJdbcStateStore.sqliteConnections("jdbc:sqlite:$f"))
        assertTrue(Files.isRegularFile(f))
        assertTrue(store.claim("k", 1).ok)
        assertFalse(PcaJdbcStateStore(PcaJdbcStateStore.sqliteConnections("jdbc:sqlite:$f")).claim("k", 1).ok)
        try {
            PcaJdbcStateStore.sqliteConnections("jdbc:postgresql://h/db")
            fail("a non-SQLite URL must be refused")
        } catch (e: IllegalArgumentException) {
        }
    }

    @Test
    fun aSqliteDataSourceHasItsFileCreatedAtConstruction() {
        val f1 = dir.resolve("ds1.db")
        val f2 = dir.resolve("ds2.db")
        PcaJdbcStateStore(org.sqlite.SQLiteDataSource().apply { url = "jdbc:sqlite:$f1" }, createTable = false)
        JdbcAtomicKv(org.sqlite.SQLiteDataSource().apply { url = "jdbc:sqlite:$f2" }, createTable = false)
        assertTrue(Files.isRegularFile(f1)) // no connection was opened: the store created it
        assertTrue(Files.isRegularFile(f2))
        assertEquals("jdbc:sqlite:$f1", PcaJdbcStateStore.jdbcUrlOf(org.sqlite.SQLiteDataSource().apply { url = "jdbc:sqlite:$f1" }))
        assertNull(PcaJdbcStateStore.jdbcUrlOf(Any()))
    }

    @Test
    fun anInMemorySqliteDatabaseIsRefused() {
        val mem = PcaJdbcStateStore.ConnectionSource { DriverManager.getConnection("jdbc:sqlite::memory:") }
        try {
            PcaJdbcStateStore(mem)
            fail("an in-memory replay store must be refused")
        } catch (e: SQLException) {
            assertTrue(e.message!!.contains("in memory"))
        }
        try {
            JdbcAtomicKv(mem)
            fail("an in-memory atomic kv must be refused")
        } catch (e: SQLException) {
            assertTrue(e.message!!.contains("in memory"))
        }
        val lazy = PcaJdbcStateStore(mem, createTable = false) // checked on first use
        try {
            lazy.claim("k", 1)
            fail("an in-memory replay store must be refused on first use")
        } catch (e: SQLException) {
        }
    }
}
