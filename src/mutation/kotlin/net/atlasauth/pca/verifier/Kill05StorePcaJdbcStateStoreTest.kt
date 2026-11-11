package net.atlasauth.pca.verifier

import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.sql.Connection
import java.sql.DatabaseMetaData
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Statement
import java.util.Collections
import java.util.Properties
import javax.sql.DataSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Mutation kills for PcaJdbcStateStore over a recording JDBC proxy on SQLite: every statement, result set and connection is closed on
 * the normal AND the failing path, the file check runs once, a failure rolls back only a manual-commit connection, consumeOnce extends
 * a live horizon and prunes expired rows, a missing row is never read, and the URL / percent-decoding edge cases.
 */
class Kill05StorePcaJdbcStateStoreTest {
    private val dir: Path = Files.createTempDirectory("k05-jdbc")

    /** What the proxied connections did. `fail(method, statement label)` injects a SQLException("injected"). */
    private class Rec {
        val log: MutableList<String> = Collections.synchronizedList(ArrayList<String>())
        var product: String? = null
        var renameMain = false
        var lose = false
        var fail: (String, String) -> Boolean = { _, _ -> false }

        fun n(e: String): Int = synchronized(log) { log.count { it == e } }
    }

    private fun call(target: Any, m: Method, a: Array<out Any?>?): Any? =
        try {
            m.invoke(target, *(a ?: arrayOf<Any?>()))
        } catch (e: InvocationTargetException) {
            throw e.targetException
        }

    private fun <T> proxy(iface: Class<T>, h: (Method, Array<out Any?>?) -> Any?): T =
        iface.cast(Proxy.newProxyInstance(javaClass.classLoader, arrayOf<Class<*>>(iface)) { _, m, a -> h(m, a) })

    private fun label(sql: String): String = sql.split(' ').take(3).joinToString(" ")

    private fun conn(raw: Connection, rec: Rec): Connection = proxy(Connection::class.java) { m, a ->
        when (m.name) {
            "close", "commit", "rollback" -> {
                rec.log.add(m.name)
                call(raw, m, a)
            }
            "getMetaData" -> {
                rec.log.add("meta")
                val md = call(raw, m, a) as DatabaseMetaData
                val p = rec.product
                if (p == null) md else proxy(DatabaseMetaData::class.java) { mm, aa -> if (mm.name == "getDatabaseProductName") p else call(md, mm, aa) }
            }
            "prepareStatement" -> stmt(call(raw, m, a) as Statement, rec, label(a!![0] as String), PreparedStatement::class.java)
            "createStatement" -> stmt(call(raw, m, a) as Statement, rec, null, Statement::class.java)
            else -> call(raw, m, a)
        }
    }

    private fun <T : Statement> stmt(raw: Statement, rec: Rec, fixed: String?, iface: Class<T>): T = proxy(iface) { m, a ->
        val first = a?.firstOrNull()
        val sql = fixed ?: if (first is String) label(first) else "stmt"
        when (m.name) {
            "close" -> {
                rec.log.add("close ${fixed ?: "stmt"}")
                call(raw, m, a)
            }
            "executeUpdate" -> {
                rec.log.add("exec $sql")
                if (rec.fail("executeUpdate", sql)) throw SQLException("injected")
                if (rec.lose && sql == "INSERT INTO pca_replay") 0 else call(raw, m, a)
            }
            "executeQuery" -> {
                rec.log.add("exec $sql")
                if (rec.fail("executeQuery", sql)) throw SQLException("injected")
                rows(call(raw, m, a) as ResultSet, rec, sql)
            }
            else -> call(raw, m, a)
        }
    }

    /** A strict ResultSet: reading a column without a current row is an error (the JDBC contract). */
    private fun rows(raw: ResultSet, rec: Rec, sql: String): ResultSet {
        var onRow = false
        return proxy(ResultSet::class.java) { m, a ->
            when (m.name) {
                "next" -> {
                    val r = call(raw, m, a) as Boolean
                    onRow = r
                    r
                }
                "getLong", "getString" -> {
                    if (!onRow) throw SQLException("no current row")
                    if (rec.fail(m.name, sql)) throw SQLException("injected")
                    if (rec.renameMain && m.name == "getString" && sql == "PRAGMA database_list" && a!![0] == 2) "temp" else call(raw, m, a)
                }
                "close" -> {
                    rec.log.add("close rs $sql")
                    call(raw, m, a)
                }
                else -> call(raw, m, a)
            }
        }
    }

    private fun tempDb(): String = AuthorizeTestKit.tempDb()

    private fun store(rec: Rec, path: String, manual: Boolean = false, createTable: Boolean = true): PcaJdbcStateStore =
        PcaJdbcStateStore(
            PcaJdbcStateStore.ConnectionSource {
                val c = AuthorizeTestKit.sqlite(path)
                if (manual) c.autoCommit = false
                conn(c, rec)
            },
            createTable = createTable,
        )

    private fun injected(block: () -> Unit) {
        try {
            block()
            fail("no SQLException")
        } catch (e: SQLException) {
            assertEquals("injected", e.message)
        }
    }

    private fun onceRows(path: String): List<String> = AuthorizeTestKit.sqlite(path).use { c ->
        c.createStatement().use { st ->
            st.executeQuery("SELECT key, retain_until FROM pca_replay_once ORDER BY key").use { rs ->
                val l = ArrayList<String>()
                while (rs.next()) l.add("${rs.getString(1)}:${rs.getLong(2)}")
                l
            }
        }
    }

    @Test
    fun tableNameIsValidatedBeforeAnyConnection() {
        val never = PcaJdbcStateStore.ConnectionSource { throw AssertionError("opened") }
        for (bad in listOf("", "1x", "a-b", "a b", "x".repeat(64))) {
            try {
                PcaJdbcStateStore(never, bad, false)
                fail(bad)
            } catch (e: IllegalArgumentException) {
                assertEquals("table must be a plain SQL identifier", e.message)
            }
        }
        assertEquals("x".repeat(63), PcaJdbcStateStore(never, "x".repeat(63), false).table)
        assertEquals("_x9", PcaJdbcStateStore(never, "_x9", false).table)
        assertEquals("pca_replay", PcaJdbcStateStore(never, createTable = false).table)
    }

    @Test
    fun everyHandleIsClosedAndTheFileIsCheckedOnce() {
        val rec = Rec()
        val s = store(rec, tempDb())
        assertEquals(Authorize.ClaimResult(true), s.claim("k", 4))
        assertEquals(Authorize.ClaimResult(false, 4L), s.claim("k", 4))
        assertEquals(Authorize.ClaimResult(false, 4L), s.claim("k", 3))
        assertEquals(4L, s.last("k"))
        assertNull(s.last("none"))
        assertEquals(1, rec.n("meta"))
        assertEquals(6, rec.n("close"))
        assertEquals(2, rec.n("close stmt"))
        assertEquals(1, rec.n("close rs PRAGMA database_list"))
        assertEquals(3, rec.n("close INSERT INTO pca_replay"))
        assertEquals(4, rec.n("close SELECT last_counter FROM"))
        assertEquals(4, rec.n("close rs SELECT last_counter FROM"))
        assertEquals(0, rec.n("rollback"))
        assertEquals(0, rec.n("commit"))
    }

    @Test
    fun aMissingRowIsNeverRead() {
        val rec = Rec()
        val s = store(rec, tempDb())
        rec.lose = true // the upsert reports 0 rows for a key that has none
        assertEquals(Authorize.ClaimResult(false, null), s.claim("fresh", 1))
    }

    @Test
    fun consumeOnceExtendsALiveHorizonAndPrunesExpiredRows() {
        val rec = Rec()
        val path = tempDb()
        val s = store(rec, path)
        assertTrue(s.consumeOnce("o", 20, 10))
        assertFalse(s.consumeOnce("o", 50, 10)) // live: the horizon becomes 50
        assertFalse(s.consumeOnce("o", 60, 30)) // still live at 30 only because it was extended to 50
        assertTrue(s.consumeOnce("o", 70, 65)) // 60 < 65: expired, taken over
        assertTrue(s.consumeOnce("a", 15, 10))
        assertTrue(s.consumeOnce("b", 100, 20)) // prunes a (15 < 20)
        assertEquals(listOf("b:100", "o:70"), onceRows(path))
        assertEquals(2, rec.n("exec UPDATE pca_replay_once SET"))
        assertEquals(6, rec.n("close DELETE FROM pca_replay_once"))
        assertEquals(6, rec.n("close INSERT INTO pca_replay_once"))
        assertEquals(2, rec.n("close UPDATE pca_replay_once SET"))
        for ((k, r, now) in listOf(Triple("", 5L, 1L), Triple("k", 1L, 5L))) {
            try {
                s.consumeOnce(k, r, now)
                fail()
            } catch (e: IllegalArgumentException) {
                assertEquals("consumeOnce needs a key and a retention horizon not before now", e.message)
            }
        }
    }

    @Test
    fun everyFailingStatementStillClosesItsHandles() {
        // the constructor's CREATE TABLE
        val r0 = Rec()
        r0.fail = { m, q -> m == "executeUpdate" && q == "CREATE TABLE IF" }
        injected { store(r0, tempDb()) }
        assertEquals(listOf(2, 1, 0), listOf(r0.n("close stmt"), r0.n("close"), r0.n("rollback")))
        // the file check's PRAGMA
        val rp = Rec()
        rp.fail = { m, q -> m == "executeQuery" && q == "PRAGMA database_list" }
        injected { store(rp, tempDb()) }
        assertEquals(listOf(1, 1, 1), listOf(rp.n("close stmt"), rp.n("close"), rp.n("meta")))

        data class Case(val prep: (PcaJdbcStateStore) -> Unit, val method: String, val sql: String, val act: (PcaJdbcStateStore) -> Unit, val closed: String)
        val cases = listOf(
            Case({}, "executeUpdate", "INSERT INTO pca_replay", { it.claim("k", 1) }, "close INSERT INTO pca_replay"),
            Case({ it.claim("k", 1) }, "executeQuery", "SELECT last_counter FROM", { it.claim("k", 1) }, "close SELECT last_counter FROM"),
            Case({ it.claim("k", 1) }, "getLong", "SELECT last_counter FROM", { it.claim("k", 1) }, "close rs SELECT last_counter FROM"),
            Case({}, "executeUpdate", "INSERT INTO pca_replay_once", { it.consumeOnce("o", 5, 1) }, "close INSERT INTO pca_replay_once"),
            Case({ it.consumeOnce("o", 5, 1) }, "executeUpdate", "UPDATE pca_replay_once SET", { it.consumeOnce("o", 6, 1) }, "close UPDATE pca_replay_once SET"),
            Case({}, "executeUpdate", "DELETE FROM pca_replay_once", { it.consumeOnce("o", 5, 1) }, "close DELETE FROM pca_replay_once"),
            Case({}, "executeQuery", "SELECT last_counter FROM", { it.last("k") }, "close SELECT last_counter FROM"),
            Case({ it.claim("k", 1) }, "getLong", "SELECT last_counter FROM", { it.last("k") }, "close rs SELECT last_counter FROM"),
        )
        for (c in cases) {
            val rec = Rec()
            val s = store(rec, tempDb())
            c.prep(s)
            val before = rec.n(c.closed)
            val closesBefore = rec.n("close")
            rec.fail = { m, q -> m == c.method && q == c.sql }
            injected { c.act(s) }
            val what = "${c.method} ${c.sql}"
            assertEquals(what, before + 1, rec.n(c.closed))
            assertEquals(what, closesBefore + 1, rec.n("close"))
            assertEquals(what, 0, rec.n("rollback"))
        }
    }

    @Test
    fun aManualCommitConnectionIsCommittedOrRolledBack() {
        val rec = Rec()
        val path = tempDb()
        val s = store(rec, path, manual = true)
        assertTrue(s.claim("k", 1).ok)
        assertEquals(2, rec.n("commit"))
        rec.fail = { m, q -> m == "executeUpdate" && q == "INSERT INTO pca_replay" }
        injected { s.claim("k", 2) }
        assertEquals(1, rec.n("rollback"))
        assertEquals(2, rec.n("commit"))
        assertEquals(1L, PcaJdbcStateStore({ AuthorizeTestKit.sqlite(path) }).last("k"))
    }

    @Test
    fun theFileCheckReadsTheProductNameCaseInsensitivelyAndTheMainRow() {
        val pg = Rec()
        pg.product = "PostgreSQL"
        PcaJdbcStateStore(PcaJdbcStateStore.ConnectionSource { conn(DriverManager.getConnection("jdbc:sqlite::memory:"), pg) })
        assertEquals(0, pg.n("exec PRAGMA database_list")) // not SQLite: not checked
        val lower = Rec()
        lower.product = "sqlite"
        try {
            PcaJdbcStateStore(PcaJdbcStateStore.ConnectionSource { conn(DriverManager.getConnection("jdbc:sqlite::memory:"), lower) })
            fail("an in-memory SQLite database must be refused whatever the case of its product name")
        } catch (e: SQLException) {
            assertTrue(e.message!!.contains("in memory"))
        }
        val noMain = Rec()
        noMain.renameMain = true
        try {
            store(noMain, tempDb())
            fail("no main database row")
        } catch (e: SQLException) {
            assertEquals(
                "the SQLite database is in memory or temporary: each connection would see its own empty database, so a replay could not be refused (use a database file)",
                e.message,
            )
        }
    }

    private fun f(u: String): Path? = PcaJdbcStateStore.sqliteFile(u)

    @Test
    fun fileUrisHostsAndPercentDecoding() {
        assertNull(f("jdbc:sqlite:file://remote"))
        assertNull(f("jdbc:sqlite:file://"))
        // a file URI path: forward slashes, and a leading '/' before a Windows drive (file:///C:/x)
        val u = dir.toString().replace('\\', '/').let { if (it.startsWith("/")) it else "/$it" }
        assertEquals(dir.resolve("a.db").toAbsolutePath(), f("jdbc:sqlite:file://LOCALHOST$u/a.db"))
        val cases = mapOf(
            "x%41" to "xA", "x%41%42" to "xAB", "x%4" to "x%4", "x%" to "x%", "x%g1" to "x%g1", "x%1g" to "x%1g",
            "x%09" to "x\t", "x%2541" to "x%41", "%41x" to "Ax", "x%4142" to "xA42",
        )
        val windows = System.getProperty("os.name").startsWith("Windows")
        for ((enc, dec) in cases) {
            if (windows && dec.contains('\t')) continue // a TAB is not a legal Windows file name character
            assertEquals(enc, dir.resolve(dec).toAbsolutePath(), f("jdbc:sqlite:file:$u/$enc"))
        }
    }

    @Test
    fun ensureHandlesTheRootAndReportsAnUncreatableFile() {
        try {
            assertEquals(Paths.get("/"), PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:/"))
        } catch (e: IOException) {
            // a kernel may answer EISDIR instead of EEXIST for the root: still an I/O refusal, never a NullPointerException
        }
        val plain = dir.resolve("plain")
        Files.write(plain, byteArrayOf(1))
        try {
            PcaJdbcStateStore.sqliteConnections("jdbc:sqlite:$plain/sub/x.db").open()
            fail("a database under a regular file cannot be created")
        } catch (e: SQLException) {
            val cause = e.cause
            assertTrue(cause is IOException)
            assertEquals("cannot create the SQLite database file: " + cause!!.message, e.message)
        }
        try {
            PcaJdbcStateStore.sqliteConnections("jdbc:postgresql://h/db")
            fail()
        } catch (e: IllegalArgumentException) {
            assertEquals("sqliteConnections needs a jdbc:sqlite: URL", e.message)
        }
    }

    @Test
    fun theCallersPropertiesReachTheDriver() {
        val p = Properties()
        p.setProperty("busy_timeout", "1234")
        PcaJdbcStateStore.sqliteConnections("jdbc:sqlite:${dir.resolve("bt.db")}", p).open().use { c ->
            c.createStatement().use { st ->
                st.executeQuery("PRAGMA busy_timeout").use { rs ->
                    assertTrue(rs.next())
                    assertEquals(1234, rs.getInt(1))
                }
            }
        }
    }

    @Test
    fun aDataSourceWithoutAUrlIsNotTouched() {
        val ds = Proxy.newProxyInstance(javaClass.classLoader, arrayOf<Class<*>>(DataSource::class.java)) { _, _, _ ->
            throw AssertionError("the store must not call the DataSource before a claim")
        } as DataSource
        assertNull(PcaJdbcStateStore.jdbcUrlOf(ds))
        assertEquals("pca_replay", PcaJdbcStateStore(ds, createTable = false).table)
    }
}
