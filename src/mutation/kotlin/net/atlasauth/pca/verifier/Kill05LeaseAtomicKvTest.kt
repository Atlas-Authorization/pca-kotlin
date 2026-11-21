package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.sql.Connection
import java.sql.DatabaseMetaData
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Statement

/**
 * Mutation kills for [MemoryAtomicKv] and [JdbcAtomicKv] (AtomicKv.kt). The JDBC store runs against a scripted in-memory fake
 * (java.lang.reflect.Proxy over the JDBC interfaces) that records every statement, commit, rollback and close, and can inject
 * a lost race, a primary-key refusal, a missing table or a failing CREATE.
 */
class Kill05LeaseAtomicKvTest {
    /** A scripted JDBC database: one table of key -> text rows. */
    private class FakeDb(val product: String = "FakeDB", val autoCommit: Boolean = true) {
        val rows = LinkedHashMap<String, String>()
        val log = ArrayList<String>()
        var opens = 0
        var connCloses = 0
        var stmts = 0
        var stmtCloses = 0
        var results = 0
        var rsCloses = 0
        var commits = 0
        var rollbacks = 0
        var createFailures = 0
        var selectError: SQLException? = null
        var beforeInsert: (() -> Unit)? = null
        var insertError: SQLException? = null
        var insertResult: Int? = null
        var beforeUpdate: (() -> Unit)? = null

        @Suppress("UNCHECKED_CAST")
        private fun <T> proxy(type: Class<T>, h: (Method, Array<out Any?>) -> Any?): T =
            Proxy.newProxyInstance(FakeDb::class.java.classLoader, arrayOf<Class<*>>(type)) { self, m, args ->
                when (m.name) {
                    "toString" -> type.simpleName
                    "hashCode" -> System.identityHashCode(self)
                    "equals" -> self === args?.get(0)
                    else -> h(m, args ?: arrayOf<Any?>())
                }
            } as T

        private fun rs(data: List<Array<String>>): ResultSet {
            results++
            var i = -1
            return proxy(ResultSet::class.java) { m, a ->
                when (m.name) {
                    "next" -> { i++; i < data.size }
                    "getString" -> data[i][(a[0] as Int) - 1]
                    "close" -> { rsCloses++; null }
                    else -> throw UnsupportedOperationException(m.name)
                }
            }
        }

        private fun statement(): Statement {
            stmts++
            return proxy(Statement::class.java) { m, a ->
                when (m.name) {
                    "executeUpdate" -> {
                        val sql = a[0] as String
                        log.add(sql)
                        if (sql.startsWith("CREATE TABLE") && createFailures > 0) { createFailures--; throw SQLException("create failed") }
                        0
                    }
                    "execute" -> { log.add(a[0] as String); false }
                    "executeQuery" -> { log.add(a[0] as String); rs(listOf(arrayOf("0", "main", "/data/fake.db"))) }
                    "close" -> { stmtCloses++; null }
                    else -> throw UnsupportedOperationException(m.name)
                }
            }
        }

        private fun prepared(sql: String): PreparedStatement {
            stmts++
            val p = HashMap<Int, String?>()
            return proxy(PreparedStatement::class.java) { m, a ->
                when (m.name) {
                    "setString" -> { p[a[0] as Int] = a[1] as String?; null }
                    "executeQuery" -> {
                        log.add(sql)
                        selectError?.let { selectError = null; throw it }
                        val v = rows[p[1]]
                        rs(if (v == null) emptyList() else listOf(arrayOf(v)))
                    }
                    "executeUpdate" -> {
                        log.add(sql)
                        if (sql.startsWith("INSERT")) {
                            beforeInsert?.invoke()
                            insertError?.let { insertError = null; throw it }
                            val forced = insertResult
                            if (forced != null) { insertResult = null; forced }
                            else if (rows.containsKey(p[1]!!)) throw SQLException("UNIQUE constraint failed", "23505", 19)
                            else { rows[p[1]!!] = p[2]!!; 1 }
                        } else {
                            beforeUpdate?.invoke()
                            if (rows[p[2]!!] == p[3]) { rows[p[2]!!] = p[1]!!; 1 } else 0
                        }
                    }
                    "close" -> { stmtCloses++; null }
                    else -> throw UnsupportedOperationException(m.name)
                }
            }
        }

        fun conn(): Connection {
            opens++
            return proxy(Connection::class.java) { m, a ->
                when (m.name) {
                    "prepareStatement" -> prepared(a[0] as String)
                    "createStatement" -> statement()
                    "getAutoCommit" -> autoCommit
                    "commit" -> { commits++; null }
                    "rollback" -> { rollbacks++; null }
                    "close" -> { connCloses++; null }
                    "getMetaData" -> proxy(DatabaseMetaData::class.java) { mm, _ ->
                        if (mm.name == "getDatabaseProductName") product else throw UnsupportedOperationException(mm.name)
                    }
                    else -> throw UnsupportedOperationException(m.name)
                }
            }
        }

        fun count(prefix: String) = log.count { it.startsWith(prefix) }

        /** Every connection, statement and result set that was opened was closed. */
        fun allClosed() {
            assertEquals("connections", opens, connCloses)
            assertEquals("statements", stmts, stmtCloses)
            assertEquals("result sets", results, rsCloses)
        }
    }

    private fun kv(db: FakeDb, table: String = JdbcAtomicKv.DEFAULT_TABLE, create: Boolean = true, attempts: Int = 1000) =
        JdbcAtomicKv(PcaJdbcStateStore.ConnectionSource { db.conn() }, table, create, attempts)

    private fun n(s: String) = Json.Num(s)

    @Test fun memoryKvCopiesInAndOut() {
        val m = MemoryAtomicKv()
        assertNull(m.get("a"))
        val v = jm("x", 1L, "l", jl(jm("y", 2L)))
        m.set("a", v)
        @Suppress("UNCHECKED_CAST")
        ((v["l"] as MutableList<Any?>)[0] as MutableMap<String, Any?>)["y"] = 9L
        v["x"] = 5L
        assertEquals(jm("x", 1L, "l", jl(jm("y", 2L))), m.get("a"))
        @Suppress("UNCHECKED_CAST")
        val out = m.get("a") as MutableMap<String, Any?>
        out["x"] = 7L
        @Suppress("UNCHECKED_CAST")
        ((out["l"] as MutableList<Any?>)[0] as MutableMap<String, Any?>)["y"] = 8L
        assertEquals(jm("x", 1L, "l", jl(jm("y", 2L))), m.get("a"))
        // update: fn gets a copy; null leaves the key; the stored value (a copy) is returned
        @Suppress("UNCHECKED_CAST")
        val same = m.update("a") { p -> (p as MutableMap<String, Any?>)["x"] = 99L; null }
        assertEquals(jm("x", 1L, "l", jl(jm("y", 2L))), same)
        assertEquals(jm("x", 1L, "l", jl(jm("y", 2L))), m.get("a"))
        val next = jl("n")
        val got = m.update("a") { next }
        assertEquals(jl("n"), got)
        next.add("later")
        assertEquals(jl("n"), m.get("a"))
        assertNull(m.update("b") { p -> assertNull(p); null })
        assertNull(m.get("b"))
        assertEquals("s", m.update("b") { "s" })
        m.set("b", null)
        assertNull(m.get("b"))
        val tree = jm("k", jl(1L, jm("z", "q")))
        val copy = MemoryAtomicKv.copyTree(tree)
        assertEquals(tree, copy)
        assertTrue(copy !== tree)
        assertSame("leaf", MemoryAtomicKv.copyTree("leaf"))
    }

    @Test fun jdbcBasicsAutoCommit() {
        val db = FakeDb()
        val s = kv(db)
        assertEquals("pca_kv", s.table)
        assertEquals(listOf("CREATE TABLE IF NOT EXISTS pca_kv (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)"), db.log)
        assertNull(s.get("a"))
        s.set("a", jm("x", 1L))
        assertEquals("{\"x\":1}", db.rows["a"])
        assertEquals(jm("x", n("1")), s.get("a"))
        assertEquals(1, db.count("INSERT INTO pca_kv (key, value) VALUES (?, ?)"))
        val up = s.update("a") { p ->
            assertEquals(jm("x", n("1")), p)
            jm("x", 2L)
        }
        assertEquals(jm("x", n("2")), up)
        assertEquals("{\"x\":2}", db.rows["a"])
        assertEquals(1, db.count("UPDATE pca_kv SET value = ? WHERE key = ? AND value = ?"))
        // a null result writes nothing and returns the stored value; fn works on a copy
        val writes = db.count("INSERT") + db.count("UPDATE")
        @Suppress("UNCHECKED_CAST")
        val kept = s.update("a") { p -> (p as MutableMap<String, Any?>)["x"] = "mutated"; null }
        assertEquals(jm("x", n("2")), kept)
        assertNull(s.update("missing") { null })
        assertEquals(writes, db.count("INSERT") + db.count("UPDATE"))
        assertEquals("{\"x\":2}", db.rows["a"])
        s.set("b", jl("v"))
        assertEquals(jl("v"), s.get("b"))
        assertEquals("[\"v\"]", db.rows["b"])
        assertEquals(0, db.commits)
        assertEquals(0, db.rollbacks)
        assertEquals(0, db.count("PRAGMA"))
        db.allClosed()
        // a custom table is used everywhere
        val db2 = FakeDb()
        val t = kv(db2, "plans_1")
        assertEquals("plans_1", t.table)
        t.set("k", "v")
        assertEquals("v", t.get("k"))
        assertEquals(setOf(
            "CREATE TABLE IF NOT EXISTS plans_1 (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)",
            "SELECT value FROM plans_1 WHERE key = ?", "INSERT INTO plans_1 (key, value) VALUES (?, ?)",
        ), db2.log.toSet())
        db2.allClosed()
    }

    @Test fun jdbcTableNameAndCreateFlag() {
        for (bad in listOf("bad-name", "1abc", "", "a b", "x".repeat(64))) {
            try {
                kv(FakeDb(), bad)
                fail(bad)
            } catch (e: IllegalArgumentException) {
                assertEquals("table must be a plain SQL identifier", e.message)
            }
        }
        val db = FakeDb()
        kv(db, "_" + "x".repeat(62))
        assertEquals(1, db.count("CREATE TABLE"))
        val off = FakeDb()
        val s = kv(off, create = false)
        assertEquals(0, off.count("CREATE"))
        assertEquals(0, off.opens)
        s.set("a", 1L)
        assertEquals(0, off.count("CREATE"))
        assertEquals(n("1"), s.get("a"))
    }

    @Test fun jdbcSqliteAndExplicitTransactions() {
        for (product in listOf("SQLite", "sqlite")) {
            val db = FakeDb(product, autoCommit = false)
            val s = kv(db)
            s.set("a", 1L)
            assertEquals(n("1"), s.get("a"))
            s.update("a") { 2L }
            // the file check runs once per store; the busy timeout once per connection; every connection commits
            assertEquals(1, db.count("PRAGMA database_list"))
            assertEquals(db.opens, db.count("PRAGMA busy_timeout=30000"))
            assertEquals(db.opens, db.commits)
            assertEquals(0, db.rollbacks)
            db.allClosed()
        }
        val other = FakeDb("PostgreSQL", autoCommit = false)
        val p = kv(other)
        p.set("a", 1L)
        assertEquals(0, other.count("PRAGMA"))
        assertEquals(other.opens, other.commits)
        // a failure inside the transaction rolls back (and does not commit), and still closes the connection
        val before = other.commits
        try {
            p.update("a") { throw IllegalStateException("boom") }
            fail()
        } catch (e: IllegalStateException) {
            assertEquals("boom", e.message)
        }
        assertEquals(1, other.rollbacks)
        assertEquals(before, other.commits)
        other.allClosed()
        val auto = FakeDb()
        val q = kv(auto)
        try {
            q.update("a") { throw IllegalStateException("boom") }
            fail()
        } catch (e: IllegalStateException) {
            assertEquals("boom", e.message)
        }
        assertEquals(0, auto.rollbacks)
        auto.allClosed()
    }

    @Test fun jdbcLostRaceReruns() {
        val db = FakeDb()
        val s = kv(db)
        s.set("c", jm("n", 1L))
        var raced = false
        db.beforeUpdate = { if (!raced) { raced = true; db.rows["c"] = "{\"n\":10}" } }
        var calls = 0
        val got = s.update("c") { p ->
            calls++
            @Suppress("UNCHECKED_CAST")
            jm("n", IntentJs.lng((p as Map<String, Any?>)["n"]) + 1)
        }
        assertEquals(2, calls)
        assertEquals(jm("n", n("11")), got)
        assertEquals("{\"n\":11}", db.rows["c"])
        assertEquals(2, db.count("UPDATE"))
        // every attempt loses: fail closed after maxAttempts
        val db2 = FakeDb()
        val t = kv(db2, attempts = 3)
        t.set("c", 1L)
        var k = 100
        db2.beforeUpdate = { db2.rows["c"] = (k++).toString() }
        try {
            t.update("c") { 5L }
            fail()
        } catch (e: IllegalStateException) {
            assertEquals("JdbcAtomicKv.update: gave up after 3 contended attempts (fail closed)", e.message)
        }
        assertEquals(3, db2.count("UPDATE"))
        db2.allClosed()
        val one = kv(FakeDb(), attempts = 1)
        assertEquals(n("4"), one.update("z") { 4L })
    }

    @Test fun jdbcInsertRace() {
        // the primary key refuses our INSERT because another writer got there first: a constraint failure, re-run on its value
        val constraint = listOf(SQLException("dup", "23505", 0), SQLException("dup", "23", 0), SQLException("dup", null, 19),
            SQLException("dup", null, 2067), SQLException("dup", "42000", 275))
        for (e in constraint) {
            for (autoCommit in listOf(true, false)) {
                val db = FakeDb(autoCommit = autoCommit)
                val s = kv(db)
                db.beforeInsert = { db.rows["c"] = "{\"n\":5}"; db.beforeInsert = null }
                db.insertError = e
                var calls = 0
                val got = s.update("c") { p ->
                    calls++
                    @Suppress("UNCHECKED_CAST")
                    jm("n", (if (p == null) 0L else IntentJs.lng((p as Map<String, Any?>)["n"])) + 1)
                }
                assertEquals("${e.sqlState}/${e.errorCode}", jm("n", n("6")), got)
                assertEquals(2, calls)
                assertEquals("{\"n\":6}", db.rows["c"])
                assertEquals(if (autoCommit) 0 else 1, db.rollbacks)
                db.allClosed()
            }
        }
        // anything else, or a constraint failure with no row to show for it, is an unknown outcome: it throws
        val unknown = listOf(SQLException("io", "42000", 0), SQLException("io", null, 256), SQLException("io", null, 18),
            SQLException("io", "x23", 0), SQLException("io", "2", 0), SQLException("io", null, 0))
        for (e in unknown) {
            val db = FakeDb()
            val s = kv(db)
            db.beforeInsert = { db.rows["c"] = "1" }
            db.insertError = e
            try {
                s.update("c") { 2L }
                fail("${e.sqlState}/${e.errorCode}")
            } catch (x: SQLException) {
                assertSame(e, x)
            }
            db.allClosed()
        }
        val db = FakeDb()
        val s = kv(db)
        val e = SQLException("dup", "23505", 19)
        db.insertError = e
        try {
            s.update("c") { 2L }
            fail()
        } catch (x: SQLException) {
            assertSame(e, x)
        }
        // an INSERT that reports no row is a lost race too
        val db3 = FakeDb()
        val s3 = kv(db3)
        db3.beforeInsert = { db3.rows["c"] = "{\"n\":7}"; db3.beforeInsert = null }
        db3.insertResult = 0
        val got = s3.update("c") { p -> if (p == null) jm("n", 0L) else jm("n", 8L) }
        assertEquals(jm("n", n("8")), got)
        assertEquals("{\"n\":8}", db3.rows["c"])
        db3.allClosed()
    }

    @Test fun jdbcMissingTableIsRecreatedOnce() {
        val msg = "[SQLITE_ERROR] SQL error or missing database (no such table: pca_kv)"
        val db = FakeDb()
        val s = kv(db)
        db.rows["a"] = "3"
        db.selectError = SQLException(msg)
        assertEquals(n("3"), s.get("a"))
        assertEquals(2, db.count("CREATE TABLE"))
        db.allClosed()
        // not created by this store, another message, or no message: rethrown as is
        for ((create, e) in listOf(false to SQLException(msg), true to SQLException("disk I/O error"), true to SQLException())) {
            val d = FakeDb()
            val t = kv(d, create = create)
            d.selectError = e
            try {
                t.get("a")
                fail("$create ${e.message}")
            } catch (x: SQLException) {
                assertSame(e, x)
            }
            assertEquals(if (create) 1 else 0, d.count("CREATE TABLE"))
            d.allClosed()
        }
    }

    @Test fun jdbcCreateRetriesWithBackoff() {
        val sleeps = ArrayList<Long>()
        val saved = JdbcAtomicKv.sleeper
        try {
            JdbcAtomicKv.sleeper = { sleeps.add(it) }
            val db = FakeDb()
            db.createFailures = 19
            kv(db)
            assertEquals(20, db.count("CREATE TABLE"))
            assertEquals((1L..19L).map { 5L * it }, sleeps)
            db.allClosed()
            sleeps.clear()
            val db2 = FakeDb()
            db2.createFailures = 20
            try {
                kv(db2)
                fail()
            } catch (e: SQLException) {
                assertEquals("create failed", e.message)
            }
            assertEquals(20, db2.count("CREATE TABLE"))
            assertEquals(19, sleeps.size)
            db2.allClosed()
        } finally {
            JdbcAtomicKv.sleeper = saved
        }
        // the default back-off really waits
        val t0 = System.nanoTime()
        JdbcAtomicKv.sleeper(30L)
        assertTrue((System.nanoTime() - t0) >= 20_000_000L)
    }
}
