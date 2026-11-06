package net.atlasauth.pca.verifier

import java.sql.Connection
import java.sql.SQLException
import javax.sql.DataSource

/**
 * A minimal atomic key/value store: the backend of [KvOperationStore] and [PlanRegistry].
 *
 * `get(key)` returns the stored JSON tree (a [Json] tree: maps, lists, strings, numbers, booleans, null) or null.
 * `update(key, fn)`: `fn(previous)` returns the value to store, or null to leave the key unchanged; the whole read-modify-write is
 * ONE atomic step of the backend (across threads for [MemoryAtomicKv], across threads, connections AND processes for
 * [JdbcAtomicKv]). `fn` can be called more than once (a lost race re-runs it), so it must be free of side effects other than
 * recording what it decided. Values must be JSON-serialisable.
 */
interface AtomicKv {
    fun get(key: String): Any?
    fun set(key: String, value: Any?)
    fun update(key: String, fn: (Any?) -> Any?): Any?
}

/** In-process [AtomicKv] (one lock). Correct for ONE process only. Values are deep-copied in and out. */
class MemoryAtomicKv : AtomicKv {
    private val m = HashMap<String, Any?>()

    @Synchronized
    override fun get(key: String): Any? = copyTree(m[key])

    @Synchronized
    override fun set(key: String, value: Any?) {
        m[key] = copyTree(value)
    }

    @Synchronized
    override fun update(key: String, fn: (Any?) -> Any?): Any? {
        val next = fn(copyTree(m[key]))
        if (next != null) m[key] = copyTree(next)
        return copyTree(m[key])
    }

    companion object {
        /** A deep copy of a JSON tree (maps and lists are copied, everything else is immutable). */
        fun copyTree(v: Any?): Any? = when (v) {
            is Map<*, *> -> {
                val out = LinkedHashMap<String, Any?>()
                for ((k, x) in v) out[k as String] = copyTree(x)
                out
            }
            is List<*> -> {
                val out = ArrayList<Any?>()
                for (x in v) out.add(copyTree(x))
                out
            }
            else -> v
        }
    }
}

/**
 * Durable [AtomicKv] over plain JDBC (no driver dependency). One row per key (`key` is the PRIMARY KEY, `value` the canonical
 * JSON text). `update` is optimistic and portable (SQLite, PostgreSQL, H2, ...): read the row, compute the next value, then write it
 * with ONE atomic statement that only succeeds if the row is still what was read (`UPDATE ... WHERE key = ? AND value = ?`, or an
 * `INSERT` that the primary key refuses when another writer got there first); a lost race re-reads and runs `fn` again. Two writers
 * can therefore never both act on the same previous value.
 *
 * Each call borrows a connection from `connections` and closes it. A connection that is not in auto-commit mode is committed
 * after each statement group (rolled back on error). A write whose outcome the database does not confirm throws (fail closed).
 *
 * SQLite: open it with [PcaJdbcStateStore.sqliteConnections] (or a DataSource whose `getUrl()`/`getJdbcUrl()` is the
 * `jdbc:sqlite:` URL); both create the database file atomically before the driver opens it. On a missing path,
 * org.xerial:sqlite-jdbc's open probe (`createNewFile()` then `delete()`) can unlink a file another connection already opened and
 * wrote to: the claims stored there are lost and the workers split across two files sharing one `-journal`. A bare
 * [PcaJdbcStateStore.ConnectionSource] is checked on first use to be a database FILE (in-memory/temporary SQLite is refused).
 */
class JdbcAtomicKv @JvmOverloads constructor(
    private val connections: PcaJdbcStateStore.ConnectionSource,
    val table: String = DEFAULT_TABLE,
    private val createTable: Boolean = true,
    private val maxAttempts: Int = 1000,
) : AtomicKv {
    @JvmOverloads
    constructor(dataSource: DataSource, table: String = DEFAULT_TABLE, createTable: Boolean = true) :
        this(PcaJdbcStateStore.sqliteReady(dataSource).let { ds -> PcaJdbcStateStore.ConnectionSource { ds.connection } }, table, createTable)

    @Volatile private var fileChecked = false

    // Statements are closed in explicit try/finally blocks (not `use`/`require`): no inline-function bytecode for the mutation run.
    init {
        if (!IDENT.matches(table)) throw IllegalArgumentException("table must be a plain SQL identifier")
        if (createTable) {
            // Idempotent DDL, so a transient failure is retried: many workers creating the table on one fresh SQLite file at once can
            // lose the journal-delete race (SQLITE_IOERR_DELETE_NOENT); a persistent failure still surfaces after the last attempt.
            var attempt = 1
            while (true) {
                try {
                    withConnection { c -> ddl(c) }
                    break
                } catch (e: SQLException) {
                    if (attempt == 20) throw e
                    sleeper(5L * attempt)
                    attempt++
                }
            }
        }
    }

    private fun ddl(c: Connection) {
        val st = c.createStatement()
        try {
            st.executeUpdate("CREATE TABLE IF NOT EXISTS $table (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)")
        } finally {
            st.close()
        }
    }

    private fun readText(c: Connection, key: String): String? {
        val st = c.prepareStatement("SELECT value FROM $table WHERE key = ?")
        try {
            st.setString(1, key)
            val rs = st.executeQuery()
            try {
                return if (rs.next()) rs.getString(1) else null
            } finally {
                rs.close()
            }
        } finally {
            st.close()
        }
    }

    private fun parse(text: String?): Any? = if (text == null) null else Json.parseLenient(text)

    override fun get(key: String): Any? = withConnection { c -> parse(readText(c, key)) }

    override fun set(key: String, value: Any?) {
        update(key) { value }
    }

    override fun update(key: String, fn: (Any?) -> Any?): Any? {
        for (attempt in 1..maxAttempts) {
            val done: Pair<Boolean, Any?> = withConnection { c ->
                val prevText = readText(c, key)
                val prev = parse(prevText)
                val next = fn(MemoryAtomicKv.copyTree(prev))
                if (next == null) return@withConnection Pair(true, prev)
                val text = Json.canonicalize(next)
                val won = if (prevText == null) insertIfAbsent(c, key, text) else replaceIf(c, key, prevText, text)
                if (won) Pair(true, parse(text)) else Pair(false, null)
            }
            if (done.first) return done.second
        }
        throw IllegalStateException("JdbcAtomicKv.update: gave up after $maxAttempts contended attempts (fail closed)")
    }

    /** True when the row still held [prevText] and now holds [text]. */
    private fun replaceIf(c: Connection, key: String, prevText: String, text: String): Boolean {
        val st = c.prepareStatement("UPDATE $table SET value = ? WHERE key = ? AND value = ?")
        try {
            st.setString(1, text)
            st.setString(2, key)
            st.setString(3, prevText)
            return st.executeUpdate() == 1
        } finally {
            st.close()
        }
    }

    /** True when this call inserted the row; false when the primary key (another writer) refused it. */
    private fun insertIfAbsent(c: Connection, key: String, text: String): Boolean {
        return try {
            val st = c.prepareStatement("INSERT INTO $table (key, value) VALUES (?, ?)")
            try {
                st.setString(1, key)
                st.setString(2, text)
                st.executeUpdate() == 1
            } finally {
                st.close()
            }
        } catch (e: SQLException) {
            // only the primary key refusing the row means another writer got there first; any other failure leaves OUR outcome
            // unknown (it may have committed), so it must not be read as a lost claim: fail closed
            if (!c.autoCommit) try { c.rollback() } catch (ignored: SQLException) {}
            // nor as a WIN (e.g. SQLITE_IOERR_DELETE_NOENT, "the row reads back as ours"): another writer can store the same text, and
            // the connection may be on a file that is being deleted (see the class doc), so an unconfirmed claim always throws
            if (isConstraint(e) && readText(c, key) != null) false else throw e
        }
    }

    private fun isSqlite(c: Connection): Boolean = c.metaData.databaseProductName.equals("SQLite", ignoreCase = true)

    /** SQLSTATE class 23 (integrity constraint), or SQLite's primary result code 19 (SQLITE_CONSTRAINT, extended codes included). */
    private fun isConstraint(e: SQLException): Boolean {
        val state = e.sqlState
        return (state != null && INTEGRITY_STATE.matches(state)) || (e.errorCode and 0xff) == 19
    }

    /** Another worker's concurrent CREATE on one fresh file can leave this connection's schema view without the table: create it again (idempotent) and retry once. */
    private fun <T> withConnection(fn: (Connection) -> T): T {
        try {
            return withConnectionOnce(fn)
        } catch (e: SQLException) {
            val msg = e.message
            if (!createTable || msg == null || !NO_TABLE.containsMatchIn(msg)) throw e
            withConnectionOnce { c -> ddl(c) }
            return withConnectionOnce(fn)
        }
    }

    private fun <T> withConnectionOnce(fn: (Connection) -> T): T {
        val c = connections.open()
        try {
            if (!fileChecked) { PcaJdbcStateStore.requireSqliteFileDatabase(c); fileChecked = true }
            try {
                if (isSqlite(c)) busyTimeout(c)
                val out = fn(c)
                if (!c.autoCommit) c.commit()
                return out
            } catch (e: Exception) {
                if (!c.autoCommit) try { c.rollback() } catch (ignored: SQLException) {}
                throw e
            }
        } finally {
            c.close()
        }
    }

    private fun busyTimeout(c: Connection) {
        val st = c.createStatement()
        try {
            st.execute("PRAGMA busy_timeout=30000")
        } finally {
            st.close()
        }
    }

    companion object {
        const val DEFAULT_TABLE = "pca_kv"
        private val IDENT = Regex("[A-Za-z_][A-Za-z0-9_]{0,62}")
        private val INTEGRITY_STATE = Regex("(?s)23.*")
        private val NO_TABLE = Regex("no such table")

        /** The DDL retry back-off (milliseconds); a seam so a test can observe it without waiting. */
        internal var sleeper: (Long) -> Unit = { ms -> Thread.sleep(ms) }
    }
}
