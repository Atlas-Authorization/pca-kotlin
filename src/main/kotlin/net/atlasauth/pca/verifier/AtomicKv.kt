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

    override fun get(key: String): Any? = synchronized(m) { copyTree(m[key]) }

    override fun set(key: String, value: Any?) {
        synchronized(m) { m[key] = copyTree(value) }
    }

    override fun update(key: String, fn: (Any?) -> Any?): Any? = synchronized(m) {
        val next = fn(copyTree(m[key]))
        if (next != null) m[key] = copyTree(next)
        copyTree(m[key])
    }

    companion object {
        /** A deep copy of a JSON tree (maps and lists are copied, everything else is immutable). */
        fun copyTree(v: Any?): Any? = when (v) {
            is Map<*, *> -> {
                val out = LinkedHashMap<String, Any?>()
                for ((k, x) in v) out[k as String] = copyTree(x)
                out
            }
            is List<*> -> v.mapTo(ArrayList()) { copyTree(it) }
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
 * after each statement group (rolled back on error).
 */
class JdbcAtomicKv @JvmOverloads constructor(
    private val connections: PcaJdbcStateStore.ConnectionSource,
    val table: String = DEFAULT_TABLE,
    private val createTable: Boolean = true,
    private val maxAttempts: Int = 1000,
) : AtomicKv {
    @JvmOverloads
    constructor(dataSource: DataSource, table: String = DEFAULT_TABLE, createTable: Boolean = true) :
        this(PcaJdbcStateStore.ConnectionSource { dataSource.connection }, table, createTable)

    init {
        require(IDENT.matches(table)) { "table must be a plain SQL identifier" }
        if (createTable) {
            // Idempotent DDL, so a transient failure is retried: many workers creating the table on one fresh SQLite file at once can
            // lose the journal-delete race (SQLITE_IOERR_DELETE_NOENT); a persistent failure still surfaces after the last attempt.
            for (attempt in 1..20) {
                try {
                    withConnection { c ->
                        c.createStatement().use {
                            it.executeUpdate("CREATE TABLE IF NOT EXISTS $table (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)")
                        }
                    }
                    break
                } catch (e: SQLException) {
                    if (attempt == 20) throw e
                    Thread.sleep(5L * attempt)
                }
            }
        }
    }

    private fun readText(c: Connection, key: String): String? = c.prepareStatement("SELECT value FROM $table WHERE key = ?").use { st ->
        st.setString(1, key)
        st.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
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
                val won = if (prevText == null) insertIfAbsent(c, key, text)
                else c.prepareStatement("UPDATE $table SET value = ? WHERE key = ? AND value = ?").use { st ->
                    st.setString(1, text)
                    st.setString(2, key)
                    st.setString(3, prevText)
                    st.executeUpdate() == 1
                }
                if (won) Pair(true, parse(text)) else Pair(false, null)
            }
            if (done.first) return done.second
        }
        throw IllegalStateException("JdbcAtomicKv.update: gave up after $maxAttempts contended attempts (fail closed)")
    }

    /** True when this call inserted the row; false when the primary key (another writer) refused it. */
    private fun insertIfAbsent(c: Connection, key: String, text: String): Boolean {
        return try {
            c.prepareStatement("INSERT INTO $table (key, value) VALUES (?, ?)").use { st ->
                st.setString(1, key)
                st.setString(2, text)
                st.executeUpdate() == 1
            }
        } catch (e: SQLException) {
            // only the primary key refusing the row means another writer got there first; any other failure leaves OUR outcome
            // unknown (it may have committed), so it must not be read as a lost claim: fail closed
            if (!c.autoCommit) try { c.rollback() } catch (ignored: SQLException) {}
            // SQLITE_IOERR_DELETE_NOENT: the journal file vanished AFTER the commit (another connection removed it): the row is stored and
            // only a successful commit by THIS statement could have put it there while the key was absent (a loser gets the PK error)
            val committedThenJournalLost = e.message?.contains("SQLITE_IOERR_DELETE_NOENT") == true && readText(c, key) == text
            if (committedThenJournalLost) true
            else if (isConstraint(e) && readText(c, key) != null) false else throw e
        }
    }

    private fun isSqlite(c: Connection): Boolean = c.metaData.databaseProductName.equals("SQLite", ignoreCase = true)

    private fun isConstraint(e: SQLException): Boolean =
        e.sqlState?.startsWith("23") == true || (e.errorCode and 0xff) == 19 && e.errorCode != 0

    /** Another worker's concurrent CREATE on one fresh file can leave this connection's schema view without the table: create it again (idempotent) and retry once. */
    private fun <T> withConnection(fn: (Connection) -> T): T {
        try {
            return withConnectionOnce(fn)
        } catch (e: SQLException) {
            if (!createTable || e.message?.contains("no such table") != true) throw e
            withConnectionOnce { c ->
                c.createStatement().use { it.executeUpdate("CREATE TABLE IF NOT EXISTS $table (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)") }
            }
            return withConnectionOnce(fn)
        }
    }

    private fun <T> withConnectionOnce(fn: (Connection) -> T): T = connections.open().use { c ->
        try {
            if (isSqlite(c)) c.createStatement().use { it.execute("PRAGMA busy_timeout=30000") }
            val out = fn(c)
            if (!c.autoCommit) c.commit()
            out
        } catch (e: Exception) {
            if (!c.autoCommit) try { c.rollback() } catch (ignored: SQLException) {}
            throw e
        }
    }

    companion object {
        const val DEFAULT_TABLE = "pca_kv"
        private val IDENT = Regex("[A-Za-z_][A-Za-z0-9_]{0,62}")
    }
}
