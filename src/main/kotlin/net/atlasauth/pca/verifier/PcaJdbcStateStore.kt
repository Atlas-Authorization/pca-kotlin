package net.atlasauth.pca.verifier

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.util.Properties
import javax.sql.DataSource

/**
 * Durable replay store over plain JDBC (no driver dependency: bring your own DataSource or connection factory). One row
 * per counter stream, `key` is the PRIMARY KEY.
 *
 * The claim is ONE statement, `INSERT ... ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE
 * excluded.last_counter > <table>.last_counter`: one row affected means this call consumed the counter. The database runs
 * it atomically, so concurrent threads, connections and processes can never both consume the same counter. The upsert
 * syntax is SQLite (3.24+) and PostgreSQL (9.5+).
 *
 * Each claim borrows a connection from `connections` and closes it. A connection that is not in auto-commit mode is
 * committed after the statement (rolled back on error).
 *
 * SQLite: open it with [sqliteConnections] (or a DataSource whose `getUrl()`/`getJdbcUrl()` is the `jdbc:sqlite:` URL). Both
 * create the database file atomically BEFORE the driver opens it: on a missing path, org.xerial:sqlite-jdbc's open probe
 * (`createNewFile()` then `delete()`) can unlink a file another connection already opened and wrote claims to (a replay would
 * then be admitted). A bare [ConnectionSource] cannot be checked before its first open (the probe runs inside it), so it is only
 * checked on first use to be a database FILE: an in-memory or temporary SQLite database is refused (each connection would see
 * its own empty database).
 */
class PcaJdbcStateStore @JvmOverloads constructor(
    private val connections: ConnectionSource,
    val table: String = DEFAULT_TABLE,
    createTable: Boolean = true,
) : Authorize.StateStore, Authorize.LastStore, Authorize.BudgetStore {
    /** Opens a JDBC connection for one claim; the store closes it. */
    fun interface ConnectionSource {
        @Throws(SQLException::class)
        fun open(): Connection
    }

    @JvmOverloads
    constructor(dataSource: DataSource, table: String = DEFAULT_TABLE, createTable: Boolean = true) :
        this(sourceOf(sqliteReady(dataSource)), table, createTable)

    @Volatile private var fileChecked = false
    private val upsert: String
    private val select: String
    private val onceTable: String
    private val onceUpsert: String
    private val onceExtend: String

    init {
        // no inline require / let in the constructors: their expansion has no source line, so its mutants cannot be placed
        if (!IDENT.matches(table)) throw IllegalArgumentException("table must be a plain SQL identifier")
        upsert = "INSERT INTO $table (key, last_counter) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET " +
            "last_counter = excluded.last_counter WHERE excluded.last_counter > $table.last_counter"
        select = "SELECT last_counter FROM $table WHERE key = ?"
        onceTable = "${table}_once"
        // consume-once: insert, or take over a record whose retention has passed (retain_until < now): ONE row affected = consumed
        onceUpsert = "INSERT INTO $onceTable (key, retain_until) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET " +
            "retain_until = excluded.retain_until WHERE $onceTable.retain_until < ?"
        onceExtend = "UPDATE $onceTable SET retain_until = ? WHERE key = ? AND retain_until < ? AND retain_until >= ?"
        if (createTable) {
            withConnection { c ->
                c.createStatement().use {
                    it.executeUpdate("CREATE TABLE IF NOT EXISTS $table (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)")
                    it.executeUpdate("CREATE TABLE IF NOT EXISTS $onceTable (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)")
                    it.executeUpdate("CREATE TABLE IF NOT EXISTS ${table}_budget (key TEXT NOT NULL PRIMARY KEY, b DOUBLE PRECISION NOT NULL, tau DOUBLE PRECISION NOT NULL, as_of DOUBLE PRECISION)")
                }
            }
        }
    }

    override fun claim(key: String, counter: Long): Authorize.ClaimResult = withConnection { c ->
        val n = c.prepareStatement(upsert).use { st ->
            st.setString(1, key)
            st.setLong(2, counter)
            st.executeUpdate()
        }
        if (n == 1) Authorize.ClaimResult(true, null)
        else c.prepareStatement(select).use { st ->
            st.setString(1, key)
            st.executeQuery().use { rs -> Authorize.ClaimResult(false, if (rs.next()) rs.getLong(1) else null) }
        }
    }

    /** TTL'd consume-once in `<table>_once` (key, retain_until): the atomic upsert above; expired rows are pruned after each call. */
    override fun consumeOnce(key: String, retainUntil: Long, now: Long): Boolean {
        require(key.isNotEmpty() && retainUntil >= now) { "consumeOnce needs a key and a retention horizon not before now" }
        return withConnection { c ->
            val n = c.prepareStatement(onceUpsert).use { st ->
                st.setString(1, key)
                st.setLong(2, retainUntil)
                st.setLong(3, now)
                st.executeUpdate()
            }
            if (n != 1) {
                // a live record: keep the longer horizon (never shorten it)
                c.prepareStatement(onceExtend).use { st ->
                    st.setLong(1, retainUntil)
                    st.setString(2, key)
                    st.setLong(3, retainUntil)
                    st.setLong(4, now)
                    st.executeUpdate()
                }
            }
            c.prepareStatement("DELETE FROM $onceTable WHERE retain_until < ?").use { st ->
                st.setLong(1, now)
                st.executeUpdate()
            }
            n == 1
        }
    }

    override fun last(key: String): Long? = withConnection { c ->
        c.prepareStatement(select).use { st ->
            st.setString(1, key)
            st.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else null }
        }
    }

    /** The trust budget of a grant and holder (`<table>_budget`), see [Authorize.BudgetStore]. */
    override fun budget(key: String): Risk.Budget? = withConnection { c ->
        c.prepareStatement("SELECT b, tau, as_of FROM ${table}_budget WHERE key = ?").use { st ->
            st.setString(1, key)
            st.executeQuery().use { rs ->
                if (!rs.next()) null else {
                    val asOf = rs.getDouble(3)
                    Risk.Budget(rs.getDouble(1), rs.getDouble(2), if (rs.wasNull()) null else asOf)
                }
            }
        }
    }

    /** ONE atomic compare-and-set: an INSERT that the primary key refuses when a row exists (old = null), else an UPDATE that matches the old values. */
    override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean = withConnection { c ->
        val n = if (old == null) {
            c.prepareStatement("INSERT INTO ${table}_budget (key, b, tau, as_of) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO NOTHING").use { st ->
                st.setString(1, key)
                st.setDouble(2, new.B)
                st.setDouble(3, new.tau)
                if (new.asOf == null) st.setNull(4, java.sql.Types.DOUBLE) else st.setDouble(4, new.asOf)
                st.executeUpdate()
            }
        } else {
            val asOfClause = if (old.asOf == null) "as_of IS NULL" else "as_of = ?"
            c.prepareStatement("UPDATE ${table}_budget SET b = ?, tau = ?, as_of = ? WHERE key = ? AND b = ? AND tau = ? AND $asOfClause").use { st ->
                st.setDouble(1, new.B)
                st.setDouble(2, new.tau)
                if (new.asOf == null) st.setNull(3, java.sql.Types.DOUBLE) else st.setDouble(3, new.asOf)
                st.setString(4, key)
                st.setDouble(5, old.B)
                st.setDouble(6, old.tau)
                if (old.asOf != null) st.setDouble(7, old.asOf)
                st.executeUpdate()
            }
        }
        n == 1
    }

    private fun <T> withConnection(fn: (Connection) -> T): T = connections.open().use { c ->
        if (!fileChecked) { requireSqliteFileDatabase(c); fileChecked = true }
        try {
            val out = fn(c)
            if (!c.autoCommit) c.commit()
            out
        } catch (e: Exception) {
            if (!c.autoCommit) try { c.rollback() } catch (ignored: SQLException) {}
            throw e
        }
    }

    companion object {
        const val DEFAULT_TABLE = "pca_replay"
        private val IDENT = Regex("[A-Za-z_][A-Za-z0-9_]{0,62}")
        private const val SQLITE_URL = "jdbc:sqlite:"

        /**
         * The database file a `jdbc:sqlite:` URL names (a plain path, relative to the working directory, or a `file:` URI), or null
         * when there is none to create: not a SQLite URL, in memory (`:memory:`, empty, `mode=memory`), read-only (`mode=ro`), a
         * classpath `:resource:`, or a `file:` URI with a remote authority.
         */
        @JvmStatic
        fun sqliteFile(jdbcUrl: String): Path? {
            if (!jdbcUrl.startsWith(SQLITE_URL)) return null
            val rest = jdbcUrl.substring(SQLITE_URL.length)
            val name = rest.substringBefore('?')
            val params = rest.substringAfter('?', "").split('&').map { it.trim().lowercase() }
            if ("mode=memory" in params || "mode=ro" in params) return null
            if (name.isEmpty() || name == ":memory:" || name.startsWith(":resource:")) return null
            if (!name.startsWith("file:")) return Paths.get(name).toAbsolutePath()
            var p = name.substring("file:".length)
            if (p.startsWith("//")) { // file://[localhost]/path
                val slash = p.indexOf('/', 2)
                if (slash < 0) return null
                val host = p.substring(2, slash)
                if (host.isNotEmpty() && !host.equals("localhost", ignoreCase = true)) return null
                p = p.substring(slash)
            }
            p = percentDecode(p)
            if (Regex("^/[A-Za-z]:").containsMatchIn(p)) p = p.substring(1) // file:///C:/x on Windows
            return if (p.isEmpty() || p == ":memory:") null else Paths.get(p).toAbsolutePath()
        }

        /** Create the database file of a `jdbc:sqlite:` URL (and its directories) if absent, atomically (CREATE_NEW); the file, or null (see [sqliteFile]). */
        @JvmStatic
        @Throws(IOException::class)
        fun ensureSqliteFile(jdbcUrl: String): Path? {
            val f = sqliteFile(jdbcUrl) ?: return null
            f.parent?.let { Files.createDirectories(it) }
            try { Files.createFile(f) } catch (ignored: FileAlreadyExistsException) {}
            return f
        }

        /**
         * The recommended SQLite [ConnectionSource]: each open first creates the database file if absent ([ensureSqliteFile]), so
         * the driver never runs its create-then-delete probe, then opens `jdbcUrl` (default `busy_timeout` 30 s).
         */
        @JvmStatic
        @JvmOverloads
        fun sqliteConnections(jdbcUrl: String, properties: Properties = Properties().apply { setProperty("busy_timeout", "30000") }): ConnectionSource {
            require(jdbcUrl.startsWith(SQLITE_URL)) { "sqliteConnections needs a jdbc:sqlite: URL" }
            val props = Properties().apply { putAll(properties) }
            return ConnectionSource {
                try { ensureSqliteFile(jdbcUrl) } catch (e: IOException) { throw SQLException("cannot create the SQLite database file: ${e.message}", e) }
                DriverManager.getConnection(jdbcUrl, props)
            }
        }

        private fun sourceOf(ds: DataSource): ConnectionSource = ConnectionSource { ds.connection }

        /** Pre-create the file of a SQLite DataSource (found by its public `getUrl()`, `getJdbcUrl()` or `getURL()`) before any open. */
        internal fun sqliteReady(dataSource: DataSource): DataSource {
            jdbcUrlOf(dataSource)?.let { ensureSqliteFile(it) }
            return dataSource
        }

        internal fun jdbcUrlOf(dataSource: Any): String? {
            for (name in arrayOf("getUrl", "getJdbcUrl", "getURL")) {
                val m = try { dataSource.javaClass.getMethod(name) } catch (e: NoSuchMethodException) { continue }
                if (m.returnType != String::class.java) continue
                return try { m.invoke(dataSource) as String? } catch (e: ReflectiveOperationException) { null }
            }
            return null
        }

        /** Refuse a SQLite connection whose main database is not a file (in memory or temporary: private to that connection). */
        @Throws(SQLException::class)
        internal fun requireSqliteFileDatabase(c: Connection) {
            if (!c.metaData.databaseProductName.equals("SQLite", ignoreCase = true)) return
            var file: String? = null
            c.createStatement().use { st ->
                st.executeQuery("PRAGMA database_list").use { rs -> while (rs.next()) if (rs.getString(2) == "main") file = rs.getString(3) }
            }
            if (file.isNullOrEmpty())
                throw SQLException("the SQLite database is in memory or temporary: each connection would see its own empty database, so a replay could not be refused (use a database file)")
        }

        private fun percentDecode(s: String): String {
            val b = s.toByteArray(Charsets.UTF_8)
            val out = ByteArrayOutputStream(b.size)
            var i = 0
            while (i < b.size) {
                val hi = if (b[i] == '%'.code.toByte() && i + 2 < b.size) Character.digit(b[i + 1].toInt(), 16) else -1
                val lo = if (hi >= 0) Character.digit(b[i + 2].toInt(), 16) else -1
                if (lo >= 0) { out.write(hi * 16 + lo); i += 3 } else { out.write(b[i].toInt()); i++ }
            }
            return String(out.toByteArray(), Charsets.UTF_8)
        }
    }
}
