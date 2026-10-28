package net.atlasauth.pca.verifier

import java.sql.Connection
import java.sql.SQLException
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
 */
class PcaJdbcStateStore @JvmOverloads constructor(
    private val connections: ConnectionSource,
    val table: String = DEFAULT_TABLE,
    createTable: Boolean = true,
) : Authorize.StateStore, Authorize.LastStore {
    /** Opens a JDBC connection for one claim; the store closes it. */
    fun interface ConnectionSource {
        @Throws(SQLException::class)
        fun open(): Connection
    }

    @JvmOverloads
    constructor(dataSource: DataSource, table: String = DEFAULT_TABLE, createTable: Boolean = true) :
        this(ConnectionSource { dataSource.connection }, table, createTable)

    private val upsert: String
    private val select: String
    private val onceTable: String
    private val onceUpsert: String
    private val onceExtend: String

    init {
        require(IDENT.matches(table)) { "table must be a plain SQL identifier" }
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
        if (n == 1) Authorize.ClaimResult(true)
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

    private fun <T> withConnection(fn: (Connection) -> T): T = connections.open().use { c ->
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
    }
}
