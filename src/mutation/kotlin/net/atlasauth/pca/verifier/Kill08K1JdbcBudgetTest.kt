package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet

/**
 * Mutation kills for the budget table of PcaJdbcStateStore: every bound parameter and every read column of the select, insert and
 * compare-and-set statements, the NULL handling of `as_of`, and the closing of each statement and result set, observed through a
 * recording proxy over a real SQLite connection.
 */
class Kill08K1JdbcBudgetTest {
    private val log = ArrayList<String>()

    private fun call(target: Any, m: Method, a: Array<out Any?>?): Any? =
        try {
            m.invoke(target, *(a ?: arrayOf<Any?>()))
        } catch (e: InvocationTargetException) {
            throw e.targetException
        }

    private fun <T> proxy(iface: Class<T>, h: (Method, Array<out Any?>?) -> Any?): T =
        iface.cast(Proxy.newProxyInstance(javaClass.classLoader, arrayOf<Class<*>>(iface)) { _, m, a -> h(m, a) })

    private fun rows(raw: ResultSet): ResultSet = proxy(ResultSet::class.java) { m, a ->
        when (m.name) {
            "next", "wasNull" -> { log.add(m.name); call(raw, m, a) }
            "getDouble" -> { log.add("getDouble(${a!![0]})"); call(raw, m, a) }
            "close" -> { log.add("close rs"); call(raw, m, a) }
            else -> call(raw, m, a)
        }
    }

    private fun stmt(raw: PreparedStatement): PreparedStatement = proxy(PreparedStatement::class.java) { m, a ->
        when (m.name) {
            "setString", "setDouble", "setNull" -> { log.add("${m.name}(${a!!.joinToString(",")})"); call(raw, m, a) }
            "executeUpdate" -> { log.add("executeUpdate"); call(raw, m, a) }
            "executeQuery" -> { log.add("executeQuery"); rows(call(raw, m, a) as ResultSet) }
            "close" -> { log.add("close st"); call(raw, m, a) }
            else -> call(raw, m, a)
        }
    }

    private fun conn(raw: Connection): Connection = proxy(Connection::class.java) { m, a ->
        if (m.name == "prepareStatement") stmt(call(raw, m, a) as PreparedStatement).also { log.add("prepare") } else call(raw, m, a)
    }

    private fun store(): PcaJdbcStateStore {
        val path = AuthorizeTestKit.tempDb()
        return PcaJdbcStateStore(PcaJdbcStateStore.ConnectionSource { conn(AuthorizeTestKit.sqlite(path)) })
    }

    private fun <T> logged(f: () -> T): Pair<T, List<String>> {
        log.clear()
        val r = f()
        return Pair(r, ArrayList(log))
    }

    private fun b(B: Double, tau: Double, asOf: Double?) = Risk.Budget(B, tau, asOf)

    @Test fun theStoreIsSharedScope() {
        assertEquals(Authorize.SCOPE_SHARED, store().scope)
    }

    @Test fun budgetReadsThreeColumnsAndClosesItsStatementAndResultSet() {
        val s = store()
        val (none, l0) = logged { s.budget("k") }
        assertNull(none)
        assertEquals(listOf("prepare", "setString(1,k)", "executeQuery", "next", "close rs", "close st"), l0)
        assertTrue(logged { s.budgetCas("k", null, b(3.5, 2.0, null)) }.first)
        val (back, l1) = logged { s.budget("k") }
        assertEquals(b(3.5, 2.0, null), back)
        assertEquals(1, l1.count { it == "getDouble(1)" })
        assertEquals(1, l1.count { it == "getDouble(2)" })
        assertEquals(1, l1.count { it == "getDouble(3)" })
        assertEquals(1, l1.count { it == "wasNull" })
        assertEquals(1, l1.count { it == "close rs" })
        assertEquals(1, l1.count { it == "close st" })
        assertTrue(s.budgetCas("k", b(3.5, 2.0, null), b(3.5, 2.0, 7.25)))
        assertEquals(b(3.5, 2.0, 7.25), s.budget("k"))
    }

    @Test fun theInsertBindsKeyBudgetTauAndANullOrValuedAsOf() {
        val s = store()
        val (ok, l) = logged { s.budgetCas("k", null, b(3.5, 2.0, null)) }
        assertTrue(ok)
        assertEquals(listOf("prepare", "setString(1,k)", "setDouble(2,3.5)", "setDouble(3,2.0)", "setNull(4,8)", "executeUpdate", "close st"), l)
        val (ok2, l2) = logged { s.budgetCas("k2", null, b(1.5, 0.25, 9.0)) }
        assertTrue(ok2)
        assertEquals(listOf("prepare", "setString(1,k2)", "setDouble(2,1.5)", "setDouble(3,0.25)", "setDouble(4,9.0)", "executeUpdate", "close st"), l2)
        assertEquals(b(1.5, 0.25, 9.0), s.budget("k2"))
        // a row exists: an insert-style compare-and-set loses
        assertFalse(s.budgetCas("k", null, b(9.0, 9.0, null)))
        assertEquals(b(3.5, 2.0, null), s.budget("k"))
    }

    @Test fun theUpdateBindsNewValuesThenKeyThenTheOldValuesAndMatchesNullAsOfWithIsNull() {
        val s = store()
        assertTrue(s.budgetCas("k", null, b(3.5, 2.0, null)))
        // old as_of is NULL: six parameters, the NULL is matched by IS NULL
        val (ok, l) = logged { s.budgetCas("k", b(3.5, 2.0, null), b(4.0, 1.5, 7.0)) }
        assertTrue(ok)
        assertEquals(
            listOf("prepare", "setDouble(1,4.0)", "setDouble(2,1.5)", "setDouble(3,7.0)", "setString(4,k)", "setDouble(5,3.5)", "setDouble(6,2.0)", "executeUpdate", "close st"),
            l,
        )
        assertEquals(b(4.0, 1.5, 7.0), s.budget("k"))
        // old as_of has a value: a seventh parameter carries it; the new as_of is NULL
        val (ok2, l2) = logged { s.budgetCas("k", b(4.0, 1.5, 7.0), b(5.0, 1.0, null)) }
        assertTrue(ok2)
        assertEquals(
            listOf("prepare", "setDouble(1,5.0)", "setDouble(2,1.0)", "setNull(3,8)", "setString(4,k)", "setDouble(5,4.0)", "setDouble(6,1.5)", "setDouble(7,7.0)", "executeUpdate", "close st"),
            l2,
        )
        assertEquals(b(5.0, 1.0, null), s.budget("k"))
    }

    @Test fun aCompareAndSetWhoseOldValueDiffersFromTheRowLoses() {
        val s = store()
        assertTrue(s.budgetCas("k", null, b(3.5, 2.0, null)))
        assertFalse(s.budgetCas("k", b(3.5, 2.0, 1.0), b(1.0, 1.0, null))) // row has NULL as_of
        assertFalse(s.budgetCas("k", b(3.5, 9.0, null), b(1.0, 1.0, null)))
        assertFalse(s.budgetCas("k", b(9.5, 2.0, null), b(1.0, 1.0, null)))
        assertFalse(s.budgetCas("other", b(3.5, 2.0, null), b(1.0, 1.0, null)))
        assertEquals(b(3.5, 2.0, null), s.budget("k"))
        assertTrue(s.budgetCas("k", b(3.5, 2.0, null), b(1.0, 1.0, 4.0)))
        assertFalse(s.budgetCas("k", b(1.0, 1.0, null), b(2.0, 2.0, null))) // row has a value
        assertFalse(s.budgetCas("k", b(1.0, 1.0, 5.0), b(2.0, 2.0, null)))
        assertEquals(b(1.0, 1.0, 4.0), s.budget("k"))
    }
}
