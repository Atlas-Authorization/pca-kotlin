package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the reference oracle of the connector action catalog (75 cases, every fn dispatched): defineAction, uncataloguedSpec, the
 * built-in rows with their digest, and catalog scenarios (lookup, alias resolution, the fail-closed resolveAction, the digest pin and
 * the no-downgrade extension). In a scenario an op that throws is {"$err": true} on both sides.
 */
@Suppress("UNCHECKED_CAST")
class ActionCatalogDiffTest {
    private val mod = "ref-catalog"

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    private fun scenario(actions: List<Any?>?, ops: List<Any?>): List<Any?> {
        val cat = ActionCatalog.buildCatalog(actions)
        fun one(op: List<Any?>): Any? = when (op[0] as String) {
            "get" -> cat.get(arg(op, 1))
            "forConnector" -> cat.forConnector(arg(op, 1))
            "all" -> cat.all()
            "resolve" -> cat.resolve(arg(op, 1), arg(op, 2))
            "resolveAction" -> ActionCatalog.resolveAction(cat, op[1] as String)
            "digest" -> ActionCatalog.catalogDigest(cat)
            "assertPinned" -> { ActionCatalog.assertCatalogPinned(cat, if (op[1] == "\$self") ActionCatalog.catalogDigest(cat) else op[1]); true }
            "extend" -> ActionCatalog.extendCatalog(cat, op[1] as List<Any?>).let { linkedMapOf("all" to it.all(), "digest" to ActionCatalog.catalogDigest(it)) }
            else -> throw IllegalStateException("op")
        }
        return ops.map { op ->
            try {
                one(op as List<Any?>)
            } catch (e: RuntimeException) {
                linkedMapOf<String, Any?>("\$err" to true)
            }
        }
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "defineAction" -> ActionCatalog.defineAction(arg(a, 0))
        "uncataloguedSpec" -> ActionCatalog.uncataloguedSpec(a[0] as String)
        "builtin" -> linkedMapOf(
            "actions" to ActionCatalog.BUILTIN_ACTIONS, "digest" to ActionCatalog.catalogDigest(ActionCatalog.DEFAULT_CATALOG), "blast" to ActionCatalog.BLAST,
        )
        "catalog" -> scenario(arg(a, 0) as List<Any?>?, a[1] as List<Any?>)
        else -> throw AssertionError("unhandled fn $fn")
    }

    private val handled = setOf("defineAction", "uncataloguedSpec", "builtin", "catalog")

    @Test fun replayAllCases() {
        assertEquals(handled, BaseOracle.fns("$mod.json.gz"))
        var total = 0
        val bad = ArrayList<String>()
        for (fn in handled) for (c in OracleCases.of(mod, fn)) {
            total++
            OracleCases.diff(c, c["out"]) { a -> call(fn, OracleCases.decNum(a) as List<Any?>) }?.let { bad.add(it) }
        }
        assertEquals(75, total)
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    /** The typed catalog and the JSON one are the same rows. */
    @Test fun theBuiltInRowsAreTheTypedCatalog() {
        assertEquals(Catalog.DEFAULT.all().map { it.verb }, ActionCatalog.DEFAULT_CATALOG.all().map { it["verb"] })
        assertEquals(false, ActionCatalog.resolveAction(ActionCatalog.DEFAULT_CATALOG, "stripe.unknown")["catalogued"])
    }
}
