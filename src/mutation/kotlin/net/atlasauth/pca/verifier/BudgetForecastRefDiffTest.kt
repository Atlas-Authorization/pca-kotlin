package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The budget forecaster against the reference corpus (ref-budget-forecast, 326 cases): forecast over the compiled policies of the simulator
 * fixtures (default, custom and empty catalogs), recommendPolicy and autonomyBoundOf with their edges. Every function, every case.
 */
@Suppress("UNCHECKED_CAST")
class BudgetForecastRefDiffTest {
    private val mod = "ref-budget-forecast"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    /** A corpus number as a double (a `{"$num": text}` wrapper decoded); anything that is not a number is NaN, which the function refuses. */
    private fun num(o: Any?): Double {
        val w = map(o)
        if (w != null && w.size == 1 && w["\$num"] is String) return Json.Num(w["\$num"] as String).let { IntentJs.num(it) ?: Double.NaN }
        return IntentJs.num(o) ?: Double.NaN
    }

    private fun out(d: Double): Any = when {
        d.isNaN() -> linkedMapOf<String, Any?>("\$num" to "NaN")
        d.isInfinite() -> linkedMapOf<String, Any?>("\$num" to (if (d > 0) "Infinity" else "-Infinity"))
        else -> StoreJs.num(d)
    }

    /** A `defineAction` row as the typed catalog row. */
    private fun specOf(row: Map<String, Any?>): Catalog.Spec = Catalog.Spec(
        row["connector"] as String, row["action"] as String, row["verb"] as String, row["reversibility"] as String, IntentJs.num(row["blastRadius"])!!,
        row["amountField"] as String?, (row["description"] as String?) ?: "", (row["aliases"] as List<Any?>?)?.map { it as String } ?: emptyList(),
        (row["traits"] as List<Any?>?)?.map { it as String } ?: emptyList(), row["resource"] as String?,
    )

    private fun compile(specO: Any?): Facade.CompiledPolicy {
        val s = map(specO)!!
        return Facade.compilePolicy(map(s["permissions"])!!, map(s["limits"]), null, s["budgetModel"] as String?, map(s["riskPolicy"]), IntentJs.num(s["now"])!!.toLong())
    }

    @Test fun everyFunction() {
        OracleCases.each(mod, "forecast") { x ->
            val plan = (x[1] as List<Any?>).map { map(it)!! }
            val cat = (x[3] as List<Any?>?)?.let { rows -> Catalog(rows.map { specOf(ActionCatalog.defineAction(it)) }) }
            BudgetForecast.forecast(compile(x[0]), plan, if (x[2] == null) null else num(x[2]), cat)
        }
        OracleCases.each(mod, "recommendPolicy") { x -> BudgetForecast.recommendPolicy(num(x[0]), num(x[1]), if (x[2] == null) null else num(x[2])) }
        OracleCases.each(mod, "autonomyBoundOf") { x ->
            val p = LinkedHashMap(map(x[0])!!)
            if (map(p["bMax"]) != null) p["bMax"] = Json.Num(num(p["bMax"]).let { AttestUtil.jsNumString(it) })
            out(BudgetForecast.autonomyBoundOf(p))
        }
        assertEquals(setOf("forecast", "recommendPolicy", "autonomyBoundOf"), BaseOracle.fns("$mod.json.gz"))
        assertEquals(326, setOf("forecast", "recommendPolicy", "autonomyBoundOf").sumOf { OracleCases.of(mod, it).size })
    }
}
