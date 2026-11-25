package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of wallet-side provenance and within-grant regret. */
@Suppress("UNCHECKED_CAST")
class IntentProvenanceDiffTest {
    private val m = "ref-intent-provenance"
    private val prefix = "action.params."

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun amt(o: Outcome): Double = (o.values[prefix + "amount"] as? Double) ?: 0.0

    private fun admits(n: String): (Outcome) -> Boolean = when (n) {
        "all" -> ({ _ -> true })
        "none" -> ({ _ -> false })
        "amountLe50" -> ({ o -> amt(o) <= 50 })
        else -> ({ o -> o.verb == "stripe.refund" })
    }

    private fun utility(n: String): (Outcome) -> Double = when (n) {
        "amount" -> ({ o -> amt(o) })
        "negAmount" -> ({ o -> -amt(o) })
        "zero" -> ({ _ -> 0.0 })
        "nan" -> ({ _ -> Double.NaN })
        else -> ({ o -> amt(o) + (if ("bob" == o.values[prefix + "recipient"]) 1000 else 0) })
    }

    private fun bind(co: Any?): IntentProvenance.RegretCase {
        val c = mp(co)
        val feasible = IntentOmega.arr(c["feasible"]).map { IntentOmega.outcomeFromJson(it) }
        return IntentProvenance.RegretCase(feasible, IntentOmega.outcomeFromJson(c["chosen"]), admits(c["admits"] as String), utility(c["utility"] as String))
    }

    @Test fun provenanceBanner() = OracleCases.each(m, "provenanceBanner") { a ->
        IntentProvenance.provenanceBanner(a[0] as String?, if (a.size > 1) a[1] as String? else null)
    }

    @Test fun isTainted() = OracleCases.each(m, "isTainted") { a -> IntentProvenance.isTainted(a[0] as String?) }

    @Test fun provenanceFriction() = OracleCases.each(m, "provenanceFriction") { a ->
        IntentProvenance.provenanceFriction(a[0] as String?, a[1] as String?, a[2] as String?)
    }

    @Test fun regret() = OracleCases.each(m, "regret") { a -> IntentProvenance.withinGrantRegret(bind(a[0])) }

    @Test fun report() = OracleCases.each(m, "report") { a ->
        IntentProvenance.regretReport(IntentOmega.arr(a[0]).map { bind(it) }, if (a.size > 1) IntentOmega.dbl(a[1]) else 1.0)
    }
}
