package net.atlasauth.pca.intent

import java.math.BigInteger
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the intent package's exact Clopper-Pearson, binomial, Hoeffding and Wilson numerics. */
@Suppress("UNCHECKED_CAST")
class IntentStatsDiffTest {
    private val m = "ref-intent-stats"

    private fun d(o: Any?): Double = o.toString().toDouble()
    private fun i(o: Any?): Int = d(o).toInt()
    private fun big(o: Any?): BigInteger = BigInteger((o as Map<String, Any?>)["\$bigint"] as String)
    private fun bigJ(b: BigInteger): Map<String, Any?> = linkedMapOf("\$bigint" to b.toString())

    /** A non-finite double is printed {"$num": "NaN"} by the reference. */
    private fun num(v: Double): Any = if (!v.isNaN() && !v.isInfinite()) v else linkedMapOf("\$num" to if (v.isNaN()) "NaN" else if (v > 0) "Infinity" else "-Infinity")

    @Test fun clopperPearsonUpper() = OracleCases.each(m, "clopperPearsonUpper") { a -> IntentStats.clopperPearsonUpper(d(a[0]), d(a[1]), d(a[2])) }

    @Test fun clopperPearsonCertified() = OracleCases.each(m, "clopperPearsonCertified") { a ->
        val c = IntentStats.clopperPearsonCertified(d(a[0]), d(a[1]), d(a[2]))
        linkedMapOf<String, Any?>("upper" to c.upper, "upperUnits" to bigJ(c.upperUnits), "lowerUnits" to bigJ(c.lowerUnits))
    }

    @Test fun binomialCdf() = OracleCases.each(m, "binomialCdf") { a -> IntentStats.binomialCdf(i(a[0]), i(a[1]), d(a[2])) }

    @Test fun doubleToDyadic() = OracleCases.each(m, "doubleToDyadic") { a ->
        val y = IntentStats.doubleToDyadic(d(a[0]))
        linkedMapOf<String, Any?>("num" to bigJ(y.num), "exp" to y.exp)
    }

    @Test fun cdfRecNumerator() = OracleCases.each(m, "cdfRecNumerator") { a -> bigJ(IntentStats.cdfRecNumerator(i(a[0]), i(a[1]), big(a[2]))) }

    @Test fun cdfExceeds() = OracleCases.each(m, "cdfExceeds") { a ->
        val al = a[3] as Map<String, Any?>
        IntentStats.cdfExceeds(i(a[0]), i(a[1]), big(a[2]), IntentStats.Dyadic(big(al["num"]), i(al["exp"])))
    }

    @Test fun hoeffdingHalfWidth() = OracleCases.each(m, "hoeffdingHalfWidth") { a ->
        num(if (a.size > 2) IntentStats.hoeffdingHalfWidth(d(a[0]), d(a[1]), d(a[2])) else IntentStats.hoeffdingHalfWidth(d(a[0]), d(a[1])))
    }

    @Test fun wilsonInterval() = OracleCases.each(m, "wilsonInterval") { a ->
        val w = if (a.size > 2) IntentStats.wilsonInterval(d(a[0]), d(a[1]), d(a[2])) else IntentStats.wilsonInterval(d(a[0]), d(a[1]))
        linkedMapOf<String, Any?>("p" to num(w.p), "lo" to num(w.lo), "hi" to num(w.hi))
    }
}
