package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the legacy-vocabulary shims. */
@Suppress("UNCHECKED_CAST")
class ActionsCompatDiffTest {
    private val M = "ref-actions-compat"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun num(o: Any?): Double = IntentJs.num(o)!!

    @Test fun normalizeReversibility() = OracleCases.each(M, "normalizeReversibility") { a -> ActionCompat.normalizeReversibility(a[0]) }

    @Test fun legacyOperationsClass() = OracleCases.each(M, "legacyOperationsClass") { a -> ActionCompat.legacyOperationsClass(a[0] as String) }

    @Test fun maxRevOf() = OracleCases.each(M, "maxRevOf") { a -> ActionCompat.maxRevOf(a[0] as String, a[1] as String) }

    @Test fun unitTagOf() = OracleCases.each(M, "unitTagOf") { a -> ActionCompat.unitTagOf(m(a[0])) }

    @Test fun blastOfFloat() = OracleCases.each(M, "blastOfFloat") { a -> ActionCompat.blastOfFloat(num(a[0])) }

    @Test fun blastExactOfFloat() = OracleCases.each(M, "blastExactOfFloat") { a -> ActionCompat.blastExactOfFloat(num(a[0])) }

    @Test fun fromCatalogSpec() = OracleCases.each(M, "fromCatalogSpec") { a -> ActionCompat.fromCatalogSpec(m(a[0]), if (a.size > 1) m(a[1]) else null) }

    @Test fun fromCatalog() = OracleCases.each(M, "fromCatalog") { a -> ActionCompat.fromCatalog(l(a[0]), if (a.size > 1) m(a[1]) else null) }
}
