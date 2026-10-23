package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.n
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for [Caveats] (PCA 0.4.1 policy-layer caveat evaluation). The TS reference (`envelopeCaveatEvaluator` in
 * predicates.ts + `max_spend` in agent-native.ts) is the oracle.
 *
 * Most of these mutants only turn a `false` verdict into a RuntimeException (NPE / ClassCastException on a missing or wrong-typed
 * field), which [Caveats.evaluateCaveats] swallows back into `false`. [Caveats.satisfied] is public and documented as total
 * ("false for anything malformed"), so the tests call it DIRECTLY: a mutant that throws fails the test.
 */
class CaveatsKillTest {
    private val NOW = n("1000")
    private fun sat(cv: Any?, ctx: Any?) = Caveats.satisfied(cv, ctx)
    private fun spendCtx(params: Any?) = m("action" to m("verb" to "pay", "params" to params))

    @Test fun nonMapCaveatOrContextIsUnsatisfiedWithoutThrowing() {
        val ok = m("type" to "budget_alloc", "limit" to n("1"))
        assertTrue(sat(ok, m("now" to NOW)))
        assertFalse(sat("budget_alloc", m("now" to NOW)))
        assertFalse(sat(l(ok), m("now" to NOW)))
        assertFalse(sat(null, m("now" to NOW)))
        assertFalse(sat(ok, "ctx"))
        assertFalse(sat(ok, l(NOW)))
        assertFalse(sat(ok, null))
    }

    @Test fun missingNowIsUnsatisfiedWithoutThrowing() {
        for (cv in listOf(m("type" to "expires", "at" to n("5")), m("type" to "not_before", "at" to n("0")),
                m("type" to "rate", "max" to n("1"), "per_secs" to n("1")), m("type" to "budget_alloc", "limit" to n("1"))))
            assertFalse("$cv", sat(cv, m("recent_action_times" to l())))
    }

    // ---- max_spend --------------------------------------------------------------------------------------

    @Test fun maxSpendZeroLimitAdmitsZeroAmount() {
        // usd >= 0 (not > 0): a zero cap admits exactly a zero amount
        assertTrue(sat(m("type" to "max_spend", "usd" to n("0")), spendCtx(m("amount" to n("0")))))
        assertFalse(sat(m("type" to "max_spend", "usd" to n("0")), spendCtx(m("amount" to n("0.01")))))
        assertTrue(sat(m("type" to "max_spend", "usd" to 0L), spendCtx(m("amount" to 0L))))
    }

    @Test fun maxSpendMalformedIsUnsatisfiedWithoutThrowing() {
        val good = m("amount" to n("5"))
        val cv = m("type" to "max_spend", "usd" to n("10"))
        assertTrue(sat(cv, spendCtx(good)))
        // limit absent / not a finite number
        assertFalse(sat(m("type" to "max_spend"), spendCtx(good)))
        assertFalse(sat(m("type" to "max_spend", "usd" to "10"), spendCtx(good)))
        assertFalse(sat(m("type" to "max_spend", "usd" to null), spendCtx(good)))
        // action / params absent or not objects
        assertFalse(sat(cv, m()))
        assertFalse(sat(cv, m("action" to "pay")))
        assertFalse(sat(cv, m("action" to l(good))))
        assertFalse(sat(cv, m("action" to m("verb" to "pay"))))
        assertFalse(sat(cv, spendCtx(null)))
        assertFalse(sat(cv, spendCtx("amount=5")))
        assertFalse(sat(cv, spendCtx(l(n("5")))))
        // amount absent / null / not a finite number
        assertFalse(sat(cv, spendCtx(m())))
        assertFalse(sat(cv, spendCtx(m("amount" to null))))
        assertFalse(sat(cv, spendCtx(m("amount" to "5"))))
        assertFalse(sat(cv, spendCtx(m("amount" to n("x")))))
        assertFalse(sat(cv, spendCtx(m("amount" to n("1e400")))))
    }

    // ---- fin: finite JSON numbers only ------------------------------------------------------------------

    @Test fun unparsableJsonNumberIsNotAZeroAndDoesNotThrow() {
        // a Json.Num whose raw text is not a number is absent, not 0: budget_alloc {limit: 0} would be satisfied
        assertFalse(sat(m("type" to "budget_alloc", "limit" to n("x")), m("now" to NOW)))
        assertTrue(sat(m("type" to "budget_alloc", "limit" to n("0")), m("now" to NOW)))
        assertFalse(sat(m("type" to "expires", "at" to n("x")), m("now" to NOW)))
        assertFalse(sat(m("type" to "expires", "at" to n("5000")), m("now" to n("x"))))
        assertFalse(sat(m("type" to "delegation_depth", "max" to n("x")), m("now" to NOW, "delegation_depth" to n("0"))))
    }

    @Test fun nanIsNotFinite() {
        // per_secs NaN: the TS `fin` refuses it; if accepted, lo = NaN admits no time and the count 0 < max passes
        val ctx = m("now" to NOW, "recent_action_times" to l(n("999")))
        assertTrue(sat(m("type" to "rate", "max" to n("2"), "per_secs" to n("1")), ctx))
        assertFalse(sat(m("type" to "rate", "max" to n("2"), "per_secs" to Double.NaN), ctx))
        assertFalse(sat(m("type" to "rate", "max" to n("2"), "per_secs" to Float.NaN), ctx))
        // now NaN: rate would otherwise pass the same way
        assertFalse(sat(m("type" to "rate", "max" to n("2"), "per_secs" to n("1")), m("now" to Double.NaN, "recent_action_times" to l())))
        assertFalse(sat(m("type" to "budget_alloc", "limit" to Double.NaN), m("now" to NOW)))
    }

    // ---- rate -------------------------------------------------------------------------------------------

    @Test fun rateWithNoRecentActionsAdmitsOne() {
        assertTrue(sat(m("type" to "rate", "max" to n("1"), "per_secs" to n("60")), m("now" to NOW, "recent_action_times" to l())))
        assertTrue(sat(m("type" to "rate", "max" to n("1"), "per_secs" to n("60")), m("now" to NOW, "recent_action_times" to ArrayList<Any?>())))
        assertFalse(sat(m("type" to "rate", "max" to n("0"), "per_secs" to n("60")), m("now" to NOW, "recent_action_times" to l())))
        assertEquals(Caveats.Result(true, listOf()),
            Caveats.evaluateCaveats(l(m("type" to "rate", "max" to n("1"), "per_secs" to n("1"))), m("now" to NOW, "recent_action_times" to l())))
    }

    @Test fun rateMalformedIsUnsatisfiedWithoutThrowing() {
        val ctx = m("now" to NOW, "recent_action_times" to l(n("999")))
        assertFalse(sat(m("type" to "rate", "per_secs" to n("1")), ctx))
        assertFalse(sat(m("type" to "rate", "max" to "2", "per_secs" to n("1")), ctx))
        assertFalse(sat(m("type" to "rate", "max" to n("2")), ctx))
        assertFalse(sat(m("type" to "rate", "max" to n("2"), "per_secs" to "1"), ctx))
        assertFalse(sat(m("type" to "rate", "max" to n("2"), "per_secs" to n("-1")), ctx))
        val cv = m("type" to "rate", "max" to n("2"), "per_secs" to n("1"))
        assertFalse(sat(cv, m("now" to NOW)))
        assertFalse(sat(cv, m("now" to NOW, "recent_action_times" to "999")))
        assertFalse(sat(cv, m("now" to NOW, "recent_action_times" to n("999"))))
        assertFalse(sat(cv, m("now" to NOW, "recent_action_times" to m("0" to n("999")))))
        assertFalse(sat(cv, m("now" to NOW, "recent_action_times" to linkedSetOf<Any?>(n("999")))))
    }

    // ---- max_blast_radius / delegation_depth --------------------------------------------------------------

    @Test fun blastRadiusAndDepthMissingFieldsAreUnsatisfiedWithoutThrowing() {
        for (type in listOf("max_blast_radius", "delegation_depth")) {
            val key = if (type == "max_blast_radius") "blast_radius" else "delegation_depth"
            assertTrue(type, sat(m("type" to type, "max" to n("3")), m("now" to NOW, key to n("3"))))
            assertFalse(type, sat(m("type" to type), m("now" to NOW, key to n("3"))))
            assertFalse(type, sat(m("type" to type, "max" to "3"), m("now" to NOW, key to n("3"))))
            assertFalse(type, sat(m("type" to type, "max" to n("3")), m("now" to NOW)))
            assertFalse(type, sat(m("type" to type, "max" to n("3")), m("now" to NOW, key to "3")))
            assertFalse(type, sat(m("type" to type), m("now" to NOW)))
        }
    }

    // ---- reversibility_max ------------------------------------------------------------------------------

    @Test fun reversibilityBoundariesAndUnknownClasses() {
        val rm = { lim: Any?, cur: Any? -> sat(m("type" to "reversibility_max", "class" to lim), m("now" to NOW, "reversibility_class" to cur)) }
        // the lowest class (index 0) on both sides is admitted
        assertTrue(rm("reversible", "reversible"))
        assertTrue(rm("irreversible", "reversible"))
        assertTrue(rm("irreversible", "irreversible"))
        assertFalse(rm("reversible", "irreversible"))
        // an unknown current class is refused even under the loosest limit; an unknown limit refuses everything
        assertFalse(rm("irreversible", "bogus"))
        assertFalse(rm("rate_limited", "Reversible"))
        assertFalse(rm("bogus", "reversible"))
        assertFalse(rm("bogus", "bogus"))
        assertFalse(rm("irreversible", null))
        assertFalse(rm(null, "reversible"))
    }

    // ---- evaluateCaveats: a throwing evaluation is unsatisfied --------------------------------------------

    @Test fun evaluationThatThrowsIsUnsatisfied() {
        // a context whose lookups throw: evaluateCaveats is total and reports the caveat as failed, never as satisfied
        val hostile = object : AbstractMap<String, Any?>() {
            override val entries: Set<Map.Entry<String, Any?>> get() = throw IllegalStateException("hostile context")
        }
        val cv = m("type" to "expires", "at" to n("5000"))
        assertEquals(Caveats.Result(false, listOf("expires")), Caveats.evaluateCaveats(l(cv), hostile))
        assertEquals(Caveats.Result(false, listOf("max_spend", "expires")),
            Caveats.evaluateCaveats(l(m("type" to "max_spend", "usd" to n("1")), cv), hostile))
    }
}
