package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The reputation input validator and the fail-closed edges of the score against the reference corpus (ref-reputation, 85 cases); reasons
 * compare exactly. The scoring, the coverage price and the signed coverage quote are replayed by CoreSweepReputationDiffTest. An input that
 * is not an object reads as an input without a subject, as in the reference.
 */
class ReputationRefDiffTest {
    private val mod = "ref-reputation"

    @Test fun everyFunction() {
        OracleCases.each(mod, "validateReputationInput") { x -> Reputation.validateReputationInput(OracleCases.decNum(x[0])) }
        OracleCases.each(mod, "reputation") { x -> Reputation.reputation(OracleCases.decNum(x[0])) }
        OracleCases.each(mod, "constants") { _ -> linkedMapOf<String, Any?>("MAX_REPUTATION_RECORDS" to Reputation.MAX_REPUTATION_RECORDS, "COVERAGE_QUOTE_DOMAIN" to Reputation.COVERAGE_QUOTE_DOMAIN) }
        val fns = setOf("validateReputationInput", "reputation", "constants")
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(85, fns.sumOf { OracleCases.of(mod, it).size })
    }

    /** The record cap is not in the corpus (it would be megabytes): exactly at it is accepted, one over it is refused. */
    @Test fun recordCap() {
        val ev = linkedMapOf<String, Any?>("agent" to "a", "outcome" to "auto")
        val events = ArrayList<Any?>()
        for (i in 0 until Reputation.MAX_REPUTATION_RECORDS) events.add(ev)
        assertEquals(null, Reputation.validateReputationInput(linkedMapOf("subject" to "s", "events" to events)))
        events.add(ev)
        assertEquals(true, Reputation.validateReputationInput(linkedMapOf("subject" to "s", "events" to events)) != null)
    }
}
