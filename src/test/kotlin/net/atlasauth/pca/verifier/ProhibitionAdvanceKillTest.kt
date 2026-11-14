package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Mutation kills for the monitor-state transition of the prohibition engine (`advanceStateStrict`, one branch per invariant kind) and for
 * the fatal-error rethrow of `Contracts.advanceContract`. Expected values follow packages/pca/src/prohibitions.ts `advanceStateStrictInner`.
 */
@Suppress("UNCHECKED_CAST")
class ProhibitionAdvanceKillTest {
    private fun n(v: Long) = IntentJs.ofLong(v)
    private fun o(vararg kv: Pair<String, Any?>): MutableMap<String, Any?> = linkedMapOf(*kv)

    private fun constitution(): Map<String, Any?> = o(
        "version" to n(1), "principal" to "p",
        "invariants" to listOf<Any?>(
            o("id" to "c1", "kind" to "cap", "when" to o("verb" to "pay"), "amount" to "action.params.n", "max" to n(100), "window_secs" to n(60)),
            o("id" to "r1", "kind" to "rate", "when" to o("verb" to "pay"), "max" to n(5), "window_secs" to n(60)),
            o("id" to "na", "kind" to "never_after", "after" to o("verb" to "close"), "forbid" to o("verb" to "pay")),
            o("id" to "rp", "kind" to "require_prior", "when" to o("verb" to "ship"), "prior" to o("verb" to "pay")),
            o("id" to "nv", "kind" to "never", "when" to o("verb" to "boom")),
        ),
    )

    private fun action(verb: String, amount: Long): Map<String, Any?> =
        o("action" to o("verb" to verb, "resource" to "acct", "params" to o("n" to n(amount))))

    private fun stateOf(r: Map<String, Any?>): Map<String, Any?> {
        assertEquals(r.toString(), true, r["ok"])
        return r["state"] as Map<String, Any?>
    }

    @Test fun eachInvariantKindAdvancesOnlyItsOwnPartOfTheState() {
        assertTrue(Prohibitions.validateConstitution(constitution()).toString(), Prohibitions.validateConstitution(constitution()).isEmpty())
        val s1 = stateOf(Prohibitions.advanceStateStrict(action("pay", 7), constitution(), Prohibitions.emptyState(n(1000)), n(2000)))
        assertEquals(1.0, Prohibitions.dv(s1["seq"]), 0.0)
        assertEquals(2000.0, Prohibitions.dv(s1["now"]), 0.0)
        // cap and rate keep a ledger row for the matching action (the cap row carries the resolved amount, the rate row counts one);
        // a never_after, a require_prior and a never invariant never write a ledger row
        val ledger1 = s1["ledger"] as Map<String, Any?>
        assertEquals(listOf("c1", "r1"), ledger1.keys.sorted())
        val cap = (ledger1["c1"] as List<Map<String, Any?>>).single()
        assertEquals(2000.0, Prohibitions.dv(cap["t"]), 0.0)
        assertEquals(7.0, Prohibitions.dv(cap["amount"]), 0.0)
        val rate = (ledger1["r1"] as List<Map<String, Any?>>).single()
        assertEquals(2000.0, Prohibitions.dv(rate["t"]), 0.0)
        assertEquals(1.0, Prohibitions.dv(rate["amount"]), 0.0)
        // the prerequisite was met by the payment and latches; the never_after trigger (a close) did not match
        val latched1 = s1["latched"] as Map<String, Any?>
        assertEquals(listOf("rp"), latched1.keys.sorted())
        assertEquals(2000.0, Prohibitions.dv(latched1["rp"]), 0.0)

        // a close latches the never_after invariant; the earlier rows stay (still inside their 60 s window) and rp is not re-latched
        val s2 = stateOf(Prohibitions.advanceStateStrict(action("close", 0), constitution(), s1, n(3000)))
        assertEquals(2.0, Prohibitions.dv(s2["seq"]), 0.0)
        val latched2 = s2["latched"] as Map<String, Any?>
        assertEquals(listOf("na", "rp"), latched2.keys.sorted())
        assertEquals(3000.0, Prohibitions.dv(latched2["na"]), 0.0)
        assertEquals(2000.0, Prohibitions.dv(latched2["rp"]), 0.0)
        val ledger2 = s2["ledger"] as Map<String, Any?>
        assertEquals(listOf("c1", "r1"), ledger2.keys.sorted())
        assertEquals(7.0, Prohibitions.dv((ledger2["c1"] as List<Map<String, Any?>>).single()["amount"]), 0.0)
        assertEquals(1, (ledger2["r1"] as List<Any?>).size)

        // a second payment after the window has passed drops the old rows and keeps only its own
        val s3 = stateOf(Prohibitions.advanceStateStrict(action("pay", 3), constitution(), s2, n(70_000)))
        val c3 = (s3["ledger"] as Map<String, Any?>)["c1"] as List<Map<String, Any?>>
        assertEquals(1, c3.size)
        assertEquals(3.0, Prohibitions.dv(c3.single()["amount"]), 0.0)
        assertEquals(70_000.0, Prohibitions.dv(c3.single()["t"]), 0.0)
    }

    // ---- the kind dispatch confirms the hash match with equals: a kind that reads as a valid kind while the constitution is
    // validated and as a different string of the same hashCode afterwards is NOT that kind (the reference compares the strings), so
    // the transition leaves that invariant's state untouched

    private fun kindFlip(base: Map<String, Any?>, sameHash: String): Map<String, Any?> = object : LinkedHashMap<String, Any?>(base) {
        var reads = 0
        override fun get(key: String): Any? = if (key == "kind" && reads++ > 0) sameHash else super.get(key)
    }

    @Test fun aKindThatOnlySharesTheHashOfAValidKindIsNotDispatchedAsIt() {
        val all = constitution()["invariants"] as List<Map<String, Any?>>
        for ((i, sameHash, verb) in listOf(Triple(0, "cbQ", "pay"), Triple(1, "rauF", "pay"), Triple(2, "never_aftfS", "close"), Triple(3, "require_pripS", "pay"))) {
            assertTrue(sameHash, (all[i]["kind"] as String).hashCode() == sameHash.hashCode() && all[i]["kind"] != sameHash)
            val c = o("version" to n(1), "principal" to "p", "invariants" to listOf<Any?>(kindFlip(all[i], sameHash)))
            val s = stateOf(Prohibitions.advanceStateStrict(action(verb, 7), c, Prohibitions.emptyState(n(1000)), n(2000)))
            assertEquals(sameHash, emptyMap<String, Any?>(), s["ledger"])
            assertEquals(sameHash, emptyMap<String, Any?>(), s["latched"])
        }
        // the control: the same invariants with a stable kind do write their state
        for ((i, verb) in listOf(0 to "pay", 2 to "close")) {
            val c = o("version" to n(1), "principal" to "p", "invariants" to listOf<Any?>(LinkedHashMap(all[i])))
            val s = stateOf(Prohibitions.advanceStateStrict(action(verb, 7), c, Prohibitions.emptyState(n(1000)), n(2000)))
            assertTrue(s.toString(), (s["ledger"] as Map<*, *>).isNotEmpty() || (s["latched"] as Map<*, *>).isNotEmpty())
        }
    }

    // ---- the fatal-error rethrow of the contract transition

    /** A state whose first read fails with the given error and which then behaves as an empty map. */
    private fun failingOnce(failure: Throwable): MutableMap<String, Any?> = object : LinkedHashMap<String, Any?>() {
        private var armed = true
        override fun get(key: String): Any? {
            if (armed) {
                armed = false
                throw failure
            }
            return super.get(key)
        }
    }

    @Test fun aFatalErrorWhileAdvancingAContractIsRethrown() {
        try {
            Contracts.advanceContract(failingOnce(InternalError("fatal")), null, null)
            fail("an InternalError must propagate")
        } catch (e: InternalError) {
            assertEquals("fatal", e.message)
        }
    }

    @Test fun anOrdinaryErrorWhileAdvancingAContractFailsClosed() {
        val r = Contracts.advanceContract(failingOnce(IllegalStateException("boom")), null, null)
        assertEquals(false, r["ok"])
        assertEquals("state", r["decidedBy"])
        assertTrue(r.toString(), (r["reasons"] as List<Any?>).contains("<state>: advance error (fail closed)"))
        assertFalse(r.toString(), (r["violated"] as List<Any?>).isEmpty())
    }
}
