package net.atlasauth.pca.verifier

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * k05 round-2 kills for the shard 14 / 17 / 18 groups (run 41911466407): ActionSchema's element checks, PcaDecision's
 * stack-overflow verdicts, the optimistic fraud-proof / settlement wire checks (string `when` arms under a colliding hash, the
 * r_margin clamp, evidence class, malformed decisions, split amounts), Bundle version order, StoreConformance with zero rounds and
 * the atomic KV stores. Expectations follow packages/pca/src (optimistic.ts, decision.ts, policy-bundle.ts, action-schema.ts).
 */
class Kill05R2StoreTest {
    private fun m(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = KUtil.m(*kv)
    private fun l(vararg v: Any?): ArrayList<Any?> = KUtil.l(*v)
    private fun n(s: String) = Json.Num(s)

    // ---- ActionSchema element checks

    @Test fun actionSchemaElementChecks() {
        fun allIn(xs: List<String>, vs: Collection<*>): Boolean = KUtil.priv(ActionSchema, "allIn", xs, vs)
        fun allStr(vs: Collection<*>): Boolean = KUtil.priv(ActionSchema, "allStr", vs)
        fun allTraitIds(vs: Collection<*>): Boolean = KUtil.priv(ActionSchema, "allTraitIds", vs)
        fun allEq(vs: Collection<*>, x: String): Boolean = KUtil.priv(ActionSchema, "allEq", vs, x)
        val tags = listOf("pii", "phi")
        assertTrue(allIn(tags, l("pii", "phi")))
        assertTrue(allIn(tags, l()))
        assertFalse(allIn(tags, l("pii", "x")))
        assertFalse(allIn(tags, l(5L, "pii")))
        assertFalse(allIn(tags, l(null)))
        assertTrue(allStr(l("a", "a".repeat(256))))
        assertTrue(allStr(l()))
        assertFalse(allStr(l("a", "a".repeat(257))))
        assertFalse(allStr(l("a", "")))
        assertFalse(allStr(l(5L, "a")))
        assertTrue(allTraitIds(l("a.b", "c.d")))
        assertTrue(allTraitIds(l()))
        assertFalse(allTraitIds(l("a.b", 5L)))
        assertFalse(allTraitIds(l(5L)))
        assertFalse(allTraitIds(l("A.b")))
        assertTrue(allEq(l("read", "read"), "read"))
        assertTrue(allEq(l(), "read"))
        assertFalse(allEq(l("read", "write"), "read"))
        assertFalse(allEq(l("write"), "read"))
    }

    // ---- PcaDecision: a stack overflow inside is a denial

    private class Throwing(val t: Throwable) : LinkedHashMap<String, Any?>() {
        override fun get(key: String): Any? = throw t
    }

    @Test fun aFailingCheckWithoutItsOwnReasonDenies() {
        val fail = mapOf("a" to "fail")
        assertEquals("deny", PcaDecision.decisionOf(false, fail, listOf("b: escalate: x")))
        assertEquals("escalate", PcaDecision.decisionOf(false, fail, listOf("b: other", "a: escalate: x")))
    }

    @Test fun stackOverflowVerdictsAreDenials() {
        val so = PcaDecision.decideTighten(Throwing(StackOverflowError()))
        assertEquals("deny", so.outcome)
        assertFalse(so.legacy)
        assertEquals(emptyList<String>(), so.offending)
        assertEquals("evaluation error (fail closed): unknown", so.reason)
        val u = PcaDecision.decideUnits(Throwing(StackOverflowError()))
        assertFalse(u.ok)
        assertEquals("evaluation error (fail closed): unknown", u.reason)
    }

    // ---- Optimistic fraud proofs

    private fun claim(cls: String = "reversible") =
        m("pcactn_digest" to "d", "bond_ref" to "b", "claimed_r" to n("0.5"), "reversibility_class" to cls)

    private fun proof(kind: String, rel: Any? = true, opt: Any? = true, r: String = "0.9"): LinkedHashMap<String, Any?> = m(
        "decision" to m("releaseGuardianShare" to rel, "optimisticAllowed" to opt, "r" to n(r)),
        "pcactn_digest" to "d", "bond_ref" to "b", "reason" to "x", "claimed_r" to n("0.5"), "kind" to kind,
    )

    @Test fun fraudProofKindsAreMatchedExactly() {
        // each kind holds for these inputs ...
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim("irreversible"), proof("irreversible")))
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim(), proof("policy-denied", rel = false)))
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim(), proof("optimistic-not-allowed", opt = false)))
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim(), proof("risk-understated")))
        // ... and a different kind with the same String.hashCode is no kind at all (the hash switch still compares the text)
        assertEquals("jSreversible".hashCode(), "irreversible".hashCode())
        assertEquals("kind", Optimistic.fraudProofWireCheck(claim("irreversible"), proof("jSreversible")))
        assertEquals("qPlicy-denied".hashCode(), "policy-denied".hashCode())
        assertEquals("kind", Optimistic.fraudProofWireCheck(claim(), proof("qPlicy-denied", rel = false)))
        assertEquals("pQtimistic-not-allowed".hashCode(), "optimistic-not-allowed".hashCode())
        assertEquals("kind", Optimistic.fraudProofWireCheck(claim(), proof("pQtimistic-not-allowed", opt = false)))
        assertEquals("sJsk-understated".hashCode(), "risk-understated".hashCode())
        assertEquals("kind", Optimistic.fraudProofWireCheck(claim(), proof("sJsk-understated")))
    }

    @Test fun riskMarginIsClampedAtZero() {
        val wide = proof("risk-understated")
        wide["r_margin"] = n("0.5") // 0.9 > 0.5 + 0.5 is false
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim(), wide))
        val negative = proof("risk-understated", r = "0.4")
        negative["r_margin"] = n("-1") // clamped to 0: 0.4 > 0.5 is false (unclamped, 0.4 > -0.5 would hold)
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim(), negative))
        val above = proof("risk-understated", r = "0.6")
        above["r_margin"] = n("-1")
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim(), above))
    }

    @Test fun malformedDecisionsAndEvidenceClass() {
        assertEquals("malformed", Optimistic.fraudProofWireCheck(claim(), proof("policy-denied", opt = "yes")))
        assertEquals("malformed", Optimistic.fraudProofWireCheck(claim(), proof("policy-denied", rel = "no")))
        val withEvidence = proof("irreversible")
        withEvidence["evidence"] = m("action" to m("action" to m("reversibility_class" to "irreversible")))
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim(), withEvidence))
        withEvidence["evidence"] = m("action" to m("action" to m("reversibility_class" to "reversible")))
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim(), withEvidence))
        withEvidence["evidence"] = m("action" to m("action" to m("reversibility_class" to 5L)))
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim(), withEvidence))
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim(), proof("irreversible")))
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim(5L.toString()), proof("irreversible")))
    }

    // ---- Optimistic settlement records

    private fun settlement(action: Any?, amount: Any?): LinkedHashMap<String, Any?> {
        val r = m("claimId" to "c", "from" to "f", "to" to "t", "at" to n("1"), "evidenceDigest" to "", "sig" to "s")
        if (action != null) r["action"] = action
        if (amount != null) r["amount"] = amount
        return r
    }

    @Test fun settlementShape() {
        assertEquals("signature", Optimistic.settlementWireCheck(settlement("open", n("10")), "g"))
        assertEquals("shape", Optimistic.settlementWireCheck(settlement("open", null), "g"))
        assertEquals("shape", Optimistic.settlementWireCheck(settlement(null, n("10")), "g"))
        assertEquals("shape", Optimistic.settlementWireCheck(settlement(5L, n("10")), "g"))
        assertEquals("shape", Optimistic.settlementWireCheck(settlement("open", n("0")), "g"))
    }

    @Test fun aSlashSplitNeedsNumericShares() {
        fun slash(reward: Any?): LinkedHashMap<String, Any?> {
            val r = settlement("slash", n("10"))
            r["evidenceDigest"] = "e"
            r["split"] = m(
                "amount" to n("10"), "challengerReward" to reward, "victimCompensation" to n("4"), "treasuryRemainder" to n("6"),
                "victimAccount" to "v", "treasuryAccount" to "t", "challengerAccount" to "c",
            )
            return r
        }
        assertEquals("signature", Optimistic.settlementWireCheck(slash(n("0")), "g"))
        assertEquals("split", Optimistic.settlementWireCheck(slash("x"), "g"))
        assertEquals("split", Optimistic.settlementWireCheck(slash(n("-1")), "g"))
    }

    // ---- Bundle version order

    @Test fun versionComponentsCompareAsNumbers() {
        assertEquals(0, Bundle.compareVersion("1.0", "1"))
        assertEquals(1, Bundle.compareVersion("1e-1", "0")) // Number("1e-1") is 0.1: a difference below 1 still orders
        assertEquals(-1, Bundle.compareVersion("0", "1e-1"))
        assertEquals(-1, Bundle.compareVersion("1.2", "1.10"))
    }

    // ---- StoreConformance: zero rounds race nothing

    @Test fun zeroRoundsRunNoRace() {
        val down = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult? = throw IllegalStateException("down")
        }
        val r = StoreConformance.runStateStore({ down }, durable = false, shared = true, threads = 1, rounds = 0, handles = 1)
        val byName = HashMap<String, StoreConformance.TestResult>()
        for (t in r.results) byName[t.test] = t
        assertEquals("fail", byName["claim-sequence"]!!.status)
        assertEquals("pass", byName["claim-burst"]!!.status)
        assertEquals("0 rounds x 1 threads", byName["claim-burst"]!!.note)
        assertEquals("pass", byName["claim-concurrent"]!!.status)
        assertEquals("0 rounds x 1 threads over 1 handles", byName["claim-concurrent"]!!.note)
    }

    // ---- atomic KV stores

    @Test fun memoryUpdateReturnsACopy() {
        val kv = MemoryAtomicKv()
        @Suppress("UNCHECKED_CAST")
        val got = kv.update("a") { m("x" to 1L) } as MutableMap<String, Any?>
        got["x"] = 2L
        assertEquals(m("x" to 1L), kv.get("a"))
    }

    @Test fun jdbcZeroAttemptsGivesUp() {
        val dir = Files.createTempDirectory("k05r2-kv")
        val kv = JdbcAtomicKv(PcaJdbcStateStore.sqliteConnections("jdbc:sqlite:${dir.resolve("kv0.db")}"), "kv0", true, 0)
        try {
            kv.update("k") { "v" }
            fail("no attempt may run")
        } catch (e: IllegalStateException) {
            assertEquals("JdbcAtomicKv.update: gave up after 0 contended attempts (fail closed)", e.message)
        }
        assertNull(kv.get("k"))
    }
}
