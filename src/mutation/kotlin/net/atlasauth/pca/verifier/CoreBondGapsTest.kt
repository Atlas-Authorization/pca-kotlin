package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The optimistic path's filing / game / snapshot side, the salted ledger commit, the intent-revocation helpers, the v2 goal parser, the
 * budget-allocation caveat and the insurance pool. The fixtures (grant, snapshots, claims, pcactns and the TS-filed fraud proofs) are
 * the ones the bond-settlement corpus carries, so a filed proof is compared with the reference's own.
 */
@Suppress("UNCHECKED_CAST")
class CoreBondGapsTest {
    private val module = "ref-core-bond-settlement-java"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private val fx: Map<String, Any?> by lazy {
        val all = LinkedHashMap<String, Any?>()
        for (c in OracleCases.of(module, "ledger")) all.putAll(m((c["args"] as List<Any?>)[0]))
        all
    }

    private fun same(what: String, want: Any?, got: Any?) {
        val g = IntentJs.normalize(OracleCases.toJson(got))
        assertTrue("$what\n  want: ${Json.canonicalize(want)}\n  got:  ${Json.canonicalize(g)}", IntentJs.jsonEquals(want, g))
    }

    @Test fun fileFraudProofMatchesTheReference() {
        // (claim, pcactn name, snapshot name) -> the proof the reference filed for it
        val specs = listOf(
            Triple("low", "low", "ok"), Triple("deny", "deny", "deny"), Triple("irr", "irr", "irr"), Triple("high", "high", "high"),
            Triple("mid-low", "mid-low", "mid"), Triple("ok-hi", "ok-hi", "ok"),
        )
        var checked = 0
        for ((c, p, s) in specs) {
            val want = fx["proof_$c"]
            val claim = fx["claim_$c"]
            val pc = fx["pc_$p"]
            val snap = fx["snap_$s"]
            if (want == null || claim == null || pc == null || snap == null) continue
            same("fileFraudProof $c", want, OptimisticAdjudication.fileFraudProof(m(claim), m(pc), m(fx["grant"]), m(snap)))
            checked++
        }
        assertTrue("the corpus fixtures cover fileFraudProof ($checked)", checked >= 4)
    }

    @Test fun fileFraudProofRefusesWhatIsNotFraud() {
        val grant = m(fx["grant"])
        // no proof without the frozen snapshot, none for an action the claim does not cover
        assertNull(OptimisticAdjudication.fileFraudProof(m(fx["claim_low"]), m(fx["pc_low"]), grant, null))
        assertNull(OptimisticAdjudication.fileFraudProof(m(fx["claim_low"]), m(fx["pc_deny"]), grant, m(fx["snap_ok"])))
    }

    @Test fun filedProofIsVerifiedAndAHonestOneIsNot() {
        val grant = m(fx["grant"])
        val v = OptimisticAdjudication.verifyFraudProof(m(fx["claim_low"]), OptimisticAdjudication.fileFraudProof(m(fx["claim_low"]), m(fx["pc_low"]), grant, m(fx["snap_ok"])), grant, fx["snap_ok"])
        assertEquals(true, v["fraudulent"])
        assertEquals(m(fx["claim_low"])["bond_ref"], v["slashBondRef"])
    }

    private fun oracle(input: String, value: Double): OptimisticAdjudication.ObjectiveOracle =
        OptimisticAdjudication.ObjectiveOracle { i, _ -> if (i == input) linkedMapOf<String, Any?>("input" to input, "value" to Json.Num(AttestUtil.jsNumString(value)), "valid" to true) else null }

    private fun step(v: Double): Map<String, Any?> = linkedMapOf("value" to Json.Num(AttestUtil.jsNumString(v)))

    private fun game(vararg steps: String, defender: List<Double>, challenger: List<Double>): Map<String, Any?> {
        val c = m(fx["claim_ok"])
        return linkedMapOf(
            "pcactn_digest" to c["pcactn_digest"], "bond_ref" to c["bond_ref"], "steps" to steps.toList(),
            "defender" to defender.map { step(it) }, "challenger" to challenger.map { step(it) },
        )
    }

    @Test fun oneStepGameIsTheOneShotDispute() {
        val claim = m(fx["claim_ok"])
        val grant = m(fx["grant"])
        val snap = fx["snap_ok"]
        val g = game("blastRadius", defender = listOf(0.1), challenger = listOf(0.95))
        val r = OptimisticAdjudication.adjudicateDisputeGame(claim, g, grant, snap, oracle("blastRadius", 0.95))
        assertEquals(true, r["converged"])
        assertEquals(0.0, IntentJs.num(r["rounds"]))
        assertEquals(0.0, IntentJs.num(r["contestedStep"]))
        val direct = OptimisticAdjudication.adjudicateDispute(
            claim, linkedMapOf("pcactn_digest" to claim["pcactn_digest"], "bond_ref" to claim["bond_ref"], "input" to "blastRadius", "asserted_value" to step(0.95)["value"]),
            grant, snap, oracle("blastRadius", 0.95),
        )
        same("verdict", IntentJs.normalize(OracleCases.toJson(direct)), m(r["verdict"]))
        assertEquals("agent-fraud", m(r["verdict"])["outcome"])
    }

    @Test fun bisectionLocalizesTheFirstDivergentStep() {
        val claim = m(fx["claim_ok"])
        val g = game("semanticDistance", "blastRadius", defender = listOf(0.2, 0.1), challenger = listOf(0.2, 0.95))
        val r = OptimisticAdjudication.adjudicateDisputeGame(claim, g, m(fx["grant"]), fx["snap_ok"], oracle("blastRadius", 0.95))
        assertEquals(true, r["converged"])
        assertEquals(1.0, IntentJs.num(r["contestedStep"]))
        assertEquals("blastRadius", r["contestedInput"])
        assertEquals(1.0, IntentJs.num(r["rounds"]))
        assertEquals("agent-fraud", m(r["verdict"])["outcome"])
    }

    @Test fun gameFailsClosed() {
        val claim = m(fx["claim_ok"])
        val grant = m(fx["grant"])
        val snap = fx["snap_ok"]
        val good = game("blastRadius", defender = listOf(0.1), challenger = listOf(0.95))
        val cases = listOf(
            "malformed" to OptimisticAdjudication.adjudicateDisputeGame(claim, "x", grant, snap, oracle("blastRadius", 0.95)),
            "no oracle" to OptimisticAdjudication.adjudicateDisputeGame(claim, good, grant, snap, null),
            "no snapshot" to OptimisticAdjudication.adjudicateDisputeGame(claim, good, grant, null, oracle("blastRadius", 0.95)),
            "identical traces" to OptimisticAdjudication.adjudicateDisputeGame(claim, game("blastRadius", defender = listOf(0.1), challenger = listOf(0.1)), grant, snap, oracle("blastRadius", 0.95)),
            "short trace" to OptimisticAdjudication.adjudicateDisputeGame(claim, game("blastRadius", "semanticDistance", defender = listOf(0.1), challenger = listOf(0.95)), grant, snap, oracle("blastRadius", 0.95)),
            "other bond" to OptimisticAdjudication.adjudicateDisputeGame(claim, LinkedHashMap(good).also { it["bond_ref"] = "elsewhere" }, grant, snap, oracle("blastRadius", 0.95)),
        )
        for ((name, r) in cases) {
            assertEquals(name, false, r["converged"])
            assertEquals(name, -1.0, IntentJs.num(r["contestedStep"]))
            val v = m(r["verdict"])
            assertEquals(name, "indeterminate", v["outcome"])
            assertEquals(name, false, v["fraudulent"])
            assertEquals(name, false, v["slashCounterBond"])
        }
    }

    @Test fun frozenSnapshotSharesNothingWithItsSource() {
        val src = LinkedHashMap(m(fx["snap_ok"]))
        val frozen = OptimisticAdjudication.freezeOpenSnapshot(src)
        same("frozen", IntentJs.normalize(OracleCases.toJson(src)), frozen)
        (src["risk"] as MutableMap<String, Any?>)["blastRadius"] = Json.Num("0.9")
        assertFalse(IntentJs.jsonEquals(IntentJs.normalize(OracleCases.toJson(src)), IntentJs.normalize(OracleCases.toJson(frozen))))
    }

    @Test fun entryCommitAndOpening() {
        val pc = m(fx["pc_ok"])
        val commit = Ledger.entryCommit("salt-1", pc)
        assertTrue(Ledger.verifyOpening(commit, linkedMapOf("salt" to "salt-1", "pcactn" to pc)))
        assertFalse(Ledger.verifyOpening(commit, linkedMapOf("salt" to "salt-2", "pcactn" to pc)))
        assertFalse(Ledger.verifyOpening(commit, linkedMapOf("salt" to "salt-1", "pcactn" to m(fx["pc_deny"]))))
        assertFalse(Ledger.verifyOpening(commit, linkedMapOf("salt" to "salt-1")))
        assertFalse(Ledger.verifyOpening(commit, null))
        assertFalse(Ledger.verifyOpening(commit, "x"))
    }

    @Test fun ledgerRootOfCommitSequences() {
        assertEquals(Ledger.EMPTY_TREE_ROOT, Ledger.ledgerRootOf(emptyList()))
        for (n in 1..9) {
            val commits = (0 until n).map { "c$it" }
            assertEquals("n=$n", MerkleLog.of(commits).root(), Ledger.ledgerRootOf(commits))
        }
    }

    @Test fun revocationHelpers() {
        assertEquals("pca-intent-profile:p1", IntentRevocation.profileRevocationScope("p1"))
        assertEquals(60, IntentRevocation.DEFAULT_REVOCATION_MAX_AGE_S["payment"])
        assertEquals(300, IntentRevocation.DEFAULT_REVOCATION_MAX_AGE_S["default"])
        assertEquals(1000.0 + 300_000.0 + 60_000.0, IntentRevocation.revocationExposureEnd(1000.0, 300_000.0), 0.0)
        assertEquals(1000.0 + 5.0 + 7.0, IntentRevocation.revocationExposureEnd(1000.0, 5.0, 7.0), 0.0)
    }

    @Test fun intentGoalV2Parses() {
        val s = Pca.b64(ByteArray(32) { 1 })
        val d = Pca.b64(ByteArray(32) { 2 })
        val p = IntentSession.parseIntentGoalV2(IntentSession.intentGoalV2(s, d))
        assertNotNull(p)
        assertEquals(s, p!!["session"])
        assertEquals(d, p["mapDigest"])
        assertNull(IntentSession.parseIntentGoalV2(IntentSession.intentGoalV2c(s, d)))
        assertNull(IntentSession.parseIntentGoalV2(IntentSession.intentGoalV2(s, d) + ":x"))
        assertNull(IntentSession.parseIntentGoalV2(IntentSession.intentGoalV2(s, "short")))
        assertNull(IntentSession.parseIntentGoalV2(null))
        assertNull(IntentSession.parseIntentGoalV2("pca-intent:v1:x"))
    }

    @Test fun budgetAllocCaveat() {
        assertEquals("budget_alloc", Pca.BUDGET_ALLOC_CAVEAT)
        val cv = Pca.budgetAllocCaveat(5.0)
        assertEquals("budget_alloc", cv["type"])
        assertTrue(Pca.isBudgetAllocCaveat(cv))
        assertFalse(Pca.isBudgetAllocCaveat(Pca.budgetAllocCaveat(-1.0)))
    }

    @Test fun insurancePoolNeverPaysWhatItDoesNotHold() {
        val pool = InsuranceCapitalPool(100.0)
        assertEquals(100.0, pool.balance(), 0.0)
        pool.collectPremium(linkedMapOf("premium" to Json.Num("5"), "declined" to false))
        pool.collectPremium(linkedMapOf("premium" to Json.Num("9"), "declined" to true)) // a declined quote credits nothing
        assertEquals(105.0, pool.balance(), 0.0)
        assertTrue(pool.canCover(105.0))
        assertFalse(pool.canCover(105.5))
        val st = pool.payClaim(30.0)
        assertEquals(75.0, IntentJs.num(st["balance"]))
        try {
            pool.payClaim(75.5)
            fail("an overdraw must be refused")
        } catch (e: IllegalStateException) {
            assertEquals(75.0, pool.balance(), 0.0)
        }
        for (bad in doubleArrayOf(0.0, -1.0, Double.NaN, Double.POSITIVE_INFINITY)) {
            try { pool.payClaim(bad); fail("payClaim($bad)") } catch (e: IllegalStateException) { /* refused */ }
        }
        try { InsuranceCapitalPool(-1.0); fail("a negative opening balance") } catch (e: IllegalStateException) { /* refused */ }
    }
}
