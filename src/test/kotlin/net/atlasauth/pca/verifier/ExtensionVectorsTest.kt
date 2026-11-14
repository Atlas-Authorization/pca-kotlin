package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The extension layer of the conformance corpus (`optimistic-vectors.json`, `ledger-vectors.json`): every vector must reproduce the
 * reference verdict exactly. Nothing is skipped; each table's size must equal the file's `counts`.
 */
@Suppress("UNCHECKED_CAST")
class ExtensionVectorsTest {
    /** The row counts of the committed corpus, asserted against the REAL table sizes (not only the file's own `counts`). */
    private val expectedCounts = mapOf(
        "optimistic_claim" to 52, "optimistic_window" to 25, "optimistic_fraud_proof" to 37, "optimistic_settlement" to 102,
        "ledger_inclusion" to 96, "ledger_consistency" to 149, "ledger_tree_head" to 64, "ledger_cosign" to 56, "ledger_head_consistency" to 26,
        "ledger_checkpoint_chain" to 23, "ledger_witnessed_head" to 30, "ledger_equivocation" to 7,
    )

    private fun rows(doc: Map<String, Any?>, table: String): List<Map<String, Any?>> {
        val arr = doc[table] as? List<Map<String, Any?>> ?: throw AssertionError("$table: missing table")
        assertEquals("$table count", Json.asLong((doc["counts"] as Map<String, Any?>)[table]).toInt(), arr.size)
        assertEquals("$table real row count (pinned in this runner)", expectedCounts[table], arr.size)
        return arr
    }

    /** `requires_suite` names a registered suite beyond the core ones: an SDK that cannot verify it must refuse (false / check `suite`). */
    private fun lacks(v: Map<String, Any?>): Boolean = (v["requires_suite"] as? String)?.let { it !in Pq.supportedSuites() } ?: false

    private fun f(v: Any?): Double = IntentJs.num(v) ?: Double.NaN

    /** The verifier pin of a vector: `{pqPins: pins}` in the reference, i.e. the optional `pins` object. */
    private fun pins(v: Map<String, Any?>): Map<String, Any?>? = v["pins"] as? Map<String, Any?>

    private fun expectOk(v: Map<String, Any?>): Boolean = (v["expect"] as Map<String, Any?>)["ok"] as Boolean

    @Test
    fun optimisticVectors() {
        val doc = ParityVectors.load("optimistic-vectors.json")
        val wp = doc["window_policy"] as Map<String, Any?>
        val pol = Optimistic.ChallengeWindowPolicy(f(wp["minWindowMs"]), f(wp["maxWindowMs"]), f(wp["maxSkewMs"]))
        for (v in rows(doc, "optimistic_claim")) {
            val got = Optimistic.claimCheck(v["claim"], v["pcactn_digest"] as String, v["signer_public"] as String, f(v["server_now"]), pol)
            val exp = v["expect"] as Map<String, Any?>
            assertEquals("claim/${v["name"]}", exp["check"], got)
            assertEquals("claim/${v["name"]} ok", exp["ok"] as Boolean, got == "ok")
        }
        for (v in rows(doc, "optimistic_window")) {
            val i = f(v["issued_at"])
            val w = f(v["challenge_window_ms"])
            val now = f(v["now"])
            val exp = v["expect"] as Map<String, Any?>
            val name = "window/${v["name"]}"
            assertEquals(name, f(exp["end"]), Optimistic.challengeWindowEnd(i, w), 0.0)
            assertEquals(name, exp["within"] as Boolean, Optimistic.withinChallengeWindow(i, w, now))
            assertEquals(name, exp["phase"], Optimistic.claimStatus(i, w, now))
        }
        for (v in rows(doc, "optimistic_fraud_proof")) {
            assertEquals("fraud/${v["name"]}", (v["expect"] as Map<String, Any?>)["check"], Optimistic.fraudProofWireCheck(v["claim"], v["proof"]))
        }
        for (v in rows(doc, "optimistic_settlement")) {
            assertEquals("settlement/${v["name"]}", if (lacks(v)) "suite" else (v["expect"] as Map<String, Any?>)["check"], Optimistic.settlementWireCheck(v["record"], v["guardian_public"] as String, pins(v)))
        }
    }

    @Test
    fun ledgerVectors() {
        val doc = ParityVectors.load("ledger-vectors.json")
        assertEquals(Ledger.EMPTY_TREE_ROOT, doc["empty_tree_root"])
        val doms = doc["domains"] as Map<String, Any?>
        assertEquals(Ledger.STH_DOMAIN, doms["sth"])
        assertEquals(Ledger.STH_WITNESS_DOMAIN, doms["sth_witness"])
        assertEquals(Ledger.LEDGER_HEAD_DOMAIN, doms["ledger_head"])
        assertEquals(Optimistic.CLAIM_DOMAIN, doms["optimistic_claim"])
        assertEquals(Optimistic.SETTLEMENT_DOMAIN, doms["settlement"])
        fun chk(table: String, v: Map<String, Any?>, got: Boolean) = assertEquals("$table/${v["name"]}", expectOk(v) && !lacks(v), got)
        for (v in rows(doc, "ledger_inclusion")) chk("inclusion", v, Ledger.verifyInclusion(v["root"] as String, v["proof"], v["leaf"]))
        for (v in rows(doc, "ledger_consistency")) chk("consistency", v, Ledger.verifyConsistency(v["old_root"], v["new_root"], v["proof"]))
        for (v in rows(doc, "ledger_tree_head")) chk("tree_head", v, Ledger.verifyTreeHead(v["sth"], v["guardian_public"] as String, null, pins(v)))
        for (v in rows(doc, "ledger_cosign")) chk("cosign", v, Ledger.verifyTreeHead(v["sth"], v["guardian_public"] as String, v["policy"] as? Map<String, Any?>, pins(v)))
        for (v in rows(doc, "ledger_head_consistency")) chk("head_consistency", v, Ledger.verifyHeadConsistency(v["older"], v["newer"], v["proof"], v["guardian_public"] as String, null, pins(v)))
        for (v in rows(doc, "ledger_checkpoint_chain")) {
            val got = Ledger.verifyCheckpointChain(v["chain"], v["guardian_public"] as String, v["policy"] as? Map<String, Any?>, pins(v))
            val exp = v["expect"] as Map<String, Any?>
            assertEquals("chain/${v["name"]}", exp["ok"] as Boolean, got.ok)
            if (!got.ok) assertEquals("chain/${v["name"]} at", Json.asLong(exp["at"]).toInt(), got.at)
        }
        for (v in rows(doc, "ledger_witnessed_head")) chk("witnessed_head", v, Ledger.verifyWitnessedHead(v["head"], v["witness_public"] as String, pins(v)))
        for (v in rows(doc, "ledger_equivocation")) {
            assertEquals("equivocation/${v["name"]}", (v["expect"] as Map<String, Any?>)["equivocation"] as Boolean, Ledger.detectEquivocation(v["a"], v["b"], v["witness_public"] as String, pins(v)))
        }
    }

    /** The corpus carries accepted ML-DSA-65 and hybrid heads, so a stale file without PQ cases cannot pass silently. */
    @Test
    fun pqCasesArePresentAndAccepted() {
        val heads = rows(ParityVectors.load("ledger-vectors.json"), "ledger_tree_head")
        for (alg in listOf("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")) {
            val ok = heads.filter { ((it["sth"] as? Map<String, Any?>)?.get("alg")) == alg && expectOk(it) }
            assertTrue("accepted $alg tree head", ok.isNotEmpty())
            assertTrue("$alg verifies only with its pin", ok.all { it["pins"] != null && Ledger.verifyTreeHead(it["sth"], it["guardian_public"] as String, null, null).not() })
        }
    }

    /** Hostile shapes never throw, and the 32-bit-wrap and unsafe-size guards hold. */
    @Test
    fun hostileInputsNeverThrow() {
        val bad = listOf("null", "1", "\"x\"", "[]", "{}", "{\"size\":1e999}", "[null]", "{\"sth\":null,\"proof\":null}").map { ParityVectors.parse(it) }
        for (v in bad) {
            assertFalse(Ledger.verifyConsistency(v, v, v))
            assertFalse(Ledger.verifyTreeHead(v, "k", null))
            assertFalse(Ledger.verifyTreeHead(v, "k", linkedMapOf("threshold" to Json.Num("0"))))
            assertFalse(Ledger.verifyWitnessedHead(v, "k"))
            assertFalse(Ledger.verifyWitnessCosignature(v, v, "k"))
            assertFalse(Ledger.verifyHeadConsistency(v, v, v, "k", null))
            assertFalse(Ledger.detectEquivocation(v, v, "k"))
            assertFalse(Ledger.verifyCheckpointChain(v, "k", null).ok)
            assertFalse(Ledger.verifyInclusion("r", v, v))
            assertTrue(Optimistic.fraudProofWireCheck(v, v) != "ok")
            assertTrue(Optimistic.settlementWireCheck(v, "k") != "ok")
            assertTrue(Optimistic.claimCheck(v, "d", "k", 0.0) != "ok")
        }
    }

    @Test
    fun windowBoundaryAndNonFinite() {
        assertTrue(Optimistic.withinChallengeWindow(100.0, 50.0, 150.0))
        assertFalse(Optimistic.withinChallengeWindow(100.0, 50.0, 151.0))
        assertEquals("finalized", Optimistic.claimStatus(100.0, 50.0, 151.0))
        assertEquals("open", Optimistic.claimStatus(100.0, 50.0, 150.0))
        assertFalse(Optimistic.withinChallengeWindow(100.0, 50.0, Double.POSITIVE_INFINITY))
        assertFalse(Optimistic.withinChallengeWindow(100.0, 50.0, Double.NaN))
    }

    @Test
    fun emptyTreeConsistencyRules() {
        val empty = Ledger.EMPTY_TREE_ROOT
        fun proof(o: Long, n: Long) = ParityVectors.parse("{\"oldSize\":$o,\"newSize\":$n,\"path\":[]}")
        assertTrue(Ledger.verifyConsistency(empty, empty, proof(0, 0)))
        assertFalse(Ledger.verifyConsistency("other", empty, proof(0, 0)))
        assertTrue(Ledger.verifyConsistency(empty, "x", proof(0, 5))) // vacuous for a non-empty new tree
        assertFalse(Ledger.verifyConsistency(empty, empty, proof(3, 2)))
        // sizes 3 and 3 + 2^32 never collide
        assertFalse(Ledger.verifyConsistency("a", "b", ParityVectors.parse("{\"oldSize\":3,\"newSize\":4294967299,\"path\":[]}")))
    }
}
