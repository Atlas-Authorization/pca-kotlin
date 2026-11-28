package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The strict profile refuses -0 wherever a wire integer is validated (mirrors the TS -0 sweep); 0 itself still passes. */
@Suppress("UNCHECKED_CAST")
class NegZeroSweepTest {
    private fun n(raw: String) = Json.Num(raw)

    @Test
    fun freshAtWireRefusesNegZero() {
        for (k in listOf("revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at")) {
            val t = linkedMapOf<String, Any?>("v" to n("1"), "scope" to "s", "policy_digest" to "d", "revocation_epoch" to n("0"),
                "ledger_tree_size" to n("0"), "budget_version" to n("0"), "policy_revision" to n("0"), "issued_at" to n("0"))
            assertFalse(k, FreshAt.validateWire(t).toString().contains("non-negative safe integer"))
            t[k] = n("-0")
            assertEquals(k, "'fresh_at.$k' must be a non-negative safe integer", FreshAt.validateWire(t))
        }
    }

    @Test
    fun ledgerConsistencyRefusesNegZeroSizes() {
        val e = Ledger.EMPTY_TREE_ROOT
        assertTrue(Ledger.verifyConsistency(e, e, mapOf("oldSize" to n("0"), "newSize" to n("0"), "path" to emptyList<Any?>())))
        assertFalse(Ledger.verifyConsistency(e, e, mapOf("oldSize" to n("-0"), "newSize" to n("0"), "path" to emptyList<Any?>())))
        assertFalse(Ledger.verifyConsistency(e, e, mapOf("oldSize" to n("0"), "newSize" to n("-0"), "path" to emptyList<Any?>())))
    }

    @Test
    fun revocationEpochRefusesNegZero() {
        for (k in listOf("epoch", "set_size", "issued_at", "not_after")) {
            val ep = linkedMapOf<String, Any?>("guardian" to "g", "instance_id" to "i", "grant_ref" to "r", "epoch" to n("0"), "set_size" to n("0"),
                "root" to "x", "issued_at" to n("0"), "not_after" to n("0"), "sig" to "s")
            assertNotEquals(k, "malformed revocation epoch", Revocation.checkEpoch(ep, "g", 0.0).reason)
            ep[k] = n("-0")
            assertEquals(k, "malformed revocation epoch", Revocation.checkEpoch(ep, "g", 0.0).reason)
        }
    }

    @Test
    fun settlementGuardianEpochRefusesNegZero() {
        val r = linkedMapOf<String, Any?>("claimId" to "c", "action" to "open", "amount" to n("5"), "from" to "a", "to" to "b", "at" to n("1"),
            "evidenceDigest" to "", "sig" to "s", "guardian_epoch" to n("0"))
        assertNotEquals("shape", Optimistic.settlementWireCheck(r, "g"))
        r["guardian_epoch"] = n("-0")
        assertEquals("shape", Optimistic.settlementWireCheck(r, "g"))
    }

    @Test
    fun grantArtifactIntegersRefuseNegZero() {
        assertTrue(K3Sig.isSafeInt(n("0")))
        assertFalse(K3Sig.isSafeInt(n("-0")))
    }

    @Test
    fun policyTemplateIntegerSlotsRefuseNegZero() {
        val def = (ParityVectors.load("policy-link-vectors.json")["template"] as Map<String, Any?>)["def"] as MutableMap<String, Any?>
        val r = PolicyAuthoring.instantiateTemplate(def, mapOf("acct" to "a42", "cap" to n("-0"), "region" to "eu", "verbs" to listOf("mail.send")))
        assertEquals("slot 'cap' must be a safe integer", r.reason)
        ((def["slots"] as MutableMap<String, Any?>)["cap"] as MutableMap<String, Any?>)["min"] = n("-0")
        assertEquals("slot 'cap'.min must be a safe integer", PolicyAuthoring.templateDefError(def))
    }
}
