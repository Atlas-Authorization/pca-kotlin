package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kill tests for FreshAt (k05 small group); reasons follow packages/pca/src/fresh-at.ts. */
class Kill05SmallFreshAtTest {
    private val label = "k05-fresh-at"
    private val signer = IntentTestKit.pub(label)
    private fun n(s: String) = Json.Num(s)

    private fun stateJson(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["revocation_epoch"] = n("1"); m["ledger_tree_size"] = n("2"); m["budget_version"] = n("3"); m["policy_revision"] = n("4"); m["policy_digest"] = "pd"
        for ((k, v) in over) m[k] = v
        return m
    }

    private fun token(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val t = LinkedHashMap<String, Any?>()
        t["v"] = n("1"); t["scope"] = "s"; t["revocation_epoch"] = n("1"); t["ledger_tree_size"] = n("2"); t["budget_version"] = n("3")
        t["policy_revision"] = n("4"); t["policy_digest"] = "pd"; t["issued_at"] = n("1000"); t["signer"] = signer
        for ((k, v) in over) t[k] = v
        t["sig"] = IntentTestKit.sign(label, IntentJs.message(FreshAt.DOMAIN, LinkedHashMap(t)))
        return t
    }

    @Test fun stateGettersAndCounters() {
        val s = FreshAt.State.fromJson(stateJson())
        assertNotNull(s)
        assertEquals(1L, s!!.revocationEpoch)
        assertEquals(2L, s.ledgerTreeSize)
        assertEquals(3L, s.budgetVersion)
        assertEquals(4L, s.policyRevision)
        assertEquals("pd", s.policyDigest)
        assertEquals(1L, s.counter("revocation_epoch"))
        assertEquals(2L, s.counter("ledger_tree_size"))
        assertEquals(3L, s.counter("budget_version"))
        assertEquals(4L, s.counter("policy_revision"))
    }

    @Test fun stateFromJsonRefusals() {
        assertNull(FreshAt.State.fromJson("x"))
        assertNull(FreshAt.State.fromJson(stateJson("revocation_epoch" to n("-1"))))
        assertNull(FreshAt.State.fromJson(stateJson("policy_revision" to n("1.5"))))
        assertNull(FreshAt.State.fromJson(stateJson("policy_digest" to n("5"))))
        assertNull(FreshAt.State.fromJson(stateJson().also { it.remove("policy_digest") }))
    }

    @Test fun policyFromJson() {
        val m = LinkedHashMap<String, Any?>()
        m["signer"] = signer; m["scope"] = "s"; m["local"] = stateJson(); m["max_token_age_ms"] = n("500"); m["require"] = true; m["side_carried"] = null
        val p = FreshAt.Policy.fromJson(m)
        assertNotNull(p)
        assertEquals(signer, p!!.signer)
        assertEquals("s", p.scope)
        assertEquals(4L, p.local.policyRevision)
        assertEquals(500L, p.maxTokenAgeMs)
        assertTrue(p.require)
        assertTrue(p.hasSideCarried)
        assertNull(p.sideCarried)
        assertNull(FreshAt.Policy.fromJson(LinkedHashMap(m).also { it["signer"] = n("1") }))
        assertNull(FreshAt.Policy.fromJson(LinkedHashMap(m).also { it["scope"] = n("1") }))
        assertNull(FreshAt.Policy.fromJson(LinkedHashMap(m).also { it["local"] = "x" }))
        assertNull(FreshAt.Policy.fromJson(LinkedHashMap(m).also { it["max_token_age_ms"] = "x" }))
        assertNull(FreshAt.Policy.fromJson(LinkedHashMap(m).also { it.remove("max_token_age_ms") })!!.maxTokenAgeMs)
    }

    @Test fun verifyRefusesASignedTokenWithABadCounter() {
        assertTrue(FreshAt.verify(token(), signer))
        assertFalse(FreshAt.verify(token("ledger_tree_size" to n("-1")), signer))
        assertFalse(FreshAt.verify(token("budget_version" to n("2.5")), signer))
    }

    @Test fun validateWireReasons() {
        val scopeMsg = "'fresh_at' scope and policy_digest must be non-empty strings"
        assertNull(FreshAt.validateWire(token()))
        assertNull(FreshAt.validateWire(token("scope" to "s".repeat(256))))
        assertEquals(scopeMsg, FreshAt.validateWire(token("scope" to "s".repeat(257))))
        assertEquals(scopeMsg, FreshAt.validateWire(token("scope" to "")))
        assertEquals(scopeMsg, FreshAt.validateWire(token("scope" to n("1"))))
        assertNull(FreshAt.validateWire(token("policy_digest" to "p".repeat(128))))
        assertEquals(scopeMsg, FreshAt.validateWire(token("policy_digest" to "p".repeat(129))))
        assertEquals(scopeMsg, FreshAt.validateWire(token("policy_digest" to "")))
        val bad = token(); bad["signer"] = "abc"
        assertEquals("'fresh_at.signer' is not canonical base64url (32 bytes)", FreshAt.validateWire(bad))
    }

    @Test fun decideReasons() {
        val local = FreshAt.State.fromJson(stateJson())!!
        val policy = FreshAt.Policy(signer, "s", local)
        val ok = FreshAt.decide(token(), true, policy, 1000L)
        assertEquals(FreshAt.Status.PASS, ok.status)
        val wrong = FreshAt.decide(token("scope" to "other"), true, policy, 1000L)
        assertEquals(FreshAt.Status.FAIL, wrong.status)
        assertEquals("wrong_scope", wrong.reason)
        // a token whose members cannot even be read fails closed as bad_token
        val throwing = object : LinkedHashMap<String, Any?>(token()) {
            override fun get(key: String): Any? = throw IllegalStateException("unreadable")
        }
        val r = FreshAt.decide(throwing, true, policy, 1000L)
        assertEquals(FreshAt.Status.FAIL, r.status)
        assertEquals("bad_token", r.reason)
    }
}
