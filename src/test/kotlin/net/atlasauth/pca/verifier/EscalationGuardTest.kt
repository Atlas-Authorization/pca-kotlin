package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * `authorize` and the ternary decision: an escalate-class verdict is `escalate` (refused, with the request), admitted only by a
 * signed answer bound to this grant, this PCActn and the holder's history; the replay claim spends it; an answer never
 * upgrades a deny. The escalate-class failure is injected through the module-internal [Authorize.coreHook].
 */
@Suppress("UNCHECKED_CAST")
class EscalationGuardTest {
    private val principal: Map<String, Any?> by lazy { (ParityVectors.load("keys.json")["principal"]) as Map<String, Any?> }
    private val seed: ByteArray get() = Pca.decodeB64uStrict(principal["seed"], 32)!!
    private val pub: String get() = principal["public"] as String
    private val c = case("envelope-predicate-within")

    @After
    fun reset() { Authorize.coreHook = null }

    private fun inject(check: String, reason: String?) {
        Authorize.coreHook = { core ->
            core.checks[check] = false
            if (reason != null) core.reasons.add("$check: $reason")
            core.allow = false
        }
    }

    private fun sign(over: Map<String, Any?> = emptyMap(), last: Long? = null, pc: Map<String, Any?> = pcactn(c), g: Map<String, Any?> = grant(c)): Map<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        body["v"] = IntentJs.ofLong(1)
        body["kind"] = "pca-escalation-answer"
        body["principal"] = pub
        body["policy_digest"] = Escalation.policyDigest(g)
        body["action_digest"] = Escalation.actionDigest(pc)
        body["history_head"] = Escalation.historyHead(last)
        body["decision"] = "allow"
        body["iat"] = IntentJs.ofLong(AuthorizeTestKit.NOW - 1000)
        body["expires_at"] = IntentJs.ofLong(AuthorizeTestKit.NOW + 600_000)
        body["nonce"] = "CQkJCQkJCQkJCQkJCQkJCQ"
        for ((k, v) in over) body[k] = v
        val msg = IntentArtifacts.artifactMessage(Escalation.ANSWER_DOMAIN, body)
        val sig = ByteArray(64)
        Ed25519.sign(seed, 0, msg, 0, msg.size, sig, 0)
        body["sig"] = Pca.b64(sig)
        return body
    }

    private fun run(answer: Any?, store: Authorize.StateStore = Authorize.MemoryStateStore(), principals: List<Escalation.Principal> = listOf(Escalation.Principal(pub)), insecure: Boolean = true) =
        Authorize.authorize(
            pcactn(c),
            Authorize.Input(
                operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) }, stateStore = store,
                isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP,
                escalationPrincipals = principals, escalationAnswer = answer, insecureUnboundApproval = insecure,
            ),
        )

    @Test
    fun unboundApprovalIsRefusedByDefault() {
        inject("provenance", "intent_required: q")
        try {
            val r = run(sign(), insecure = false)
            assertFalse(r.allow)
            assertTrue(r.reasons.toString(), r.reasons.any { it.contains("approval render is required") })
            assertTrue(run(sign()).allow)
        } finally {
            Authorize.coreHook = null
        }
    }

    @Test
    fun withoutInjectionTheFixtureIsAnAllow() {
        val r = run(null)
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals("allow", r.decision)
        assertNull(r.escalation)
    }

    @Test
    fun escalateIsRefusedWithTheRequestAndNeverAllow() {
        inject("provenance", "intent_required: a question")
        val r = run(null)
        assertFalse(r.allow)
        assertEquals("escalate", r.decision)
        assertEquals(403, r.status)
        val req = r.escalation!!
        assertEquals("pca-escalation-request", req["kind"])
        assertEquals(Escalation.policyDigest(grant(c)), req["policy_digest"])
        assertEquals(Escalation.actionDigest(pcactn(c)), req["action_digest"])
        assertEquals(Escalation.historyHead(null), req["history_head"])
        assertEquals(AuthorizeTestKit.AUD, req["aud"])
        assertTrue((req["reasons"] as List<*>).any { it.toString() == "provenance: intent_required: a question" })
        assertEquals(IntentJs.ofLong(AuthorizeTestKit.NOW + 3_600_000), req["expires_at"])
        assertEquals("fail", r.checks["provenance"])
    }

    @Test
    fun aBoundAnswerAdmitsOnceAndTheCounterSpendsIt() {
        inject("provenance", "intent_required: q")
        val store = Authorize.MemoryStateStore()
        val a = sign()
        val ok = run(a, store)
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("allow", ok.decision)
        assertEquals(pub, ok.escalation!!["answered_by"])
        assertEquals("pass", ok.checks["escalation"])
        assertEquals("pass", ok.checks["provenance"])
        assertTrue(ok.reasons.contains("escalation: answered allow by principal ${pub.take(8)}"))
        val again = run(a, store)
        assertFalse(again.allow)
        assertEquals("escalate", again.decision) // the counter was spent: the answer is bound to the OLD history head
        assertTrue(again.reasons.toString(), again.reasons.any { it.contains("another state of the history") })
    }

    @Test
    fun answersThatDoNotBindAreRefusedAndStayEscalate() {
        inject("provenance", "intent_required: q")
        fun refused(a: Any?, why: String) {
            val r = run(a)
            assertFalse(why, r.allow)
            assertEquals(why, "escalate", r.decision)
            assertTrue("$why ${r.reasons}", r.reasons.any { it.startsWith("escalation: ") && it.contains(why) })
        }
        refused(sign(mapOf("policy_digest" to Pca.b64(ByteArray(32)))), "another policy")
        refused(sign(mapOf("action_digest" to Pca.b64(ByteArray(32)))), "another action")
        refused(sign(last = 7L), "another state of the history")
        refused(sign(mapOf("expires_at" to IntentJs.ofLong(AuthorizeTestKit.NOW - 1), "iat" to IntentJs.ofLong(AuthorizeTestKit.NOW - 2000))), "expired")
        refused(sign(mapOf("decision" to "deny")), "the principal answered deny")
        val tampered = LinkedHashMap(sign())
        tampered["decision"] = "deny"
        refused(tampered, "signature invalid")
        refused("not an object", "malformed escalation answer")
    }

    @Test
    fun anUnpinnedPrincipalOrNoPrincipalsNeverAdmits() {
        inject("provenance", "intent_required: q")
        val other = Escalation.Principal(Pca.b64(ByteArray(32) { 7 }))
        val r = run(sign(), principals = listOf(other))
        assertEquals("escalate", r.decision)
        assertTrue(r.reasons.any { it.contains("not pinned by this verifier") })
        val none = run(sign(), principals = emptyList())
        assertEquals("escalate", none.decision)
        assertFalse(none.allow)
    }

    @Test
    fun anAnswerNeverUpgradesADeny() {
        inject("provenance", "hard failure") // no escalate prefix: a deny
        val r = run(sign())
        assertFalse(r.allow)
        assertEquals("deny", r.decision)
        assertNull(r.escalation)
        inject("provenance", null) // a failing check with no reason of its own is a hard failure
        assertEquals("deny", run(sign()).decision)
    }

    @Test
    fun oneNonEscalateFailureAmongEscalateOnesIsADeny() {
        Authorize.coreHook = { core ->
            core.checks["provenance"] = false
            core.reasons.add("provenance: intent_required: q")
            core.checks["classes"] = false
            core.reasons.add("classes: rejected")
            core.allow = false
        }
        val r = run(sign())
        assertEquals("deny", r.decision)
        assertFalse(r.allow)
    }

    @Test
    fun everyEscalateClassCheckIsUpgradedTogether() {
        Authorize.coreHook = { core ->
            core.checks["provenance"] = false
            core.reasons.add("provenance: intent_required: q")
            core.checks["tighten"] = false
            core.reasons.add("tighten: escalate: asked by tighten rule 'a'")
            core.allow = false
        }
        val r = run(sign())
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals("pass", r.checks["tighten"])
    }

    @Test
    fun aStoreWithoutLastIsRefusedAtConstruction() {
        val bare = object : Authorize.StateStore {
            override fun claim(key: String, counter: Long): Authorize.ClaimResult = Authorize.ClaimResult(true)
        }
        try {
            run(null, bare)
            fail("a store without last() must be refused when principals are configured")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("LastStore"))
        }
        // without principals the same store is fine
        val ok = Authorize.authorize(
            pcactn(c),
            Authorize.Input(AuthorizeTestKit.op(c), AuthorizeTestKit.AUD, { grant(c) }, bare, { _, _ -> false }, now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP),
        )
        assertTrue(ok.allow)
        try {
            Authorize.AuthorizeOptions(bare, { _, _ -> false }, escalationPrincipals = listOf(Escalation.Principal(pub)))
            fail("AuthorizeOptions must refuse it too")
        } catch (e: IllegalArgumentException) {
            assertNotNull(e.message)
        }
    }

    @Test
    fun theJdbcStoreImplementsLast() {
        val st = AuthorizeTestKit.jdbcStore()
        assertNull(st.last("k"))
        assertTrue(st.claim("k", 5).ok)
        assertEquals(5L, st.last("k"))
    }

    @Test
    fun legacyModelPolarityIsReportedOnTheDecision() {
        val g = ParityVectors.obj(
            """{"caveats":[{"type":"envelope","goal_commit":"g","caveats":[],"agent_binding":{},
            "risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,"kappa":1,"lambda":0,"rho":0,"bMax":0},
            "model_polarity":"legacy","predicates":[{"verb":"*","where":[{"field":"env.class.tone","op":"eq","value":"x"}]}]}]}""",
        )
        val d = IntentV2.decide(ParityVectors.obj("""{"aud":"a","action":{"verb":"v","resource":"r"}}"""), g, null, 0L)
        assertTrue(d.legacyModelPolarity)
        assertEquals(listOf("tighten"), d.checks.map { it.name })
        assertTrue(d.checks[0].ok)
    }
}
