package net.atlasauth.pca.agent

import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The HTTP agent client against a scripted resource server. */
@Suppress("UNCHECKED_CAST")
class PcaAgentTest {
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
    private val agentEd = Keys.edFromSeed(ByteArray(32) { 1 })
    private val agent = Keys.ed25519(agentEd)
    private val env = Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy())
    private val grant = Issue.mintGrant(principal, agentEd.id(), null, env, "g", "s").grant
    private val node = Issue.obj("id" to "n1", "verb" to "read", "resource" to "doc/1", "params_digest" to Pca.paramsDigest(null))

    private class Log(val calls: MutableList<Pair<String, String>> = ArrayList())

    private fun client(log: Log, answer: (String, String, String?) -> FetchResponse, verify: Boolean = false, key: Keys.SuiteKey? = agent): AgentClient =
        PcaAgent.createAgent(
            CreateAgentOptions(
                grant = grant, agentKey = key, rsBaseUrl = "https://rs.example/", audience = "ins_1", now = { 1_800_000_000_000L },
                fetch = FetchLike { m, u, _, b -> log.calls.add(m to u); answer(m, u, b) }, verifyReceipts = verify,
            ),
        )

    private fun planOk(): (String, String, String?) -> FetchResponse = { _, _, _ -> FetchResponse(200, """{"plan_root":"${Issue.commitPlan(listOf(node)).root}"}""") }

    @Test fun createAgentRefusesAnEmptyAudienceAndARelativeUrl() {
        for (o in listOf(CreateAgentOptions(grant = grant, rsBaseUrl = "https://x", audience = ""), CreateAgentOptions(grant = grant, rsBaseUrl = "/x", audience = "a"),
            CreateAgentOptions(grant = grant, rsBaseUrl = "ftp://x", audience = "a"))) {
            try { PcaAgent.createAgent(o); fail("expected build_failed") } catch (e: PcaAgentError) { assertEquals("build_failed", e.code) }
        }
    }

    @Test fun actBeforeCommitPlanIsNoPlan() {
        val r = client(Log(), planOk()).act("n1") as ActResult.Error
        assertEquals("no_plan", r.error.code)
    }

    @Test fun commitPlanNeedsTheServerToEchoTheRoot() {
        val c = client(Log(), { _, _, _ -> FetchResponse(200, """{"plan_root":"other"}""") })
        try { c.commitPlan(listOf(node)); fail("expected bad_response") } catch (e: PcaAgentError) { assertEquals("bad_response", e.code) }
        val c2 = client(Log(), { _, _, _ -> FetchResponse(200, "not json") })
        try { c2.commitPlan(listOf(node)); fail("expected bad_response") } catch (e: PcaAgentError) { assertEquals("bad_response", e.code) }
    }

    @Test fun allowNeedsAnExplicitTrueAndAReceipt() {
        val log = Log()
        var reply = """{"verdict":{"allow":true},"receipt":{"root":"r","commit":"c","index":0,"inclusion_proof":{}}}"""
        val c = client(log, { m, u, b -> if (u.endsWith("/plans")) planOk()(m, u, b) else FetchResponse(200, reply) })
        assertEquals(Issue.commitPlan(listOf(node)).root, c.commitPlan(listOf(node)))
        val ok = c.act("n1") as ActResult.Allowed
        assertTrue(ok.verdict.allow)
        assertEquals(1L, c.counter)
        reply = """{"verdict":{"allow":true}}"""
        assertEquals("bad_response", (c.act("n1") as ActResult.Error).error.code)
        reply = """{"verdict":{"allow":true},"allow":false,"receipt":{}}"""
        assertTrue(c.act("n1") is ActResult.Denied)
        reply = """{"verdict":{"allow":"true"},"receipt":{}}"""
        assertTrue(c.act("n1") is ActResult.Denied)
        assertEquals(4L, c.counter) // a counter is never reused
        assertEquals("unknown_node", (c.act("zz") as ActResult.Error).error.code)
    }

    @Test fun anAllowWhoseInclusionProofFailsIsAnError() {
        val c = client(Log(), { m, u, b ->
            if (u.endsWith("/plans")) planOk()(m, u, b) else FetchResponse(200, """{"verdict":{"allow":true},"receipt":{"root":"r","commit":"c","inclusion_proof":{}}}""")
        }, verify = true)
        c.commitPlan(listOf(node))
        assertEquals("bad_response", (c.act("n1") as ActResult.Error).error.code)
    }

    @Test fun aStepUpIsReportedAndPolledUntilDecided() {
        var polls = 0
        val c = client(Log(), { m, u, b ->
            when {
                u.endsWith("/plans") -> planOk()(m, u, b)
                u.endsWith("/actions") -> FetchResponse(202, """{"stepup_id":"s/1","required_t":3}""")
                else -> { polls++; if (polls < 2) FetchResponse(200, """{"status":"pending"}""") else FetchResponse(200, """{"status":"approved"}""") }
            }
        })
        c.commitPlan(listOf(node))
        val s = c.act("n1") as ActResult.StepUp
        assertEquals("s/1", s.stepupId)
        assertEquals(3.0, s.requiredT, 0.0)
        assertEquals("approved", c.awaitStepUp("s/1", pollMs = 1L, timeoutMs = 10_000L).status)
    }

    @Test fun aClientErrorOnPollIsFinalAndNeverApproves() {
        val c = client(Log(), { _, _, _ -> FetchResponse(404, """{"status":"approved"}""") })
        val o = c.awaitStepUp("x", pollMs = 1L, timeoutMs = 1000L)
        assertEquals("denied", o.status)
        assertEquals(404, o.httpStatus)
        assertFalse(o.status == "approved")
    }

    @Test fun delegateExtendsTheChainAndNeedsAKey() {
        val c = client(Log(), planOk())
        val sub = c.delegate(Keys.edFromSeed(ByteArray(32) { 2 }).id(), emptyList())
        assertEquals(2, sub.chain.size)
        assertNotNull(sub.agentPublic)
        try { client(Log(), planOk(), key = null).delegate("x"); fail("expected no_secret") } catch (e: PcaAgentError) { assertEquals("no_secret", e.code) }
        assertTrue(Json.canonicalize(sub.chain).isNotEmpty())
    }
}
