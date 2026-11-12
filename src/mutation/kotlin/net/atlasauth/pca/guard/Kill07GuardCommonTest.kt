package net.atlasauth.pca.guard

import net.atlasauth.pca.guard.Kill06GuardKit.EMPTY
import net.atlasauth.pca.guard.Kill06GuardKit.cfg
import net.atlasauth.pca.guard.Kill06GuardKit.plain
import net.atlasauth.pca.guard.Kill06GuardKit.utf8
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.AuthorizeTestKit
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The seams of `PcaGuard` (outcome mapping, workflow step, denial bodies) pinned directly, plus the pcactn a denial reports. */
@Suppress("UNCHECKED_CAST")
class Kill07GuardCommonTest {
    private val sc = GuardFixtures.within()
    private fun res(reason: String?, pcactn: Map<String, Any?>? = null, escalation: Map<String, Any?>? = null, status: Int = 403) =
        Authorize.Result(false, status, linkedMapOf("policy" to "fail"), listOf("policy: x"), reason, pcactn = pcactn, escalation = escalation)

    // ---- GuardOutcome.operation ----

    @Test
    fun theOperationOfARefusalIsNullWhateverIsBound() {
        val op = Authorize.AuthorizedOperation("v", "/r", "pd", "id")
        val denied = GuardOutcome(
            false, 403, null, "", "deny", Authorize.Result(false, 403, emptyMap(), emptyList(), null, operation = op), null, null, op, "k",
        )
        assertNull(denied.operation)
        val viaAuthorization = GuardOutcome(true, 200, null, "", "allow", Authorize.Result(true, 200, emptyMap(), emptyList(), null, operation = op))
        assertSame(op, viaAuthorization.operation)
        val bound = GuardOutcome(true, 200, null, "", "allow", null, null, null, op, "k")
        assertSame(op, bound.operation)
        // an allow whose authorization carries no operation falls back to the bound one (the elvis is not skipped)
        val fallback = GuardOutcome(true, 200, null, "", "allow", Authorize.Result(true, 200, emptyMap(), emptyList(), null), null, null, op, "k")
        assertSame(op, fallback.operation)
    }

    // ---- denial / plain / verdictDenial ----

    @Test
    fun aDenialWithoutAReasonSaysDenied() {
        val o = PcaGuard.denial(res(null), null)
        val b = GuardFixtures.parse(o.body)
        assertEquals("denied", b["reason"])
        assertEquals("denied", b["error_description"])
        assertEquals(explainRefusal("denied").docs, b["doc"])
        assertEquals("insufficient_authority", b["error"])
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", o.wwwAuthenticate)
        val unauth = PcaGuard.denial(res("chain: x", status = 401), null)
        assertEquals(401, unauth.status)
        assertEquals("PCA realm=\"pca\", error=\"invalid_pcactn\"", unauth.wwwAuthenticate)
        assertEquals("chain: x", GuardFixtures.parse(unauth.body)["reason"])
    }

    @Test
    fun aDenialBodyThatCannotBeSerializedFallsBackToTheErrorCode() {
        val o = PcaGuard.denial(res("policy: x", escalation = linkedMapOf("k" to Any())), null)
        assertEquals("{\"error\":\"insufficient_authority\"}", o.body)
        assertEquals(403, o.status)
        val u = PcaGuard.denial(res("chain: x", escalation = linkedMapOf("k" to Any()), status = 401), null)
        assertEquals("{\"error\":\"invalid_pcactn\"}", u.body)
    }

    @Test
    fun theChallengeOfAPlainRefusalIsOn401And403Only() {
        for (s in listOf(401, 403)) {
            val o = PcaGuard.plain(s, "c", "d")
            assertEquals(s, o.status)
            assertEquals("PCA realm=\"pca\", error=\"c\"", o.wwwAuthenticate)
        }
        for (s in listOf(400, 402, 404, 409, 500)) assertNull(PcaGuard.plain(s, "c", "d").wwwAuthenticate)
    }

    @Test
    fun aVerdictWithoutAReasonIsDenied() {
        val v = Pca.Verdict()
        val o = PcaGuard.verdictDenial(v, linkedMapOf("grant_ref" to "g"))
        val b = GuardFixtures.parse(o.body)
        assertEquals("denied", b["reason"])
        assertEquals("denied", b["error_description"])
        assertEquals(explainRefusal("denied").docs, b["doc"])
        assertEquals(403, o.status)
        assertEquals("deny", o.decision)
        assertSame(v, o.verdict)
        v.reason = "chain: bad"
        val r = GuardFixtures.parse(PcaGuard.verdictDenial(v, linkedMapOf()).body)
        assertEquals("chain: bad", r["reason"])
        assertEquals("chain: bad", r["error_description"])
    }

    // ---- the workflow step ----

    private val gated get() = Authorize.AuthorizeOptions(null, null, workflow = Authorize.WorkflowGate("p", "r", false), risk = AuthorizeTestKit.calmRisk)
    private val ungated get() = Authorize.AuthorizeOptions(null, null, risk = AuthorizeTestKit.calmRisk)
    private val unreadable = listOf(
        linkedMapOf<String, Any?>("units" to 5L), linkedMapOf("units" to "x"), linkedMapOf("units" to listOf(1L)),
        linkedMapOf("step" to 5L), linkedMapOf("step" to listOf("a")), linkedMapOf("goal_digest" to 5L), linkedMapOf("goal_digest" to linkedMapOf<String, Any?>()),
    )

    @Test
    fun noGateMeansNoStepWhateverIsGiven() {
        val explicit = Authorize.WorkflowStep("c", null, "s")
        val env = linkedMapOf<Any?, Any?>("workflow" to linkedMapOf("commitment" to "c", "step" to "s"))
        assertNull(PcaGuard.workflowStep(ungated, explicit, env))
        assertNull(PcaGuard.workflowStep(ungated, null, env))
        assertSame(explicit, PcaGuard.workflowStep(gated, explicit, env))
    }

    @Test
    fun withAGateTheStepComesFromTheEnvelopeMember() {
        assertNull(PcaGuard.workflowStep(gated, null, null))
        assertNull(PcaGuard.workflowStep(gated, null, linkedMapOf<Any?, Any?>("other" to 1L)))
        val full = linkedMapOf<String, Any?>(
            "commitment" to "c", "receipts" to listOf("r"), "step" to "s", "units" to linkedMapOf<String, Any?>("a" to "b"), "goal_digest" to "g",
        )
        val s = PcaGuard.workflowStep(gated, null, linkedMapOf<Any?, Any?>("workflow" to full))!!
        assertEquals("c", s.commitment)
        assertEquals(listOf("r"), s.receipts)
        assertEquals("s", s.step)
        assertEquals(mapOf("a" to "b"), s.units)
        assertEquals("g", s.goalDigest)
        // absent members are the empty ones; the rest is carried
        val bare = PcaGuard.workflowStep(gated, null, linkedMapOf<Any?, Any?>("workflow" to linkedMapOf("commitment" to "c", "receipts" to listOf("r"), "step" to "s")))!!
        assertEquals("c", bare.commitment)
        assertEquals(listOf("r"), bare.receipts)
        assertEquals("s", bare.step)
        assertEquals(emptyMap<String, Any?>(), bare.units)
        assertNull(bare.goalDigest)
        // an absent step is a step with no id; its commitment and receipts are still carried
        val noStep = PcaGuard.workflowStep(gated, null, linkedMapOf<Any?, Any?>("workflow" to linkedMapOf("commitment" to "c", "receipts" to listOf("r"))))!!
        assertNull(noStep.step)
        assertEquals("c", noStep.commitment)
        assertEquals(listOf("r"), noStep.receipts)
    }

    @Test
    fun anUnreadableMemberIsAnEmptyStep() {
        val cases = ArrayList<Any?>(listOf(null, 5L, "x", listOf(1L), true))
        for (m in cases) assertEmptyStep(PcaGuard.workflowStep(gated, null, linkedMapOf<Any?, Any?>("workflow" to m)))
        for (bad in unreadable) {
            val m = linkedMapOf<String, Any?>("commitment" to "c", "receipts" to listOf("r"), "step" to "s")
            m.putAll(bad)
            assertEmptyStep(PcaGuard.workflowStep(gated, null, linkedMapOf<Any?, Any?>("workflow" to m)))
        }
    }

    private fun assertEmptyStep(s: Authorize.WorkflowStep?) {
        assertNotNull(s)
        assertNull(s!!.commitment)
        assertNull(s.receipts)
        assertNull(s.step)
        assertEquals(emptyMap<String, Any?>(), s.units)
        assertNull(s.goalDigest)
    }

    // ---- executeAnswer ----

    private fun outcome(status: String, replayed: Boolean = false, result: Any? = null, reason: String? = null, authorization: Authorize.Result? = null) =
        Operations.ExecuteOutcome(status, "id", result = result, replayed = replayed, reason = reason, authorization = authorization)

    @Test
    fun aCommittedOutcomeIsTheRecordedResult() {
        for (replayed in listOf(false, true)) {
            val r = PcaGuard.executeAnswer(outcome("committed", replayed, result = "res"), null)
            assertNull(r.refusal)
            assertEquals(replayed, r.replayed)
            assertEquals("res", r.result)
        }
    }

    @Test
    fun theOtherOutcomesAreRefusals() {
        val f = PcaGuard.executeAnswer(outcome("failed", reason = "secret"), null)
        plain(f.refusal!!, 500, "operation_failed", "the operation failed")
        assertFalse(f.replayed)
        assertNull(f.result)
        plain(PcaGuard.executeAnswer(outcome("aborted", reason = "why"), null).refusal!!, 403, "operation_aborted", "why")
        plain(PcaGuard.executeAnswer(outcome("aborted"), null).refusal!!, 403, "operation_aborted", "aborted")
        plain(PcaGuard.executeAnswer(outcome("pending"), null).refusal!!, 409, "operation_in_progress", "another execution of this operation is in flight")
        plain(PcaGuard.executeAnswer(outcome("uncertain", reason = "why"), null).refusal!!, 409, "operation_uncertain", "why")
        plain(PcaGuard.executeAnswer(outcome("uncertain"), null).refusal!!, 409, "operation_uncertain", "outcome unknown")
        for (replayed in listOf(false, true)) {
            val r = PcaGuard.executeAnswer(outcome("refused", replayed, result = "res", reason = "no way"), null)
            plain(r.refusal!!, 403, "access_denied", "no way")
            assertFalse(r.replayed)
            assertNull(r.result)
        }
        plain(PcaGuard.executeAnswer(outcome("refused"), null).refusal!!, 403, "access_denied", "denied")
        plain(PcaGuard.executeAnswer(outcome("anything-else", reason = "r"), null).refusal!!, 403, "access_denied", "r")
    }

    @Test
    fun aStatusThatOnlyCollidesWithAKnownOneIsNotThatOne() {
        // same String.hashCode as the real name, different text: a hash-only match must not be taken for the name
        for (name in listOf("committed", "denied", "failed", "aborted", "pending", "uncertain")) {
            val twin = (name[0] + 1).toString() + (name[1] - 31) + name.substring(2)
            assertEquals(name.hashCode(), twin.hashCode())
            assertFalse(name == twin)
            val r = PcaGuard.executeAnswer(outcome(twin, reason = "twin"), null)
            plain(r.refusal!!, 403, "access_denied", "twin")
            assertFalse(r.replayed)
        }
    }

    @Test
    fun aDeniedOutcomeReportsTheDecodedProofElseTheRequestOne() {
        val decoded = linkedMapOf<String, Any?>("grant_ref" to "decoded")
        val request = linkedMapOf<String, Any?>("grant_ref" to "request")
        val withProof = PcaGuard.executeAnswer(outcome("denied", authorization = res("policy: x", pcactn = decoded)), request).refusal!!
        assertSame(decoded, withProof.pcactn)
        val without = PcaGuard.executeAnswer(outcome("denied", authorization = res("policy: x")), request).refusal!!
        assertSame(request, without.pcactn)
        // a proof that is not an object is not reported; nothing throws
        val text = PcaGuard.executeAnswer(outcome("denied", authorization = res("policy: x")), "x").refusal!!
        assertNull(text.pcactn)
        assertEquals(403, text.status)
        assertEquals("policy: x", GuardFixtures.parse(text.body)["reason"])
        assertEquals("deny", text.decision)
    }

    // ---- the proof a denial reports ----

    private fun bodyOf(pcactn: Any?): ByteArray = utf8(Json.canonicalize(linkedMapOf<String, Any?>("pcactn" to pcactn)))

    @Test
    fun aProofGivenAsJsonTextIsReportedAsTheDecodedObject() {
        val unknown = sc.withPcactn { it["grant_ref"] = "no-such-grant" }
        val body = bodyOf(Json.canonicalize(unknown.pcactn))
        val c = cfg(sc, GuardFixtures.options())
        val d = PcaGuard.decide(c, null, null, body, sc.operation, null, null)
        assertEquals(401, d.status)
        assertNotNull(d.authorization)
        assertEquals("no-such-grant", d.pcactn!!["grant_ref"])
        val e = cfg(sc, GuardFixtures.options(), executor = GuardFixtures.executor())
        val x = PcaGuard.execute(e, null, null, body, sc.operation, null, null) { "done" }.refusal!!
        assertEquals(401, x.status)
        assertNotNull(x.authorization)
        assertEquals("no-such-grant", x.pcactn!!["grant_ref"])
    }

    @Test
    fun aProofThatIsNotAnObjectIsRefusedByTheConfigCheckNotByAFault() {
        val incomplete = Authorize.AuthorizeOptions(null, null, risk = AuthorizeTestKit.calmRisk)
        for (pc in listOf<Any?>("x", 5L)) {
            val d = PcaGuard.decide(cfg(sc, null), null, null, bodyOf(pc), sc.operation, null, null)
            assertEquals(403, d.status)
            assertTrue(d.body, d.authorization!!.reason!!.startsWith("authorize_config:"))
            assertNull(d.pcactn)
            val e = cfg(sc, incomplete, executor = GuardFixtures.executor())
            val x = PcaGuard.execute(e, null, null, bodyOf(pc), sc.operation, null, null) { "done" }.refusal!!
            assertEquals(403, x.status)
            assertTrue(x.body, x.authorization!!.reason!!.startsWith("authorize_config:"))
            assertNull(x.pcactn)
        }
    }

    @Test
    fun aDenialBeforeTheProofIsReadReportsTheRequestOne() {
        val incomplete = Authorize.AuthorizeOptions(null, null, risk = AuthorizeTestKit.calmRisk)
        val e = cfg(sc, incomplete, executor = GuardFixtures.executor())
        val x = PcaGuard.execute(e, sc.header, null, EMPTY, sc.operation, null, null) { "done" }.refusal!!
        assertEquals(403, x.status)
        assertTrue(x.body, x.authorization!!.reason!!.startsWith("authorize_config:"))
        assertEquals(sc.pcactn["grant_ref"], x.pcactn!!["grant_ref"])
        val d = PcaGuard.decide(cfg(sc, incomplete), sc.header, null, EMPTY, sc.operation, null, null)
        assertTrue(d.body, d.authorization!!.reason!!.startsWith("authorize_config:"))
        assertEquals(sc.pcactn["grant_ref"], d.pcactn!!["grant_ref"])
    }
}
