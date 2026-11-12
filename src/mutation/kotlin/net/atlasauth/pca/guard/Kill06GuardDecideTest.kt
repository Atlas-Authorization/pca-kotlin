package net.atlasauth.pca.guard

import net.atlasauth.pca.guard.Kill06GuardKit.EMPTY
import net.atlasauth.pca.guard.Kill06GuardKit.MAX
import net.atlasauth.pca.guard.Kill06GuardKit.QUICK
import net.atlasauth.pca.guard.Kill06GuardKit.REF
import net.atlasauth.pca.guard.Kill06GuardKit.cfg
import net.atlasauth.pca.guard.Kill06GuardKit.decide
import net.atlasauth.pca.guard.Kill06GuardKit.hdr
import net.atlasauth.pca.guard.Kill06GuardKit.padded
import net.atlasauth.pca.guard.Kill06GuardKit.pre
import net.atlasauth.pca.guard.Kill06GuardKit.utf8
import net.atlasauth.pca.verifier.ArgProvenance
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `PcaGuard.decide`: proof extraction, the authorize path, the denial body and the signature-only path. */
@Suppress("UNCHECKED_CAST")
class Kill06GuardDecideTest {
    private val sc = GuardFixtures.within()
    private val az get() = GuardFixtures.options()

    // ---- extraction from the header ----

    @Test
    fun aHeaderThatIsNotCanonicalBase64urlIs401() {
        for (h in listOf("not base64url!", "e30=", "e 30", "*")) {
            val o = decide(sc, cfg(sc, az), header = h)
            pre(o, 401, "invalid_request", "PCA-Action is not canonical base64url")
        }
    }

    @Test
    fun aHeaderThatIsNotUtf8Is401() {
        val bad = Pca.b64(byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x7B))
        pre(decide(sc, cfg(sc, az), header = bad), 401, "invalid_request", "PCA-Action is not canonical base64url")
        val overlong = Pca.b64(byteArrayOf(0xC0.toByte(), 0x80.toByte()))
        pre(decide(sc, cfg(sc, az), header = overlong), 401, "invalid_request", "PCA-Action is not canonical base64url")
    }

    @Test
    fun aHeaderPastTheArtifactLimitIs401() {
        val big = Pca.b64(ByteArray(MAX + 1) { 'a'.code.toByte() })
        pre(decide(sc, cfg(sc, az), header = big), 401, "invalid_request", "PCActn is too large")
        // at the limit it is not too large: it fails later, as not JSON
        val atLimit = Pca.b64(ByteArray(MAX) { 'a'.code.toByte() })
        pre(decide(sc, cfg(sc, az), header = atLimit), 401, "invalid_request", "PCActn is not strict JSON")
    }

    @Test
    fun aHeaderThatIsNotStrictJsonOrNotAnObjectIs401() {
        for (t in listOf("{", "{\"a\":1,}", "nope")) pre(decide(sc, cfg(sc, az), header = hdr(t)), 401, "invalid_request", "PCActn is not strict JSON")
        for (t in listOf("[1]", "5", "\"x\"", "null", "true")) pre(decide(sc, cfg(sc, az), header = hdr(t)), 401, "invalid_request", "PCActn is not a JSON object")
    }

    @Test
    fun noHeaderAndNoBodyIs401WithAPlainChallenge() {
        pre(decide(sc, cfg(sc, az), header = null), 401, null, "no PCA-Action header and no PCActn body")
        // an empty header is no header
        pre(decide(sc, cfg(sc, az), header = ""), 401, null, "no PCA-Action header and no PCActn body")
    }

    // ---- extraction from the body ----

    @Test
    fun anEmptyHeaderFallsBackToTheBody() {
        val o = decide(sc, cfg(sc, az), header = "", body = utf8(sc.body), prov = null)
        assertTrue(o.body, o.allowed)
        val o2 = decide(sc, cfg(sc, az), header = null, body = utf8(sc.body), prov = null)
        assertTrue(o2.body, o2.allowed)
    }

    @Test
    fun aBodyThatIsNotUtf8IsRefused() {
        val o = decide(sc, cfg(sc, az), header = null, body = byteArrayOf(0xFF.toByte(), 0x7B))
        pre(o, 401, "invalid_request", "request body is not valid UTF-8")
    }

    @Test
    fun aBodyPastTheArtifactLimitIsRefused() {
        val o = decide(sc, cfg(sc, az), header = null, body = ByteArray(MAX + 1) { 'a'.code.toByte() })
        pre(o, 401, "invalid_request", "request body is too large")
        // at the limit it parses (and fails as not JSON)
        pre(decide(sc, cfg(sc, az), header = null, body = ByteArray(MAX) { 'a'.code.toByte() }), 401, "invalid_request", "request body is not strict JSON")
    }

    @Test
    fun aBodyThatIsNotStrictJsonIsRefused() {
        for (t in listOf("{", "{\"a\":1,}", "nope"))
            pre(decide(sc, cfg(sc, az), header = null, body = utf8(t)), 401, "invalid_request", "request body is not strict JSON")
    }

    @Test
    fun aBodyWithoutAPcactnMemberIsRefusedWithAPlainChallenge() {
        for (t in listOf("[1]", "{}", "{\"pcactn\":null}", "{\"other\":1}", "5", "null"))
            pre(decide(sc, cfg(sc, az), header = null, body = utf8(t)), 401, null, "no \"pcactn\" field in request body")
    }

    // ---- decide itself ----

    @Test
    fun aThrowingClockFailsClosed() {
        val boom: () -> Long = { throw IllegalStateException("clock") }
        pre(decide(sc, cfg(sc, az, clock = boom)), 403, "insufficient_authority", "guard error (fail closed)")
        pre(decide(sc, cfg(sc, null, sigOnly = true, clock = boom)), 403, "insufficient_authority", "guard error (fail closed)")
    }

    // ---- authorize mode ----

    @Test
    fun anAllowCarriesTheAuthorizationVerdictAndPcactn() {
        val o = decide(sc, cfg(sc, az))
        assertTrue(o.body, o.allowed)
        assertEquals(200, o.status)
        assertNull(o.wwwAuthenticate)
        assertEquals("", o.body)
        assertEquals("allow", o.decision)
        assertNotNull(o.authorization)
        assertTrue(o.authorization!!.allow)
        assertNotNull(o.verdict)
        assertTrue(o.verdict!!.allow)
        assertEquals(sc.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        assertNull(o.boundOperation)
        assertNull(o.idempotencyKey)
        assertEquals(sc.operation.verb, o.operation!!.verb)
    }

    @Test
    fun aMissingAuthorizeConfigIs403NamingWhatIsMissing() {
        val o = decide(sc, cfg(sc, null))
        assertFalse(o.allowed)
        assertEquals(403, o.status)
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", o.wwwAuthenticate)
        val b = GuardFixtures.parse(o.body)
        assertEquals(setOf("error", "error_description", "reason", "checks", "decision", "doc", "missing"), b.keys)
        assertEquals("insufficient_authority", b["error"])
        val reason = b["reason"] as String
        assertTrue(reason, reason.startsWith("authorize_config: missing required component(s)"))
        assertEquals(reason, b["error_description"])
        assertEquals(QUICK, b["doc"])
        assertEquals("deny", b["decision"])
        val missing = b["missing"] as List<*>
        assertTrue(missing.toString(), missing.contains("stateStore"))
        assertEquals(o.authorization!!.missing, missing)
        // no verdict was reached, but the request's own PCActn is reported
        assertNull(o.verdict)
        assertEquals(sc.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        assertEquals("deny", o.decision)
    }

    @Test
    fun aPcactnThatIsNotAnObjectIsNotReportedBack() {
        val o = decide(sc, cfg(sc, null), header = null, body = utf8(Json.canonicalize(linkedMapOf<String, Any?>("pcactn" to "x"))))
        assertEquals(403, o.status)
        assertNull(o.pcactn)
        assertNull(decide(sc, cfg(sc, null), header = null, body = utf8("{\"pcactn\":5}")).pcactn)
    }

    @Test
    fun aMissingOperationDeniesAndStillReportsThePcactn() {
        val o = decide(sc, cfg(sc, az), op = null)
        assertFalse(o.allowed)
        assertEquals(403, o.status)
        val b = GuardFixtures.parse(o.body)
        assertTrue(b["reason"] as String, (b["reason"] as String).startsWith("operation:"))
        assertEquals(REF + "#operation", b["doc"])
        assertEquals(sc.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        assertFalse(b.containsKey("missing"))
        assertFalse(b.containsKey("escalation"))
    }

    @Test
    fun aPolicyDenialHasTheFullBody() {
        val bad = GuardFixtures.overLimit()
        val o = decide(bad, cfg(bad, az))
        assertFalse(o.allowed)
        assertEquals(403, o.status)
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", o.wwwAuthenticate)
        assertEquals("deny", o.decision)
        val b = GuardFixtures.parse(o.body)
        assertEquals(setOf("error", "error_description", "reason", "checks", "decision", "doc"), b.keys)
        assertEquals("insufficient_authority", b["error"])
        val r = o.authorization!!
        assertEquals(r.reason, b["reason"])
        assertEquals(r.reason, b["error_description"])
        assertEquals(r.checks, b["checks"])
        assertEquals(r.decision, b["decision"])
        assertEquals(explainRefusal(r.reason).docs, b["doc"])
        assertNotNull(o.verdict)
        assertEquals(bad.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        assertNull(o.operation)
    }

    @Test
    fun anUnauthenticatedProofIs401InvalidPcactn() {
        for (s in listOf(GuardFixtures.wrongAudience(), GuardFixtures.within().withPcactn { it["sig"] = "A".repeat(86) })) {
            val o = decide(s, cfg(s, az))
            assertFalse(o.allowed)
            assertEquals(401, o.status)
            assertEquals("PCA realm=\"pca\", error=\"invalid_pcactn\"", o.wwwAuthenticate)
            val b = GuardFixtures.parse(o.body)
            assertEquals("invalid_pcactn", b["error"])
            assertEquals(o.authorization!!.reason, b["reason"])
        }
    }

    @Test
    fun anEscalateCarriesTheRequestAndNoMissingMember() {
        val e = GuardFixtures.escalating()
        val o = decide(e, cfg(e, GuardFixtures.options(GuardFixtures.principals())))
        assertFalse(o.allowed)
        assertEquals(403, o.status)
        assertEquals("escalate", o.decision)
        val b = GuardFixtures.parse(o.body)
        assertEquals(setOf("error", "error_description", "reason", "checks", "decision", "doc", "escalation"), b.keys)
        assertEquals("escalate", b["decision"])
        assertEquals("pca-escalation-request", (b["escalation"] as Map<String, Any?>)["kind"])
        assertEquals(o.authorization!!.escalation, b["escalation"])
        assertNotNull(o.verdict)
        assertNotNull(o.pcactn)
    }

    // ---- the operation size limit and the provenance in the body ----

    @Test
    fun aBodyAtTheLimitStillMapsTheOperationAndOneByteMoreDoesNot() {
        val atLimit = decide(sc, cfg(sc, az), body = ByteArray(MAX))
        assertTrue(atLimit.body, atLimit.allowed)
        val over = decide(sc, cfg(sc, az), body = ByteArray(MAX + 1))
        assertFalse(over.allowed)
        assertEquals(403, over.status)
        assertTrue(over.authorization!!.reason!!, over.authorization!!.reason!!.startsWith("operation:"))
    }

    @Test
    fun theProvenanceMemberOfABodyAtTheLimitIsRead() {
        val o = decide(sc, cfg(sc, az), body = padded(sc, MAX), prov = null)
        assertTrue(o.body, o.allowed)
        val over = decide(sc, cfg(sc, az), body = padded(sc, MAX + 1), prov = null)
        assertFalse(over.allowed)
        assertTrue(over.authorization!!.reason!!, over.authorization!!.reason!!.startsWith("operation:"))
    }

    @Test
    fun theProvenanceHeaderWinsOverTheBodyAndAnEmptyOneIsNone() {
        // a header that does not decode fails the gate closed even when the body carries a good bundle
        val bad = decide(sc, cfg(sc, az), body = utf8(sc.body), prov = "!!not-a-bundle")
        assertFalse(bad.allowed)
        assertEquals("fail", bad.authorization!!.checks["provenance_flow"])
        // an empty header is no header: the body's bundle is used
        val ok = decide(sc, cfg(sc, az), body = utf8(sc.body), prov = "")
        assertTrue(ok.body, ok.allowed)
        // the header alone is enough
        assertTrue(decide(sc, cfg(sc, az), body = EMPTY, prov = sc.provenanceHeader).allowed)
        // no bundle at all: a sensitive operation does not run
        val none = decide(sc, cfg(sc, az), body = EMPTY, prov = null)
        assertFalse(none.allowed)
        assertEquals("fail", none.authorization!!.checks["provenance_flow"])
    }

    // ---- the intent policy ----

    @Test
    fun anActiveIntentPolicyIsPassedToTheVerifier() {
        val ip = Pca.IntentPolicy(require = true)
        assertTrue(decide(sc, cfg(sc, az)).allowed)
        assertFalse(decide(sc, cfg(sc, az, ip = ip)).allowed)
        assertFalse(decide(sc, cfg(sc, null, ip = ip, sigOnly = true)).allowed)
        assertTrue(decide(sc, cfg(sc, null, sigOnly = true)).allowed)
    }

    // ---- escalation answers ----

    private fun escalate(
        header: String?, body: ByteArray = EMPTY, principals: Boolean = true,
    ): GuardOutcome {
        val e = GuardFixtures.escalating()
        val opts = if (principals) GuardFixtures.options(GuardFixtures.principals()) else GuardFixtures.options()
        return decide(e, cfg(e, opts), esc = header, body = body)
    }

    private fun assertEscalate(o: GuardOutcome) {
        assertFalse(o.body, o.allowed)
        assertEquals(o.body, 403, o.status)
        assertEquals("escalate", o.decision)
        assertNotNull(o.authorization)
    }

    private val answer get() = GuardFixtures.signedAllow(GuardFixtures.escalating())
    private fun answerBody(a: Any? = answer): ByteArray = utf8(Json.canonicalize(linkedMapOf<String, Any?>("escalation_answer" to a)))

    @Test
    fun aSignedAnswerInTheHeaderAdmits() {
        val o = escalate(GuardFixtures.headerOf(answer))
        assertTrue(o.body, o.allowed)
        assertEquals("allow", o.decision)
    }

    @Test
    fun aSignedAnswerInTheBodyAdmitsWhenThereIsNoHeader() {
        assertTrue(escalate(null, answerBody()).allowed)
        assertTrue(escalate("", answerBody()).allowed)
    }

    @Test
    fun anUnreadableHeaderAnswerLeavesTheEscalate() {
        assertEscalate(escalate("!!not base64!!"))
        assertEscalate(escalate(Pca.b64(byteArrayOf(0xFF.toByte(), 0xFE.toByte()))))
        assertEscalate(escalate(hdr("{")))
        assertEscalate(escalate(hdr("nope")))
        // a present header is the only source: a good answer in the body is not consulted
        assertEscalate(escalate("!!not base64!!", answerBody()))
        assertEscalate(escalate(hdr("{"), answerBody()))
    }

    @Test
    fun noAnswerOrAnUnreadableBodyAnswerLeavesTheEscalate() {
        assertEscalate(escalate(null))
        assertEscalate(escalate(""))
        assertEscalate(escalate(null, byteArrayOf(0xFF.toByte(), 0x7B)))
        assertEscalate(escalate(null, utf8("{")))
        assertEscalate(escalate(null, utf8("[1]")))
        assertEscalate(escalate(null, utf8("5")))
        assertEscalate(escalate(null, utf8("{}")))
        assertEscalate(escalate(null, utf8("{\"escalation_answer\":null}")))
        assertEscalate(escalate(null, utf8("{\"other\":1}")))
    }

    @Test
    fun withoutAPinnedPrincipalTheAnswerIsNotReadAtAll() {
        for (o in listOf(escalate(GuardFixtures.headerOf(answer), principals = false), escalate(null, answerBody(), principals = false))) {
            assertEscalate(o)
            assertTrue(o.authorization!!.reasons.toString(), o.authorization!!.reasons.none { it.startsWith("escalation:") })
        }
    }

    // ---- the K5 workflow step ----

    private val wfCase get() = GuardFixtures.workflowCall("pay-after-quote", 1).first
    private fun wfOpts() = GuardFixtures.workflowOptions()

    private fun viaBody(c: GuardFixtures.WorkflowCall, member: Any?, withMember: Boolean = true, opts: Authorize.AuthorizeOptions = wfOpts()): GuardOutcome {
        val env = linkedMapOf<String, Any?>("pcactn" to c.scenario.pcactn, ArgProvenance.BODY_MEMBER to GuardFixtures.provenance(c.scenario.operation))
        if (withMember) env["workflow"] = member
        return decide(c.scenario, cfg(c.scenario, opts), header = null, body = utf8(Json.canonicalize(env)), prov = null)
    }

    private fun viaCallback(c: GuardFixtures.WorkflowCall, step: Authorize.WorkflowStep?, opts: Authorize.AuthorizeOptions = wfOpts()): GuardOutcome =
        decide(c.scenario, cfg(c.scenario, opts), wf = step)

    private fun same(a: GuardOutcome, b: GuardOutcome) {
        assertEquals(a.allowed, b.allowed)
        assertEquals(a.status, b.status)
        assertEquals(a.decision, b.decision)
        assertEquals(a.authorization!!.reason, b.authorization!!.reason)
    }

    private fun step(m: Map<String, Any?>): Authorize.WorkflowStep =
        Authorize.WorkflowStep(m["commitment"], m["receipts"], m["step"] as String?, (m["units"] as Map<String, Any?>?) ?: emptyMap(), m["goal_digest"] as String?)

    private fun assertWorkflowRefused(o: GuardOutcome) {
        assertFalse(o.body, o.allowed)
        assertEquals(o.body, 403, o.status)
        assertNotNull("not a guard error: " + o.body, o.authorization)
        assertTrue(o.authorization!!.reason!!, o.authorization!!.reason!!.startsWith("workflow:"))
    }

    @Test
    fun aWorkflowMemberOfTheBodyIsTheStepAndACallbackWinsOverIt() {
        val c = wfCase
        assertTrue(viaBody(c, c.member).body, viaBody(c, c.member).allowed)
        assertTrue(viaCallback(c, c.step).allowed)
        // the explicit step wins over a member the envelope carries
        val both = decide(
            c.scenario, cfg(c.scenario, wfOpts()), header = null,
            body = utf8(Json.canonicalize(linkedMapOf<String, Any?>("pcactn" to c.scenario.pcactn, ArgProvenance.BODY_MEMBER to GuardFixtures.provenance(c.scenario.operation), "workflow" to 5))),
            prov = null, wf = c.step,
        )
        assertTrue(both.body, both.allowed)
    }

    @Test
    fun noStepIsNoneWhenOptionalAndRefusedWhenRequired() {
        val (c, _) = GuardFixtures.workflowCall("workflow-optional-and-absent")
        // header transport: no envelope at all
        assertTrue(viaCallback(c, null).allowed)
        // body transport without the member
        assertTrue(viaBody(c, null, withMember = false).allowed)
        val (r, _) = GuardFixtures.workflowCall("workflow-required-but-absent")
        val req = GuardFixtures.workflowOptions(required = true)
        assertWorkflowRefused(viaCallback(r, null, req))
        assertWorkflowRefused(viaBody(r, null, withMember = false, opts = req))
    }

    @Test
    fun anUnreadableWorkflowMemberIsAStepTheGateRefuses() {
        val c = wfCase
        for (m in listOf<Any?>(null, 5, "x", listOf(1), true)) assertWorkflowRefused(viaBody(c, m))
        fun mod(k: String, v: Any?): Map<String, Any?> = LinkedHashMap(c.member!!).also { it[k] = v }
        assertWorkflowRefused(viaBody(c, mod("units", 5)))
        assertWorkflowRefused(viaBody(c, mod("units", "x")))
        assertWorkflowRefused(viaBody(c, mod("units", listOf(1))))
        assertWorkflowRefused(viaBody(c, mod("step", 5)))
        assertWorkflowRefused(viaBody(c, mod("step", listOf("pay"))))
        assertWorkflowRefused(viaBody(c, mod("goal_digest", 5)))
        assertWorkflowRefused(viaBody(c, mod("goal_digest", linkedMapOf<String, Any?>())))
    }

    @Test
    fun theMembersOfAReadableStepAreCarriedExactly() {
        val c = wfCase
        val m = c.member!!
        assertTrue(viaBody(c, m).allowed)
        // an absent units / goal_digest are the empty ones, exactly as the callback form
        fun without(vararg ks: String): Map<String, Any?> = LinkedHashMap(m).also { for (k in ks) it.remove(k) }
        for (variant in listOf(without("units"), without("goal_digest"), without("units", "goal_digest"))) {
            val a = viaBody(c, variant)
            same(a, viaCallback(c, step(variant)))
            assertTrue(a.body, a.allowed)
        }
        // an absent step is a step with no id: the same refusal as the callback form
        val noStep = without("step")
        val a = viaBody(c, noStep)
        assertFalse(a.allowed)
        same(a, viaCallback(c, step(noStep)))
        // units and goal digest reach the gate unchanged
        for (units in listOf(linkedMapOf<String, Any?>("amount" to "usd"), linkedMapOf<String, Any?>("amount" to "usd", "x" to "y"))) {
            val variant = LinkedHashMap(m).also { it["units"] = units }
            val b = viaBody(c, variant)
            assertFalse(b.body, b.allowed)
            same(b, viaCallback(c, step(variant)))
            assertTrue(b.authorization!!.reason!!, b.authorization!!.reason!!.startsWith("workflow:"))
        }
        val goal = LinkedHashMap(m).also { it["goal_digest"] = "A".repeat(43) }
        same(viaBody(c, goal), viaCallback(c, step(goal)))
    }

    // ---- signature-only mode ----

    private fun sig(s: GuardFixtures.Scenario = sc) = cfg(s, null, sigOnly = true)

    @Test
    fun signatureOnlyAllowsAValidProofWithoutAnAuthorization() {
        val o = decide(sc, sig(), prov = null)
        assertTrue(o.body, o.allowed)
        assertEquals(200, o.status)
        assertNull(o.wwwAuthenticate)
        assertEquals("", o.body)
        assertEquals("allow", o.decision)
        assertNull(o.authorization)
        assertNotNull(o.verdict)
        assertTrue(o.verdict!!.allow)
        assertEquals(sc.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        assertNull(o.boundOperation)
        assertNull(o.idempotencyKey)
        assertNull(o.operation)
    }

    @Test
    fun signatureOnlyRefusesAPcactnThatIsNotAnObject() {
        for (t in listOf("5", "\"x\"", "[1]", "true")) {
            val body = utf8("{\"pcactn\":$t}")
            pre(decide(sc, sig(), header = null, body = body), 401, "invalid_request", "PCActn is not a JSON object")
        }
    }

    @Test
    fun signatureOnlyRefusesAMissingOrEmptyGrantRef() {
        val msg = "PCActn has no grant_ref"
        pre(decide(sc.withPcactn { it.remove("grant_ref") }, sig(), header = sc.withPcactn { it.remove("grant_ref") }.header), 401, "invalid_grant", msg)
        for (v in listOf<Any?>("", 5, null, listOf("a"))) {
            val s = sc.withPcactn { it["grant_ref"] = v }
            pre(decide(s, sig(), header = s.header), 401, "invalid_grant", msg)
        }
    }

    @Test
    fun signatureOnlyRefusesAnUnknownOrFailingGrant() {
        val msg = "grant_ref does not resolve to a known grant"
        val unknown = sc.withPcactn { it["grant_ref"] = "no-such-grant" }
        pre(decide(unknown, sig(), header = unknown.header), 401, "invalid_grant", msg, doc = "$REF#grant_ref")
        // a throwing resolver is "not found", never an allow
        val throwing = PcaGuardConfig(sc.audience, { throw IllegalStateException("db down") }, null, null, true, { sc.now })
        pre(decide(sc, throwing), 401, "invalid_grant", msg, doc = "$REF#grant_ref")
    }

    @Test
    fun signatureOnlyDenialHasTheVerdictBody() {
        val bad = sc.withPcactn { it["sig"] = "A".repeat(86) }
        val o = decide(bad, sig(bad), header = bad.header)
        assertFalse(o.allowed)
        assertEquals(403, o.status)
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", o.wwwAuthenticate)
        assertEquals("deny", o.decision)
        assertNull(o.authorization)
        val v = o.verdict!!
        assertFalse(v.allow)
        assertTrue(v.reason.isNotEmpty())
        assertEquals(bad.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        val b = GuardFixtures.parse(o.body)
        assertEquals(setOf("error", "error_description", "reason", "checks", "decision", "doc"), b.keys)
        assertEquals("insufficient_authority", b["error"])
        assertEquals(v.reason, b["reason"])
        assertEquals(v.reason, b["error_description"])
        assertEquals(v.checks, b["checks"])
        assertTrue(v.checks.values.contains(false))
        assertEquals("deny", b["decision"])
        assertEquals(explainRefusal(v.reason).docs, b["doc"])
        assertNull(o.operation)
    }
}
