package net.atlasauth.pca.guard

import net.atlasauth.pca.guard.Kill06GuardKit.EMPTY
import net.atlasauth.pca.guard.Kill06GuardKit.MAX
import net.atlasauth.pca.guard.Kill06GuardKit.QUICK
import net.atlasauth.pca.guard.Kill06GuardKit.cfg
import net.atlasauth.pca.guard.Kill06GuardKit.hdr
import net.atlasauth.pca.guard.Kill06GuardKit.padded
import net.atlasauth.pca.guard.Kill06GuardKit.plain
import net.atlasauth.pca.guard.Kill06GuardKit.pre
import net.atlasauth.pca.guard.Kill06GuardKit.utf8
import net.atlasauth.pca.verifier.ArgProvenance
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `PcaGuard.execute` (run-once execution through the operation executor) and `PcaGuard.unreadable`. */
@Suppress("UNCHECKED_CAST")
class Kill06GuardExecuteTest {
    private val sc = GuardFixtures.within()
    private var ran = 0
    private val seen = ArrayList<GuardOutcome>()

    private fun run(
        s: GuardFixtures.Scenario, config: PcaGuardConfig, header: String? = s.header, esc: String? = null, body: ByteArray = EMPTY,
        op: Authorize.Operation? = s.operation, wf: Authorize.WorkflowStep? = null, prov: String? = s.provenanceHeader,
        fn: (GuardOutcome) -> Any? = { "done" },
    ): GuardRun = PcaGuard.execute(config, header, esc, body, op, wf, prov) { o ->
        ran++
        seen.add(o)
        fn(o)
    }

    private fun conf(
        s: GuardFixtures.Scenario = sc, ex: PcaExecutorConfig? = GuardFixtures.executor(), az: Authorize.AuthorizeOptions? = GuardFixtures.options(),
        ip: Pca.IntentPolicy? = null, clock: () -> Long = { s.now },
    ): PcaGuardConfig = cfg(s, az, ip = ip, executor = ex, clock = clock)

    private fun stale(s: GuardFixtures.Scenario, state: String, ageMs: Long, error: String? = "test"): Operations.Store {
        val store = Operations.MemoryStore()
        val op = s.operation
        val rec = linkedMapOf<String, Any?>(
            "id" to Pca.hashCanonical(s.pcactn), "state" to state, "verb" to op.verb, "resource" to op.resource,
            "params_digest" to Pca.paramsDigest(op.params), "reversibility" to "irreversible", "startedAt" to s.now - ageMs, "executingAt" to s.now - ageMs,
        )
        if (error != null) rec["error"] = error
        store.create(rec)
        return store
    }

    // ---- configuration and extraction ----

    @Test
    fun withoutAnExecutorEverythingIsRefusedAndNothingRuns() {
        val r = run(sc, conf(ex = null))
        assertNull(r.result)
        assertFalse(r.replayed)
        pre(r.refusal!!, 403, "authorize_config", "authorize_config: no executor is configured (fail closed)", doc = QUICK)
        assertEquals(0, ran)
    }

    @Test
    fun anUnreadableProofIsRefusedBeforeAnythingRuns() {
        val r = run(sc, conf(), header = "not base64url!")
        assertNull(r.result)
        assertFalse(r.replayed)
        pre(r.refusal!!, 401, "invalid_request", "PCA-Action is not canonical base64url")
        pre(run(sc, conf(), header = null).refusal!!, 401, null, "no PCA-Action header and no PCActn body")
        pre(run(sc, conf(), header = hdr("[1]")).refusal!!, 401, "invalid_request", "PCActn is not a JSON object")
        assertEquals(0, ran)
    }

    @Test
    fun aThrowingClockFailsClosed() {
        val r = run(sc, conf(clock = { throw IllegalStateException("clock") }))
        assertNull(r.result)
        assertFalse(r.replayed)
        pre(r.refusal!!, 403, "insufficient_authority", "guard error (fail closed)")
        assertEquals(0, ran)
    }

    // ---- the run itself ----

    @Test
    fun anAllowRunsTheHandlerOnceWithTheBoundOperation() {
        val classes = ArrayList<Authorize.Operation>()
        val ex = PcaExecutorConfig(Operations.MemoryStore(), { Operations.Recheck.OK }, "irreversible", { classes.add(it); "irreversible" })
        val first = run(sc, conf(ex = ex))
        assertNull(first.refusal)
        assertFalse(first.replayed)
        assertEquals("done", first.result)
        assertEquals(1, ran)
        // the executor asked the server's catalog for the operation's class
        assertEquals(listOf(sc.operation), classes)
        val o = seen.single()
        assertTrue(o.allowed)
        assertEquals(200, o.status)
        assertNull(o.wwwAuthenticate)
        assertEquals("", o.body)
        assertEquals("allow", o.decision)
        assertNull(o.authorization)
        assertNull(o.verdict)
        assertEquals(sc.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        assertEquals(sc.operation.verb, o.boundOperation!!.verb)
        assertEquals(sc.operation.resource, o.boundOperation!!.resource)
        assertEquals(Pca.hashCanonical(sc.pcactn), o.idempotencyKey)
        assertEquals(o.boundOperation, o.operation)
        assertEquals(o.idempotencyKey, o.boundOperation!!.id)
    }

    @Test
    fun aRetryIsAnsweredFromTheRecordWithoutRunningAgain() {
        val c = conf()
        assertEquals("done", run(sc, c).result)
        val again = run(sc, c, fn = { "second" })
        assertNull(again.refusal)
        assertTrue(again.replayed)
        assertEquals("done", again.result)
        assertEquals(1, ran)
    }

    @Test
    fun aHandlerThatThrowsIs500WithoutAChallenge() {
        val r = run(sc, conf(), fn = { throw IllegalStateException("secret-detail") })
        assertNull(r.result)
        assertFalse(r.replayed)
        plain(r.refusal!!, 500, "operation_failed", "the operation failed")
        assertFalse(r.refusal!!.body.contains("secret-detail"))
        assertEquals(1, ran)
    }

    @Test
    fun aDeniedAuthorizationIsTheDenialBody() {
        val bad = GuardFixtures.overLimit()
        val r = run(bad, conf(bad))
        assertNull(r.result)
        assertFalse(r.replayed)
        val o = r.refusal!!
        assertFalse(o.allowed)
        assertEquals(403, o.status)
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", o.wwwAuthenticate)
        assertEquals("deny", o.decision)
        val b = GuardFixtures.parse(o.body)
        assertEquals(setOf("error", "error_description", "reason", "checks", "decision", "doc"), b.keys)
        assertEquals(o.authorization!!.reason, b["reason"])
        assertEquals(o.authorization!!.checks, b["checks"])
        assertNotNull(o.verdict)
        assertEquals(bad.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        assertEquals(0, ran)

        val wrong = GuardFixtures.wrongAudience()
        val u = run(wrong, conf(wrong)).refusal!!
        assertEquals(401, u.status)
        assertEquals("PCA realm=\"pca\", error=\"invalid_pcactn\"", u.wwwAuthenticate)
        assertEquals(0, ran)
    }

    @Test
    fun aDenialWithoutAReadablePcactnReportsTheRequestOne() {
        // the operation cannot be mapped: authorize refuses before reading the proof, the guard reports the proof it extracted
        val o = run(sc, conf(), op = null).refusal!!
        assertEquals(403, o.status)
        assertTrue(o.authorization!!.reason!!, o.authorization!!.reason!!.startsWith("operation:"))
        assertEquals(sc.pcactn["grant_ref"], o.pcactn!!["grant_ref"])
        // a body pcactn that is not an object has none to report
        val bodyOnly = utf8(Json.canonicalize(linkedMapOf<String, Any?>("pcactn" to "x")))
        val missing = PcaGuard.execute(
            PcaGuardConfig(sc.audience, { null }, GuardFixtures.options(), null, false, { sc.now }, GuardFixtures.executor()), null, null, bodyOnly, sc.operation, null, null,
        ) { "done" }
        assertNull(missing.refusal!!.pcactn)
        assertEquals(0, ran)
    }

    // ---- the executor's other outcomes ----

    @Test
    fun anInFlightOperationIs409InProgress() {
        val r = run(sc, conf(ex = GuardFixtures.executor(GuardFixtures.storeWith(sc, "executing"))))
        assertNull(r.result)
        assertFalse(r.replayed)
        plain(r.refusal!!, 409, "operation_in_progress", "another execution of this operation is in flight")
        assertEquals(0, ran)
    }

    @Test
    fun anUnknownOutcomeIs409UncertainWithTheRecordedReason() {
        val r = run(sc, conf(ex = GuardFixtures.executor(GuardFixtures.storeWith(sc, "uncertain"))))
        assertNull(r.result)
        assertFalse(r.replayed)
        plain(r.refusal!!, 409, "operation_uncertain", "test")
        assertEquals(0, ran)
        val noText = run(sc, conf(ex = GuardFixtures.executor(stale(sc, "uncertain", 10, error = null))))
        plain(noText.refusal!!, 409, "operation_uncertain", "outcome unknown")
        assertEquals(0, ran)
    }

    @Test
    fun aRefusedRecheckIs403AbortedWithItsReason() {
        val ex = GuardFixtures.executor(recheck = { Operations.Recheck.refuse("approval withdrawn") })
        val r = run(sc, conf(ex = ex))
        assertNull(r.result)
        assertFalse(r.replayed)
        plain(r.refusal!!, 403, "operation_aborted", "recheck: approval withdrawn")
        assertEquals(0, ran)
    }

    @Test
    fun anAbortedRecordWithoutTextIsJustAborted() {
        val r = run(sc, conf(ex = GuardFixtures.executor(stale(sc, "aborted", 10, error = null))))
        plain(r.refusal!!, 403, "operation_aborted", "aborted")
    }

    @Test
    fun theExecutorsPendingTimeoutIsTheConfiguredOne() {
        // 1 s old: in flight under the default (5 min) ...
        val flight = run(sc, conf(ex = GuardFixtures.executor(stale(sc, "executing", 1000))))
        plain(flight.refusal!!, 409, "operation_in_progress")
        // ... settled uncertain under a 500 ms timeout
        val short = PcaExecutorConfig(stale(sc, "executing", 1000), { Operations.Recheck.OK }, "irreversible", null, 500.0)
        plain(run(sc, conf(ex = short)).refusal!!, 409, "operation_uncertain")
        // a claim that never started is aborted under the short timeout and in flight under the default
        val claim = PcaExecutorConfig(stale(sc, "pending", 1000), { Operations.Recheck.OK }, "irreversible", null, 500.0)
        plain(run(sc, conf(ex = claim)).refusal!!, 403, "operation_aborted")
        plain(run(sc, conf(ex = GuardFixtures.executor(stale(sc, "pending", 1000)))).refusal!!, 409, "operation_in_progress")
        assertEquals(0, ran)
    }

    // ---- body, provenance and size ----

    @Test
    fun theProvenanceOfTheBodyIsUsedWhenNoHeaderCarriesIt() {
        val r = run(sc, conf(), body = utf8(sc.body), prov = null)
        assertNull(r.refusal)
        assertEquals("done", r.result)
        assertEquals(1, ran)
        // with neither header nor body bundle a sensitive operation is not run
        val none = run(GuardFixtures.within(), conf(GuardFixtures.within()), prov = null)
        assertNotNull(none.refusal)
        assertEquals(1, ran)
    }

    @Test
    fun theBodyLimitAppliesToTheOperation() {
        val atLimit = run(sc, conf(), body = ByteArray(MAX))
        assertNull(atLimit.refusal)
        assertEquals(1, ran)
        val s2 = GuardFixtures.within()
        val over = run(s2, conf(s2), body = ByteArray(MAX + 1))
        assertEquals(403, over.refusal!!.status)
        assertTrue(over.refusal!!.authorization!!.reason!!, over.refusal!!.authorization!!.reason!!.startsWith("operation:"))
        assertEquals(1, ran)
        val s3 = GuardFixtures.within()
        val prov = run(s3, conf(s3), body = padded(s3, MAX), prov = null)
        assertNull(prov.refusal)
        assertEquals(2, ran)
    }

    @Test
    fun anActiveIntentPolicyIsEnforced() {
        val r = run(sc, conf(ip = Pca.IntentPolicy(require = true)))
        assertNotNull(r.refusal)
        assertEquals(403, r.refusal!!.status)
        assertEquals(0, ran)
        assertNull(run(sc, conf()).refusal)
    }

    // ---- escalation answers ----

    private fun escalate(header: String?, body: ByteArray = EMPTY, principals: Boolean = true): GuardRun {
        val e = GuardFixtures.escalating()
        val az = if (principals) GuardFixtures.options(GuardFixtures.principals()) else GuardFixtures.options()
        return run(e, conf(e, az = az), esc = header, body = body)
    }

    private val answer get() = GuardFixtures.signedAllow(GuardFixtures.escalating())
    private fun answerBody(): ByteArray = utf8(Json.canonicalize(linkedMapOf<String, Any?>("escalation_answer" to answer)))

    @Test
    fun aSignedAnswerAdmitsFromTheHeaderOrTheBody() {
        assertNull(escalate(GuardFixtures.headerOf(answer)).refusal)
        assertNull(escalate(null, answerBody()).refusal)
        assertNull(escalate("", answerBody()).refusal)
        assertEquals(3, ran)
    }

    @Test
    fun withoutAnAnswerTheEscalateStandsAndIsNeverRun() {
        for (r in listOf(escalate(null), escalate("!!"), escalate(null, utf8("{}")), escalate(null, answerBody(), principals = false), escalate(GuardFixtures.headerOf(answer), principals = false))) {
            val o = r.refusal!!
            assertEquals(403, o.status)
            assertEquals("escalate", o.decision)
            assertEquals("escalate", GuardFixtures.parse(o.body)["decision"])
            assertTrue(o.authorization!!.reasons.none { it.startsWith("escalation: no principal") })
        }
        assertEquals(0, ran)
        val unpinned = escalate(GuardFixtures.headerOf(answer), principals = false).refusal!!
        assertTrue(unpinned.authorization!!.reasons.toString(), unpinned.authorization!!.reasons.none { it.startsWith("escalation:") })
    }

    // ---- the K5 workflow step ----

    private fun wfConf(c: GuardFixtures.WorkflowCall) = conf(c.scenario, az = GuardFixtures.workflowOptions())

    @Test
    fun aWorkflowStepFromTheBodyOrTheCallbackIsAdmitted() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 1)
        val viaBody = run(c.scenario, wfConf(c), header = null, body = utf8(c.body), prov = null)
        assertNull(viaBody.refusal)
        val (c2, _) = GuardFixtures.workflowCall("pay-after-quote", 1)
        val viaCallback = run(c2.scenario, wfConf(c2), wf = c2.step)
        assertNull(viaCallback.refusal)
        assertEquals(2, ran)
    }

    @Test
    fun aWorkflowStepThatBreaksAnEdgeIsRefusedWithTheGateReason() {
        val (c, _) = GuardFixtures.workflowCall("amount-over-the-quote")
        val viaBody = run(c.scenario, wfConf(c), header = null, body = utf8(c.body), prov = null).refusal!!
        assertEquals(403, viaBody.status)
        assertEquals("workflow: edge_relation (step pay)", GuardFixtures.parse(viaBody.body)["reason"])
        val (c2, _) = GuardFixtures.workflowCall("amount-over-the-quote")
        val viaCallback = run(c2.scenario, wfConf(c2), wf = c2.step).refusal!!
        assertEquals("workflow: edge_relation (step pay)", GuardFixtures.parse(viaCallback.body)["reason"])
        // the explicit step is the one used, not the member of an envelope that carries another
        val (ok, _) = GuardFixtures.workflowCall("pay-after-quote", 1)
        val both = run(
            ok.scenario, wfConf(ok), header = null, prov = null, wf = ok.step,
            body = utf8(Json.canonicalize(linkedMapOf<String, Any?>("pcactn" to ok.scenario.pcactn, ArgProvenance.BODY_MEMBER to GuardFixtures.provenance(ok.scenario.operation), "workflow" to 5))),
        )
        assertNull(both.refusal)
        assertEquals(1, ran) // allowed: the handler runs once (the two refusals above never ran it)
    }

    // ---- unreadable ----

    @Test
    fun anUnreadableRecordedResultIs409Uncertain() {
        val o = PcaGuard.unreadable()
        plain(o, 409, "operation_uncertain", "the recorded result is unreadable")
    }
}
