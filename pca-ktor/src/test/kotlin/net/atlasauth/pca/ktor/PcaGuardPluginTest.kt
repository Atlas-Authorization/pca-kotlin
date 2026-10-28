package net.atlasauth.pca.ktor

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.GuardFixtures.Scenario
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.guard.explainRefusal
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Operations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The Ktor plugin end to end over `testApplication`: grants and PCActns signed by the reference implementation. */
@Suppress("UNCHECKED_CAST")
class PcaGuardPluginTest {
    private val ran = AtomicInteger(0)

    private fun PcaKtorConfig.setup(sc: Scenario, az: Authorize.AuthorizeOptions?, sigOnly: Boolean = false) {
        audience = sc.audience
        resolveGrant = { ref -> if (ref == sc.grant["id"]) sc.grant else null }
        authorize = az
        signatureOnly = sigOnly
        clock = { sc.now }
        if (!sigOnly) operation = { _, _ -> sc.operation }
    }

    private fun app(cfg: PcaKtorConfig.() -> Unit, block: suspend ApplicationTestBuilder.() -> Unit) = runBlocking {
        testApplication {
            application {
                routing {
                    route("/pay") {
                        install(PcaGuardPlugin, cfg)
                        get("/send") {
                            ran.incrementAndGet()
                            val o = call.pca!!
                            call.respondText("ran:${o.operation?.verb}:${o.verdict?.allow}:${o.decision}:${o.pcactn != null}")
                        }
                        get("/boom") {
                            ran.incrementAndGet()
                            error("secret-detail")
                        }
                        post("/send") {
                            ran.incrementAndGet()
                            call.respondText("ran:${call.pca!!.operation?.verb}")
                        }
                    }
                }
            }
            block()
        }
    }

    private suspend fun ApplicationTestBuilder.send(sc: Scenario, answer: Map<String, Any?>? = null): HttpResponse =
        client.get("/pay/send") {
            header(PcaGuard.HEADER, sc.header)
            if (answer != null) header(PcaGuard.ESCALATION_HEADER, GuardFixtures.headerOf(answer))
        }

    @Test
    fun noAuthorizeConfigurationIsRefusedWithAuthorizeConfig() {
        val sc = GuardFixtures.within()
        app({ setup(sc, null) }) {
            val r = send(sc)
            assertEquals(403, r.status.value)
            val body = r.bodyAsText()
            assertTrue(body, body.contains("authorize_config: missing required component(s)"))
            assertTrue(body, body.contains("stateStore"))
            assertTrue(r.headers["WWW-Authenticate"]!!.startsWith("PCA realm=\"pca\""))
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun missingProofIs401WithAChallenge() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = client.get("/pay/send")
            assertEquals(401, r.status.value)
            assertEquals("PCA realm=\"pca\"", r.headers["WWW-Authenticate"])
            // every refusal body names the page that explains it; the reason strings are unchanged
            val body = GuardFixtures.parse(r.bodyAsText())
            assertEquals("pca_required", body["error"])
            assertEquals("https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md", body["doc"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun undecodableHeaderIs401() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = client.get("/pay/send") { header(PcaGuard.HEADER, "not base64url!") }
            assertEquals(401, r.status.value)
            assertEquals("PCA realm=\"pca\", error=\"invalid_request\"", r.headers["WWW-Authenticate"])
        }
    }

    @Test
    fun badSignatureIs401() {
        val sc = GuardFixtures.within().withPcactn { it["sig"] = "A".repeat(86) }
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = send(sc)
            assertEquals(401, r.status.value)
            assertTrue(r.headers["WWW-Authenticate"]!!.contains("invalid_pcactn"))
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun wrongAudienceIs401() {
        val sc = GuardFixtures.wrongAudience()
        app({ setup(sc, GuardFixtures.options()) }) {
            assertEquals(401, send(sc).status.value)
        }
    }

    @Test
    fun validProofRunsTheHandlerWhichSeesTheVerdictAndTheOperation() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = send(sc)
            assertEquals(r.bodyAsText(), 200, r.status.value)
            assertEquals("ran:payments.send:true:allow:true", r.bodyAsText())
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun bodyTransportIsAccepted() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = client.post("/pay/send") { setBody(sc.body) }
            assertEquals(r.bodyAsText(), 200, r.status.value)
            assertEquals("ran:payments.send", r.bodyAsText())
        }
    }

    @Test
    fun replayIsRefusedAndTheHandlerRunsOnce() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()) }) {
            assertEquals(200, send(sc).status.value)
            val again = send(sc)
            assertEquals(403, again.status.value)
            assertTrue(again.bodyAsText(), again.bodyAsText().contains("replay"))
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun paramsAndVerbMismatchAre403() {
        for (sc in listOf(GuardFixtures.overLimit(), GuardFixtures.otherVerb())) {
            app({ setup(sc, GuardFixtures.options()) }) {
                val r = send(sc)
                assertEquals(403, r.status.value)
                val body = GuardFixtures.parse(r.bodyAsText())
                val reason = body["reason"] as String
                assertEquals(explainRefusal(reason).docs, body["doc"])
                assertTrue(body["doc"] as String, (body["doc"] as String).startsWith("https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#"))
            }
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun escalateIsRefusedWithTheRequestAndNeverAnAllow() {
        val sc = GuardFixtures.escalating()
        app({ setup(sc, GuardFixtures.options(GuardFixtures.principals())) }) {
            val r = send(sc)
            assertEquals(403, r.status.value)
            val b = GuardFixtures.parse(r.bodyAsText())
            assertEquals("escalate", b["decision"])
            assertEquals("pca-escalation-request", (b["escalation"] as Map<String, Any?>)["kind"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun aValidSignedAnswerReEntersAndIsSpentOnce() {
        val sc = GuardFixtures.escalating()
        val answer = GuardFixtures.signedAllow(sc)
        app({ setup(sc, GuardFixtures.options(GuardFixtures.principals())) }) {
            val ok = send(sc, answer)
            assertEquals(ok.bodyAsText(), 200, ok.status.value)
            // the core verdict is the pre-answer one (escalate: allow=false); the DECISION is the answered allow
            assertTrue(ok.bodyAsText(), ok.bodyAsText().startsWith("ran:payments.send:false:allow"))
            val again = send(sc, answer)
            val againBody = again.bodyAsText()
            assertEquals("second use of the answer: " + againBody, 403, again.status.value)
            assertEquals("second use of the answer: " + againBody, "escalate", GuardFixtures.parse(againBody)["decision"])
        }
        assertEquals("handler runs", 1, ran.get())
    }

    @Test
    fun anAnswerFromAnUnpinnedPrincipalStaysEscalate() {
        val sc = GuardFixtures.escalating()
        val answer = GuardFixtures.signedAllow(sc)
        app({ setup(sc, GuardFixtures.options()) }) { // no principal pinned: the answer is not even read
            val r = send(sc, answer)
            assertEquals(403, r.status.value)
            assertEquals("escalate", GuardFixtures.parse(r.bodyAsText())["decision"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun signatureOnlyIsAnExplicitOptIn() {
        val sc = GuardFixtures.overLimit()
        app({ setup(sc, null, sigOnly = true) }) {
            // the policy is NOT enforced in this mode: the validly signed $400 passes
            val r = send(sc)
            assertEquals(r.bodyAsText(), 200, r.status.value)
        }
        val bad = GuardFixtures.within().withPcactn { it["sig"] = "A".repeat(86) }
        app({ setup(bad, null, sigOnly = true) }) {
            assertEquals(403, send(bad).status.value)
        }
    }

    @Test
    fun signatureOnlyTogetherWithAuthorizeIsAConfigurationError() {
        val sc = GuardFixtures.within()
        try {
            PcaGuardConfig(sc.audience, { null }, GuardFixtures.options(), null, true)
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertNotNull(e.message)
        }
    }

    @Test
    fun aThrowingOrNullOperationMapperDenies() {
        val sc = GuardFixtures.within()
        for (m in listOf<suspend (io.ktor.server.application.ApplicationCall, ByteArray) -> Authorize.Operation?>({ _, _ -> null }, { _, _ -> throw IllegalStateException("x") })) {
            app({ setup(sc, GuardFixtures.options()); operation = m }) {
                val r = send(sc)
                assertEquals(403, r.status.value)
                assertFalse(r.bodyAsText().contains("ran:"))
            }
        }
        assertEquals(0, ran.get())
    }

    // ---- run-once execution (the executor) ----

    @Test
    fun anExecutorRunsTheHandlerOnceAndAnswersARetryFromTheRecord() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val first = send(sc)
            assertEquals(first.bodyAsText(), 200, first.status.value)
            val text = first.bodyAsText()
            assertTrue(text, text.startsWith("ran:payments.send"))
            assertNull(first.headers["PCA-Replayed"])
            val again = send(sc)
            assertEquals(200, again.status.value)
            assertEquals(text, again.bodyAsText())
            assertEquals("true", again.headers["PCA-Replayed"])
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun aHandlerFailureIs500WithoutTheErrorText() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val r = client.get("/pay/boom") { header(PcaGuard.HEADER, sc.header) }
            assertEquals(500, r.status.value)
            val body = r.bodyAsText()
            assertEquals("operation_failed", GuardFixtures.parse(body)["error"])
            assertFalse(body, body.contains("secret-detail"))
            assertNull(r.headers["WWW-Authenticate"])
            // the failure is recorded: a retry does not run the handler again
            val again = client.get("/pay/boom") { header(PcaGuard.HEADER, sc.header) }
            assertEquals(500, again.status.value)
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun anInFlightOperationIs409AndTheHandlerDoesNotRun() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(GuardFixtures.storeWith(sc, "executing")) }) {
            val r = send(sc)
            assertEquals(409, r.status.value)
            assertEquals("operation_in_progress", GuardFixtures.parse(r.bodyAsText())["error"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun anUnknownOutcomeIs409Uncertain() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(GuardFixtures.storeWith(sc, "uncertain")) }) {
            val r = send(sc)
            assertEquals(409, r.status.value)
            assertEquals("operation_uncertain", GuardFixtures.parse(r.bodyAsText())["error"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun aRefusedRecheckIs403Aborted() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(recheck = { Operations.Recheck.refuse("approval withdrawn") }) }) {
            val r = send(sc)
            assertEquals(403, r.status.value)
            assertEquals("operation_aborted", GuardFixtures.parse(r.bodyAsText())["error"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun anExecutorStillDeniesWhatAuthorizeDenies() {
        val sc = GuardFixtures.overLimit()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            assertEquals(403, send(sc).status.value)
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun anExecutorNeedsAuthorizeOptions() {
        try {
            PcaGuardConfig("a", { null }, null, null, false, { 0L }, GuardFixtures.executor())
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertNotNull(e.message)
        }
    }

    // ---- K5 workflow admission (the fixture cases of authorize-workflow-fixtures.json) ----

    private fun PcaKtorConfig.setupWorkflow(c: GuardFixtures.WorkflowCall, az: Authorize.AuthorizeOptions, viaCallback: Boolean) {
        setup(c.scenario, az)
        if (viaCallback) workflowStep = { _, _ -> c.step }
    }

    @Test
    fun workflowStepFromTheCallbackPasses() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        app({ setupWorkflow(c, GuardFixtures.workflowOptions(), true) }) {
            val r = send(c.scenario)
            assertEquals(r.bodyAsText(), 200, r.status.value)
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun workflowStepFromTheBodyMemberPasses() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        app({ setupWorkflow(c, GuardFixtures.workflowOptions(), false) }) {
            val r = client.post("/pay/send") { setBody(c.body) }
            assertEquals(r.bodyAsText(), 200, r.status.value)
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun workflowStepViolatingAnEdgeIs403() {
        val (c, _) = GuardFixtures.workflowCall("amount-over-the-quote")
        for (viaCallback in listOf(true, false)) {
            app({ setupWorkflow(c, GuardFixtures.workflowOptions(), viaCallback) }) {
                val r = if (viaCallback) send(c.scenario) else client.post("/pay/send") { setBody(c.body) }
                assertEquals(403, r.status.value)
                assertTrue(r.bodyAsText(), r.bodyAsText().contains("workflow: edge_relation (step pay)"))
            }
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun workflowRequiredAndAbsentIs403() {
        val (c, required) = GuardFixtures.workflowCall("workflow-required-but-absent")
        assertTrue(required)
        app({ setupWorkflow(c, GuardFixtures.workflowOptions(required = true), true) }) {
            val r = send(c.scenario)
            assertEquals(403, r.status.value)
            assertTrue(r.bodyAsText(), r.bodyAsText().contains("workflow: this call carries no workflow step (fail closed)"))
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun aThrowingWorkflowCallbackIsARefusedStepNotNoStep() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        app({ setupWorkflow(c, GuardFixtures.workflowOptions(), false); workflowStep = { _, _ -> error("boom") } }) {
            assertEquals(403, send(c.scenario).status.value)
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun noWorkflowOptionChangesNothing() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        // without a gate the step is ignored; the PCActn itself is decided as before
        app({ setupWorkflow(c, GuardFixtures.workflowOptions(gate = false), true) }) {
            val r = send(c.scenario)
            assertEquals(r.bodyAsText(), 200, r.status.value)
        }
        assertEquals(1, ran.get())
    }
}
