package net.atlasauth.pca.spring

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletResponse
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.function.Supplier
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.GuardFixtures.Scenario
import net.atlasauth.pca.guard.GuardOutcome
import net.atlasauth.pca.guard.PcaExecutorConfig
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Operations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/** The servlet filter, the MVC interceptor and the auto-configuration, with grants and PCActns signed by the reference implementation. */
@Suppress("UNCHECKED_CAST")
class PcaSpringTest {
    private fun filter(sc: Scenario, az: Authorize.AuthorizeOptions?, sigOnly: Boolean = false) =
        PcaFilter(sc.config(az, sigOnly), if (sigOnly) null else PcaOperationMapper { _, _ -> sc.operation })

    private fun request(sc: Scenario?, answer: Map<String, Any?>? = null, body: String? = null): MockHttpServletRequest {
        val r = MockHttpServletRequest("POST", "/pay/send")
        if (sc != null && body == null) r.addHeader(PcaGuard.HEADER, sc.header)
        if (answer != null) r.addHeader(PcaGuard.ESCALATION_HEADER, GuardFixtures.headerOf(answer))
        if (body != null) r.setContent(body.toByteArray(Charsets.UTF_8))
        return r
    }

    private class Ran(val res: MockHttpServletResponse, val chain: MockFilterChain) {
        val passed: Boolean get() = chain.request != null
        val outcome: GuardOutcome? get() = chain.request?.getAttribute(PCA_ATTRIBUTE) as? GuardOutcome
        val json: Map<String, Any?> get() = GuardFixtures.parse(res.contentAsString)
    }

    private fun run(f: PcaFilter, r: MockHttpServletRequest): Ran {
        val res = MockHttpServletResponse()
        val chain = MockFilterChain()
        f.doFilter(r, res, chain)
        return Ran(res, chain)
    }

    @Test
    fun noAuthorizeConfigurationIsRefusedWithAuthorizeConfig() {
        val sc = GuardFixtures.within()
        val ran = run(filter(sc, null), request(sc))
        assertFalse(ran.passed)
        assertEquals(403, ran.res.status)
        assertTrue(ran.res.contentAsString, ran.res.contentAsString.contains("authorize_config: missing required component(s)"))
        assertTrue(ran.res.getHeader("WWW-Authenticate")!!.startsWith("PCA realm=\"pca\""))
    }

    @Test
    fun missingProofIs401() {
        val sc = GuardFixtures.within()
        val ran = run(filter(sc, GuardFixtures.options()), request(null))
        assertFalse(ran.passed)
        assertEquals(401, ran.res.status)
        assertEquals("PCA realm=\"pca\"", ran.res.getHeader("WWW-Authenticate"))
    }

    @Test
    fun badSignatureIs401() {
        val sc = GuardFixtures.within().withPcactn { it["sig"] = "A".repeat(86) }
        val ran = run(filter(sc, GuardFixtures.options()), request(sc))
        assertFalse(ran.passed)
        assertEquals(401, ran.res.status)
        assertTrue(ran.res.getHeader("WWW-Authenticate")!!.contains("invalid_pcactn"))
    }

    @Test
    fun validProofContinuesTheChainWithTheVerdictAndTheOperation() {
        val sc = GuardFixtures.within()
        val ran = run(filter(sc, GuardFixtures.options()), request(sc))
        assertTrue(ran.res.contentAsString, ran.passed)
        val o = ran.outcome!!
        assertTrue(o.allowed)
        assertEquals("allow", o.decision)
        assertEquals("payments.send", o.operation!!.verb)
        assertEquals(true, o.verdict!!.allow)
        assertNotNull(o.pcactn)
    }

    @Test
    fun bodyTransportIsAcceptedAndTheBodyStaysReadable() {
        val sc = GuardFixtures.within()
        val ran = run(filter(sc, GuardFixtures.options()), request(sc, body = sc.body))
        assertTrue(ran.res.contentAsString, ran.passed)
        assertEquals(sc.body, String(ran.chain.request!!.inputStream.readAllBytes(), Charsets.UTF_8))
    }

    @Test
    fun replayIsRefusedAndTheChainRunsOnce() {
        val sc = GuardFixtures.within()
        val f = filter(sc, GuardFixtures.options())
        assertTrue(run(f, request(sc)).passed)
        val again = run(f, request(sc))
        assertFalse(again.passed)
        assertEquals(403, again.res.status)
        assertTrue(again.res.contentAsString.contains("replay"))
    }

    @Test
    fun paramsVerbAndAudienceMismatch() {
        for (sc in listOf(GuardFixtures.overLimit(), GuardFixtures.otherVerb())) {
            val ran = run(filter(sc, GuardFixtures.options()), request(sc))
            assertFalse(ran.passed)
            assertEquals(403, ran.res.status)
        }
        val wa = GuardFixtures.wrongAudience()
        val ran = run(filter(wa, GuardFixtures.options()), request(wa))
        assertFalse(ran.passed)
        assertEquals(401, ran.res.status)
    }

    @Test
    fun escalateIsRefusedWithTheRequestAndNeverAnAllow() {
        val sc = GuardFixtures.escalating()
        val ran = run(filter(sc, GuardFixtures.options(GuardFixtures.principals())), request(sc))
        assertFalse(ran.passed)
        assertEquals(403, ran.res.status)
        assertEquals("escalate", ran.json["decision"])
        assertEquals("pca-escalation-request", (ran.json["escalation"] as Map<String, Any?>)["kind"])
    }

    @Test
    fun aValidSignedAnswerReEntersAndIsSpentOnce() {
        val sc = GuardFixtures.escalating()
        val answer = GuardFixtures.signedAllow(sc)
        val f = filter(sc, GuardFixtures.options(GuardFixtures.principals()))
        val ok = run(f, request(sc, answer))
        assertTrue(ok.res.contentAsString, ok.passed)
        assertEquals("allow", ok.outcome!!.decision)
        val again = run(f, request(sc, answer))
        assertFalse(again.passed)
        assertEquals("escalate", again.json["decision"])
    }

    @Test
    fun signatureOnlyIsAnExplicitOptIn() {
        val sc = GuardFixtures.overLimit()
        assertTrue(run(filter(sc, null, sigOnly = true), request(sc)).passed) // the policy is not enforced in this mode
        val bad = GuardFixtures.within().withPcactn { it["sig"] = "A".repeat(86) }
        val ran = run(filter(bad, null, sigOnly = true), request(bad))
        assertFalse(ran.passed)
        assertEquals(403, ran.res.status)
        try {
            PcaGuardConfig(sc.audience, { null }, GuardFixtures.options(), null, true)
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertNotNull(e.message)
        }
    }

    @Test
    fun aNullOrThrowingMapperDenies() {
        val sc = GuardFixtures.within()
        for (m in listOf(PcaOperationMapper { _, _ -> null }, PcaOperationMapper { _, _ -> throw IllegalStateException("x") })) {
            val ran = run(PcaFilter(sc.config(GuardFixtures.options()), m), request(sc))
            assertFalse(ran.passed)
            assertEquals(403, ran.res.status)
        }
    }

    // ---- the MVC interceptor (header transport only) ----

    @Test
    fun interceptorAllowsAndRefuses() {
        val sc = GuardFixtures.within()
        val i = PcaInterceptor(sc.config(GuardFixtures.options()), PcaOperationMapper { _, _ -> sc.operation })
        val ok = MockHttpServletRequest("GET", "/pay/send")
        ok.addHeader(PcaGuard.HEADER, sc.header)
        assertTrue(i.preHandle(ok, MockHttpServletResponse(), Any()))
        assertEquals("payments.send", (ok.getAttribute(PCA_ATTRIBUTE) as GuardOutcome).operation!!.verb)
        val replay = MockHttpServletRequest("GET", "/pay/send")
        replay.addHeader(PcaGuard.HEADER, sc.header)
        val res = MockHttpServletResponse()
        assertFalse(i.preHandle(replay, res, Any()))
        assertEquals(403, res.status)
        val none = MockHttpServletResponse()
        assertFalse(i.preHandle(MockHttpServletRequest("GET", "/pay/send"), none, Any()))
        assertEquals(401, none.status)
        assertNull(replay.getAttribute(PCA_ATTRIBUTE))
    }

    @Test
    fun interceptorWithoutAuthorizeOptionsRefusesEverything() {
        val sc = GuardFixtures.within()
        val req = MockHttpServletRequest("GET", "/pay/send")
        req.addHeader(PcaGuard.HEADER, sc.header)
        val res = MockHttpServletResponse()
        assertFalse(PcaInterceptor(sc.config(null)).preHandle(req, res, Any()))
        assertEquals(403, res.status)
        assertTrue(res.contentAsString.contains("authorize_config"))
    }

    // ---- the auto-configuration ----

    private fun runner(sc: Scenario) = WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(PcaAutoConfiguration::class.java))
        .withBean(Clock::class.java, Supplier { Clock.fixed(Instant.ofEpochMilli(sc.now), ZoneOffset.UTC) })

    @Test
    fun autoConfigurationIsOffUnlessEnabled() {
        runner(GuardFixtures.within()).run { ctx -> assertTrue(ctx.getBeansOfType(PcaFilter::class.java).isEmpty()) }
    }

    @Test
    fun enabledWithoutComponentsRefusesEverything() {
        val sc = GuardFixtures.within()
        runner(sc).withPropertyValues("atlas.pca.enabled=true", "atlas.pca.audience=${sc.audience}").run { ctx ->
            val ran = run(ctx.getBean(PcaFilter::class.java), request(sc))
            assertFalse(ran.passed)
            assertEquals(403, ran.res.status)
            assertTrue(ran.res.contentAsString.contains("authorize_config"))
            assertEquals(listOf("/*"), ctx.getBean(FilterRegistrationBean::class.java).urlPatterns.toList())
        }
    }

    @Test
    fun enabledWithBeansEnforcesThePipeline() {
        val sc = GuardFixtures.within()
        runner(sc)
            .withPropertyValues("atlas.pca.enabled=true", "atlas.pca.audience=${sc.audience}", "atlas.pca.url-patterns=/pay/*")
            .withBean(PcaGrantResolver::class.java, Supplier { PcaGrantResolver { ref -> if (ref == sc.grant["id"]) sc.grant else null } })
            .withBean(Authorize.AuthorizeOptions::class.java, Supplier { GuardFixtures.options() })
            .withBean(PcaOperationMapper::class.java, Supplier { PcaOperationMapper { _, _ -> sc.operation } })
            .run { ctx ->
                val f = ctx.getBean(PcaFilter::class.java)
                assertEquals(listOf("/pay/*"), ctx.getBean(FilterRegistrationBean::class.java).urlPatterns.toList())
                assertTrue(run(f, request(sc)).passed)
                assertEquals(403, run(f, request(sc)).res.status) // replay
                assertNotNull(ctx.getBean(PcaInterceptor::class.java))
            }
    }

    // ---- run-once execution (the executor) ----

    private class Handler(val fail: Boolean = false) {
        var runs = 0
        val chain = FilterChain { _, res ->
            runs++
            if (fail) throw IllegalStateException("secret-detail")
            val r = res as HttpServletResponse
            r.status = 201
            r.addHeader("X-Mark", "1")
            r.contentType = "text/plain"
            r.outputStream.write("created".toByteArray(Charsets.UTF_8))
        }
    }

    private fun runWith(f: PcaFilter, r: MockHttpServletRequest, h: Handler): MockHttpServletResponse {
        val res = MockHttpServletResponse()
        f.doFilter(r, res, h.chain)
        return res
    }

    private fun execFilter(sc: Scenario, executor: PcaExecutorConfig) =
        PcaFilter(sc.config(GuardFixtures.options(), executor = executor), PcaOperationMapper { _, _ -> sc.operation })

    @Test
    fun anExecutorRunsTheHandlerOnceAndAnswersARetryFromTheRecord() {
        val sc = GuardFixtures.within()
        val f = execFilter(sc, GuardFixtures.executor())
        val h = Handler()
        val first = runWith(f, request(sc), h)
        assertEquals(first.contentAsString, 201, first.status)
        assertEquals("created", first.contentAsString)
        assertEquals("1", first.getHeader("X-Mark"))
        assertNull(first.getHeader("PCA-Replayed"))
        val again = runWith(f, request(sc), h)
        assertEquals(201, again.status)
        assertEquals("created", again.contentAsString)
        assertEquals("1", again.getHeader("X-Mark"))
        assertEquals("true", again.getHeader("PCA-Replayed"))
        assertEquals(1, h.runs)
    }

    @Test
    fun aHandlerFailureIs500WithoutTheErrorText() {
        val sc = GuardFixtures.within()
        val f = execFilter(sc, GuardFixtures.executor())
        val h = Handler(fail = true)
        val res = runWith(f, request(sc), h)
        assertEquals(500, res.status)
        assertEquals("operation_failed", GuardFixtures.parse(res.contentAsString)["error"])
        assertFalse(res.contentAsString, res.contentAsString.contains("secret-detail"))
        assertNull(res.getHeader("WWW-Authenticate"))
        assertEquals(500, runWith(f, request(sc), h).status) // recorded: not run again
        assertEquals(1, h.runs)
    }

    @Test
    fun anInFlightOperationIs409AndAnUnknownOutcomeIs409Uncertain() {
        val sc = GuardFixtures.within()
        for ((state, code) in listOf("executing" to "operation_in_progress", "uncertain" to "operation_uncertain")) {
            val h = Handler()
            val res = runWith(execFilter(sc, GuardFixtures.executor(GuardFixtures.storeWith(sc, state))), request(sc), h)
            assertEquals(409, res.status)
            assertEquals(code, GuardFixtures.parse(res.contentAsString)["error"])
            assertEquals(0, h.runs)
        }
    }

    @Test
    fun aRefusedRecheckIs403Aborted() {
        val sc = GuardFixtures.within()
        val h = Handler()
        val res = runWith(execFilter(sc, GuardFixtures.executor(recheck = { Operations.Recheck.refuse("approval withdrawn") })), request(sc), h)
        assertEquals(403, res.status)
        assertEquals("operation_aborted", GuardFixtures.parse(res.contentAsString)["error"])
        assertEquals(0, h.runs)
    }

    @Test
    fun anExecutorStillDeniesWhatAuthorizeDenies() {
        val sc = GuardFixtures.overLimit()
        val h = Handler()
        assertEquals(403, runWith(execFilter(sc, GuardFixtures.executor()), request(sc), h).status)
        assertEquals(0, h.runs)
    }

    @Test
    fun anExecutorCannotRunInsideTheInterceptor() {
        val sc = GuardFixtures.within()
        val i = PcaInterceptor(sc.config(GuardFixtures.options(), executor = GuardFixtures.executor()), PcaOperationMapper { _, _ -> sc.operation })
        try {
            i.preHandle(request(sc), MockHttpServletResponse(), Any())
            fail("expected IllegalStateException")
        } catch (e: IllegalStateException) {
            assertNotNull(e.message)
        }
    }

    // ---- K5 workflow admission (the fixture cases of authorize-workflow-fixtures.json) ----

    private fun wfFilter(c: GuardFixtures.WorkflowCall, az: Authorize.AuthorizeOptions, viaCallback: Boolean) =
        PcaFilter(
            c.scenario.config(az), PcaOperationMapper { _, _ -> c.scenario.operation },
            if (viaCallback) PcaWorkflowStepMapper { _, _ -> c.step } else null,
        )

    @Test
    fun workflowStepFromTheMapperOrTheBodyMemberPasses() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        assertTrue(run(wfFilter(c, GuardFixtures.workflowOptions(), true), request(c.scenario)).passed)
        val viaBody = run(wfFilter(c, GuardFixtures.workflowOptions(), false), request(null, body = c.body))
        assertTrue(viaBody.res.contentAsString, viaBody.passed)
    }

    @Test
    fun workflowStepViolatingAnEdgeIs403() {
        val (c, _) = GuardFixtures.workflowCall("amount-over-the-quote")
        val byMapper = run(wfFilter(c, GuardFixtures.workflowOptions(), true), request(c.scenario))
        val byBody = run(wfFilter(c, GuardFixtures.workflowOptions(), false), request(null, body = c.body))
        for (ran in listOf(byMapper, byBody)) {
            assertFalse(ran.passed)
            assertEquals(403, ran.res.status)
            assertTrue(ran.res.contentAsString, ran.res.contentAsString.contains("workflow: edge_relation (step pay)"))
        }
    }

    @Test
    fun workflowRequiredAndAbsentIs403() {
        val (c, required) = GuardFixtures.workflowCall("workflow-required-but-absent")
        assertTrue(required)
        val ran = run(wfFilter(c, GuardFixtures.workflowOptions(required = true), true), request(c.scenario))
        assertFalse(ran.passed)
        assertEquals(403, ran.res.status)
        assertTrue(ran.res.contentAsString, ran.res.contentAsString.contains("workflow: this call carries no workflow step (fail closed)"))
    }

    @Test
    fun aThrowingWorkflowMapperIsARefusedStepNotNoStep() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        val f = PcaFilter(
            c.scenario.config(GuardFixtures.workflowOptions()), PcaOperationMapper { _, _ -> c.scenario.operation },
            PcaWorkflowStepMapper { _, _ -> error("boom") },
        )
        val ran = run(f, request(c.scenario))
        assertFalse(ran.passed)
        assertEquals(403, ran.res.status)
    }

    @Test
    fun theInterceptorTakesTheWorkflowStepFromTheMapper() {
        val (c, _) = GuardFixtures.workflowCall("amount-over-the-quote")
        val i = PcaInterceptor(
            c.scenario.config(GuardFixtures.workflowOptions()), PcaOperationMapper { _, _ -> c.scenario.operation }, PcaWorkflowStepMapper { _, _ -> c.step },
        )
        val res = MockHttpServletResponse()
        assertFalse(i.preHandle(request(c.scenario), res, Any()))
        assertEquals(403, res.status)
        assertTrue(res.contentAsString, res.contentAsString.contains("workflow: edge_relation (step pay)"))
    }

    @Test
    fun noWorkflowOptionChangesNothing() {
        val (c, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        assertTrue(run(wfFilter(c, GuardFixtures.workflowOptions(gate = false), true), request(c.scenario)).passed)
    }
}
