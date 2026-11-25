package net.atlasauth.pca.spring

import jakarta.servlet.DispatcherType
import jakarta.servlet.FilterChain
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.lang.reflect.Proxy
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.EnumSet
import java.util.function.Supplier
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.GuardFixtures.Scenario
import net.atlasauth.pca.guard.GuardOutcome
import net.atlasauth.pca.guard.PcaExecutorConfig
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.guard.RecordedResponse
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/** Surface-shard survivors of PcaSpring.kt and PcaAutoConfiguration.kt: the refusal / replay writers, buffering, the cached body and the wiring. */
@Suppress("UNCHECKED_CAST")
class Kill06SpringTest {
    // ---- helpers ----

    private val kt = Class.forName("net.atlasauth.pca.spring.PcaSpringKt")

    private fun writeRefusal(res: HttpServletResponse, out: GuardOutcome) {
        val m = kt.getDeclaredMethod("writeRefusal", HttpServletResponse::class.java, GuardOutcome::class.java)
        m.isAccessible = true
        m.invoke(null, res, out)
    }

    private fun writeRecorded(res: HttpServletResponse, rec: RecordedResponse, replayed: Boolean) {
        val m = kt.getDeclaredMethod("writeRecorded", HttpServletResponse::class.java, RecordedResponse::class.java, java.lang.Boolean.TYPE)
        m.isAccessible = true
        m.invoke(null, res, rec, replayed)
    }

    private fun request(sc: Scenario?, answer: Map<String, Any?>? = null, body: String? = null, method: String = "POST"): MockHttpServletRequest {
        val r = MockHttpServletRequest(method, "/pay/send")
        if (sc != null && body == null) {
            r.addHeader(PcaGuard.HEADER, sc.header)
            r.addHeader(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
        }
        if (answer != null) r.addHeader(PcaGuard.ESCALATION_HEADER, GuardFixtures.headerOf(answer))
        if (body != null) r.setContent(body.toByteArray(Charsets.UTF_8))
        return r
    }

    private class Ran(val res: MockHttpServletResponse, val chain: MockFilterChain) {
        val passed: Boolean get() = chain.request != null
    }

    private fun run(f: PcaFilter, r: MockHttpServletRequest): Ran {
        val res = MockHttpServletResponse()
        val chain = MockFilterChain()
        f.doFilter(r, res, chain)
        return Ran(res, chain)
    }

    private class Spy {
        var req: HttpServletRequest? = null
        var body: ByteArray? = null
        fun op(sc: Scenario) = PcaOperationMapper { r, b -> req = r; body = b; sc.operation }
        fun wf() = PcaWorkflowStepMapper { r, b -> req = r; body = b; null }
    }

    private inline fun <reified T : Any> untouchable(): T = Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { p, m, a ->
        when (m.name) {
            "equals" -> p === a!![0]
            "hashCode" -> 1
            "toString" -> "untouchable"
            else -> throw AssertionError("touched ${m.name}")
        }
    } as T

    // ---- writeRefusal ----

    @Test
    fun refusalChallengeOnlyOn401And403() {
        for (st in listOf(400, 401, 402, 403, 404, 409, 500)) {
            val res = MockHttpServletResponse()
            res.status = 200
            res.setHeader("X-Old", "1")
            res.contentType = "text/plain"
            res.outputStream.write("old".toByteArray())
            writeRefusal(res, GuardOutcome(false, st, null, "é{}", "deny"))
            assertEquals(st, res.status)
            assertNull("reset clears headers", res.getHeader("X-Old"))
            val want = if (st == 401 || st == 403) "PCA realm=\"pca\"" else null
            assertEquals("status $st", want, res.getHeader("WWW-Authenticate"))
            assertEquals("application/json;charset=UTF-8", res.contentType)
            assertEquals(4, res.contentLength) // bytes, not chars
            assertEquals("é{}", res.contentAsString) // the old body is gone
        }
    }

    @Test
    fun refusalKeepsTheOutcomesOwnChallenge() {
        for (st in listOf(401, 409)) {
            val res = MockHttpServletResponse()
            writeRefusal(res, GuardOutcome(false, st, "PCA custom=1", "{}", "deny"))
            assertEquals("PCA custom=1", res.getHeader("WWW-Authenticate"))
            assertEquals(listOf("PCA custom=1"), res.getHeaders("WWW-Authenticate"))
        }
    }

    // ---- writeRecorded ----

    @Test
    fun recordedResponseIsReplayedWithoutDuplicatingHeaders() {
        val bytes = "héllo".toByteArray(Charsets.UTF_8)
        val rec = RecordedResponse(201, "text/plain", linkedMapOf("X-A" to listOf("new"), "X-B" to listOf("b1", "b2")), bytes)
        val res = MockHttpServletResponse()
        res.addHeader("X-A", "old")
        writeRecorded(res, rec, false)
        assertEquals(201, res.status)
        assertEquals(listOf("old"), res.getHeaders("X-A"))
        assertEquals(listOf("b1", "b2"), res.getHeaders("X-B"))
        assertEquals("text/plain", res.contentType)
        assertNull(res.getHeader("PCA-Replayed"))
        assertEquals(bytes.size, res.contentLength)
        assertArrayEquals(bytes, res.contentAsByteArray)
    }

    @Test
    fun recordedContentTypeNeverOverridesAnExistingOne() {
        val rec = RecordedResponse(200, "text/plain", linkedMapOf<String, List<String>>(), "x".toByteArray())
        val res = MockHttpServletResponse()
        res.contentType = "application/xml"
        writeRecorded(res, rec, false)
        assertEquals("application/xml", res.contentType)
        val none = MockHttpServletResponse()
        writeRecorded(none, RecordedResponse(200, null, linkedMapOf<String, List<String>>(), "x".toByteArray()), false)
        assertNull(none.contentType)
        assertEquals(1, none.contentLength)
    }

    @Test
    fun replayedRecordCarriesTheReplayHeader() {
        val res = MockHttpServletResponse()
        writeRecorded(res, RecordedResponse(200, null, linkedMapOf<String, List<String>>(), ByteArray(0)), true)
        assertEquals("true", res.getHeader("PCA-Replayed"))
        assertEquals(listOf("true"), res.getHeaders("PCA-Replayed"))
    }

    // ---- constructors ----

    @Test
    fun signatureOnlyCannotBeCombinedWithAnOperationMapper() {
        val sc = GuardFixtures.within()
        val mapper = PcaOperationMapper { _, _ -> sc.operation }
        try {
            PcaFilter(sc.config(null, true), mapper)
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertEquals("signatureOnly cannot be combined with an operation mapper", e.message)
        }
        try {
            PcaInterceptor(sc.config(null, true), mapper)
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertEquals("signatureOnly cannot be combined with an operation mapper", e.message)
        }
        // the other three combinations construct
        PcaFilter(sc.config(null, true))
        PcaFilter(sc.config(GuardFixtures.options()), mapper)
        PcaFilter(sc.config(GuardFixtures.options()))
        PcaInterceptor(sc.config(null, true))
        PcaInterceptor(sc.config(GuardFixtures.options()), mapper)
        PcaInterceptor(sc.config(GuardFixtures.options()))
    }

    @Test
    fun constructorOverloadsDefaultTheMappersToNull() {
        val sc = GuardFixtures.within()
        val mapper = PcaOperationMapper { _, _ -> sc.operation }
        assertEquals(403, run(PcaFilter(sc.config(GuardFixtures.options())), request(sc)).res.status) // no mapper: no operation: denied
        assertTrue(run(PcaFilter(sc.config(GuardFixtures.options()), mapper), request(sc)).passed)
        assertTrue(run(PcaFilter(sc.config(GuardFixtures.options()), mapper, null), request(sc)).passed)
        val res = MockHttpServletResponse()
        assertFalse(PcaInterceptor(sc.config(GuardFixtures.options())).preHandle(request(sc), res, Any()))
        assertEquals(403, res.status)
        assertTrue(PcaInterceptor(sc.config(GuardFixtures.options()), mapper).preHandle(request(sc), MockHttpServletResponse(), Any()))
        assertTrue(PcaInterceptor(sc.config(GuardFixtures.options()), mapper, null).preHandle(request(sc), MockHttpServletResponse(), Any()))
    }

    // ---- doFilter ----

    @Test
    fun nonHttpTrafficPassesStraightThrough() {
        val sc = GuardFixtures.within()
        val f = PcaFilter(sc.config(GuardFixtures.options()), PcaOperationMapper { _, _ -> sc.operation })
        var seen: Pair<ServletRequest, ServletResponse>? = null
        val chain = FilterChain { rq, rs -> seen = Pair(rq, rs) }

        val plainReq = untouchable<ServletRequest>()
        val httpRes = MockHttpServletResponse()
        f.doFilter(plainReq, httpRes, chain)
        assertSame(plainReq, seen!!.first)
        assertSame(httpRes, seen!!.second)
        assertEquals(200, httpRes.status)

        seen = null
        val httpReq = MockHttpServletRequest("POST", "/pay/send") // no proof: a guarded request would be refused
        val plainRes = untouchable<ServletResponse>()
        f.doFilter(httpReq, plainRes, chain)
        assertSame(httpReq, seen!!.first)
        assertSame(plainRes, seen!!.second)
    }

    @Test
    fun authorizeModeAlwaysBuffersTheBodyForTheMapper() {
        val sc = GuardFixtures.within()
        val spy = Spy()
        val r = request(sc)
        r.setContent("BODYX".toByteArray())
        run(PcaFilter(sc.config(GuardFixtures.options()), spy.op(sc)), r)
        assertArrayEquals("BODYX".toByteArray(), spy.body)
        assertTrue(spy.req is CachedBodyRequest)
    }

    @Test
    fun signatureOnlyWithAHeaderLeavesTheBodyAlone() {
        val sc = GuardFixtures.within()
        val spy = Spy()
        val r = request(sc)
        r.setContent("BODYX".toByteArray())
        val ran = run(PcaFilter(sc.config(null, true), null, spy.wf()), r)
        assertTrue(ran.res.contentAsString, ran.passed)
        assertSame(r, spy.req)
        assertEquals(0, spy.body!!.size)
        assertSame(r, ran.chain.request)
        assertArrayEquals("BODYX".toByteArray(), r.inputStream.readAllBytes()) // still unread
    }

    @Test
    fun signatureOnlyWithoutOrWithAnEmptyHeaderReadsTheBodyTransport() {
        val sc = GuardFixtures.within()
        for (emptyHeader in listOf(false, true)) {
            val spy = Spy()
            val r = request(null, body = sc.body)
            if (emptyHeader) r.addHeader(PcaGuard.HEADER, "")
            val ran = run(PcaFilter(sc.config(null, true), null, spy.wf()), r)
            assertTrue("emptyHeader=$emptyHeader ${ran.res.contentAsString}", ran.passed)
            assertTrue(spy.req is CachedBodyRequest)
            assertArrayEquals(sc.body.toByteArray(Charsets.UTF_8), spy.body)
            assertEquals(sc.body, String(ran.chain.request!!.inputStream.readAllBytes(), Charsets.UTF_8))
        }
    }

    // ---- the executor path ----

    private class Handler {
        var runs = 0
        var attr: Any? = null
        val chain = FilterChain { rq, rs ->
            runs++
            attr = rq.getAttribute(PCA_ATTRIBUTE)
            (rs as HttpServletResponse).status = 201
        }
    }

    private fun execFilter(sc: Scenario, az: Authorize.AuthorizeOptions, executor: PcaExecutorConfig) =
        PcaFilter(sc.config(az, executor = executor), PcaOperationMapper { _, _ -> sc.operation })

    @Test
    fun theExecutorPathForwardsTheEscalationAnswerAndTheVerdictAttribute() {
        val sc = GuardFixtures.escalating()
        val h = Handler()
        val f = execFilter(sc, GuardFixtures.options(GuardFixtures.principals()), GuardFixtures.executor())
        val res = MockHttpServletResponse()
        f.doFilter(request(sc, GuardFixtures.signedAllow(sc)), res, h.chain)
        assertEquals(res.contentAsString, 201, res.status)
        assertEquals(1, h.runs)
        val a = h.attr as GuardOutcome
        assertTrue(a.allowed)
        assertEquals("allow", a.decision)
        // without the answer the same request is an escalate refusal and the handler never runs
        val h2 = Handler()
        val res2 = MockHttpServletResponse()
        execFilter(sc, GuardFixtures.options(GuardFixtures.principals()), GuardFixtures.executor()).doFilter(request(sc), res2, h2.chain)
        assertEquals(403, res2.status)
        assertEquals(0, h2.runs)
    }

    @Test
    fun anUnreadableRecordIsAnUncertain409() {
        val sc = GuardFixtures.within()
        val h = Handler()
        val res = MockHttpServletResponse()
        execFilter(sc, GuardFixtures.options(), GuardFixtures.executor(GuardFixtures.storeWith(sc, "committed"))).doFilter(request(sc), res, h.chain)
        assertEquals(res.contentAsString, 409, res.status)
        val j = GuardFixtures.parse(res.contentAsString)
        assertEquals("operation_uncertain", j["error"])
        assertEquals("the recorded result is unreadable", j["error_description"])
        assertNull(res.getHeader("WWW-Authenticate"))
        assertEquals("application/json;charset=UTF-8", res.contentType)
        assertEquals(0, h.runs)
    }

    // ---- the interceptor ----

    @Test
    fun theInterceptorHandsTheMappersAnEmptyBody() {
        val sc = GuardFixtures.within()
        val opSpy = Spy()
        val wfSpy = Spy()
        val r = request(sc, method = "GET")
        r.setContent("BODYX".toByteArray())
        val i = PcaInterceptor(sc.config(GuardFixtures.options()), opSpy.op(sc), wfSpy.wf())
        assertTrue(i.preHandle(r, MockHttpServletResponse(), Any()))
        assertEquals(0, opSpy.body!!.size)
        assertEquals(0, wfSpy.body!!.size)
        assertSame(r, opSpy.req)
        assertSame(r, wfSpy.req)
    }

    @Test
    fun theInterceptorForwardsTheEscalationAnswer() {
        val sc = GuardFixtures.escalating()
        val i = PcaInterceptor(sc.config(GuardFixtures.options(GuardFixtures.principals())), PcaOperationMapper { _, _ -> sc.operation })
        assertTrue(i.preHandle(request(sc, GuardFixtures.signedAllow(sc), method = "GET"), MockHttpServletResponse(), Any()))
        val res = MockHttpServletResponse()
        assertFalse(i.preHandle(request(sc, method = "GET"), res, Any()))
        assertEquals(403, res.status)
    }

    // ---- the cached body ----

    private fun cached(body: ByteArray, enc: String?, declared: Int = 0): CachedBodyRequest {
        val inner = object : MockHttpServletRequest() {
            override fun getCharacterEncoding(): String? = enc
        }
        inner.setContent(ByteArray(declared))
        return CachedBodyRequest(inner, body)
    }

    @Test
    fun cachedBodyStreamReadsFinishesAndRejectsListeners() {
        val c = cached("ab".toByteArray(), null)
        val s = c.inputStream
        assertTrue(s.isReady)
        assertFalse(s.isFinished)
        assertEquals('a'.code, s.read())
        assertFalse(s.isFinished)
        val rest = ByteArray(4)
        assertEquals(1, s.read(rest, 1, 3))
        assertEquals('b'.code.toByte(), rest[1])
        assertTrue(s.isFinished)
        assertEquals(-1, s.read())
        assertTrue(cached(ByteArray(0), null).inputStream.isFinished)
        try {
            s.setReadListener(null)
            fail("expected UnsupportedOperationException")
        } catch (e: UnsupportedOperationException) {
            // as designed
        }
        try {
            s.setReadListener(object : ReadListener {
                override fun onDataAvailable() {}
                override fun onAllDataRead() {}
                override fun onError(t: Throwable?) {}
            })
            fail("expected UnsupportedOperationException")
        } catch (e: UnsupportedOperationException) {
            // as designed
        }
    }

    @Test
    fun cachedBodyReaderUsesTheRequestCharsetAndFallsBackToUtf8() {
        val bytes = "é".toByteArray(Charsets.UTF_8) // C3 A9
        assertEquals("é", cached(bytes, null).reader.readText())
        assertEquals("é", cached(bytes, "bogus-charset").reader.readText())
        assertEquals("é", cached(bytes, "UTF-8").reader.readText())
        assertEquals("Ã©", cached(bytes, "ISO-8859-1").reader.readText())
    }

    @Test
    fun cachedBodyReportsItsOwnLength() {
        val c = cached("abcdefg".toByteArray(), null, declared = 3)
        assertEquals(7, c.contentLength)
        assertEquals(7L, c.contentLengthLong)
    }

    // ---- properties ----

    @Test
    fun propertiesDefaultsAndAccessors() {
        val p = PcaProperties()
        assertFalse(p.enabled)
        assertFalse(p.signatureOnly)
        assertEquals(0, p.order)
        p.enabled = true
        p.signatureOnly = true
        p.order = 5
        assertTrue(p.enabled)
        assertTrue(p.signatureOnly)
        assertEquals(5, p.order)
        p.enabled = false
        p.signatureOnly = false
        p.order = -3
        assertFalse(p.enabled)
        assertFalse(p.signatureOnly)
        assertEquals(-3, p.order)
    }

    // ---- the auto-configuration ----

    private fun bare() = WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(PcaAutoConfiguration::class.java))

    private fun runner(sc: Scenario) =
        bare().withBean(Clock::class.java, Supplier { Clock.fixed(Instant.ofEpochMilli(sc.now), ZoneOffset.UTC) })

    @Test
    fun withoutOptionalBeansTheConfigHasNoneOfThem() {
        val before = System.currentTimeMillis()
        bare().withPropertyValues("atlas.pca.enabled=true", "atlas.pca.audience=aud").run { ctx ->
            assertNull(ctx.startupFailure)
            val c = ctx.getBean(PcaGuardConfig::class.java)
            assertNull(c.resolveGrant)
            assertNull(c.authorize)
            assertNull(c.intentPolicy)
            assertNull(c.executor)
            assertFalse(c.signatureOnly)
            assertEquals("aud", c.audience)
            val t = c.clock()
            assertTrue("system clock: $t", t >= before && t <= System.currentTimeMillis())
            val reg = ctx.getBean(FilterRegistrationBean::class.java)
            assertEquals(0, reg.order)
            assertTrue(reg.servletRegistrationBeans.isEmpty())
            val f = AbstractRegField.dispatcherTypes(reg)
            assertEquals(EnumSet.of(DispatcherType.REQUEST), f)
        }
    }

    private object AbstractRegField {
        fun dispatcherTypes(reg: FilterRegistrationBean<*>): Any? {
            val f = Class.forName("org.springframework.boot.web.servlet.AbstractFilterRegistrationBean").getDeclaredField("dispatcherTypes")
            f.isAccessible = true
            return f.get(reg)
        }
    }

    @Test
    fun everyOptionalBeanReachesTheGuardConfig() {
        val sc = GuardFixtures.within()
        val az = GuardFixtures.options()
        val policy = Pca.IntentPolicy(require = true)
        val exec = GuardFixtures.executor()
        val grant = mapOf<String, Any?>("id" to "g-1")
        runner(sc)
            .withPropertyValues("atlas.pca.enabled=true", "atlas.pca.audience=aud", "atlas.pca.order=7")
            .withBean(PcaGrantResolver::class.java, Supplier { PcaGrantResolver { ref -> if (ref == "g-1") grant else null } })
            .withBean(Authorize.AuthorizeOptions::class.java, Supplier { az })
            .withBean(Pca.IntentPolicy::class.java, Supplier { policy })
            .withBean(PcaExecutorConfig::class.java, Supplier { exec })
            .run { ctx ->
                assertNull(ctx.startupFailure)
                val c = ctx.getBean(PcaGuardConfig::class.java)
                assertSame(grant, c.resolveGrant!!("g-1"))
                assertNull(c.resolveGrant!!("other"))
                assertSame(az, c.authorize)
                assertSame(policy, c.intentPolicy)
                assertSame(exec, c.executor)
                assertEquals(sc.now, c.clock())
                assertEquals(7, ctx.getBean(FilterRegistrationBean::class.java).order)
            }
    }

    @Test
    fun signatureOnlyPropertyReachesTheConfigAndSkipsTheOperationMapper() {
        val sc = GuardFixtures.within()
        runner(sc)
            .withPropertyValues("atlas.pca.enabled=true", "atlas.pca.audience=${sc.audience}", "atlas.pca.signature-only=true")
            .withBean(PcaGrantResolver::class.java, Supplier { PcaGrantResolver { ref -> if (ref == sc.grant["id"]) sc.grant else null } })
            .withBean(PcaOperationMapper::class.java, Supplier { PcaOperationMapper { _, _ -> sc.operation } })
            .run { ctx ->
                assertNull(ctx.startupFailure)
                assertTrue(ctx.getBean(PcaGuardConfig::class.java).signatureOnly)
                assertNotNull(ctx.getBean(PcaFilter::class.java))
                val i = ctx.getBean(PcaInterceptor::class.java)
                assertTrue(i.preHandle(request(sc, method = "GET"), MockHttpServletResponse(), Any()))
            }
    }

    private fun workflowRunner(c: GuardFixtures.WorkflowCall) = runner(c.scenario)
        .withPropertyValues("atlas.pca.enabled=true", "atlas.pca.audience=${c.scenario.audience}")
        .withBean(PcaGrantResolver::class.java, Supplier { PcaGrantResolver { ref -> if (ref == c.scenario.grant["id"]) c.scenario.grant else null } })
        .withBean(Authorize.AuthorizeOptions::class.java, Supplier { GuardFixtures.workflowOptions() })
        .withBean(PcaOperationMapper::class.java, Supplier { PcaOperationMapper { _, _ -> c.scenario.operation } })
        .withBean(PcaWorkflowStepMapper::class.java, Supplier { PcaWorkflowStepMapper { _, _ -> c.step } })

    @Test
    fun theFilterBeanUsesTheOperationAndWorkflowMapperBeans() {
        val (bad, _) = GuardFixtures.workflowCall("amount-over-the-quote")
        workflowRunner(bad).run { ctx ->
            val ran = run(ctx.getBean(PcaFilter::class.java), request(bad.scenario))
            assertFalse(ran.passed)
            assertEquals(403, ran.res.status)
            assertTrue(ran.res.contentAsString, ran.res.contentAsString.contains("workflow: edge_relation (step pay)"))
        }
        val (good, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        workflowRunner(good).run { ctx ->
            val ran = run(ctx.getBean(PcaFilter::class.java), request(good.scenario))
            assertTrue(ran.res.contentAsString, ran.passed)
        }
    }

    @Test
    fun theInterceptorBeanUsesTheOperationAndWorkflowMapperBeans() {
        val (bad, _) = GuardFixtures.workflowCall("amount-over-the-quote")
        workflowRunner(bad).run { ctx ->
            val res = MockHttpServletResponse()
            assertFalse(ctx.getBean(PcaInterceptor::class.java).preHandle(request(bad.scenario, method = "GET"), res, Any()))
            assertEquals(403, res.status)
            assertTrue(res.contentAsString, res.contentAsString.contains("workflow: edge_relation (step pay)"))
        }
        val (good, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        workflowRunner(good).run { ctx ->
            assertTrue(ctx.getBean(PcaInterceptor::class.java).preHandle(request(good.scenario, method = "GET"), MockHttpServletResponse(), Any()))
        }
    }
}
