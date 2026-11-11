package net.atlasauth.pca.ktor

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.response.ApplicationSendPipeline
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteWriteChannel
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.GuardFixtures.Scenario
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import io.ktor.server.response.header as respHeader

/**
 * The plugin's coroutine state machines. Every send, every mapper and the downstream handler really suspend here (a delay in the
 * send pipeline, in the operation mapper, in the workflow callback, in the request body and in the handler), so each resume point,
 * each spilled local and each state of the compiled continuations is crossed with a different value. A probe interceptor installed
 * after the plugin counts how often the rest of the pipeline is entered: a refusal must end the pipeline (`finish()`).
 */
@Suppress("UNCHECKED_CAST")
class Kill07KtorPluginSuspendTest {
    private val ran = AtomicInteger(0)
    private val probe = AtomicInteger(0)
    private val probeCall = AtomicInteger(0)

    private class SlowBody(private val parts: List<String>) : OutgoingContent.WriteChannelContent() {
        override suspend fun writeTo(channel: ByteWriteChannel) {
            for (p in parts) {
                val b = p.toByteArray(Charsets.UTF_8)
                channel.writeFully(b, 0, b.size)
                channel.flush()
                delay(20)
            }
        }
    }

    private fun PcaKtorConfig.setup(sc: Scenario, az: Authorize.AuthorizeOptions?) {
        audience = sc.audience
        resolveGrant = { ref -> if (ref == sc.grant["id"]) sc.grant else null }
        authorize = az
        clock = { sc.now }
        operation = { _, _ -> delay(15); sc.operation }
    }

    private fun app(cfg: PcaKtorConfig.() -> Unit, block: suspend ApplicationTestBuilder.() -> Unit) = runBlocking {
        testApplication {
            application {
                // every response goes through a suspending send interceptor: respondText / respondBytes really suspend
                intercept(ApplicationCallPipeline.Setup) {
                    call.response.pipeline.intercept(ApplicationSendPipeline.Before) { delay(15) }
                }
                routing {
                    route("/pay") {
                        install(PcaGuardPlugin, cfg)
                        intercept(ApplicationCallPipeline.Plugins) { probe.incrementAndGet() }
                        intercept(ApplicationCallPipeline.Call) { probeCall.incrementAndGet() }
                        get("/send") {
                            delay(15)
                            ran.incrementAndGet()
                            call.respondText("ran:${call.pca!!.operation?.verb}")
                        }
                        post("/send") {
                            delay(15)
                            ran.incrementAndGet()
                            call.respondText("ran:${call.pca!!.operation?.verb}")
                        }
                        get("/rich") {
                            delay(15)
                            ran.incrementAndGet()
                            call.response.respHeader("X-Trace", "t1")
                            call.respondText("rich-body", ContentType.Text.Plain, HttpStatusCode.Created)
                        }
                        get("/silent") {
                            delay(15)
                            ran.incrementAndGet()
                        }
                        get("/boom") {
                            delay(15)
                            ran.incrementAndGet()
                            error("secret-detail")
                        }
                    }
                }
            }
            block()
        }
    }

    private suspend fun ApplicationTestBuilder.hit(path: String, sc: Scenario): HttpResponse =
        client.get(path) {
            header(PcaGuard.HEADER, sc.header)
            header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
        }

    private fun opId(sc: Scenario) = Pca.hashCanonical(sc.pcactn)

    // ---- the plain path ----

    @Test
    fun aRefusalWhoseSendSuspendsStillCarriesEverythingAndEndsThePipeline() {
        val sc = GuardFixtures.overLimit()
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = hit("/pay/send", sc)
            assertEquals(403, r.status.value)
            assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", r.headers["WWW-Authenticate"])
            assertTrue(r.headers["Content-Type"]!!.startsWith("application/json"))
            assertEquals("insufficient_authority", GuardFixtures.parse(r.bodyAsText())["error"])
            val none = client.get("/pay/send")
            assertEquals(401, none.status.value)
            assertEquals("PCA realm=\"pca\"", none.headers["WWW-Authenticate"])
            assertEquals("pca_required", GuardFixtures.parse(none.bodyAsText())["error"])
        }
        assertEquals(0, ran.get())
        assertEquals(0, probe.get())
        assertEquals(0, probeCall.get())
    }

    @Test
    fun anAllowWithSuspendingMapperAndSlowBodyRunsTheRestOfThePipelineOnce() {
        val sc = GuardFixtures.within()
        val mapBody = AtomicReference<String?>(null)
        val wfBody = AtomicReference<String?>(null)
        app({
            setup(sc, GuardFixtures.options())
            operation = { _, b -> delay(15); mapBody.set(String(b, Charsets.UTF_8)); sc.operation }
            workflowStep = { _, b -> delay(15); wfBody.set(String(b, Charsets.UTF_8)); null }
        }) {
            val r = client.post("/pay/send") {
                header(PcaGuard.HEADER, sc.header)
                header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
                setBody(SlowBody(listOf("ab", "cd")))
            }
            assertEquals(r.bodyAsText(), 200, r.status.value)
            assertEquals("ran:payments.send", r.bodyAsText())
            assertNull(r.headers["WWW-Authenticate"])
        }
        assertEquals("abcd", mapBody.get())
        assertEquals("abcd", wfBody.get())
        assertEquals(1, ran.get())
        assertEquals(1, probe.get())
        assertEquals(1, probeCall.get())
    }

    @Test
    fun aMapperOrWorkflowCallbackThatFailsAfterSuspendingIsAFailClosedDenial() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); operation = { _, _ -> delay(15); error("mapper failed") } }) {
            val r = hit("/pay/send", sc)
            assertEquals(r.bodyAsText(), 403, r.status.value)
            assertTrue(r.headers["WWW-Authenticate"]!!.startsWith("PCA realm=\"pca\""))
        }
        assertEquals(0, ran.get())
        assertEquals(0, probe.get())

        val (good, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
        val seen = AtomicInteger(0)
        app({
            setup(good.scenario, GuardFixtures.workflowOptions())
            workflowStep = { _, _ -> delay(15); seen.incrementAndGet(); good.step }
        }) {
            val ok = hit("/pay/send", good.scenario)
            assertEquals(ok.bodyAsText(), 200, ok.status.value)
        }
        assertEquals(1, seen.get())
        assertEquals(1, ran.get())
        app({
            setup(good.scenario, GuardFixtures.workflowOptions())
            workflowStep = { _, _ -> delay(15); seen.incrementAndGet(); error("step failed") }
        }) {
            val bad = hit("/pay/send", good.scenario)
            assertEquals(bad.bodyAsText(), 403, bad.status.value)
        }
        assertEquals(2, seen.get())
        assertEquals(1, ran.get())
    }

    // ---- the executor path ----

    @Test
    fun theExecutorPathRunsThenReplaysWithTheSuspendingSendAndHandler() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val first = hit("/pay/rich", sc)
            assertEquals(201, first.status.value)
            assertEquals("rich-body", first.bodyAsText())
            assertEquals("t1", first.headers["X-Trace"])
            assertNull(first.headers["PCA-Replayed"])
            assertEquals(1, probe.get())
            assertEquals(1, probeCall.get())
            val again = hit("/pay/rich", sc)
            assertEquals(201, again.status.value)
            assertEquals("rich-body", again.bodyAsText())
            assertEquals("true", again.headers["PCA-Replayed"])
            assertEquals(1, again.headers.getAll("PCA-Replayed")!!.size)
            assertEquals("t1", again.headers["X-Trace"])
            assertTrue(again.headers["Content-Type"]!!.startsWith("text/plain"))
        }
        assertEquals(1, ran.get())
        // the replay answers from the record: the rest of the pipeline is not entered a second time
        assertEquals(1, probe.get())
        assertEquals(1, probeCall.get())
    }

    @Test
    fun executorRefusalsEndThePipelineWithTheirOwnStatusAndChallenge() {
        val sc = GuardFixtures.overLimit()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val r = hit("/pay/send", sc)
            assertEquals(403, r.status.value)
            assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", r.headers["WWW-Authenticate"])
            assertEquals("insufficient_authority", GuardFixtures.parse(r.bodyAsText())["error"])
            val none = client.get("/pay/send")
            assertEquals(401, none.status.value)
            assertEquals("PCA realm=\"pca\"", none.headers["WWW-Authenticate"])
        }
        val w = GuardFixtures.within()
        app({ setup(w, GuardFixtures.options()); executor = GuardFixtures.executor(recheck = { Operations.Recheck.refuse("approval withdrawn") }) }) {
            val r = hit("/pay/send", w)
            assertEquals(403, r.status.value)
            assertEquals("PCA realm=\"pca\", error=\"operation_aborted\"", r.headers["WWW-Authenticate"])
            assertEquals("operation_aborted", GuardFixtures.parse(r.bodyAsText())["error"])
        }
        for (state in listOf("executing", "uncertain")) {
            app({ setup(w, GuardFixtures.options()); executor = GuardFixtures.executor(GuardFixtures.storeWith(w, state)) }) {
                val r = hit("/pay/send", w)
                assertEquals(409, r.status.value)
                assertNull(r.headers["WWW-Authenticate"])
                assertEquals(if (state == "executing") "operation_in_progress" else "operation_uncertain", GuardFixtures.parse(r.bodyAsText())["error"])
            }
        }
        assertEquals(0, ran.get())
        assertEquals(0, probe.get())
        assertEquals(0, probeCall.get())
    }

    @Test
    fun executorHandlerFailuresAreRecordedAndAnswered500WithNoDetail() {
        val sc = GuardFixtures.within()
        for ((path, reason) in listOf("/pay/silent" to "the handler sent no response", "/pay/boom" to "secret-detail")) {
            val store = Operations.MemoryStore()
            app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
                val r = hit(path, sc)
                assertEquals(500, r.status.value)
                val body = r.bodyAsText()
                assertEquals("operation_failed", GuardFixtures.parse(body)["error"])
                assertTrue(body, !body.contains(reason))
                assertNull(r.headers["WWW-Authenticate"])
            }
            val rec = store.get(opId(sc))!!
            assertEquals("failed", rec["state"])
            assertTrue(rec.toString(), (rec["error"] as String).contains(reason))
        }
    }

    @Test
    fun aCommittedRecordIsReplayedAndAnUnreadableOneIs409UnderASuspendingSend() {
        val sc = GuardFixtures.within()
        fun committed(result: Any?): Operations.Store {
            val store = GuardFixtures.storeWith(sc, "committed")
            val id = opId(sc)
            val rec = LinkedHashMap(store.get(id)!!)
            rec["result"] = result
            assertTrue(store.transition(id, "committed", rec))
            return store
        }
        val ok = linkedMapOf<String, Any?>(
            "status" to 418L, "contentType" to "text/plain; charset=UTF-8", "headers" to linkedMapOf("X-Rec" to listOf("a", "b")),
            "body" to Base64.getEncoder().encodeToString("hello".toByteArray()),
        )
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(committed(ok)) }) {
            val r = hit("/pay/send", sc)
            assertEquals(418, r.status.value)
            assertEquals("hello", r.bodyAsText())
            assertEquals("a,b", r.headers.getAll("X-Rec")!!.joinToString(","))
            assertEquals("true", r.headers["PCA-Replayed"])
        }
        val noType = linkedMapOf<String, Any?>("status" to 200L, "contentType" to null, "headers" to linkedMapOf<String, Any?>(), "body" to Base64.getEncoder().encodeToString("raw".toByteArray()))
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(committed(noType)) }) {
            val r = hit("/pay/send", sc)
            assertEquals(200, r.status.value)
            assertEquals("raw", r.bodyAsText())
            assertEquals("true", r.headers["PCA-Replayed"])
        }
        for (bad in listOf<Any?>("not a map", linkedMapOf<String, Any?>("status" to 1.5, "contentType" to "text/plain", "headers" to linkedMapOf<String, Any?>(), "body" to "eA=="))) {
            app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(committed(bad)) }) {
                val r = hit("/pay/send", sc)
                assertEquals(409, r.status.value)
                assertNull(r.headers["WWW-Authenticate"])
                assertNull(r.headers["PCA-Replayed"])
                assertEquals("the recorded result is unreadable", GuardFixtures.parse(r.bodyAsText())["error_description"])
            }
        }
        assertEquals(0, ran.get())
        assertEquals(0, probe.get())
        assertEquals(0, probeCall.get())
    }

    @Test
    fun theDefaultClockIsTheSystemClock() {
        val before = System.currentTimeMillis()
        val t = PcaKtorConfig().clock()
        val after = System.currentTimeMillis()
        assertTrue("$before <= $t <= $after", t in before..after)
    }
}
