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
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
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
 * The plugin's compiled coroutine state machines, resumed from every combination of suspended and not-suspended: each of the five
 * suspension points (response send, operation mapper, workflow callback, request body, route handler) either really suspends
 * (`delay`) or returns at once, one at a time, none, and all. A corrupted resume (a wrong label, a lost spilled local, a skipped
 * `throwOnFailure`) throws or jumps to the wrong case AFTER the response may already have gone out, so the client status alone cannot
 * see it: a Setup-phase interceptor records every Throwable that escapes the rest of the pipeline and each run requires none.
 */
class Kill08KtorPluginResumeTest {
    private val ran = AtomicInteger(0)
    private val probe = AtomicInteger(0)
    private val probeCall = AtomicInteger(0)
    private val thrown = CopyOnWriteArrayList<Throwable>()

    private class Sus(val on: Set<String>) {
        suspend fun pause(k: String) { if (k in on) delay(10) }
        override fun toString() = on.toString()
    }

    private class SlowBody(private val parts: List<String>) : OutgoingContent.WriteChannelContent() {
        override suspend fun writeTo(channel: ByteWriteChannel) {
            for (p in parts) {
                val b = p.toByteArray(Charsets.UTF_8)
                channel.writeFully(b, 0, b.size)
                channel.flush()
                delay(15)
            }
        }
    }

    private val points = listOf("send", "mapper", "wf", "body", "handler")
    private val modes: List<Sus> =
        listOf(Sus(emptySet()), Sus(points.toSet())) + points.map { Sus(setOf(it)) }

    private fun PcaKtorConfig.setup(sc: Scenario, s: Sus, az: Authorize.AuthorizeOptions?) {
        audience = sc.audience
        resolveGrant = { ref -> if (ref == sc.grant["id"]) sc.grant else null }
        authorize = az
        clock = { sc.now }
        operation = { _, _ -> s.pause("mapper"); sc.operation }
    }

    private fun app(s: Sus, cfg: PcaKtorConfig.() -> Unit, block: suspend ApplicationTestBuilder.() -> Unit) {
        ran.set(0); probe.set(0); probeCall.set(0); thrown.clear()
        runBlocking {
            testApplication {
                application {
                    intercept(ApplicationCallPipeline.Setup) {
                        call.response.pipeline.intercept(ApplicationSendPipeline.Before) { s.pause("send") }
                        try {
                            proceed()
                        } catch (t: kotlin.coroutines.cancellation.CancellationException) {
                            throw t
                        } catch (t: Throwable) {
                            thrown.add(t)
                            throw t
                        }
                    }
                    routing {
                        route("/pay") {
                            install(PcaGuardPlugin, cfg)
                            intercept(ApplicationCallPipeline.Plugins) { probe.incrementAndGet() }
                            intercept(ApplicationCallPipeline.Call) { probeCall.incrementAndGet() }
                            get("/send") {
                                s.pause("handler")
                                ran.incrementAndGet()
                                call.respondText("ran:${call.pca!!.operation?.verb}")
                            }
                            post("/send") {
                                s.pause("handler")
                                ran.incrementAndGet()
                                call.respondText("ran:${call.pca!!.operation?.verb}")
                            }
                            get("/rich") {
                                s.pause("handler")
                                ran.incrementAndGet()
                                call.response.respHeader("X-Trace", "t1")
                                call.respondText("rich-body", ContentType.Text.Plain, HttpStatusCode.Created)
                            }
                            get("/silent") {
                                s.pause("handler")
                                ran.incrementAndGet()
                            }
                            get("/boom") {
                                s.pause("handler")
                                ran.incrementAndGet()
                                error("secret-detail")
                            }
                        }
                    }
                }
                block()
            }
        }
    }

    private suspend fun ApplicationTestBuilder.hit(path: String, sc: Scenario): HttpResponse =
        client.get(path) {
            header(PcaGuard.HEADER, sc.header)
            header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
        }

    private fun check(s: Sus, ranN: Int, probeN: Int) {
        assertEquals("$s: escaped Throwables ${thrown.map { it.toString() }}", 0, thrown.size)
        assertEquals("$s: handler runs", ranN, ran.get())
        assertEquals("$s: Plugins probe", probeN, probe.get())
        assertEquals("$s: Call probe", probeN, probeCall.get())
    }

    private fun opId(sc: Scenario) = Pca.hashCanonical(sc.pcactn)

    @Test
    fun plainAllowAndRefusalResumeCleanlyFromEverySuspensionMix() {
        for (s in modes) {
            val sc = GuardFixtures.within()
            val seen = AtomicInteger(0)
            app(s, {
                setup(sc, s, GuardFixtures.options())
                workflowStep = { _, b -> s.pause("wf"); seen.incrementAndGet(); assertEquals("abcd", String(b, Charsets.UTF_8)); null }
            }) {
                val r = client.post("/pay/send") {
                    header(PcaGuard.HEADER, sc.header)
                    header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
                    setBody(SlowBody(listOf("ab", "cd")))
                }
                assertEquals("$s ${r.bodyAsText()}", 200, r.status.value)
                assertEquals("ran:payments.send", r.bodyAsText())
                assertNull(r.headers["WWW-Authenticate"])
            }
            check(s, 1, 1)
            assertEquals(1, seen.get())

            val over = GuardFixtures.overLimit()
            app(s, { setup(over, s, GuardFixtures.options()) }) {
                val r = hit("/pay/send", over)
                assertEquals(403, r.status.value)
                assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", r.headers["WWW-Authenticate"])
                assertTrue(r.headers["Content-Type"]!!.startsWith("application/json"))
                assertEquals("insufficient_authority", GuardFixtures.parse(r.bodyAsText())["error"])
                val none = client.get("/pay/send")
                assertEquals(401, none.status.value)
                assertEquals("PCA realm=\"pca\"", none.headers["WWW-Authenticate"])
            }
            check(s, 0, 0)
        }
    }

    @Test
    fun failingMapperAndWorkflowCallbacksAreFailClosedFromEverySuspensionMix() {
        for (s in modes) {
            val sc = GuardFixtures.within()
            app(s, { setup(sc, s, GuardFixtures.options()); operation = { _, _ -> s.pause("mapper"); error("mapper failed") } }) {
                val r = hit("/pay/send", sc)
                assertEquals("$s ${r.bodyAsText()}", 403, r.status.value)
                assertTrue(r.headers["WWW-Authenticate"]!!.startsWith("PCA realm=\"pca\""))
            }
            check(s, 0, 0)
            app(s, { setup(sc, s, GuardFixtures.options()); operation = { _, _ -> s.pause("mapper"); null } }) {
                assertEquals(403, hit("/pay/send", sc).status.value)
            }
            check(s, 0, 0)

            val (good, _) = GuardFixtures.workflowCall("pay-after-quote", 0)
            val seen = AtomicInteger(0)
            app(s, {
                setup(good.scenario, s, GuardFixtures.workflowOptions())
                workflowStep = { _, _ -> s.pause("wf"); seen.incrementAndGet(); good.step }
            }) {
                val ok = hit("/pay/send", good.scenario)
                assertEquals("$s ${ok.bodyAsText()}", 200, ok.status.value)
            }
            assertEquals(1, seen.get())
            check(s, 1, 1)
            app(s, {
                setup(good.scenario, s, GuardFixtures.workflowOptions())
                workflowStep = { _, _ -> s.pause("wf"); seen.incrementAndGet(); error("step failed") }
            }) {
                assertEquals(403, hit("/pay/send", good.scenario).status.value)
            }
            assertEquals(2, seen.get())
            check(s, 0, 0)
        }
    }

    @Test
    fun executorRunReplayAndEveryRefusalResumeCleanlyFromEverySuspensionMix() {
        for (s in modes) {
            val sc = GuardFixtures.within()
            app(s, { setup(sc, s, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
                val first = hit("/pay/rich", sc)
                assertEquals("$s", 201, first.status.value)
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
            check(s, 1, 1)

            val over = GuardFixtures.overLimit()
            app(s, { setup(over, s, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
                val r = hit("/pay/send", over)
                assertEquals(403, r.status.value)
                assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", r.headers["WWW-Authenticate"])
                assertEquals("insufficient_authority", GuardFixtures.parse(r.bodyAsText())["error"])
                val none = client.get("/pay/send")
                assertEquals(401, none.status.value)
                assertEquals("PCA realm=\"pca\"", none.headers["WWW-Authenticate"])
            }
            check(s, 0, 0)

            app(s, { setup(sc, s, GuardFixtures.options()); executor = GuardFixtures.executor(recheck = { Operations.Recheck.refuse("approval withdrawn") }) }) {
                val r = hit("/pay/send", sc)
                assertEquals(403, r.status.value)
                assertEquals("PCA realm=\"pca\", error=\"operation_aborted\"", r.headers["WWW-Authenticate"])
                assertEquals("operation_aborted", GuardFixtures.parse(r.bodyAsText())["error"])
            }
            check(s, 0, 0)

            for (state in listOf("executing", "uncertain")) {
                app(s, { setup(sc, s, GuardFixtures.options()); executor = GuardFixtures.executor(GuardFixtures.storeWith(sc, state)) }) {
                    val r = hit("/pay/send", sc)
                    assertEquals(409, r.status.value)
                    assertNull(r.headers["WWW-Authenticate"])
                    assertEquals(if (state == "executing") "operation_in_progress" else "operation_uncertain", GuardFixtures.parse(r.bodyAsText())["error"])
                }
                check(s, 0, 0)
            }
        }
    }

    @Test
    fun executorHandlerFailuresAndRecordedResponsesResumeCleanlyFromEverySuspensionMix() {
        for (s in modes) {
            val sc = GuardFixtures.within()
            for ((path, reason) in listOf("/pay/silent" to "the handler sent no response", "/pay/boom" to "secret-detail")) {
                val store = Operations.MemoryStore()
                app(s, { setup(sc, s, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
                    val r = hit(path, sc)
                    assertEquals("$s $path", 500, r.status.value)
                    val body = r.bodyAsText()
                    assertEquals("operation_failed", GuardFixtures.parse(body)["error"])
                    assertTrue(body, !body.contains(reason))
                    assertNull(r.headers["WWW-Authenticate"])
                }
                check(s, 1, 1)
                val rec = store.get(opId(sc))!!
                assertEquals("failed", rec["state"])
                assertTrue(rec.toString(), (rec["error"] as String).contains(reason))
            }

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
            app(s, { setup(sc, s, GuardFixtures.options()); executor = GuardFixtures.executor(committed(ok)) }) {
                val r = hit("/pay/send", sc)
                assertEquals("$s", 418, r.status.value)
                assertEquals("hello", r.bodyAsText())
                assertEquals("a,b", r.headers.getAll("X-Rec")!!.joinToString(","))
                assertEquals("true", r.headers["PCA-Replayed"])
            }
            check(s, 0, 0)
            val noType = linkedMapOf<String, Any?>("status" to 200L, "contentType" to null, "headers" to linkedMapOf<String, Any?>(), "body" to Base64.getEncoder().encodeToString("raw".toByteArray()))
            app(s, { setup(sc, s, GuardFixtures.options()); executor = GuardFixtures.executor(committed(noType)) }) {
                val r = hit("/pay/send", sc)
                assertEquals(200, r.status.value)
                assertEquals("raw", r.bodyAsText())
                assertEquals("true", r.headers["PCA-Replayed"])
            }
            check(s, 0, 0)
            for (bad in listOf<Any?>("not a map", linkedMapOf<String, Any?>("status" to 1.5, "contentType" to "text/plain", "headers" to linkedMapOf<String, Any?>(), "body" to "eA=="))) {
                app(s, { setup(sc, s, GuardFixtures.options()); executor = GuardFixtures.executor(committed(bad)) }) {
                    val r = hit("/pay/send", sc)
                    assertEquals(409, r.status.value)
                    assertNull(r.headers["WWW-Authenticate"])
                    assertNull(r.headers["PCA-Replayed"])
                    assertEquals("the recorded result is unreadable", GuardFixtures.parse(r.bodyAsText())["error_description"])
                }
                check(s, 0, 0)
            }
        }
    }
}
