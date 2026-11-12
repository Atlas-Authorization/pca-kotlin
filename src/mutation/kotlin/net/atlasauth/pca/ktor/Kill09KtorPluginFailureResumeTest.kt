package net.atlasauth.pca.ktor

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.NullBody
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.request.ApplicationReceivePipeline
import io.ktor.server.response.ApplicationSendPipeline
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.GuardFixtures.Scenario
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import io.ktor.server.response.header as respHeader

/**
 * The plugin's compiled coroutine state machines resumed with a FAILURE. A suspended call (the request body, the operation mapper, the
 * workflow callback, a response send, the executor path) that is resumed with an exception makes the original `throwOnFailure` rethrow it;
 * a mutant that drops that call goes on with the `Result.Failure` object as if it were the value. Each failure is injected after a real
 * `delay` so the call really suspended first. A Setup-phase interceptor runs the rest of the pipeline in a supervisor scope and records
 * every Throwable that escapes it (then ends the pipeline and answers 599 itself, so the client never hangs): the tests assert what
 * escaped and which later stage did or did not run.
 */
class Kill09KtorPluginFailureResumeTest {
    private val ran = AtomicInteger(0)
    private val probe = AtomicInteger(0)
    private val mapperCalls = AtomicInteger(0)
    private val wfCalls = AtomicInteger(0)
    private val clockCalls = AtomicInteger(0)
    private val escaped = CopyOnWriteArrayList<Throwable>()
    private val scopeJob = AtomicReference<Job?>(null)
    private val gate = CountDownLatch(1)

    /** A store whose commit fails with an Error once [gate] opens (the worker dies AFTER the handler callback returned). */
    private class DyingStore(private val inner: Operations.MemoryStore, private val gate: CountDownLatch) : Operations.Store {
        override val scope: String get() = inner.scope
        override fun create(record: Map<String, Any?>): Map<String, Any?>? = inner.create(record)
        override fun get(id: String): Map<String, Any?>? = inner.get(id)
        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean {
            if (from == "executing") {
                gate.await(10, TimeUnit.SECONDS)
                throw AssertionError("store down")
            }
            return inner.transition(id, from, next)
        }
    }

    /** `send`: thrown once by a Before-send interceptor after a delay; `receive`: thrown by a Before-receive interceptor after a delay. */
    private class Faults(val send: Throwable? = null, val receive: Throwable? = null, val receiveValue: Any? = null)

    private fun PcaKtorConfig.setup(sc: Scenario, az: Authorize.AuthorizeOptions?) {
        audience = sc.audience
        resolveGrant = { ref -> if (ref == sc.grant["id"]) sc.grant else null }
        authorize = az
        clock = { clockCalls.incrementAndGet(); sc.now }
        operation = { _, _ -> mapperCalls.incrementAndGet(); sc.operation }
    }

    private fun app(f: Faults, cfg: PcaKtorConfig.() -> Unit, dispatcher: CoroutineDispatcher? = null, block: suspend ApplicationTestBuilder.() -> Unit) {
        ran.set(0); probe.set(0); mapperCalls.set(0); wfCalls.set(0); clockCalls.set(0); escaped.clear(); scopeJob.set(null)
        val ctx: CoroutineContext = dispatcher ?: EmptyCoroutineContext
        runBlocking {
            testApplication {
                application {
                    intercept(ApplicationCallPipeline.Setup) {
                        val sendFail = f.send
                        val once = AtomicBoolean(true)
                        if (sendFail != null) {
                            call.response.pipeline.intercept(ApplicationSendPipeline.Before) {
                                delay(10)
                                if (once.compareAndSet(true, false)) throw sendFail
                            }
                        }
                        val receiveFail = f.receive
                        if (receiveFail != null) {
                            call.request.pipeline.intercept(ApplicationReceivePipeline.Before) {
                                delay(10)
                                throw receiveFail
                            }
                        }
                        val receiveValue = f.receiveValue
                        if (receiveValue != null) {
                            call.request.pipeline.intercept(ApplicationReceivePipeline.After) {
                                proceedWith(receiveValue)
                            }
                        }
                        try {
                            withContext(ctx) {
                                supervisorScope {
                                    scopeJob.set(coroutineContext[Job])
                                    proceed()
                                }
                            }
                        } catch (t: Throwable) {
                            escaped.add(t)
                            finish()
                        }
                        if (call.response.status() == null) {
                            runCatching { call.respondText("no response", status = HttpStatusCode.fromValue(599)) }
                        }
                    }
                    routing {
                        route("/pay") {
                            install(PcaGuardPlugin, cfg)
                            intercept(ApplicationCallPipeline.Plugins) { probe.incrementAndGet() }
                            get("/send") {
                                ran.incrementAndGet()
                                call.respondText("ran:${call.pca?.operation?.verb}")
                            }
                            get("/plain") {
                                ran.incrementAndGet()
                                call.respondText("plain-body")
                            }
                            get("/nocontent") {
                                ran.incrementAndGet()
                                call.respond(HttpStatusCode.NoContent)
                            }
                            get("/ka") {
                                ran.incrementAndGet()
                                call.response.respHeader("X-Ka", "k1")
                                call.response.respHeader("Keep-Alive", "timeout=5")
                                call.respondText("ka-body")
                            }
                            get("/gated") {
                                ran.incrementAndGet()
                                launch { delay(100); gate.countDown() }
                                call.respondText("gated")
                            }
                            get("/cancel") {
                                ran.incrementAndGet()
                                throw CancellationException("handler-cancel")
                            }
                        }
                    }
                }
                block()
            }
        }
    }

    private suspend fun ApplicationTestBuilder.hit(path: String, sc: Scenario, seconds: Long = 30): HttpResponse =
        withTimeout(seconds * 1000) {
            client.get(path) {
                header(PcaGuard.HEADER, sc.header)
                header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
            }
        }

    private fun opId(sc: Scenario) = Pca.hashCanonical(sc.pcactn)

    private fun committed(sc: Scenario, result: Any?): Operations.Store {
        val store = GuardFixtures.storeWith(sc, "committed")
        val id = opId(sc)
        val rec = LinkedHashMap(store.get(id)!!)
        rec["result"] = result
        assertTrue(store.transition(id, "committed", rec))
        return store
    }

    private fun recorded(contentType: String?): Map<String, Any?> = linkedMapOf(
        "status" to 200L, "contentType" to contentType, "headers" to linkedMapOf<String, Any?>(),
        "body" to Base64.getEncoder().encodeToString("raw".toByteArray()),
    )

    private fun awaitState(store: Operations.Store, id: String, state: String): Map<String, Any?>? = runBlocking {
        withTimeoutOrNull(5000) {
            var r = store.get(id)
            while (r == null || r["state"] != state) {
                delay(25)
                r = store.get(id)
            }
            r
        }
    }

    // ---- install: the body, the mapper and the workflow callback resumed with a CancellationException ----

    @Test
    fun aRequestBodyReadThatFailsWithACancellationEndsThePipelineBeforeTheMapper() {
        val sc = GuardFixtures.within()
        app(Faults(receive = CancellationException("receive cancelled")), { setup(sc, GuardFixtures.options()) }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertTrue(escaped[0] is CancellationException)
        assertEquals(0, mapperCalls.get())
        assertEquals(0, probe.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun anOperationMapperThatFailsWithACancellationEndsThePipelineBeforeTheWorkflowCallback() {
        val sc = GuardFixtures.within()
        app(Faults(), {
            setup(sc, GuardFixtures.options())
            operation = { _, _ -> delay(10); throw CancellationException("mapper cancelled") }
            workflowStep = { _, _ -> wfCalls.incrementAndGet(); null }
        }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertTrue(escaped[0] is CancellationException)
        assertEquals(0, wfCalls.get())
        assertEquals(0, clockCalls.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun aWorkflowCallbackThatFailsWithACancellationEndsThePipelineBeforeTheDecision() {
        val sc = GuardFixtures.within()
        app(Faults(), {
            setup(sc, GuardFixtures.options())
            workflowStep = { _, _ -> delay(10); throw CancellationException("workflow cancelled") }
        }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertTrue(escaped[0] is CancellationException)
        assertEquals(1, mapperCalls.get())
        assertEquals(0, clockCalls.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun withNoMapperAConfiguredWorkflowCallbackThatSuspendsStillGetsTheBodyAndTheRequestIsRefused() {
        val sc = GuardFixtures.within()
        app(Faults(), {
            audience = sc.audience
            resolveGrant = { ref -> if (ref == sc.grant["id"]) sc.grant else null }
            authorize = GuardFixtures.options()
            clock = { clockCalls.incrementAndGet(); sc.now }
            workflowStep = { _, _ -> delay(10); wfCalls.incrementAndGet(); null }
        }) {
            val r = hit("/pay/send", sc)
            val text = r.bodyAsText()
            assertEquals(text, 403, r.status.value)
            assertFalse(text, text.contains("guard error"))
        }
        assertTrue(escaped.toString(), escaped.isEmpty())
        assertEquals(1, wfCalls.get())
        assertEquals(0, ran.get())
    }

    // ---- install: a refusal whose send fails ----

    @Test
    fun aRefusalWhoseSendFailsAfterSuspendingEscapesThePlugin() {
        val sc = GuardFixtures.overLimit()
        app(Faults(send = IllegalStateException("send failed")), { setup(sc, GuardFixtures.options()) }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertEquals("send failed", escaped[0].message)
        assertEquals(0, probe.get())
        assertEquals(0, ran.get())
    }

    // ---- the executor path ----

    @Test
    fun aReplayWithAnUnparseableContentTypeFailsTheCallAndNeverReachesTheHandler() {
        val sc = GuardFixtures.within()
        app(Faults(), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(committed(sc, recorded("not-a-content-type"))) }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertEquals(0, probe.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun aReplaySendThatFailsAfterSuspendingEscapesTheExecutorPath() {
        val sc = GuardFixtures.within()
        app(Faults(send = IllegalStateException("replay send failed")), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(committed(sc, recorded("text/plain"))) }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertEquals("replay send failed", escaped[0].message)
        assertEquals(0, probe.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun anExecutorRefusalWhoseSendIsCancelledEscapesTheExecutorPath() {
        val sc = GuardFixtures.within()
        app(Faults(send = CancellationException("send cancelled")), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(GuardFixtures.storeWith(sc, "executing")) }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertTrue(escaped[0] is CancellationException)
        assertEquals(0, probe.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun anUnreadableRecordWhoseRefusalSendIsCancelledEscapesTheExecutorPath() {
        val sc = GuardFixtures.within()
        app(Faults(send = CancellationException("unreadable send cancelled")), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(committed(sc, "not a map")) }) { hit("/pay/send", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        assertTrue(escaped[0] is CancellationException)
        assertEquals(0, probe.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun anExecutorRefusalWhoseSendFailsOrdinarilyIsSwallowedBecauseTheResponseMayAlreadyBeOut() {
        val sc = GuardFixtures.within()
        app(Faults(send = IllegalStateException("send failed")), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(GuardFixtures.storeWith(sc, "executing")) }) {
            val r = hit("/pay/send", sc)
            // the refusal never went out (its send failed), so the client sees the framework status, not the handler's 200
            assertTrue(r.status.value.toString(), r.status.value == 599 || r.status.value == 404)
        }
        assertTrue(escaped.toString(), escaped.isEmpty())
        assertEquals(0, probe.get())
        assertEquals(0, ran.get())
    }

    @Test
    fun theRecordedResponseKeepsTheStatusLessAndTypeLessShapesAndLeavesOutFrameworkHeaders() {
        val sc = GuardFixtures.within()
        val id = opId(sc)

        var store = Operations.MemoryStore()
        app(Faults(), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/plain", sc)
            assertEquals(r.bodyAsText(), 200, r.status.value)
            assertEquals("plain-body", r.bodyAsText())
        }
        assertTrue(escaped.toString(), escaped.isEmpty())
        var res = awaitState(store, id, "committed")!!["result"] as Map<*, *>
        assertEquals(200L, res["status"])

        store = Operations.MemoryStore()
        app(Faults(), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/nocontent", sc)
            assertEquals(r.bodyAsText(), 204, r.status.value)
        }
        assertTrue(escaped.toString(), escaped.isEmpty())
        res = awaitState(store, id, "committed")!!["result"] as Map<*, *>
        assertEquals(204L, res["status"])
        assertEquals(null, res["contentType"])

        store = Operations.MemoryStore()
        app(Faults(), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/ka", sc)
            assertEquals(r.bodyAsText(), 200, r.status.value)
        }
        assertTrue(escaped.toString(), escaped.isEmpty())
        res = awaitState(store, id, "committed")!!["result"] as Map<*, *>
        val names = (res["headers"] as Map<*, *>).keys.map { (it as String).lowercase() }
        assertTrue(names.toString(), "x-ka" in names)
        assertFalse(names.toString(), "keep-alive" in names)
    }

    @Test
    fun aHandlerCancellationIsHandedToTheWorkerAsItsOwnFailureNotAsAnAbandonment() {
        val sc = GuardFixtures.within()
        val store = Operations.MemoryStore()
        app(Faults(), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) { hit("/pay/cancel", sc) }
        assertEquals(escaped.toString(), 1, escaped.size)
        val rec = awaitState(store, opId(sc), "failed")
        assertNotNull("the operation never reached failed", rec)
        // The executor records the message of what done.get() throws. The expected value is computed from this JDK for the very
        // completion the plugin makes: a JDK whose get() rethrows the completion yields "handler-cancel" (the finally block's
        // "abandoned" would differ), a JDK that wraps it yields its own fixed text for any completion.
        val probeFuture = java.util.concurrent.CompletableFuture<Any?>()
        probeFuture.completeExceptionally(CancellationException("handler-cancel"))
        val expected = try { probeFuture.get(); "" } catch (e: Exception) { e.message ?: e.javaClass.simpleName }
        if (expected == "handler-cancel") assertEquals(expected, rec!!["error"])
        assertNotEquals("abandoned", rec!!["error"])
    }

    @Test
    fun theExecutorWorkerRunsOnTheIoDispatcherNotOnTheCallsOwnDispatcher() {
        val sc = GuardFixtures.within()
        val names = CopyOnWriteArrayList<String>()
        val n = AtomicInteger(0)
        val own = Executors.newFixedThreadPool(2) { r -> Thread(r, "pca-call-" + n.incrementAndGet()).also { it.isDaemon = true } }.asCoroutineDispatcher()
        try {
            app(Faults(), {
                setup(sc, GuardFixtures.options())
                executor = GuardFixtures.executor(recheck = { names.add(Thread.currentThread().name); Operations.Recheck.OK })
            }, own) {
                val r = hit("/pay/send", sc)
                assertEquals(r.bodyAsText(), 200, r.status.value)
            }
        } finally {
            own.close()
        }
        assertTrue("the recheck never ran", names.isNotEmpty())
        assertTrue(names.toString(), names.all { it.startsWith("DefaultDispatcher-worker") })
    }

    @Test
    fun aWorkerStartedOnAnAlreadyCancelledScopeNeverRunsTheGuard() {
        val sc = GuardFixtures.within()
        app(Faults(), {
            setup(sc, GuardFixtures.options())
            executor = GuardFixtures.executor()
            operation = { _, _ -> scopeJob.get()?.cancel(); mapperCalls.incrementAndGet(); sc.operation }
        }) { runCatching { hit("/pay/send", sc, 10) } }
        // the cancelled scope must end the call with a CancellationException: a mutant that skips the check cannot pass by escaping nothing
        assertTrue(escaped.toString(), escaped.any { it is CancellationException })
        // give a (wrongly started) worker on the IO pool time to reach the clock
        runBlocking { withTimeoutOrNull(1000) { while (clockCalls.get() == 0) delay(20) } }
        assertEquals(0, clockCalls.get())
    }

    @Test
    fun aWorkerThatDiesWithAnErrorIsNotTurnedIntoAClassCastException() {
        val sc = GuardFixtures.within()
        app(Faults(), {
            setup(sc, GuardFixtures.options())
            executor = GuardFixtures.executor(recheck = { throw AssertionError("recheck down") })
        }) { runCatching { hit("/pay/send", sc, 10) } }
        assertTrue(escaped.toString(), escaped.none { it is ClassCastException })
    }

    @Test
    fun aWorkerThatDiesAfterTheHandlerIsNotTurnedIntoAClassCastExceptionByTheAwait() {
        val sc = GuardFixtures.within()
        app(Faults(), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(DyingStore(Operations.MemoryStore(), gate)) }) { runCatching { hit("/pay/gated", sc, 15) } }
        assertTrue(escaped.toString(), escaped.none { it is ClassCastException })
    }

    /** The worker runs inline (Unconfined): the select / the executeOnce call complete without ever suspending. */
    @Test
    fun anExecutorRefusalCompletesWhenTheWorkerFinishesBeforeTheSelect() {
        val sc = GuardFixtures.overLimit()
        val saved = executeWorkerDispatcher
        executeWorkerDispatcher = kotlinx.coroutines.Dispatchers.Unconfined
        try {
            app(Faults(), { setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
                val r = hit("/pay/send", sc, 10)
                assertEquals(r.bodyAsText(), 403, r.status.value)
                assertEquals("insufficient_authority", GuardFixtures.parse(r.bodyAsText())["error"])
                val none = withTimeout(10_000) { client.get("/pay/send") }
                assertEquals(401, none.status.value)
            }
        } finally {
            executeWorkerDispatcher = saved
        }
        assertTrue(escaped.toString(), escaped.isEmpty())
        assertEquals(0, ran.get())
    }

    @Test
    fun aReceiveThatYieldsNullBodyStillGivesTheMapperAnEmptyBody() {
        val sc = GuardFixtures.within()
        val seen = AtomicReference<Int?>(null)
        app(Faults(receiveValue = NullBody), {
            setup(sc, GuardFixtures.options())
            operation = { _, b -> seen.set(b.size); mapperCalls.incrementAndGet(); sc.operation }
        }) { hit("/pay/send", sc, 10) }
        assertEquals(escaped.toString(), 0, escaped.size)
        assertEquals(1, mapperCalls.get())
        assertEquals(0, seen.get())
    }
}
