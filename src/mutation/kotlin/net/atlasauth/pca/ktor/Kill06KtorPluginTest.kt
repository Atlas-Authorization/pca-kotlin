package net.atlasauth.pca.ktor

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondOutputStream
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.GuardFixtures.Scenario
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import io.ktor.server.response.header as respHeader

/** The Ktor plugin's request path and run-once executor path, line by line (every status, header, record and failure text). */
@Suppress("UNCHECKED_CAST")
class Kill06KtorPluginTest {
    private val ran = AtomicInteger(0)

    private fun PcaKtorConfig.setup(sc: Scenario, az: Authorize.AuthorizeOptions?) {
        audience = sc.audience
        resolveGrant = { ref -> if (ref == sc.grant["id"]) sc.grant else null }
        authorize = az
        clock = { sc.now }
        operation = { _, _ -> sc.operation }
    }

    private fun app(cfg: PcaKtorConfig.() -> Unit, block: suspend ApplicationTestBuilder.() -> Unit) = runBlocking {
        testApplication {
            application {
                routing {
                    route("/pay") {
                        install(PcaGuardPlugin, cfg)
                        get("/send") {
                            ran.incrementAndGet()
                            call.respondText("ran:${call.pca!!.operation?.verb}")
                        }
                        post("/send") {
                            ran.incrementAndGet()
                            call.respondText("ran:${call.pca!!.operation?.verb}")
                        }
                        get("/idem") {
                            val o = call.pca!!
                            call.respondText(
                                "${o.allowed}|${o.decision}|${o.operation?.verb}|${o.idempotencyKey == o.operation?.id}|${o.idempotencyKey != null}|" +
                                    "${o.pcactn != null}|${o.authorization == null}",
                            )
                        }
                        get("/rich") {
                            ran.incrementAndGet()
                            call.response.respHeader("X-Trace", "t1")
                            call.response.respHeader("X-Multi", "a")
                            call.response.respHeader("X-Multi", "b")
                            call.respondText("rich-body", ContentType.Text.Plain, HttpStatusCode.Created)
                        }
                        get("/accepted") {
                            ran.incrementAndGet()
                            call.response.status(HttpStatusCode.Accepted)
                            call.respondText("acc")
                        }
                        get("/nocontent") {
                            ran.incrementAndGet()
                            call.respond(HttpStatusCode.NoContent)
                        }
                        get("/stream") {
                            ran.incrementAndGet()
                            call.respondOutputStream(ContentType.Text.Plain) { write("x".toByteArray()) }
                        }
                        get("/silent") {
                            ran.incrementAndGet()
                        }
                        get("/boom") {
                            ran.incrementAndGet()
                            error("secret-detail")
                        }
                    }
                }
            }
            block()
        }
    }

    private suspend fun ApplicationTestBuilder.hit(path: String, sc: Scenario, answer: Map<String, Any?>? = null): HttpResponse =
        client.get(path) {
            header(PcaGuard.HEADER, sc.header)
            header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
            if (answer != null) header(PcaGuard.ESCALATION_HEADER, GuardFixtures.headerOf(answer))
        }

    private fun opId(sc: Scenario) = Pca.hashCanonical(sc.pcactn)

    // ---- the plain path ----

    @Test
    fun aRefusalIsJsonWithTheStatusTheChallengeAndNoHandlerRun() {
        val sc = GuardFixtures.overLimit()
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = hit("/pay/send", sc)
            assertEquals(403, r.status.value)
            assertTrue(r.headers["Content-Type"]!!, r.headers["Content-Type"]!!.startsWith("application/json"))
            assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", r.headers["WWW-Authenticate"])
            val body = GuardFixtures.parse(r.bodyAsText())
            assertEquals("insufficient_authority", body["error"])
            assertEquals("deny", body["decision"])
            val again = client.get("/pay/send")
            assertEquals(401, again.status.value)
            assertEquals("PCA realm=\"pca\"", again.headers["WWW-Authenticate"])
            assertTrue(again.headers["Content-Type"]!!.startsWith("application/json"))
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun anAllowRunsTheHandlerExactlyOnceAndNothingElseIsSent() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()) }) {
            val r = hit("/pay/send", sc)
            assertEquals(200, r.status.value)
            assertEquals("ran:payments.send", r.bodyAsText())
            assertNull(r.headers["WWW-Authenticate"])
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun theOperationMapperAndTheWorkflowCallbackReceiveTheCallAndTheBufferedBody() {
        val sc = GuardFixtures.within()
        val mapBody = AtomicReference<String?>(null)
        val mapPath = AtomicReference<String?>(null)
        val wfBody = AtomicReference<String?>(null)
        val wfPath = AtomicReference<String?>(null)
        app({
            setup(sc, GuardFixtures.options())
            operation = { c, b -> mapBody.set(String(b, Charsets.UTF_8)); mapPath.set(c.request.local.uri); sc.operation }
            workflowStep = { c, b -> wfBody.set(String(b, Charsets.UTF_8)); wfPath.set(c.request.local.uri); null }
        }) {
            val r = client.post("/pay/send") { setBody(sc.body) }
            assertEquals(r.bodyAsText(), 200, r.status.value)
        }
        assertEquals(sc.body, mapBody.get())
        assertEquals("/pay/send", mapPath.get())
        assertEquals(sc.body, wfBody.get())
        assertEquals("/pay/send", wfPath.get())
    }

    @Test
    fun aRequestWithoutABodyIsBufferedAsEmpty() {
        val sc = GuardFixtures.within()
        val size = AtomicInteger(-1)
        app({ setup(sc, GuardFixtures.options()); operation = { _, b -> size.set(b.size); sc.operation } }) {
            assertEquals(200, hit("/pay/send", sc).status.value)
        }
        assertEquals(0, size.get())
    }

    @Test
    fun aBodyThatCannotBeReadIsBufferedAsEmpty() {
        val sc = GuardFixtures.within()
        val size = AtomicInteger(-1)
        runBlocking {
            testApplication {
                application {
                    routing {
                        route("/eat") {
                            // consumes the body first: the plugin's own receive then fails (no DoubleReceive), which it treats as empty
                            intercept(ApplicationCallPipeline.Plugins) { call.receive<ByteArray>() }
                            install(PcaGuardPlugin) {
                                setup(sc, GuardFixtures.options())
                                operation = { _, b -> size.set(b.size); sc.operation }
                            }
                            get("/x") { call.respondText("ok") }
                        }
                    }
                }
                val r = client.get("/eat/x") {
                    header(PcaGuard.HEADER, sc.header)
                    header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
                }
                assertEquals(r.bodyAsText(), 200, r.status.value)
            }
        }
        assertEquals(0, size.get())
    }

    @Test
    fun anIntentPolicyIsForwardedToTheVerifier() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); intentPolicy = Pca.IntentPolicy(require = true) }) {
            val r = hit("/pay/send", sc)
            assertEquals(403, r.status.value)
            assertTrue(r.bodyAsText(), r.bodyAsText().contains("intent binding"))
        }
        assertEquals(0, ran.get())
    }

    // ---- the executor path: what the handler sees ----

    @Test
    fun theHandlerSeesTheAllowWithItsBoundOperationAndIdempotencyKey() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val r = hit("/pay/idem", sc)
            assertEquals(r.bodyAsText(), 200, r.status.value)
            assertEquals("true|allow|payments.send|true|true|true|true", r.bodyAsText())
        }
    }

    @Test
    fun theEscalationAnswerAndTheBodyTransportReachTheExecutor() {
        val sc = GuardFixtures.escalating()
        val answer = GuardFixtures.signedAllow(sc)
        app({ setup(sc, GuardFixtures.options(GuardFixtures.principals())); executor = GuardFixtures.executor() }) {
            val held = hit("/pay/send", sc)
            assertEquals(403, held.status.value)
            assertEquals("escalate", GuardFixtures.parse(held.bodyAsText())["decision"])
        }
        assertEquals(0, ran.get())
        app({ setup(sc, GuardFixtures.options(GuardFixtures.principals())); executor = GuardFixtures.executor() }) {
            val ok = hit("/pay/send", sc, answer)
            assertEquals(ok.bodyAsText(), 200, ok.status.value)
            assertEquals("ran:payments.send", ok.bodyAsText())
        }
        assertEquals(1, ran.get())
        val w = GuardFixtures.within()
        app({ setup(w, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val r = client.post("/pay/send") { setBody(w.body) }
            assertEquals(r.bodyAsText(), 200, r.status.value)
            assertEquals("ran:payments.send", r.bodyAsText())
        }
    }

    @Test
    fun theProvenanceHeaderReachesTheExecutor() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val r = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header) }
            assertEquals(403, r.status.value)
            assertTrue(r.bodyAsText(), (GuardFixtures.parse(r.bodyAsText())["reason"] as String).contains("provenance_flow"))
            assertEquals(0, ran.get())
        }
    }

    // ---- the executor path: recording and replaying the handler's response ----

    @Test
    fun aRecordedResponseIsReplayedWithItsStatusContentTypeAndHeaders() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val first = hit("/pay/rich", sc)
            assertEquals(201, first.status.value)
            assertEquals("rich-body", first.bodyAsText())
            assertEquals("t1", first.headers["X-Trace"])
            assertEquals("a,b", first.headers.getAll("X-Multi")!!.joinToString(","))
            assertNull(first.headers["PCA-Replayed"])
            val again = hit("/pay/rich", sc)
            assertEquals(201, again.status.value)
            assertEquals("rich-body", again.bodyAsText())
            assertEquals("true", again.headers["PCA-Replayed"])
            assertEquals("t1", again.headers["X-Trace"])
            assertEquals("a,b", again.headers.getAll("X-Multi")!!.joinToString(","))
            assertTrue(again.headers["Content-Type"]!!, again.headers["Content-Type"]!!.startsWith("text/plain"))
            assertEquals(1, again.headers.getAll("Content-Type")!!.size)
            assertEquals(1, again.headers.getAll("PCA-Replayed")!!.size)
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun aStatusSetOnTheResponseIsRecordedWhenTheBodyCarriesNone() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            assertEquals(202, hit("/pay/accepted", sc).status.value)
            val again = hit("/pay/accepted", sc)
            assertEquals(202, again.status.value)
            assertEquals("acc", again.bodyAsText())
            assertEquals("true", again.headers["PCA-Replayed"])
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun anEmptyResponseIsRecordedAndReplayedEmpty() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            assertEquals(204, hit("/pay/nocontent", sc).status.value)
            val again = hit("/pay/nocontent", sc)
            assertEquals(204, again.status.value)
            assertEquals("", again.bodyAsText())
            assertEquals("true", again.headers["PCA-Replayed"])
        }
        assertEquals(1, ran.get())
    }

    @Test
    fun aPlainOkIsRecordedAs200() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            assertEquals(200, hit("/pay/send", sc).status.value)
            val again = hit("/pay/send", sc)
            assertEquals(200, again.status.value)
            assertEquals("ran:payments.send", again.bodyAsText())
            assertEquals("true", again.headers["PCA-Replayed"])
        }
    }

    // ---- the executor path: failures name their cause in the record, never in the response ----

    @Test
    fun aStreamedBodyIsAFailureRecordedWithItsReason() {
        val sc = GuardFixtures.within()
        val store = Operations.MemoryStore()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/stream", sc)
            assertEquals(500, r.status.value)
            val body = r.bodyAsText()
            assertEquals("operation_failed", GuardFixtures.parse(body)["error"])
            assertFalse(body, body.contains("in-memory"))
            assertNull(r.headers["WWW-Authenticate"])
            assertTrue(r.headers["Content-Type"]!!.startsWith("application/json"))
        }
        val rec = store.get(opId(sc))!!
        assertEquals("failed", rec["state"])
        assertTrue(rec.toString(), (rec["error"] as String).contains("the response is not an in-memory body"))
    }

    @Test
    fun aHandlerThatSendsNothingIsAFailureRecordedWithItsReason() {
        val sc = GuardFixtures.within()
        val store = Operations.MemoryStore()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/silent", sc)
            assertEquals(500, r.status.value)
            assertEquals("operation_failed", GuardFixtures.parse(r.bodyAsText())["error"])
        }
        val rec = store.get(opId(sc))!!
        assertEquals("failed", rec["state"])
        assertTrue(rec.toString(), (rec["error"] as String).contains("the handler sent no response"))
    }

    @Test
    fun aThrowingHandlerIsRecordedWithItsOwnMessage() {
        val sc = GuardFixtures.within()
        val store = Operations.MemoryStore()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/boom", sc)
            assertEquals(500, r.status.value)
            assertFalse(r.bodyAsText(), r.bodyAsText().contains("secret-detail"))
        }
        val rec = store.get(opId(sc))!!
        assertEquals("failed", rec["state"])
        val err = rec["error"] as String
        assertTrue(err, err.contains("secret-detail"))
        assertFalse(err, err.contains("abandoned"))
    }

    // ---- the executor path: refusals ----

    @Test
    fun executorRefusalsCarryTheChallengeOnlyWhereTheStatusAsksForIt() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(recheck = { Operations.Recheck.refuse("approval withdrawn") }) }) {
            val r = hit("/pay/send", sc)
            assertEquals(403, r.status.value)
            assertEquals("PCA realm=\"pca\", error=\"operation_aborted\"", r.headers["WWW-Authenticate"])
            assertTrue(r.headers["Content-Type"]!!.startsWith("application/json"))
            val b = GuardFixtures.parse(r.bodyAsText())
            assertEquals("operation_aborted", b["error"])
            assertTrue(b.toString(), (b["error_description"] as String).contains("approval withdrawn"))
            assertEquals("deny", b["decision"])
        }
        assertEquals(0, ran.get())
        for (state in listOf("executing", "uncertain")) {
            app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(GuardFixtures.storeWith(sc, state)) }) {
                val r = hit("/pay/send", sc)
                assertEquals(409, r.status.value)
                assertNull(r.headers["WWW-Authenticate"])
                assertTrue(r.headers["Content-Type"]!!.startsWith("application/json"))
                assertEquals(if (state == "executing") "operation_in_progress" else "operation_uncertain", GuardFixtures.parse(r.bodyAsText())["error"])
            }
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun aMissingProofInExecutorModeIs401WithTheChallengeAndNoRun() {
        val sc = GuardFixtures.within()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val r = client.get("/pay/send")
            assertEquals(401, r.status.value)
            assertEquals("PCA realm=\"pca\"", r.headers["WWW-Authenticate"])
            assertTrue(r.headers["Content-Type"]!!.startsWith("application/json"))
            assertEquals("pca_required", GuardFixtures.parse(r.bodyAsText())["error"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun anAuthorizeDenialInExecutorModeIs403WithTheChallengeAndNoRun() {
        val sc = GuardFixtures.overLimit()
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor() }) {
            val r = hit("/pay/send", sc)
            assertEquals(403, r.status.value)
            assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", r.headers["WWW-Authenticate"])
            assertEquals("insufficient_authority", GuardFixtures.parse(r.bodyAsText())["error"])
        }
        assertEquals(0, ran.get())
    }

    // ---- the executor path: an earlier committed record is answered from the store ----

    private fun committed(sc: Scenario, result: Any?): Operations.Store {
        val store = GuardFixtures.storeWith(sc, "committed")
        val id = opId(sc)
        val rec = LinkedHashMap(store.get(id)!!)
        rec["result"] = result
        assertTrue(store.transition(id, "committed", rec))
        return store
    }

    private fun result(status: Any?, contentType: String?, headers: Any?, body: String) = linkedMapOf<String, Any?>(
        "status" to status, "contentType" to contentType, "headers" to headers,
        "body" to Base64.getEncoder().encodeToString(body.toByteArray()),
    )

    @Test
    fun aCommittedRecordIsReplayedWithoutTheFrameworkOwnedHeaders() {
        val sc = GuardFixtures.within()
        val store = committed(
            sc,
            result(
                418L, "text/plain; charset=UTF-8",
                linkedMapOf("X-Rec" to listOf("a", "b"), "Content-Length" to listOf("999"), "content-type" to listOf("x/y"), "Connection" to listOf("close")),
                "hello",
            ),
        )
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/send", sc)
            assertEquals(418, r.status.value)
            assertEquals("hello", r.bodyAsText())
            assertEquals("a,b", r.headers.getAll("X-Rec")!!.joinToString(","))
            assertEquals("true", r.headers["PCA-Replayed"])
            assertTrue(r.headers["Content-Type"]!!, r.headers["Content-Type"]!!.startsWith("text/plain"))
            assertNotEquals("999", r.headers["Content-Length"])
            assertNotEquals("close", r.headers["Connection"])
        }
        assertEquals(0, ran.get())
    }

    @Test
    fun aCommittedRecordWithoutAContentTypeIsStillReplayed() {
        val sc = GuardFixtures.within()
        val store = committed(sc, result(200L, null, linkedMapOf<String, Any?>(), "raw"))
        app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
            val r = hit("/pay/send", sc)
            assertEquals(200, r.status.value)
            assertEquals("raw", r.bodyAsText())
            assertEquals("true", r.headers["PCA-Replayed"])
        }
    }

    @Test
    fun anUnreadableCommittedRecordIs409UncertainWithoutAChallenge() {
        val sc = GuardFixtures.within()
        val bad = listOf<Any?>(
            "not a map",
            result(1.5, "text/plain", linkedMapOf<String, Any?>(), "x"),
            result(200L, "text/plain", null, "x"),
        )
        for (rec in bad) {
            val store = committed(sc, rec)
            app({ setup(sc, GuardFixtures.options()); executor = GuardFixtures.executor(store) }) {
                val r = hit("/pay/send", sc)
                assertEquals(rec.toString(), 409, r.status.value)
                assertNull(r.headers["WWW-Authenticate"])
                assertNull(r.headers["PCA-Replayed"])
                assertTrue(r.headers["Content-Type"]!!.startsWith("application/json"))
                val b = GuardFixtures.parse(r.bodyAsText())
                assertEquals("operation_uncertain", b["error"])
                assertEquals("the recorded result is unreadable", b["error_description"])
            }
        }
        assertEquals(0, ran.get())
    }
}
