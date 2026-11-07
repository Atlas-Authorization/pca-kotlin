package net.atlasauth.pca.ktor

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.BaseRouteScopedPlugin
import io.ktor.server.request.receive
import io.ktor.server.response.ApplicationSendPipeline
import io.ktor.server.response.header
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import io.ktor.util.AttributeKey
import io.ktor.util.pipeline.PipelineContext
import java.util.concurrent.CompletableFuture
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.selects.select
import net.atlasauth.pca.guard.GuardOutcome
import net.atlasauth.pca.guard.PcaExecutorConfig
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.guard.RecordedResponse
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca

/**
 * Configuration of the [PcaGuardPlugin].
 *
 * The default is the full authorize path: set [authorize] (replay store, revocation check, ...) and [operation] (what the
 * route will execute, from your routing and the parsed request, never from the proof). With no [authorize] every request is
 * refused with 403 `authorize_config` naming what is missing: the plugin never downgrades to signature-only by itself.
 * [signatureOnly] is the explicit opt-in (signature, chain, audience and validity only); combining it with [authorize] throws
 * [IllegalArgumentException] when the plugin is installed.
 */
class PcaKtorConfig {
    var audience: String? = null
    var resolveGrant: ((String) -> Map<String, Any?>?)? = null
    var authorize: Authorize.AuthorizeOptions? = null
    var intentPolicy: Pca.IntentPolicy? = null
    var signatureOnly: Boolean = false

    /** Epoch milliseconds. */
    var clock: () -> Long = { System.currentTimeMillis() }

    /**
     * Maps the call (and its buffered body, empty when there is none) to the operation the route will execute. A null return,
     * an exception or a missing mapper denies in authorize mode.
     */
    var operation: (suspend (ApplicationCall, ByteArray) -> Authorize.Operation?)? = null

    /**
     * Workflow admission (K5): set `authorize = AuthorizeOptions(..., workflow = WorkflowGate(principal, rsSigner, required))` to turn it on. This
     * callback returns the workflow step the call is; without it the step is read from the JSON body member `workflow` (`commitment`,
     * `receipts`, `step`, `units`, `goal_digest`) when the PCActn itself came from the body. A throwing callback is a refused step, never "no step".
     */
    var workflowStep: (suspend (ApplicationCall, ByteArray) -> Authorize.WorkflowStep?)? = null

    /**
     * Run-once execution (T3): with an operations store the downstream handler runs inside `Operations.Executor`. A retry of the
     * same PCActn is answered from the record with `PCA-Replayed: true` (the handler does not run again); a handler failure is 500
     * `operation_failed` (no error text), an in-flight one 409 `operation_in_progress`, an unknown outcome 409 `operation_uncertain`,
     * a refused re-check 403 `operation_aborted`. The recorded response is the handler's in-memory body (text, JSON, bytes); a
     * streamed body cannot be recorded and counts as a failure. Needs [authorize]. The handler blocks one IO worker while it runs.
     */
    var executor: PcaExecutorConfig? = null
}

/** The call attribute a passing request carries: the [GuardOutcome] with the verdict, the PCActn and the authorized operation. */
val PcaOutcomeKey: AttributeKey<GuardOutcome> = AttributeKey("AtlasPcaOutcome")

/** The outcome of a call that passed the guard, or null when the guard did not run for it. */
val ApplicationCall.pca: GuardOutcome? get() = attributes.getOrNull(PcaOutcomeKey)

/**
 * Ktor server plugin that enforces Proof-Carrying Authority. Install it on the application or on a route:
 * `install(PcaGuardPlugin) { audience = "..."; resolveGrant = {...}; authorize = AuthorizeOptions(...); operation = { call, body -> ... } }`.
 *
 * The PCActn is read from the `PCA-Action` header (strict unpadded base64url of JSON) or a JSON body `{"pcactn": ...}`. A
 * refusal answers 401 (no, undecodable or unauthenticated proof) or 403 with a `WWW-Authenticate: PCA realm="pca"` challenge and
 * a JSON body; an escalate answers 403 with `decision: "escalate"` and the request to put to the principal. The handler runs only
 * on an allow, and then reads [pca] (verdict, PCActn, bound operation).
 *
 * The plugin reads the request body once; install `DoubleReceive` if a handler also receives it.
 */
class PcaGuardPlugin private constructor(
    internal val guard: PcaGuardConfig,
    internal val mapper: (suspend (ApplicationCall, ByteArray) -> Authorize.Operation?)?,
    internal val workflowStep: (suspend (ApplicationCall, ByteArray) -> Authorize.WorkflowStep?)? = null,
) {
    companion object : BaseRouteScopedPlugin<PcaKtorConfig, PcaGuardPlugin> {
        override val key: AttributeKey<PcaGuardPlugin> = AttributeKey("AtlasPca")

        override fun install(pipeline: ApplicationCallPipeline, configure: PcaKtorConfig.() -> Unit): PcaGuardPlugin {
            val c = PcaKtorConfig().apply(configure)
            val plugin = PcaGuardPlugin(
                PcaGuardConfig(c.audience, c.resolveGrant, c.authorize, c.intentPolicy, c.signatureOnly, c.clock, c.executor), c.operation, c.workflowStep,
            )
            pipeline.intercept(ApplicationCallPipeline.Plugins) {
                val body: ByteArray = try {
                    call.receive<ByteArray>()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    ByteArray(0)
                }
                val op: Authorize.Operation? = try {
                    plugin.mapper?.invoke(call, body)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    null // fail closed: authorize refuses a missing operation
                }
                val wf: Authorize.WorkflowStep? = try {
                    plugin.workflowStep?.invoke(call, body)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Authorize.WorkflowStep(null, null, null) // fail closed: the gate refuses a step it cannot read
                }
                if (plugin.guard.executor != null) {
                    executeOnce(plugin.guard, body, op, wf)
                    return@intercept
                }
                val out = PcaGuard.decide(
                    plugin.guard, call.request.headers[PcaGuard.HEADER], call.request.headers[PcaGuard.ESCALATION_HEADER], body, op, wf,
                    call.request.headers[PcaGuard.PROVENANCE_HEADER],
                )
                if (out.allowed) {
                    call.attributes.put(PcaOutcomeKey, out)
                } else {
                    call.response.header(HttpHeaders.WWWAuthenticate, out.wwwAuthenticate ?: "PCA realm=\"pca\"")
                    call.respondText(out.body, ContentType.Application.Json, HttpStatusCode.fromValue(out.status))
                    finish()
                }
            }
            return plugin
        }
    }
}

private suspend fun ApplicationCall.respondRefusal(out: GuardOutcome) {
    try {
        if (out.wwwAuthenticate != null) response.header(HttpHeaders.WWWAuthenticate, out.wwwAuthenticate!!)
        respondText(out.body, ContentType.Application.Json, HttpStatusCode.fromValue(out.status))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        // the handler already sent its response: nothing more can be said
    }
}

/**
 * The executor path. The core executor is blocking, so it runs on a worker whose handler callback hands control back here; the rest
 * of the pipeline (the route handler) runs on this coroutine and its response is captured for the operation record.
 */
private suspend fun PipelineContext<Unit, ApplicationCall>.executeOnce(guard: PcaGuardConfig, body: ByteArray, op: Authorize.Operation?, wf: Authorize.WorkflowStep?) {
    val go = CompletableDeferred<GuardOutcome>()
    val done = CompletableFuture<Any?>()
    val proofHeader = call.request.headers[PcaGuard.HEADER]
    val escalation = call.request.headers[PcaGuard.ESCALATION_HEADER]
    val provenance = call.request.headers[PcaGuard.PROVENANCE_HEADER]
    val worker = async(Dispatchers.IO) {
        PcaGuard.execute(guard, proofHeader, escalation, body, op, wf, provenance) { o ->
            go.complete(o)
            done.get() // the handler's recorded result, or its failure
        }
    }
    try {
        val started = select<GuardOutcome?> {
            go.onAwait { it }
            worker.onAwait { null }
        }
        if (started != null) {
            try {
                done.complete(runDownstream(started))
            } catch (e: CancellationException) {
                done.completeExceptionally(e)
                throw e
            } catch (e: Exception) {
                done.completeExceptionally(e)
            }
        }
    } finally {
        done.completeExceptionally(CancellationException("abandoned")) // no-op once completed; frees the worker otherwise
    }
    val run = worker.await()
    val refusal = run.refusal
    if (refusal != null) {
        call.respondRefusal(refusal)
        finish()
        return
    }
    if (!run.replayed) {
        finish() // the handler's own response already went out
        return
    }
    val rec = RecordedResponse.of(run.result)
    if (rec == null) {
        call.respondRefusal(PcaGuard.unreadable())
        finish()
        return
    }
    for ((name, values) in rec.headers) for (v in values) call.response.header(name, v)
    call.response.header("PCA-Replayed", "true")
    call.respondBytes(rec.body, rec.contentType?.let { ContentType.parse(it) }, HttpStatusCode.fromValue(rec.status))
    finish()
}

/** Run the rest of the pipeline and return its response as the JSON tree to record. */
private suspend fun PipelineContext<Unit, ApplicationCall>.runDownstream(started: GuardOutcome): Any? {
    call.attributes.put(PcaOutcomeKey, started)
    var captured: RecordedResponse? = null
    call.response.pipeline.intercept(ApplicationSendPipeline.After) { content ->
        val bytes = when (content) {
            is OutgoingContent.ByteArrayContent -> content.bytes()
            is OutgoingContent.NoContent -> ByteArray(0)
            else -> throw IllegalStateException("the response is not an in-memory body")
        }
        val headers = LinkedHashMap<String, List<String>>()
        for ((n, vs) in call.response.headers.allValues().entries()) if (RecordedResponse.recorded(n)) headers[n] = vs.toList()
        captured = RecordedResponse((content as? OutgoingContent)?.status?.value ?: call.response.status()?.value ?: 200, (content as? OutgoingContent)?.contentType?.toString(), headers, bytes)
    }
    proceed()
    return (captured ?: throw IllegalStateException("the handler sent no response")).toRecord()
}
