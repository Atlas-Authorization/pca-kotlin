package net.atlasauth.pca.spring

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import jakarta.servlet.http.HttpServletResponse
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.nio.charset.Charset
import net.atlasauth.pca.guard.GuardOutcome
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.guard.RecordedResponse
import net.atlasauth.pca.verifier.Authorize
import org.springframework.web.servlet.HandlerInterceptor
import org.springframework.web.util.ContentCachingResponseWrapper

/** The request attribute a passing request carries: the [GuardOutcome] (verdict, PCActn, authorized operation). */
const val PCA_ATTRIBUTE = "pca"

/**
 * Maps a request to the operation the handler will execute (from your routing and the parsed body, never from the proof).
 * `body` is the buffered request body (empty when there is none, and always empty in [PcaInterceptor]). A null return, an
 * exception or no mapper at all denies in authorize mode.
 */
fun interface PcaOperationMapper {
    fun map(request: HttpServletRequest, body: ByteArray): Authorize.Operation?
}

/**
 * Maps a request to the workflow step it is (K5; used when `Authorize.AuthorizeOptions.workflow` is set). Without one the step is read from
 * the JSON body member `workflow` when the PCActn itself came from the body. A throwing mapper is a refused step, never "no step".
 */
fun interface PcaWorkflowStepMapper {
    fun map(request: HttpServletRequest, body: ByteArray): Authorize.WorkflowStep?
}

private fun mapWorkflow(mapper: PcaWorkflowStepMapper?, request: HttpServletRequest, body: ByteArray): Authorize.WorkflowStep? =
    try {
        mapper?.map(request, body)
    } catch (e: RuntimeException) {
        Authorize.WorkflowStep(null, null, null) // fail closed: the gate refuses a step it cannot read
    }

/** Resolves a PCActn's `grant_ref` to the stored root grant (null = unknown). Register one as a bean for the auto-configuration. */
fun interface PcaGrantResolver {
    fun resolve(grantRef: String): Map<String, Any?>?
}

private fun mapOperation(mapper: PcaOperationMapper?, request: HttpServletRequest, body: ByteArray): Authorize.Operation? =
    try {
        mapper?.map(request, body)
    } catch (e: RuntimeException) {
        null // fail closed: authorize refuses a missing operation
    }

private fun writeRefusal(resp: HttpServletResponse, out: GuardOutcome) {
    resp.reset()
    resp.status = out.status
    resp.setHeader("WWW-Authenticate", out.wwwAuthenticate ?: "PCA realm=\"pca\"")
    resp.contentType = "application/json;charset=UTF-8"
    val bytes = out.body.toByteArray(Charsets.UTF_8)
    resp.setContentLength(bytes.size)
    resp.outputStream.write(bytes)
}

/** The handler's recorded response, replayed: the status, the headers the response does not already carry, the body. */
private fun writeRecorded(resp: HttpServletResponse, rec: RecordedResponse, replayed: Boolean) {
    resp.status = rec.status
    for ((name, values) in rec.headers) if (!resp.containsHeader(name)) for (v in values) resp.addHeader(name, v)
    if (resp.contentType == null && rec.contentType != null) resp.contentType = rec.contentType
    if (replayed) resp.setHeader("PCA-Replayed", "true")
    resp.setContentLength(rec.body.size)
    resp.outputStream.write(rec.body)
}

/**
 * A servlet [Filter] that enforces Proof-Carrying Authority on every request it covers. The PCActn comes from the `PCA-Action`
 * header (strict unpadded base64url of JSON) or a JSON body `{"pcactn": ...}`; the body is buffered so downstream code still
 * reads it. The default is the full authorize path (see [PcaGuardConfig]): without authorize options every request is refused
 * with 403 `authorize_config`; signature-only is the explicit opt-in. A refusal answers 401 or 403 with a
 * `WWW-Authenticate: PCA realm="pca"` challenge and a JSON body (an escalate carries `decision` and the `escalation` request)
 * and does not continue the chain; an allow sets the [PCA_ATTRIBUTE] request attribute to the [GuardOutcome].
 *
 * With [PcaGuardConfig.executor] the chain (the handler) runs inside `Operations.Executor`, at most once per authorization: its
 * response is buffered and recorded, a retry of the same PCActn is answered from the record with `PCA-Replayed: true`, a handler
 * failure is 500 `operation_failed` (no error text), an in-flight one 409 `operation_in_progress`, an unknown outcome 409
 * `operation_uncertain` and a refused re-check 403 `operation_aborted`. Streamed bodies are not supported there.
 */
class PcaFilter @JvmOverloads constructor(
    private val config: PcaGuardConfig,
    private val operation: PcaOperationMapper? = null,
    private val workflowStep: PcaWorkflowStepMapper? = null,
) : Filter {
    init {
        require(!(config.signatureOnly && operation != null)) { "signatureOnly cannot be combined with an operation mapper" }
    }

    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        if (request !is HttpServletRequest || response !is HttpServletResponse) {
            chain.doFilter(request, response)
            return
        }
        val header: String? = request.getHeader(PcaGuard.HEADER)
        // the operation mapper reads the body, so authorize mode always buffers it; signature-only only when the header is absent
        val needBody = !config.signatureOnly || header.isNullOrEmpty()
        val buffered: ByteArray = if (needBody) request.inputStream.readAllBytes() else ByteArray(0)
        val downstream: HttpServletRequest = if (needBody) CachedBodyRequest(request, buffered) else request
        val op = if (config.signatureOnly) null else mapOperation(operation, downstream, buffered)
        val wf = mapWorkflow(workflowStep, downstream, buffered)
        if (config.executor != null) {
            executeOnce(request, response, chain, downstream, header, buffered, op, wf)
            return
        }
        val out = PcaGuard.decide(config, header, request.getHeader(PcaGuard.ESCALATION_HEADER), buffered, op, wf)
        if (out.allowed) {
            downstream.setAttribute(PCA_ATTRIBUTE, out)
            chain.doFilter(downstream, response)
        } else {
            writeRefusal(response, out)
        }
    }

    private fun executeOnce(
        request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain, downstream: HttpServletRequest,
        header: String?, buffered: ByteArray, op: Authorize.Operation?, wf: Authorize.WorkflowStep?,
    ) {
        val run = PcaGuard.execute(config, header, request.getHeader(PcaGuard.ESCALATION_HEADER), buffered, op, wf) { started ->
            downstream.setAttribute(PCA_ATTRIBUTE, started)
            val cached = ContentCachingResponseWrapper(response)
            chain.doFilter(downstream, cached)
            val headers = LinkedHashMap<String, List<String>>()
            for (n in cached.headerNames) if (RecordedResponse.recorded(n)) headers[n] = cached.getHeaders(n).toList()
            RecordedResponse(cached.status, cached.contentType, headers, cached.contentAsByteArray).toRecord()
        }
        val refusal = run.refusal
        if (refusal != null) {
            writeRefusal(response, refusal)
            return
        }
        val rec = RecordedResponse.of(run.result)
        if (rec == null) writeRefusal(response, PcaGuard.unreadable()) else writeRecorded(response, rec, run.replayed)
    }
}

/**
 * A Spring MVC [HandlerInterceptor] sharing the filter's decision. Header transport only: it never reads the body (reading it
 * in `preHandle` would consume it before a `@RequestBody` handler), so the mapper gets an empty body; map from the route and
 * query, or use [PcaFilter] for body-delivered proofs. It cannot be used with [PcaGuardConfig.executor] (every request fails closed).
 */
class PcaInterceptor @JvmOverloads constructor(
    private val config: PcaGuardConfig,
    private val operation: PcaOperationMapper? = null,
    private val workflowStep: PcaWorkflowStepMapper? = null,
) : HandlerInterceptor {
    init {
        require(!(config.signatureOnly && operation != null)) { "signatureOnly cannot be combined with an operation mapper" }
    }

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        // an interceptor cannot run the handler inside the executor: fail closed rather than let it run unrecorded
        check(config.executor == null) { "the interceptor cannot run the handler inside an executor; use PcaFilter" }
        val empty = ByteArray(0)
        val op = if (config.signatureOnly) null else mapOperation(operation, request, empty)
        val out = PcaGuard.decide(config, request.getHeader(PcaGuard.HEADER), request.getHeader(PcaGuard.ESCALATION_HEADER), empty, op, mapWorkflow(workflowStep, request, empty))
        if (out.allowed) {
            request.setAttribute(PCA_ATTRIBUTE, out)
            return true
        }
        writeRefusal(response, out)
        return false
    }
}

/** Wraps a request so its already-read body can be read again downstream. */
internal class CachedBodyRequest(request: HttpServletRequest, private val body: ByteArray) : HttpServletRequestWrapper(request) {
    override fun getInputStream(): ServletInputStream {
        val buf = ByteArrayInputStream(body)
        return object : ServletInputStream() {
            override fun isFinished(): Boolean = buf.available() == 0
            override fun isReady(): Boolean = true
            override fun setReadListener(listener: ReadListener?) { throw UnsupportedOperationException() }
            override fun read(): Int = buf.read()
            override fun read(b: ByteArray, off: Int, len: Int): Int = buf.read(b, off, len)
        }
    }

    override fun getReader(): BufferedReader {
        var cs: Charset = Charsets.UTF_8
        val enc = characterEncoding
        if (enc != null) {
            try { cs = Charset.forName(enc) } catch (e: RuntimeException) { /* keep UTF-8 */ }
        }
        return BufferedReader(InputStreamReader(ByteArrayInputStream(body), cs))
    }

    override fun getContentLength(): Int = body.size

    override fun getContentLengthLong(): Long = body.size.toLong()
}
