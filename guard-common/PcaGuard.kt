package net.atlasauth.pca.guard

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import net.atlasauth.pca.verifier.ArgProvenance
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca

/**
 * What a guard (the Ktor plugin, the Spring filter / interceptor) is configured with. Shared by both integrations; it has no
 * Ktor or Spring dependency.
 *
 * The default is the full [Authorize.authorize] path: the proof must authorize exactly the operation the host derives from the
 * request, the envelope and caveats are enforced, revocation must answer `false`, and the counter is consumed atomically in
 * [authorize]'s state store. With no [authorize] options every request is refused with 403 `authorize_config` naming the
 * missing components: a guard never downgrades to signature-only on its own. [signatureOnly] is the explicit opt-in (signature,
 * chain, audience, validity only); giving it together with [authorize] throws [IllegalArgumentException].
 */
class PcaGuardConfig(
    val audience: String?,
    val resolveGrant: ((String) -> Map<String, Any?>?)?,
    val authorize: Authorize.AuthorizeOptions? = null,
    val intentPolicy: Pca.IntentPolicy? = null,
    val signatureOnly: Boolean = false,
    /** Epoch milliseconds. */
    val clock: () -> Long = { System.currentTimeMillis() },
    /** Run the downstream handler at most once per authorization through [Operations.Executor] (see [PcaExecutorConfig]); null = off. */
    val executor: PcaExecutorConfig? = null,
) {
    init {
        require(!(signatureOnly && authorize != null)) { "signatureOnly cannot be combined with authorize options" }
        require(executor == null || (authorize != null && !signatureOnly)) { "an executor needs authorize options and cannot be combined with signatureOnly" }
        if (signatureOnly) require(audience != null && audience != "" && resolveGrant != null) { "signatureOnly needs an audience and a resolveGrant" }
    }
}

/**
 * Run-once execution of the downstream handler (T3): an allowed request runs the handler inside [Operations.Executor] with a
 * record per operation id, so a retry of the same PCActn is answered from the record (header `PCA-Replayed: true`) and the handler
 * does not run again. [operations] is required; the other members are those of [Operations.Executor] (an irreversible operation needs a
 * [recheck]). The handler's response is the recorded result, so it must be an in-memory body (text, JSON, bytes).
 */
class PcaExecutorConfig @JvmOverloads constructor(
    val operations: Operations.Store,
    val recheck: ((Operations.ExecutionHandle) -> Operations.Recheck)? = null,
    val recheckFor: String = "irreversible",
    val reversibilityClassOf: ((Authorize.Operation) -> String?)? = null,
    val pendingTimeoutMs: Double = Operations.PENDING_TIMEOUT_MS.toDouble(),
)

/** A handler response as recorded in an operation record: a JSON tree (status, content type, headers, base64 body). */
class RecordedResponse(val status: Int, val contentType: String?, val headers: Map<String, List<String>>, val body: ByteArray) {
    fun toRecord(): Map<String, Any?> = linkedMapOf(
        "status" to status.toLong(), "contentType" to contentType, "headers" to headers,
        "body" to Base64.getEncoder().encodeToString(body),
    )

    companion object {
        /** Headers the framework owns; never recorded or replayed. */
        fun recorded(name: String): Boolean = name.lowercase() !in setOf("content-length", "transfer-encoding", "connection", "keep-alive", "content-type")

        /** The response a record holds, or null when the record is unreadable. */
        fun of(rec: Any?): RecordedResponse? = try {
            val m = rec as Map<*, *>
            val st = m["status"]
            if (!Json.isSafeInt(st)) null
            else {
                val hs = LinkedHashMap<String, List<String>>()
                for ((k, v) in m["headers"] as Map<*, *>) if (recorded(k as String)) hs[k] = (v as List<*>).map { it as String }
                RecordedResponse(Json.asLong(st).toInt(), m["contentType"] as String?, hs, Base64.getDecoder().decode(m["body"] as String))
            }
        } catch (e: RuntimeException) {
            null
        }
    }
}

/**
 * What [PcaGuard.execute] answered: a [refusal] to send (nothing more runs), or the handler's recorded [result] (`replayed` = answered
 * from an earlier record, the handler did not run).
 */
class GuardRun(val refusal: GuardOutcome?, val replayed: Boolean = false, val result: Any? = null)

/**
 * The decision for one request. [allowed] is exactly "the handler may run". On a refusal [status], [wwwAuthenticate] and [body]
 * are what to answer with. [authorization] (authorize mode) carries the bound operation; [verdict] and [pcactn] are set once a
 * proof was decoded and verified.
 */
class GuardOutcome(
    val allowed: Boolean,
    val status: Int,
    val wwwAuthenticate: String?,
    val body: String,
    val decision: String,
    val authorization: Authorize.Result? = null,
    val verdict: Pca.Verdict? = null,
    val pcactn: Map<String, Any?>? = null,
    /** The operation an executor-run allow is bound to (there [authorization] and [verdict] are not available). */
    val boundOperation: Authorize.AuthorizedOperation? = null,
    /** The operation id to pass as the idempotency key of the downstream call (executor mode). */
    val idempotencyKey: String? = null,
) {
    /** The operation an allow is bound to (authorize mode), else null. */
    val operation: Authorize.AuthorizedOperation? get() = if (allowed) authorization?.operation ?: boundOperation else null
}

object PcaGuard {
    /** The header carrying a base64url(JSON) PCActn. */
    const val HEADER = "PCA-Action"

    /** The header carrying the principal's base64url(JSON) escalation answer. */
    const val ESCALATION_HEADER = "PCA-Escalation-Answer"

    /** The header carrying the agent's base64url(JSON) provenance bundle (else the body member `pca_provenance`). */
    const val PROVENANCE_HEADER = ArgProvenance.HEADER

    /**
     * The provenance bundle of a request for `authorize`: the `PCA-Provenance` header wins (passed raw: one that does not decode fails the
     * gate closed), else the body member `pca_provenance` (a body that is not strict JSON carries none).
     */
    private fun provenanceOf(provenanceHeader: String?, body: ByteArray): Pair<Any?, String?> =
        if (provenanceHeader != null && provenanceHeader != "") Pair(null, provenanceHeader)
        else Pair(if (body.size > Pca.MAX_ARTIFACT_BYTES) null else ArgProvenance.bundleFromBody(body), null)

    /** [envelope] is the parsed JSON body when the PCActn was read from it (header absent), else null. */
    private class Extracted(val pcactn: Any?, val failure: GuardOutcome?, val envelope: Map<*, *>? = null)

    private fun strictUtf8(b: ByteArray): String? = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString()
    } catch (e: CharacterCodingException) {
        null
    }

    private fun jsonString(m: Map<String, Any?>): String = try {
        Json.canonicalize(m)
    } catch (e: RuntimeException) {
        "{\"error\":\"${m["error"]}\"}"
    }

    private fun challenge(code: String?): String = if (code == null) "PCA realm=\"pca\"" else "PCA realm=\"pca\", error=\"$code\""

    /** A refusal before any verdict (no proof, undecodable, unknown grant). The description stays in the body, never the header. */
    private fun refuse(status: Int, code: String?, desc: String): GuardOutcome {
        val body = linkedMapOf<String, Any?>("error" to (code ?: "pca_required"), "error_description" to desc, "decision" to "deny", "doc" to explainRefusal(desc).docs)
        return GuardOutcome(false, status, challenge(code), jsonString(body), "deny")
    }

    private fun extract(header: String?, body: ByteArray): Extracted {
        if (header != null && header != "") {
            // STRICT unpadded base64url -> STRICT UTF-8 -> strict JSON; nothing is trimmed or normalized
            val raw = Pca.decodeB64uStrict(header, -1)
            val text = if (raw == null) null else strictUtf8(raw)
            if (text == null) return Extracted(null, refuse(401, "invalid_request", "$HEADER is not canonical base64url"))
            if (Pca.artifactTooLarge(text)) return Extracted(null, refuse(401, "invalid_request", "PCActn is too large"))
            val parsed = try { Json.parse(text) } catch (e: RuntimeException) { return Extracted(null, refuse(401, "invalid_request", "PCActn is not strict JSON")) }
            if (parsed !is Map<*, *>) return Extracted(null, refuse(401, "invalid_request", "PCActn is not a JSON object"))
            return Extracted(parsed, null)
        }
        if (body.isNotEmpty()) {
            val text = strictUtf8(body) ?: return Extracted(null, refuse(401, "invalid_request", "request body is not valid UTF-8"))
            if (Pca.artifactTooLarge(text)) return Extracted(null, refuse(401, "invalid_request", "request body is too large"))
            val env = try { Json.parse(text) } catch (e: RuntimeException) { return Extracted(null, refuse(401, "invalid_request", "request body is not strict JSON")) }
            val pc = (env as? Map<*, *>)?.get("pcactn")
            if (pc == null) return Extracted(null, refuse(401, null, "no \"pcactn\" field in request body"))
            return Extracted(pc, null, env as Map<*, *>)
        }
        return Extracted(null, refuse(401, null, "no $HEADER header and no PCActn body"))
    }

    /**
     * The workflow step of the request: the host's [explicit] one (a per-request callback), else the body member `workflow`
     * {commitment, receipts, step, units, goal_digest} of the envelope the PCActn came from. Read only when a workflow gate is configured.
     * An unreadable member (not an object, `step` / `goal_digest` / `units` of the wrong type) is a step with `step = null`, which the
     * gate refuses, never "no step".
     */
    private fun workflowStep(az: Authorize.AuthorizeOptions, explicit: Authorize.WorkflowStep?, envelope: Map<*, *>?): Authorize.WorkflowStep? {
        if (az.workflow == null) return null
        if (explicit != null) return explicit
        if (envelope == null || !envelope.containsKey("workflow")) return null
        val w = envelope["workflow"] as? Map<*, *> ?: return Authorize.WorkflowStep(null, null, null)
        val units = w["units"]
        val step = w["step"]
        val goal = w["goal_digest"]
        if ((units != null && units !is Map<*, *>) || (step != null && step !is String) || (goal != null && goal !is String))
            return Authorize.WorkflowStep(null, null, null)
        @Suppress("UNCHECKED_CAST")
        return Authorize.WorkflowStep(w["commitment"], w["receipts"], step as String?, (units as Map<String, Any?>?) ?: emptyMap(), goal as String?)
    }

    /** The escalation answer: the header (strict base64url JSON), else the body member `escalation_answer`; null when absent or unreadable. */
    private fun escalationAnswer(header: String?, body: ByteArray): Any? = try {
        if (header != null && header != "") {
            val raw = Pca.decodeB64uStrict(header, -1)
            val text = if (raw == null) null else strictUtf8(raw)
            if (text == null) null else Json.parse(text)
        } else if (body.isEmpty()) null
        else {
            val text = strictUtf8(body)
            val env = if (text == null) null else Json.parse(text)
            (env as? Map<*, *>)?.get("escalation_answer")
        }
    } catch (e: RuntimeException) {
        null
    }

    /**
     * Decide one request. [header] is the `PCA-Action` value, [body] the (buffered) request body, [operation] what the handler
     * will execute (from the host's own routing, never from the proof; null denies in authorize mode), [provenanceHeader] the
     * `PCA-Provenance` value (provenance by default: without a bundle a sensitive operation escalates). Never throws.
     */
    fun decide(
        config: PcaGuardConfig, header: String?, escalationHeader: String?, body: ByteArray, operation: Authorize.Operation?,
        workflowCall: Authorize.WorkflowStep? = null, provenanceHeader: String? = null,
    ): GuardOutcome = try {
        val ex = extract(header, body)
        if (ex.failure != null) ex.failure
        else if (config.signatureOnly) signatureOnly(config, ex.pcactn)
        else authorize(config, ex, escalationHeader, body, operation, workflowCall, provenanceHeader)
    } catch (e: Exception) {
        refuse(403, "insufficient_authority", "guard error (fail closed)")
    }

    private fun authorize(
        config: PcaGuardConfig, ex: Extracted, escalationHeader: String?, body: ByteArray, operation: Authorize.Operation?,
        workflowCall: Authorize.WorkflowStep?, provenanceHeader: String?,
    ): GuardOutcome {
        val pcactn = ex.pcactn
        // an absent option set is an empty one: authorize answers 403 authorize_config naming what is missing
        val az = config.authorize ?: Authorize.AuthorizeOptions(null, null)
        // a body larger than the artifact limit cannot be mapped: no operation, so authorize refuses
        val op = if (body.size > Pca.MAX_ARTIFACT_BYTES) null else operation
        val answer = if (az.escalationPrincipals.isEmpty()) null else escalationAnswer(escalationHeader, body)
        val (bundle, provHeader) = provenanceOf(provenanceHeader, body)
        val r = az.run(
            pcactn, op, config.audience, config.resolveGrant, config.clock(), config.intentPolicy, null, answer,
            workflowCall = workflowStep(az, workflowCall, ex.envelope), provenance = bundle, provenanceHeader = provHeader,
        )
        @Suppress("UNCHECKED_CAST")
        val p = r.pcactn ?: (pcactn as? Map<String, Any?>)
        if (r.allow) return GuardOutcome(true, 200, null, "", "allow", r, r.verdict, p)
        return denial(r, p)
    }

    private fun denial(r: Authorize.Result, p: Map<String, Any?>?): GuardOutcome {
        val code = if (r.status == 401) "invalid_pcactn" else "insufficient_authority"
        val reason = r.reason ?: "denied"
        val out = linkedMapOf<String, Any?>(
            "error" to code, "error_description" to reason, "reason" to reason, "checks" to r.checks, "decision" to r.decision, "doc" to explainRefusal(reason).docs,
        )
        if (r.escalation != null) out["escalation"] = r.escalation
        if (r.missing != null) out["missing"] = r.missing
        return GuardOutcome(false, r.status, challenge(code), jsonString(out), r.decision, r, r.verdict, p)
    }

    /** A refusal of the executor path; the challenge header only on 401 / 403. */
    private fun plain(status: Int, code: String, desc: String): GuardOutcome {
        val body = linkedMapOf<String, Any?>("error" to code, "error_description" to desc, "decision" to "deny", "doc" to explainRefusal(desc).docs)
        return GuardOutcome(false, status, if (status == 401 || status == 403) challenge(code) else null, jsonString(body), "deny")
    }

    /** The answer for a recorded result that cannot be read back. */
    fun unreadable(): GuardOutcome = plain(409, "operation_uncertain", "the recorded result is unreadable")

    /**
     * Decide one request AND run the handler through [Operations.Executor] ([PcaGuardConfig.executor] is required). [fn] is the handler: it
     * runs at most once per authorization and returns the JSON tree to record ([RecordedResponse.toRecord]); a throw is recorded `failed`
     * (500 `operation_failed`, no error text). A retry of the same PCActn is [GuardRun.replayed]; an in-flight record is 409
     * `operation_in_progress`, an unknown outcome 409 `operation_uncertain`, a refused re-check 403 `operation_aborted`. Never throws.
     */
    fun execute(
        config: PcaGuardConfig, header: String?, escalationHeader: String?, body: ByteArray, operation: Authorize.Operation?,
        workflowCall: Authorize.WorkflowStep? = null, provenanceHeader: String? = null, fn: (GuardOutcome) -> Any?,
    ): GuardRun {
        val ec = config.executor ?: return GuardRun(refuse(403, "authorize_config", "authorize_config: no executor is configured (fail closed)"))
        return try {
            val ex = extract(header, body)
            if (ex.failure != null) return GuardRun(ex.failure)
            val az = config.authorize ?: Authorize.AuthorizeOptions(null, null)
            val op = if (body.size > Pca.MAX_ARTIFACT_BYTES) null else operation
            val answer = if (az.escalationPrincipals.isEmpty()) null else escalationAnswer(escalationHeader, body)
            val executor = Operations.Executor(
                ec.operations, az, config.audience, config.resolveGrant, ec.recheck, ec.recheckFor, ec.reversibilityClassOf, ec.pendingTimeoutMs, config.clock,
            )
            val (bundle, provHeader) = provenanceOf(provenanceHeader, body)
            val o = executor.execute(ex.pcactn, op, config.intentPolicy, null, answer, workflowStep(az, workflowCall, ex.envelope), bundle, provHeader) { h ->
                fn(GuardOutcome(true, 200, null, "", "allow", null, null, h.pcactn, h.operation, h.idempotencyKey))
            }
            when (o.status) {
                "committed" -> GuardRun(null, o.replayed, o.result)
                "denied" -> {
                    val d = o.authorization!!
                    @Suppress("UNCHECKED_CAST")
                    GuardRun(denial(d, d.pcactn ?: (ex.pcactn as? Map<String, Any?>)))
                }
                "failed" -> GuardRun(plain(500, "operation_failed", "the operation failed"))
                "aborted" -> GuardRun(plain(403, "operation_aborted", o.reason ?: "aborted"))
                "pending" -> GuardRun(plain(409, "operation_in_progress", "another execution of this operation is in flight"))
                "uncertain" -> GuardRun(plain(409, "operation_uncertain", o.reason ?: "outcome unknown"))
                else -> GuardRun(plain(403, "access_denied", o.reason ?: "denied"))
            }
        } catch (e: Exception) {
            GuardRun(refuse(403, "insufficient_authority", "guard error (fail closed)"))
        }
    }

    private fun signatureOnly(config: PcaGuardConfig, pcactn: Any?): GuardOutcome {
        val p = pcactn as? Map<*, *> ?: return refuse(401, "invalid_request", "PCActn is not a JSON object")
        val grantRef = p["grant_ref"] as? String
        if (grantRef == null || grantRef == "") return refuse(401, "invalid_grant", "PCActn has no grant_ref")
        // a throwing resolver is "not found", never an allow
        val grant = (try { config.resolveGrant!!(grantRef) } catch (e: Exception) { null })
            ?: return refuse(401, "invalid_grant", "grant_ref does not resolve to a known grant")
        val v = Pca.verifyPcactn(pcactn, grant, config.clock(), Pca.Audience.Of(config.audience!!), null, config.intentPolicy, null)
        @Suppress("UNCHECKED_CAST")
        val pm = pcactn as Map<String, Any?>
        if (v.allow) return GuardOutcome(true, 200, null, "", "allow", null, v, pm)
        val reason = if (v.reason.isEmpty()) "denied" else v.reason
        val out = linkedMapOf<String, Any?>("error" to "insufficient_authority", "error_description" to reason, "reason" to reason, "checks" to v.checks, "decision" to "deny", "doc" to explainRefusal(reason).docs)
        return GuardOutcome(false, 403, challenge("insufficient_authority"), jsonString(out), "deny", null, v, pm)
    }
}
