package net.atlasauth.pca.openaiagents

import net.atlasauth.pca.verifier.ArgProvenance
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.webbotauth.WbaJs

/**
 * OpenAI Agents SDK guard: makes every agent tool call proof-carrying and policy-gated at the LOCAL execution boundary. [withPcaTool] wraps a
 * tool's `execute(input, runContext)` so it first REQUIRES a proof-carrying action (taken from the run context by the PCA-Action convention),
 * VERIFIES it (fail closed: [PcaToolDenied]) and only then runs the original tool. Guardrails trip a run that lacks a valid proof.
 *
 * Structural, no vendor package: a tool is a function over JSON trees, the run context a JSON object whose `context` member is the caller's
 * bag (the proof rides there as `pca` / `pcaProof`).
 *
 * Two modes. Full (the default): every call runs [Authorize.authorize], the input must hash to the signed params digest, the grant's
 * predicates, limits and caveats are evaluated, revocation is required and a replay store makes each PCActn single-use; a missing component
 * is refused per call. Signature-only: the proof's signature, capability chain, plan inclusion, audience and validity window are checked, NOT
 * that the grant permits this call. Either way this does not replace the resource server when a tool makes a remote call.
 *
 * Step-up: [reviewToolCall] / [pendingStepUps] / [pcaNeedsApproval] / [withApproval] map a risky tool to the SDK's `needsApproval` interruption;
 * the review itself is an injected [ReviewAction] (the native core has no action reviewer). Not ported: the JS attach side (`withPCA`).
 */
@Suppress("UNCHECKED_CAST")
object OpenAiAgentsGuard {
    // ---- proof sources ----

    /** An encoded PCActn string from a `{pca | pcaProof}` bag; null when neither is a string. */
    @JvmStatic
    fun proofFromBag(bag: Any?): String? = if (bag is Map<*, *>) (bag["pca"] ?: bag["pcaProof"]) as? String else null

    /** Default proof source: `runContext.context.{pca|pcaProof}`, then `runContext.{pca|pcaProof}`. */
    @JvmStatic
    fun proofFromRunContext(input: Map<String, Any?>?, runContext: Map<String, Any?>): Any? = proofFromBag(runContext["context"]) ?: proofFromBag(runContext)

    /** Default provenance source: `{pcaProvenance | pca_provenance | PCA-Provenance}` on `runContext.context`, then on `runContext`. */
    @JvmStatic
    fun provenanceFromRunContext(input: Map<String, Any?>?, runContext: Map<String, Any?>): Any? {
        for (bag in listOf(runContext["context"], runContext)) {
            if (bag !is Map<*, *>) continue
            val v = bag["pcaProvenance"] ?: bag["pca_provenance"] ?: bag["PCA-Provenance"]
            if (v != null) return v
        }
        return null
    }

    /** A proof source reading a base64url PCA-Action header from a headers-like bag on the tool input. */
    @JvmStatic
    @JvmOverloads
    fun proofFromInputHeaders(field: String = "headers", header: String = "PCA-Action"): ProofSource = ProofSource { input, _ ->
        ((input?.get(field) as? Map<*, *>)?.get(header)) as? String
    }

    /** The guardrail-side default: the proof from the run context the SDK passes as `args.context`. */
    @JvmStatic
    fun guardrailProofFromContext(args: Map<String, Any?>): Any? {
        val outer = args["context"]
        val inner = (outer as? Map<*, *>)?.get("context")
        return proofFromBag(inner) ?: proofFromBag(outer)
    }

    // ---- configuration types ----

    /** Finds the proof for a call: (input, runContext) to a PCActn object or an encoded string; null fails closed. */
    fun interface ProofSource { fun find(input: Map<String, Any?>?, runContext: Map<String, Any?>): Any? }

    /** Finds the provenance bundle of a call (a parsed bundle, or the encoded `PCA-Provenance` header text); null is an unlabelled call. */
    fun interface ProvenanceSource { fun find(input: Map<String, Any?>?, runContext: Map<String, Any?>): Any? }

    /** A tool's `execute(input, runContext)`. */
    fun interface AgentExecute { fun execute(input: Map<String, Any?>, runContext: Map<String, Any?>?): Any? }

    /** Records every result a tool returns as UNTRUSTED tool output. [ArgProvenance.Recorder] fits through [ToolOutputRecorder.of]. */
    fun interface ToolOutputRecorder {
        fun tool(name: String, output: Any?)

        companion object {
            @JvmStatic fun of(r: ArgProvenance.Recorder): ToolOutputRecorder = ToolOutputRecorder { n, o -> r.tool(n, o) }
        }
    }

    /** A verification outcome of a custom verifier. */
    class VerifyOutcome @JvmOverloads constructor(val allow: Boolean, val reason: String? = null, val checks: Map<String, String>? = null)

    /** Signature-only verification: the grant the proof must chain to. Plan roots default to "nothing authorized" (every call refused); name the authorized roots or set [insecureSkipPlanRootCheck]. */
    class VerifyGrant @JvmOverloads constructor(
        val grant: Map<String, Any?>,
        /** Verifier clock (epoch ms), evaluated per call; default the wall clock. */
        val now: (() -> Long)? = null,
        val allowedSuites: List<String>? = null,
        val authorizedPlanRoots: List<String>? = null,
        val insecureSkipPlanRootCheck: Boolean = false,
    )

    /** What [WithPcaToolOptions.authorize] gets besides the call: the guard's own audience (the input must carry it) and the call's provenance. */
    class AuthorizeContext(val audience: String, val provenance: Any?, val provenanceHeader: String?)

    /** Full mode: builds the per-call [Authorize.Input] (operation, grant resolver, state store, revocation check, ...); its audience must be the one in the context. */
    fun interface AuthorizeBuilder { fun build(input: Map<String, Any?>, runContext: Map<String, Any?>, ctx: AuthorizeContext): Authorize.Input }

    /** Why a guarded execute or guardrail refused: missing, malformed, verify, binding, policy, replay, revoked or config. */
    class PcaToolDenied @JvmOverloads constructor(message: String, val verb: String, val kind: String, val checks: Map<String, String>? = null) :
        RuntimeException("PCA tool denied ($kind) for $verb: $message")

    /** The options of [withPcaTool]; a per-tool override is the same type with only the members to change set. */
    data class WithPcaToolOptions(
        /** Find the proof for a call. Default [proofFromRunContext]. */
        val require: ProofSource? = null,
        /** "full" (default) or "signature-only". */
        val mode: String? = null,
        /** Signature-only: the grant to chain to. */
        val verify: VerifyGrant? = null,
        /** Signature-only: a custom verifier (instead of [verify]). */
        val verifyFn: ((Map<String, Any?>) -> VerifyOutcome)? = null,
        /** Full mode (the default). */
        val authorize: AuthorizeBuilder? = null,
        /** This verifier's audience, matched against the PCActn's signed aud. Required (an accept-any audience is not supported). */
        val audience: String? = null,
        /** Defense in depth: the proof's action verb must equal this (bind the proof to THIS tool). */
        val verb: String? = null,
        /** Where the provenance bundle of a call is. Default [provenanceFromRunContext]. */
        val provenance: ProvenanceSource? = null,
        val recorder: ToolOutputRecorder? = null,
        val onDeny: ((PcaToolDenied, Map<String, Any?>) -> Unit)? = null,
        /** Observe a successful verification (the PCActn, the tool input) before the original execute runs. */
        val onVerified: ((Map<String, Any?>, Map<String, Any?>) -> Unit)? = null,
    )

    // ---- the proof pipeline ----

    // a string is tried as raw encoded JSON, then as a PCA-Action header value
    private fun toPcActn(input: Any?): Map<String, Any?> {
        if (input is Map<*, *>) return input as Map<String, Any?>
        if (input !is String) throw IllegalStateException("a proof is a PCActn object or an encoded string")
        try {
            val raw = Json.parse(input)
            if (raw is Map<*, *>) return raw as Map<String, Any?>
        } catch (e: RuntimeException) { /* the header form */ }
        val text = WbaJs.decodePcaHeader(input) ?: throw IllegalStateException("the proof is not a PCA-Action header value")
        return Json.parse(text) as? Map<String, Any?> ?: throw IllegalStateException("the proof is not a JSON object")
    }

    private fun verbOf(p: Map<String, Any?>): String = (p["action"] as? Map<*, *>)?.get("verb") as? String ?: ""

    private fun runVerify(verify: VerifyGrant?, fn: ((Map<String, Any?>) -> VerifyOutcome)?, pcactn: Map<String, Any?>, audience: String): VerifyOutcome {
        if (fn != null) return fn(pcactn)
        val v = verify!!
        val verdict = Pca.verifyPcactn(
            pcactn, v.grant, (v.now ?: { System.currentTimeMillis() })(), Pca.Audience.Of(audience), allowedSuites = v.allowedSuites,
            authorizedPlanRoots = v.authorizedPlanRoots, insecureSkipPlanRootCheck = v.insecureSkipPlanRootCheck,
        )
        val checks = LinkedHashMap<String, String>()
        for ((k, ok) in verdict.checks) checks[k] = if (ok) "pass" else "fail"
        return VerifyOutcome(verdict.allow, verdict.reason.ifEmpty { null }, checks)
    }

    // the kind of a refused full-policy decision, from the first failing check
    private fun kindOf(r: Authorize.Result): String {
        if (!r.missing.isNullOrEmpty()) return "config"
        return when (r.checks.entries.firstOrNull { it.value == "fail" }?.key ?: "") {
            "authorize_config" -> "config"
            "replay" -> "replay"
            "revocation", "freshness" -> "revoked"
            "operation", "params_digest" -> "binding"
            "policy", "plan_state", "plan_root_authorized", "provenance_flow" -> "policy"
            else -> "verify"
        }
    }

    private fun checkMode(mode: String?, hasVerify: Boolean, hasAuthorize: Boolean, who: String) {
        val m = mode ?: "full"
        require(m == "full" || m == "signature-only") { "$who: unknown mode '$m'" }
        if (m == "signature-only") {
            require(!hasAuthorize) { "$who: `authorize` is the full mode; drop it, or drop mode 'signature-only'" }
            require(hasVerify) { "$who: mode 'signature-only' needs `verify` or `verifyFn`" }
        } else {
            require(hasAuthorize) { "$who: pass `authorize` (full policy, the default mode), or set mode 'signature-only' with `verify`" }
            require(!hasVerify) { "$who: `verify` checks the signature only: set mode 'signature-only' to use it, and drop `authorize`" }
        }
    }

    /**
     * Wrap a tool's `execute(input, runContext)` so each call first REQUIRES + VERIFIES a proof-carrying action (fail closed: [PcaToolDenied]),
     * then runs the original. Throws [IllegalArgumentException] at construction on a missing or contradictory configuration.
     */
    @JvmStatic
    fun withPcaTool(toolName: String?, execute: AgentExecute, options: WithPcaToolOptions): AgentExecute {
        checkMode(options.mode, options.verify != null || options.verifyFn != null, options.authorize != null, "with_pca_tool")
        require(!(options.verify != null && options.verifyFn != null)) { "with_pca_tool: give exactly one of `verify` and `verifyFn`" }
        val audience = options.audience
        require(!audience.isNullOrEmpty()) { "with_pca_tool: `audience` (this verifier's id) is required" }
        val source = options.require ?: ProofSource { i, r -> proofFromRunContext(i, r) }
        val prov = options.provenance ?: ProvenanceSource { i, r -> provenanceFromRunContext(i, r) }
        val label = options.verb ?: toolName ?: "(tool)"
        return AgentExecute { input, runContextOrNull ->
            val runContext = runContextOrNull ?: LinkedHashMap()
            val pcactn: Map<String, Any?> = try {
                val raw = source.find(input, runContext) ?: throw PcaToolDenied("no proof-carrying action present on the call", label, "missing")
                val decoded = try { toPcActn(raw) } catch (cause: RuntimeException) { throw PcaToolDenied("proof could not be decoded: " + cause.message, label, "malformed") }
                val verb = verbOf(decoded)
                if (options.verb != null && verb != options.verb) throw PcaToolDenied("proof is for '$verb', not this tool's '${options.verb}'", verb, "binding")
                val authorize = options.authorize
                if (authorize != null) {
                    val d = try {
                        val p = prov.find(input, runContext)
                        val ai = authorize.build(input, runContext, AuthorizeContext(audience, if (p is String) null else p, p as? String))
                        if (ai.audience != audience) throw IllegalStateException("the authorize input's audience is not the guard's audience")
                        Authorize.authorize(decoded, ai)
                    } catch (e: RuntimeException) {
                        throw PcaToolDenied("the authorize configuration failed: " + e.message, if (verb == "") label else verb, "config")
                    }
                    if (!d.allow) throw PcaToolDenied(d.reason ?: "denied", if (verb == "") label else verb, kindOf(d), d.checks)
                } else {
                    val r = runVerify(options.verify, options.verifyFn, decoded, audience)
                    if (!r.allow) throw PcaToolDenied(r.reason ?: "verification failed", if (verb == "") label else verb, "verify", r.checks)
                }
                decoded
            } catch (e: PcaToolDenied) {
                options.onDeny?.invoke(e, input)
                throw e
            }
            options.onVerified?.invoke(pcactn, input)
            val output = execute.execute(input, runContextOrNull)
            options.recorder?.tool(verbOf(pcactn).ifEmpty { label }, output)
            output
        }
    }

    private fun merge(b: WithPcaToolOptions, o: WithPcaToolOptions?): WithPcaToolOptions {
        if (o == null) return b
        // a per-tool verify or authorize replaces the shared mode (the two are exclusive)
        val mode = when {
            o.authorize != null -> b.copy(authorize = o.authorize, verify = null, verifyFn = null, mode = o.mode)
            o.verify != null || o.verifyFn != null -> b.copy(authorize = null, verify = o.verify, verifyFn = o.verifyFn, mode = o.mode ?: b.mode)
            else -> b.copy(mode = o.mode ?: b.mode)
        }
        return mode.copy(
            require = o.require ?: b.require, audience = o.audience ?: b.audience, verb = o.verb ?: b.verb, onDeny = o.onDeny ?: b.onDeny,
            onVerified = o.onVerified ?: b.onVerified, provenance = o.provenance ?: b.provenance, recorder = o.recorder ?: b.recorder,
        )
    }

    /**
     * Guard a whole `{name: execute}` set in one call. Every tool is guarded with the shared options (override per tool via [per], or limit the
     * set via [only]; the others pass through unchanged, the same instance).
     */
    @JvmStatic
    @JvmOverloads
    fun pcaTools(tools: Map<String, AgentExecute>, options: WithPcaToolOptions, per: Map<String, WithPcaToolOptions>? = null, only: Collection<String>? = null): Map<String, AgentExecute> {
        val res = LinkedHashMap<String, AgentExecute>()
        for ((name, tool) in tools) res[name] = if (only != null && !only.contains(name)) tool else withPcaTool(name, tool, merge(options, per?.get(name)))
        return res
    }

    // ---- guardrails: reject a run / tool call lacking a valid proof ----

    /** What an Agents-SDK guardrail returns: a tripwire plus free-form info. */
    class GuardrailOutput(val tripwireTriggered: Boolean, val outputInfo: Map<String, Any?>)

    /** A guardrail: a name and an execute over the SDK's guardrail args. */
    class AgentGuardrail(val name: String, val execute: (Map<String, Any?>) -> GuardrailOutput)

    class PcaGuardrailOptions @JvmOverloads constructor(
        /** Find the proof for a run: the guardrail args (`{context, ...}`) to a PCActn object or string. Default [guardrailProofFromContext]. */
        val require: ((Map<String, Any?>) -> Any?)? = null,
        val verify: VerifyGrant? = null,
        val verifyFn: ((Map<String, Any?>) -> VerifyOutcome)? = null,
        val audience: String? = null,
        val verb: String? = null,
        val name: String? = null,
    )

    private fun guardrailExecute(o: PcaGuardrailOptions): (Map<String, Any?>) -> GuardrailOutput {
        require((o.verify == null) != (o.verifyFn == null)) { "guardrail: give exactly one of `verify` and `verifyFn`" }
        val audience = o.audience
        require(!audience.isNullOrEmpty()) { "guardrail: `audience` (this verifier's id) is required" }
        val source = o.require ?: { a -> guardrailProofFromContext(a) }
        val label = o.verb ?: "(run)"
        return { args ->
            try {
                val raw = source(args) ?: throw PcaToolDenied("no proof-carrying action present on the call", label, "missing")
                val pcactn = try { toPcActn(raw) } catch (cause: RuntimeException) { throw PcaToolDenied("proof could not be decoded: " + cause.message, label, "malformed") }
                val verb = verbOf(pcactn)
                if (o.verb != null && verb != o.verb) throw PcaToolDenied("proof is for '$verb', not this tool's '${o.verb}'", verb, "binding")
                val r = runVerify(o.verify, o.verifyFn, pcactn, audience)
                if (!r.allow) throw PcaToolDenied(r.reason ?: "verification failed", if (verb == "") label else verb, "verify", r.checks)
                GuardrailOutput(false, linkedMapOf("verb" to verb))
            } catch (e: PcaToolDenied) {
                val info = linkedMapOf<String, Any?>("kind" to e.kind, "verb" to e.verb, "reason" to e.message)
                if (e.checks != null) info["checks"] = LinkedHashMap<String, Any?>(e.checks)
                GuardrailOutput(true, info)
            }
        }
    }

    /**
     * An input guardrail: runs once at the top of a run and trips the tripwire (rejecting the run before any step executes) when the run context
     * carries no valid proof. Signature-only: a run-level guardrail sees no single tool call to bind; put the authority check on the tool.
     */
    @JvmStatic
    fun pcaInputGuardrail(o: PcaGuardrailOptions): AgentGuardrail = AgentGuardrail(o.name ?: "pca-input-guardrail", guardrailExecute(o))

    /** A tool guardrail: the same proof gate scoped to a tool call (read the proof from the tool input with `require`). */
    @JvmStatic
    fun pcaToolGuard(o: PcaGuardrailOptions): AgentGuardrail = AgentGuardrail(o.name ?: "pca-tool-guard", guardrailExecute(o))

    // ---- step-up: map a risky tool to needsApproval / the interruption flow ----

    /** Maps a tool name (and its input) to the PCA action to review (`{verb, resource, params?}`); null treats the tool as unguarded (auto). */
    fun interface ToolIntent { fun map(tool: String, input: Map<String, Any?>?): Map<String, Any?>? }

    /** Reviews one intended action against the agent's grant: `{kind: auto}` | `{kind: deny, reason}` | `{kind: step_up, request}`. */
    fun interface ReviewAction { fun review(verb: String, resource: String, params: Map<String, Any?>?): Map<String, Any?> }

    /** Options of [reviewToolCall]. [review] is required for any tool [intent] maps (without one such a tool is denied: fail closed). */
    open class StepUpOptions @JvmOverloads constructor(val intent: ToolIntent, val review: ReviewAction? = null)

    /** The outcome of reviewing one intended tool call. */
    class ToolReview(val tool: String, val review: Map<String, Any?>)

    /** A step-up a tool call raised (what the approval inbox / co-sign round / SDK interruption receives). */
    class ToolStepUp(val tool: String, val request: Map<String, Any?>)

    /** Reviews one intended tool call. A tool the intent does not map is unguarded (auto). */
    @JvmStatic
    fun reviewToolCall(tool: String, input: Map<String, Any?>?, opts: StepUpOptions): ToolReview {
        val mapped = opts.intent.map(tool, input) ?: return ToolReview(tool, linkedMapOf("kind" to "auto"))
        val reviewer = opts.review ?: return ToolReview(tool, linkedMapOf("kind" to "deny", "reason" to "no reviewer is configured for a guarded tool"))
        val verb = mapped["verb"] as? String
        val resource = mapped["resource"] as? String
        if (verb == null || resource == null) return ToolReview(tool, linkedMapOf("kind" to "deny", "reason" to "the intent names no verb and resource"))
        return ToolReview(tool, reviewer.review(verb, resource, (mapped["params"] as? Map<String, Any?>) ?: input))
    }

    /** The step-up requests from a batch of reviews (auto and deny are filtered out). */
    @JvmStatic
    fun pendingStepUps(reviews: List<ToolReview>): List<ToolStepUp> =
        reviews.filter { it.review["kind"] == "step_up" }.map { ToolStepUp(it.tool, it.review["request"] as Map<String, Any?>) }

    /** Options of [pcaNeedsApproval]. */
    class NeedsApprovalOptions @JvmOverloads constructor(
        intent: ToolIntent,
        review: ReviewAction? = null,
        /** The tool name to review (default "(tool)"). */
        val toolName: String? = null,
        /** True when a step-up request has already been co-signed (your FROST / CIBA result): it is then let through. */
        val approved: ((Map<String, Any?>) -> Boolean)? = null,
        /** Receives each step-up this call raised: push it to the approval inbox / open the co-sign round. */
        val onStepUp: ((ToolStepUp) -> Unit)? = null,
        /** Whether a policy deny also routes to approval (so the run interrupts and the approver rejects it). Default true. */
        val denyNeedsApproval: Boolean = true,
    ) : StepUpOptions(intent, review)

    /**
     * Builds a needsApproval callback (run context, tool input) from PCA risk review: auto returns false; a step-up not yet approved is routed
     * to [NeedsApprovalOptions.onStepUp] and returns true (the SDK interrupts for a tier-2/3 co-sign); an already approved step-up returns false;
     * a deny returns [NeedsApprovalOptions.denyNeedsApproval] (default true: interrupt so the approver can reject it, fail safe).
     */
    @JvmStatic
    fun pcaNeedsApproval(opts: NeedsApprovalOptions): (Map<String, Any?>, Map<String, Any?>) -> Boolean {
        val toolName = opts.toolName ?: "(tool)"
        return { _, input ->
            val review = reviewToolCall(toolName, input, opts).review
            when (review["kind"]) {
                "auto" -> false
                "deny" -> opts.denyNeedsApproval
                else -> {
                    val request = review["request"] as Map<String, Any?>
                    if (opts.approved?.invoke(request) == true) false
                    else {
                        opts.onStepUp?.invoke(ToolStepUp(toolName, request))
                        true
                    }
                }
            }
        }
    }

    /** The needsApproval callback of a tool named [toolName] (the intent lookup is seeded with it unless [NeedsApprovalOptions.toolName] is set). */
    @JvmStatic
    fun withApproval(toolName: String?, opts: NeedsApprovalOptions): (Map<String, Any?>, Map<String, Any?>) -> Boolean =
        pcaNeedsApproval(NeedsApprovalOptions(opts.intent, opts.review, opts.toolName ?: toolName ?: "(tool)", opts.approved, opts.onStepUp, opts.denyNeedsApproval))
}
