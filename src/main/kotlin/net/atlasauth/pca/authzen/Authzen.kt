package net.atlasauth.pca.authzen

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Decide
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaCore

/**
 * PCA behind the OpenID AuthZEN Authorization API 1.0: a Policy Decision Point (Access Evaluation, the Access Evaluations boxcar, the COAZ
 * MCP-tool profile, the AARP approval-required step-up), a framework-agnostic handler over {path, body} maps and the three Search APIs.
 * Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy denial or any thrown error is
 * `decision: false`. Requests, bodies and responses are `Map<String, Any?>` trees (parsed JSON; member names as on the wire).
 *
 * The proof is verified by the native core verifier ([PcaCore]); the Policy-VM decision defaults to [Decide] and the static policy admission
 * (`admitsConcrete`) to the analyzer's exact admission; a PDP may replace either through the config hooks ([PolicyVm], [Admits]). The verifier enforcement gates of a resolved
 * context are not supported: a context carrying `enforce` fails closed.
 *
 * Config keys (reference names): resolve ([Resolver], required), audience (String; present as null = accept any; absent = fail closed
 * when the PCActn carries an aud), authorizedPlanRoots (List), insecureSkipPlanRootCheck, now (`() -> Long`), toolCapability
 * ([ToolCapability]), requireProof (default true), authorizer ([Authorizer]), requireAuthorizer (default true), maxEvaluations (default
 * 100), policyVm ([PolicyVm]), admitsConcrete ([Admits]). A resolved context is {grant, chain?, policy, plan?, risk?, budget?, enforce?,
 * toAction?}; `toAction` is a `(Map<String, Any?>) -> Map<String, Any?>`.
 */
@Suppress("UNCHECKED_CAST")
object Authzen {
    const val PCA_APPROVAL_KEY = "pca_approval"
    const val PCA_ACTION_KEY = "pca_action"
    const val PCA_PROVENANCE_KEY = "pca_provenance"
    const val DEFAULT_MAX_EVALUATIONS = 100
    const val EVALUATION_PATH = "/access/v1/evaluation"
    const val EVALUATIONS_PATH = "/access/v1/evaluations"
    const val COAZ_TOOL_PATH = "/access/v1/mcp/tool/evaluation"
    const val SEARCH_SUBJECT_PATH = "/access/v1/search/subject"
    const val SEARCH_RESOURCE_PATH = "/access/v1/search/resource"
    const val SEARCH_ACTION_PATH = "/access/v1/search/action"
    const val MAX_SEARCH_LIMIT = 1000

    /** Resolve the PCA authority for a request: a context map, or null to DENY. May throw (a throw fails closed). */
    fun interface Resolver { fun resolve(req: Map<String, Any?>): Map<String, Any?>? }

    /** The Core authorizer (replay counter, budget, revocation): input {operation, pcactn, provenance?}, result {allow, reason?}. */
    fun interface Authorizer { fun authorize(input: Map<String, Any?>): Map<String, Any?> }

    /** An MCP tool name to the capability (verb) it requires. */
    fun interface ToolCapability { fun capability(toolName: String): String }

    /** The Policy-VM: decide over the PCActn and the context {grant, chain, plan?, params, risk, budget, now, subject?, env?}. */
    fun interface PolicyVm { fun decide(pcactn: Map<String, Any?>, ctx: Map<String, Any?>): Map<String, Any?> }

    /** Static admission of a mapped action under a policy ("could this ever be allowed?"). */
    fun interface Admits { fun admits(policy: Any?, action: Map<String, Any?>): Boolean }

    /** One search provider function. */
    fun interface SearchFn { fun search(req: Map<String, Any?>): Map<String, Any?> }

    /** A JSON member that is absent (JavaScript undefined), distinct from null. */
    private val UNDEF = Any()
    private val MALFORMED = Any()

    // ---- helpers ----

    private fun isRec(x: Any?) = x is Map<*, *>
    private fun rec(x: Any?) = x as Map<String, Any?>
    private fun isStr(x: Any?) = x is String

    /** x[k] in JavaScript: UNDEF for an absent member or a primitive / array, a throw for null. */
    private fun prop(x: Any?, k: String): Any? {
        if (x == null) throw IllegalStateException("Cannot read properties of null (reading '$k')")
        return if (x is Map<*, *> && x.containsKey(k)) x[k] else UNDEF
    }

    private fun numEq(x: Any?, v: Double) = Js.num(x) == v

    /** A JavaScript template-literal rendering of a JSON value. */
    private fun js(v: Any?): String = if (v === UNDEF) "undefined" else Js.template(v)

    private fun err(e: Throwable) = e.message ?: ""

    private fun ok(e: Throwable): Boolean = e is Exception || e is StackOverflowError

    // ---- guards ----

    @JvmStatic fun isAuthzenSubject(x: Any?) = isRec(x) && isStr(rec(x)["type"]) && isStr(rec(x)["id"])
    @JvmStatic fun isAuthzenAction(x: Any?) = isRec(x) && isStr(rec(x)["name"])
    @JvmStatic fun isAuthzenResource(x: Any?) = isRec(x) && isStr(rec(x)["type"]) && isStr(rec(x)["id"])

    @JvmStatic
    fun isAccessEvaluationRequest(x: Any?) = isRec(x) && isAuthzenSubject(rec(x)["subject"]) && isAuthzenAction(rec(x)["action"]) &&
        isAuthzenResource(rec(x)["resource"]) && (!rec(x).containsKey("context") || isRec(rec(x)["context"]))

    @JvmStatic fun isAccessEvaluationsRequest(x: Any?) = isRec(x) && rec(x)["evaluations"] is List<*>

    @JvmStatic
    fun isCoazToolAuthorizationRequest(x: Any?) =
        isRec(x) && isAuthzenSubject(rec(x)["subject"]) && isRec(rec(x)["tool"]) && isStr(rec(rec(x)["tool"])["name"])

    private fun isRequiredThreshold(x: Any?) = isRec(x) && (numEq(rec(x)["t"], 1.0) || numEq(rec(x)["t"], 2.0) || numEq(rec(x)["t"], 3.0)) &&
        isStr(rec(x)["proof"]) && rec(x)["optimisticAllowed"] is Boolean

    // ---- AARP ----

    /** The AARP pending-approval reference of a decision, or null. */
    @JvmStatic
    fun approvalOf(resp: Any?): Map<String, Any?>? {
        val ctx = prop(resp, "context")
        if (ctx === UNDEF) return null
        val p = prop(ctx, PCA_APPROVAL_KEY)
        if (p !is Map<*, *> || p["approval_required"] != true || !isStr(p["auth_req_id"])) return null
        val m = rec(p)
        val tier = if (numEq(m["tier"], 3.0)) 3L else 2L
        val rt = m["required_threshold"]
        return linkedMapOf(
            "approval_required" to true, "auth_req_id" to m["auth_req_id"], "tier" to Js.n(tier),
            "required_threshold" to if (isRequiredThreshold(rt)) rt
            else linkedMapOf("t" to Js.n(tier), "proof" to if (tier == 3L) "strong" else "standard", "optimisticAllowed" to false),
            "goal_commit" to if (isStr(m["goal_commit"])) m["goal_commit"] else "",
            "risk" to if (Js.isNumber(m["risk"])) m["risk"] else Js.n(1),
            "reason" to if (isStr(m["reason"])) m["reason"] else "approval required",
            "requested_at" to if (Js.isNumber(m["requested_at"])) m["requested_at"] else Js.n(0),
        )
    }

    @JvmStatic fun isApprovalRequired(resp: Any?) = approvalOf(resp) != null

    // ---- mapping ----

    private fun answer(decision: Boolean, context: Map<String, Any?>): Map<String, Any?> = linkedMapOf("decision" to decision, "context" to context)

    private fun deny(reason: String, status: Long? = null): Map<String, Any?> {
        val context = linkedMapOf<String, Any?>(
            "reason_admin" to linkedMapOf("denied" to true, "reason" to reason), "reason_user" to linkedMapOf("message" to reason),
        )
        if (status != null) context["error"] = linkedMapOf("status" to Js.n(status), "message" to reason)
        return answer(false, context)
    }

    private fun refused(admin: Map<String, Any?>, userMessage: String) =
        answer(false, linkedMapOf("reason_admin" to admin, "reason_user" to linkedMapOf("message" to userMessage)))

    private fun permit(reason: String) = answer(true, linkedMapOf("reason_admin" to linkedMapOf("reason" to reason)))

    private fun pickReversibility(req: Map<String, Any?>): String? {
        val fromAction = rec(req["action"])["properties"]
        if (isRec(fromAction) && isStr(rec(fromAction)["reversibility_class"])) return rec(fromAction)["reversibility_class"] as String
        val fromCtx = req["context"]
        if (isRec(fromCtx) && isStr(rec(fromCtx)["reversibility_class"])) return rec(fromCtx)["reversibility_class"] as String
        return null
    }

    private fun envFromContext(context: Any?): Map<String, Any?>? {
        if (!isRec(context)) return null
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in rec(context)) if (k != PCA_ACTION_KEY && k != PCA_APPROVAL_KEY) out[k] = v
        return out.ifEmpty { null }
    }

    /**
     * The default AuthZEN to PCA action mapping: verb = action.name; resource = "type:id" (just the type when id is empty); params =
     * resource.properties overlaid by action.properties; subject = subject.properties; env = context minus the PCA keys.
     */
    @JvmStatic
    fun defaultToAction(req: Map<String, Any?>): Map<String, Any?> {
        val res = rec(req["resource"])
        val act = rec(req["action"])
        val type = res["type"] as String
        val id = res["id"] as String
        val params = LinkedHashMap<String, Any?>()
        if (isRec(res["properties"])) params.putAll(rec(res["properties"]))
        if (isRec(act["properties"])) params.putAll(rec(act["properties"]))
        val out = linkedMapOf<String, Any?>("verb" to act["name"], "resource" to if (id.isNotEmpty()) "$type:$id" else type, "params" to params)
        pickReversibility(req)?.let { out["reversibilityClass"] = it }
        val subjProps = rec(req["subject"])["properties"]
        if (isRec(subjProps)) out["subject"] = subjProps
        envFromContext(req["context"])?.let { out["env"] = it }
        return out
    }

    /** The forwarded PCActn tree, null when absent, or [MALFORMED]. */
    private fun pcactnFromContext(context: Any?): Any? {
        if (!isRec(context)) return null
        val raw = rec(context)[PCA_ACTION_KEY] ?: return null
        if (raw !is String) return MALFORMED
        return try {
            if (Pca.artifactTooLarge(raw)) MALFORMED else Json.parse(raw).takeIf { it is Map<*, *> } ?: MALFORMED
        } catch (e: RuntimeException) {
            MALFORMED
        } catch (e: StackOverflowError) {
            MALFORMED
        }
    }

    private fun paramsOf(action: Map<String, Any?>): Map<String, Any?> = if (isRec(action["params"])) rec(action["params"]) else LinkedHashMap()

    private fun freshBudget(grant: Any?, now: Long): Map<String, Any?> {
        val rp = Authorize.readEnvelope(grant)?.get("risk_policy")
        val bMax = if (isRec(rp)) rec(rp)["bMax"] else null
        return linkedMapOf("B" to if (Js.isFinite(bMax)) bMax else Js.n(0), "tau" to Js.n(now), "asOf" to Js.n(now))
    }

    /** The AARP approval-required decision from a step-up Policy-VM result. */
    private fun approvalRequired(p: Map<String, Any?>, decision: Map<String, Any?>, grant: Any?, now: Long): Map<String, Any?> {
        val thr = decision["requiredThreshold"]
        val t = Js.num(rec(thr)["t"])!!
        val tier = if (t >= 3) 3L else 2L
        val reasons = decision["reasons"]
        val reason = (reasons as? List<*>)?.firstOrNull() ?: "requires tier-$tier co-sign"
        val action = rec(p["action"])
        val body = linkedMapOf<String, Any?>(
            "d" to "atlas-pca/authzen/aarp/v1", "verb" to action["verb"], "resource" to action["resource"], "params_digest" to action["params_digest"],
        )
        if (p.containsKey("counter")) body["counter"] = p["counter"]
        body["at"] = Js.n(now)
        val authReqId = Pca.hashCanonical(body)
        val env = Authorize.readEnvelope(grant)
        val pending = linkedMapOf(
            "approval_required" to true, "auth_req_id" to authReqId, "tier" to Js.n(tier), "required_threshold" to thr,
            "goal_commit" to (env?.get("goal_commit") ?: ""), "risk" to decision["r"], "reason" to reason, "requested_at" to Js.n(now),
        )
        return answer(
            false,
            linkedMapOf(
                "id" to authReqId,
                "reason_admin" to linkedMapOf("stage" to "step_up", "risk" to decision["r"], "threshold" to thr, "reasons" to reasons),
                "reason_user" to linkedMapOf("message" to "approval required before this action can proceed"),
                PCA_APPROVAL_KEY to pending,
            ),
        )
    }

    /** Merge boxcar defaults with one item; null when a required piece is still missing (fail closed). Throws for a null item. */
    private fun mergeEvaluation(defaults: Map<String, Any?>, item: Any?): Map<String, Any?>? {
        if (item == null) throw IllegalStateException("Cannot read properties of null (reading 'subject')")
        val it: Map<String, Any?> = if (isRec(item)) rec(item) else emptyMap()
        val subject = it["subject"] ?: defaults["subject"]
        val action = it["action"] ?: defaults["action"]
        val resource = it["resource"] ?: defaults["resource"]
        val context = it["context"] ?: defaults["context"]
        if (!isAuthzenSubject(subject) || !isAuthzenAction(action) || !isAuthzenResource(resource)) return null
        val out = linkedMapOf("subject" to subject, "action" to action, "resource" to resource)
        if (it["context"] != null || defaults.containsKey("context")) out["context"] = context
        return out
    }

    // ---- the PDP ----

    /** The Policy Decision Point over a config (see the object comment). */
    @JvmStatic fun authzenPdp(config: Map<String, Any?>) = AuthzenPdp(config)

    class AuthzenPdp internal constructor(private val config: Map<String, Any?>) {
        private val clock: () -> Long = (config["now"] as? Function0<*>)?.let { f -> { (f() as Number).toLong() } } ?: { System.currentTimeMillis() }

        private fun cfg(k: String) = config[k]

        /** AuthZEN Access Evaluation: one {subject, action, resource, context} to one decision. */
        fun evaluate(reqO: Any?): Map<String, Any?> {
            val now = clock()
            return try {
                evaluateInner(rec(reqO), now)
            } catch (e: Throwable) {
                if (!ok(e)) throw e
                deny("evaluation error (fail closed): ${err(e)}", 500)
            }
        }

        private fun evaluateInner(req: Map<String, Any?>, now: Long): Map<String, Any?> {
            val resolver = cfg("resolve") as? Resolver ?: throw IllegalStateException("authzen: config.resolve is not provided (fail closed)")
            val ctx = resolver.resolve(req) ?: return deny("no PCA authority resolved for this request")

            val mapped = (ctx["toAction"] as? Function1<Map<String, Any?>, Map<String, Any?>>)?.invoke(req) ?: defaultToAction(req)
            val carried = pcactnFromContext(req["context"])
            if (carried === MALFORMED) return deny("context carries a malformed PCActn")

            // static path: no PCActn, "is this admissible under the declared authority at all?"
            if (carried == null) {
                if (cfg("requireProof") != false) return deny("a signed PCActn is required (requireProof)")
                val admits = cfg("admitsConcrete") as? Admits ?: Admits { pol, act -> net.atlasauth.pca.analyzer.Analyzer.admitsConcrete(pol, act) }
                return if (admits.admits(ctx["policy"], mapped)) permit("statically admissible under the declared authority")
                else deny("action is not admissible under the declared authority")
            }

            // proof-carrying path: verify the PCActn, then run the Policy-VM decision
            val p = rec(carried)
            val authorizer = cfg("authorizer") as? Authorizer
            if (cfg("requireAuthorizer") != false && authorizer == null) return deny("no replay/revocation authorizer is configured (requireAuthorizer)")

            // The proof must be FOR the action asked about: verb + resource, and the request's attributes must hash to the signed params_digest.
            val act = if (p.containsKey("action")) p["action"] else UNDEF
            if (act === UNDEF || act == null) throw IllegalStateException("Cannot read properties of ${if (act == null) "null" else "undefined"} (reading 'verb')")
            val verb = prop(act, "verb")
            val resource = prop(act, "resource")
            if (!(verb is String && verb == mapped["verb"]) || !(resource is String && resource == mapped["resource"])) {
                return deny("the PCActn authorizes ${js(verb)} on ${js(resource)}, not the requested ${js(mapped["verb"])} on ${js(mapped["resource"])}")
            }
            val reqParams = paramsOf(mapped)
            if (Pca.paramsDigest(reqParams) != prop(act, "params_digest")) return deny("the request attributes do not match the PCActn's signed params_digest")

            if (ctx["enforce"] != null) throw IllegalStateException("authzen: enforce gates are not supported by this verifier (fail closed)")
            val co = PcaCore.Options(if (isRec(ctx["grant"])) rec(ctx["grant"]) else LinkedHashMap())
            co.nowEpoch = now
            // a string must equal the PCActn's aud, an explicit null accepts any, an omitted audience fails closed when the PCActn carries one
            if (config.containsKey("audience")) co.audience = (config["audience"] as String?)?.let { Pca.Audience.Of(it) } ?: Pca.Audience.Any
            co.authorizedPlanRoots = (cfg("authorizedPlanRoots") as? List<*>)?.filterIsInstance<String>()
            co.insecureSkipPlanRootCheck = cfg("insecureSkipPlanRootCheck") == true
            val verify = PcaCore.verify(p, co)
            if (!verify.allow) {
                return refused(
                    linkedMapOf(
                        "denied" to true, "stage" to "verify", "checks" to LinkedHashMap(verify.checks),
                        "reason" to (verify.reason?.takeIf { it.isNotEmpty() } ?: "PCActn verification failed"),
                    ),
                    "the proof-carrying action did not verify",
                )
            }

            val dctx = linkedMapOf<String, Any?>("grant" to ctx["grant"], "chain" to (ctx["chain"] ?: p["cap_chain"]))
            if (ctx["plan"] != null) dctx["plan"] = ctx["plan"]
            dctx["params"] = reqParams
            dctx["risk"] = ctx["risk"] ?: LinkedHashMap<String, Any?>()
            dctx["budget"] = ctx["budget"] ?: freshBudget(ctx["grant"], now)
            dctx["now"] = Js.n(now)
            if (mapped["subject"] != null) dctx["subject"] = mapped["subject"]
            if (mapped["env"] != null) dctx["env"] = mapped["env"]
            val vm = cfg("policyVm") as? PolicyVm ?: PolicyVm { pc, c -> Decide.decide(Decide.deriveDecideInput(pc, c)) }
            val decision = vm.decide(p, dctx)

            if (!Js.truthy(decision["releaseGuardianShare"])) {
                return refused(
                    linkedMapOf("denied" to true, "stage" to "policy", "reasons" to decision["reasons"], "risk" to decision["r"]),
                    "the policy does not permit this action",
                )
            }

            if (Js.truthy(decision["admit"])) {
                if (authorizer != null) {
                    val input = linkedMapOf<String, Any?>(
                        "operation" to linkedMapOf("verb" to mapped["verb"], "resource" to mapped["resource"], "params" to reqParams), "pcactn" to p,
                    )
                    val provenance = if (isRec(req["context"])) rec(req["context"])[PCA_PROVENANCE_KEY] else null
                    if (provenance != null) input["provenance"] = provenance
                    val az = authorizer.authorize(input)
                    if (!Js.truthy(az["allow"])) {
                        val admin = linkedMapOf<String, Any?>("denied" to true, "stage" to "authorize")
                        if (az["reason"] != null) admin["reason"] = az["reason"]
                        return refused(admin, "the proof-carrying action was not authorized")
                    }
                }
                return answer(true, linkedMapOf("reason_admin" to linkedMapOf("stage" to "policy", "risk" to decision["r"], "threshold" to decision["requiredThreshold"])))
            }
            // Admissible but needs a guardian / human co-sign: AARP approval-required (step-up).
            return approvalRequired(p, decision, ctx["grant"], now)
        }

        /** AuthZEN Access Evaluations: the boxcar endpoint with default inheritance and the evaluations_semantic. */
        fun evaluations(reqO: Any?): Map<String, Any?> {
            if (reqO == null) throw IllegalStateException("Cannot read properties of null (reading 'evaluations')")
            val req: Map<String, Any?> = if (isRec(reqO)) rec(reqO) else emptyMap()
            val items = req["evaluations"] as? List<*> ?: return linkedMapOf("evaluations" to ArrayList<Any?>())
            val options = req["options"]
            val semantic = (if (isRec(options)) rec(options)["evaluations_semantic"] else null) ?: "execute_all"
            if (semantic != "execute_all" && semantic != "deny_on_first_deny" && semantic != "permit_on_first_permit") return refuse(items, "unsupported evaluations_semantic")
            val maxO = cfg("maxEvaluations")
            val max = if (maxO == null) DEFAULT_MAX_EVALUATIONS.toDouble() else Js.num(maxO)!!
            if (items.size > max) return refuse(items, "too many evaluations (limit ${if (max.isInfinite()) "Infinity" else js(maxO)})")
            val merged = items.map { mergeEvaluation(req, it) }
            val res = ArrayList<Any?>()
            for (m in merged) {
                val r = if (m == null) deny("incomplete evaluation (missing subject/action/resource)", 400) else evaluate(m)
                res.add(r)
                if (semantic == "deny_on_first_deny" && r["decision"] == false) break
                if (semantic == "permit_on_first_permit" && r["decision"] == true) break
            }
            return linkedMapOf("evaluations" to res)
        }

        private fun refuse(items: List<*>, reason: String): Map<String, Any?> = linkedMapOf("evaluations" to items.map { deny(reason, 400) })

        /** COAZ profile: authorize an MCP tool invocation (tool to required capability to decision). */
        fun evaluateTool(req: Map<String, Any?>): Map<String, Any?> {
            val tool = rec(req["tool"])
            val name = tool["name"] as String
            val capability = try {
                (cfg("toolCapability") as? ToolCapability)?.capability(name) ?: name
            } catch (e: Exception) {
                return linkedMapOf(
                    "decision" to false, "tool" to name, "required_capability" to "",
                    "context" to deny("evaluation error (fail closed): ${err(e)}", 500)["context"],
                )
            }
            val action = linkedMapOf<String, Any?>("name" to capability)
            if (tool.containsKey("arguments")) action["properties"] = tool["arguments"]
            val mapped = linkedMapOf("subject" to req["subject"], "action" to action, "resource" to linkedMapOf("type" to "mcp_tool", "id" to name))
            if (req.containsKey("context")) mapped["context"] = req["context"]
            val resp = evaluate(mapped)
            val out = linkedMapOf("decision" to resp["decision"], "tool" to name, "required_capability" to capability)
            if (resp.containsKey("context")) out["context"] = resp["context"]
            return out
        }

        /** The framework-agnostic handler: {path, body} to {status, body}. A malformed body is a 400, any thrown error a 500 with no detail. */
        fun handle(req: Map<String, Any?>): Map<String, Any?> = try {
            route(req)
        } catch (e: RuntimeException) {
            response(500, error("internal error"))
        } catch (e: StackOverflowError) {
            response(500, error("internal error"))
        }

        private fun route(req: Map<String, Any?>): Map<String, Any?> {
            val path = prop(req, "path")
            val body = req["body"]
            when (path) {
                EVALUATION_PATH -> {
                    if (!isAccessEvaluationRequest(body)) return response(400, error("invalid AuthZEN Access Evaluation request"))
                    return response(200, evaluate(body))
                }
                EVALUATIONS_PATH -> {
                    // AuthZEN section 7: an absent or empty `evaluations` array is a plain single Access Evaluation.
                    if (isRec(body) && (!rec(body).containsKey("evaluations") || (rec(body)["evaluations"] as? List<*>)?.isEmpty() == true)) {
                        if (!isAccessEvaluationRequest(body)) return response(400, error("invalid AuthZEN Access Evaluations request"))
                        return response(200, evaluate(body))
                    }
                    if (!isAccessEvaluationsRequest(body)) return response(400, error("invalid AuthZEN Access Evaluations request"))
                    return response(200, evaluations(body))
                }
                COAZ_TOOL_PATH -> {
                    if (!isCoazToolAuthorizationRequest(body)) return response(400, error("invalid COAZ MCP-tool authorization request"))
                    return response(200, evaluateTool(rec(body)))
                }
            }
            return response(404, error("unknown AuthZEN path: ${js(path)}"))
        }
    }

    private fun error(m: String): Map<String, Any?> = linkedMapOf("error" to m)

    private fun response(status: Long, body: Any?): Map<String, Any?> = linkedMapOf("status" to Js.n(status), "body" to body)

    @JvmStatic fun authzenHandler(pdp: AuthzenPdp, req: Map<String, Any?>) = pdp.handle(req)

    // ---- search ----

    private fun str(x: Any?) = x is String && x.isNotEmpty()

    private fun entity(x: Any?, needId: Boolean): Boolean {
        if (!isRec(x)) return false
        val m = rec(x)
        return str(m["type"]) && (!needId || str(m["id"])) && (!m.containsKey("properties") || isRec(m["properties"]))
    }

    private fun action(x: Any?): Boolean {
        if (!isRec(x)) return false
        val m = rec(x)
        return str(m["name"]) && (!m.containsKey("properties") || isRec(m["properties"]))
    }

    private fun pageOk(b: Map<String, Any?>): Boolean {
        if (!b.containsKey("page")) return true
        val p = b["page"]
        if (!isRec(p)) return false
        val m = rec(p)
        if (m.containsKey("token") && m["token"] !is String) return false
        if (m.containsKey("limit")) {
            val l = m["limit"]
            if (!Js.isInteger(l) || Math.abs(Js.num(l)!!) > 9007199254740991.0 || Js.num(l)!! < 0 || Js.isNegZero(l)) return false
        }
        return !m.containsKey("properties") || isRec(m["properties"])
    }

    private fun base(b: Map<String, Any?>) = (!b.containsKey("context") || isRec(b["context"])) && pageOk(b)

    @JvmStatic
    fun isSubjectSearch(b: Any?) = isRec(b) && base(rec(b)) && entity(rec(b)["subject"], false) && action(rec(b)["action"]) && entity(rec(b)["resource"], true)

    @JvmStatic
    fun isResourceSearch(b: Any?) = isRec(b) && base(rec(b)) && entity(rec(b)["subject"], true) && action(rec(b)["action"]) && entity(rec(b)["resource"], false)

    @JvmStatic
    fun isActionSearch(b: Any?) = isRec(b) && base(rec(b)) && !rec(b).containsKey("action") && entity(rec(b)["subject"], true) && entity(rec(b)["resource"], true)

    /** The metadata fragment for /.well-known/authzen-configuration: an endpoint per supported search (`provider`: searchSubject / searchResource / searchAction). */
    @JvmStatic
    fun searchMetadata(base: String, provider: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        if (provider["searchSubject"] is SearchFn) out["search_subject_endpoint"] = base + SEARCH_SUBJECT_PATH
        if (provider["searchResource"] is SearchFn) out["search_resource_endpoint"] = base + SEARCH_RESOURCE_PATH
        if (provider["searchAction"] is SearchFn) out["search_action_endpoint"] = base + SEARCH_ACTION_PATH
        return out
    }

    /** The queried entity's id is ignored if present (spec): strip it so a provider cannot be steered by it. */
    private fun stripId(req: Map<String, Any?>, key: String): Map<String, Any?> {
        val e = LinkedHashMap(rec(req[key]))
        e.remove("id")
        return LinkedHashMap(req).also { it[key] = e }
    }

    private fun shape(r: Map<String, Any?>, limit: Any?, typeOk: (Any?) -> Boolean): Map<String, Any?> {
        val resultsO = prop(r, "results") as? List<*> ?: throw IllegalStateException("r.results.filter is not a function")
        val seen = HashSet<String>()
        val results = ArrayList<Any?>()
        for (t in resultsO) {
            val k = Js.stringify(t)
            if (!typeOk(t) || k in seen) continue
            seen.add(k)
            results.add(t)
        }
        var capped: List<Any?> = results
        if (limit !== UNDEF && limit != null && Js.num(limit)!! > 0) {
            val lim = Math.min(Js.num(limit)!!, Int.MAX_VALUE.toDouble()).toInt()
            capped = ArrayList(results.subList(0, Math.min(lim, results.size)))
        }
        // A provider that ignores the requested limit would make us hide results behind a page marker we cannot resume: fail closed.
        if (capped.size < results.size) throw IllegalStateException("provider returned more than the page limit")
        val out = LinkedHashMap<String, Any?>()
        val pg = r["page"]
        if (Js.truthy(pg)) {
            val pm: Map<String, Any?> = if (isRec(pg)) rec(pg) else emptyMap()
            val page = LinkedHashMap<String, Any?>()
            if (pm.containsKey("next_token")) page["next_token"] = pm["next_token"]
            page["count"] = Js.n(capped.size.toLong())
            if (pm.containsKey("total")) page["total"] = pm["total"]
            if (Js.truthy(pm["properties"])) page["properties"] = pm["properties"]
            out["page"] = page
        }
        if (Js.truthy(r["context"])) out["context"] = r["context"]
        out["results"] = capped
        return out
    }

    private fun entityType(type: String): (Any?) -> Boolean = { e ->
        if (e == null) throw IllegalStateException("Cannot read properties of null (reading 'type')")
        isRec(e) && type == rec(e)["type"]
    }

    /** The search handler over a provider; returns null for a path that is not a search path, so it can be chained after the PDP handler. */
    @JvmStatic
    fun authzenSearchHandler(provider: Map<String, Any?>, req: Map<String, Any?>): Map<String, Any?>? = try {
        val path = prop(req, "path")
        val body = req["body"]
        val page = if (isRec(body)) rec(body)["page"] else null
        val limit = if (isRec(page) && rec(page).containsKey("limit")) rec(page)["limit"] else UNDEF
        when (path) {
            SEARCH_SUBJECT_PATH -> {
                val fn = provider["searchSubject"] as? SearchFn
                if (fn == null) response(404, error("subject search is not supported"))
                else if (!isSubjectSearch(body)) response(400, error("invalid AuthZEN subject search request"))
                else response(200, shape(fn.search(stripId(rec(body), "subject")), limit, entityType(rec(rec(body)["subject"])["type"] as String)))
            }
            SEARCH_RESOURCE_PATH -> {
                val fn = provider["searchResource"] as? SearchFn
                if (fn == null) response(404, error("resource search is not supported"))
                else if (!isResourceSearch(body)) response(400, error("invalid AuthZEN resource search request"))
                else response(200, shape(fn.search(stripId(rec(body), "resource")), limit, entityType(rec(rec(body)["resource"])["type"] as String)))
            }
            SEARCH_ACTION_PATH -> {
                val fn = provider["searchAction"] as? SearchFn
                if (fn == null) response(404, error("action search is not supported"))
                else if (!isActionSearch(body)) response(400, error("invalid AuthZEN action search request"))
                else response(200, shape(fn.search(rec(body)), limit) { true })
            }
            else -> null
        }
    } catch (e: Throwable) {
        if (!ok(e)) throw e
        response(500, error("internal error"))
    }
}
