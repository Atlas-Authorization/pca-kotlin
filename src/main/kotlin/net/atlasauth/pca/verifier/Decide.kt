package net.atlasauth.pca.verifier

/**
 * The Policy VM decision (the reference's `decide`): whether the guardian share may be released for an action, the threshold and proof
 * it then needs, the risk, the budget admission and the budget afterwards. Pure and total: any fault is a denial carrying a reason (fail
 * closed).
 *
 * The input and the result are the reference's objects as [Json] trees. Input members: `grant`, `pqPins?`, `trustedRoot?`, `chain?`,
 * `action` (`{action: {verb, resource, params, reversibility_class}, subject?, env?, toolBinding?}`), `plan?`, `risk` (any of
 * `semanticDistance, reversibility, blastRadius, taint, confidence, age`), `budget` (`{B, tau, asOf?}`), `now`, `nodeId?`, `goalNodeId?`,
 * `caveatContext?` (`recentActionTimes, reversibilityClass, blastRadius, delegationDepth`), `ageHorizonMs?`, `rFloor?`, `chainVerified?`,
 * `k1?` (a [CaveatLang.K1Input]). Result members: `releaseGuardianShare, requiredThreshold {t, proof, optimisticAllowed}, r, admit,
 * needStepUp, reasons, budget, k1Bound?`.
 */
/** `deriveDecideInput` was called without `ctx.grant` (the verifier's own stored grant). Never defaulted from the artifact. */
class DecideInputGrantRequired : IllegalArgumentException(
    "deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant",
) {
    val code: String = "grant_required"
}

@Suppress("UNCHECKED_CAST")
object Decide {
    /** Classes recognised as non-irreversible (so the optimistic fast path may be offered); anything else is treated as irreversible. */
    private val FAST_PATH_CLASSES = listOf("reversible", "rate_limited", "costly")
    private val KEYS = listOf("semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age")

    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: LinkedHashMap()

    /**
     * The tool call an action denotes, for `tool_schema` caveats: `tool` is the signed verb, `args` the (digest-checked) params, and
     * `toolSignatureDigest` the signed tool binding when there is one. A missing params object reads as `{}`.
     */
    @JvmStatic
    fun toolCallOf(action: Any?): Map<String, Any?> {
        val a = map(map(action)["action"])
        val out = linkedMapOf<String, Any?>("tool" to (a["verb"] as? String ?: ""), "args" to (a["params"] as? Map<*, *> ?: LinkedHashMap<String, Any?>()))
        val binding = map(action)["toolBinding"]
        if (binding is String) out["toolSignatureDigest"] = binding
        return out
    }

    /**
     * Extend a stock caveat context with the action and the derived tool call so `predicates` and `tool_schema` caveats can be
     * evaluated. The derived members are applied LAST: a caller-supplied context can never substitute a different action or tool call.
     */
    @JvmStatic
    fun agentCaveatContext(base: Map<String, Any?>, action: Any?): Map<String, Any?> {
        val out = LinkedHashMap(base)
        out["action"] = action
        out["toolCall"] = toolCallOf(action)
        return out
    }

    /**
     * THE reversibility class of an action, shared by every path that evaluates `reversibility_max` caveats: the action's own class,
     * else the class of the plan node the action is bound to ([nodeId], the SIGNED plan node id), else null, which no `reversibility_max`
     * caveat accepts and which is not fast-path eligible (fail closed).
     */
    @JvmStatic
    fun resolveReversibilityClass(action: Any?, plan: List<*>?, nodeId: Any?): String? {
        val own = map(map(action)["action"])["reversibility_class"]
        if (own != null) return own as? String
        if (nodeId !is String) return null
        val node = plan?.firstOrNull { it is Map<*, *> && it["id"] == nodeId } as? Map<*, *>
        return node?.get("reversibility_class") as? String
    }

    private fun denied(reason: String, budget: Any?): Map<String, Any?> = linkedMapOf(
        "releaseGuardianShare" to false, "requiredThreshold" to linkedMapOf("t" to 3, "proof" to "strong", "optimisticAllowed" to false),
        "r" to 1, "admit" to false, "needStepUp" to true, "reasons" to arrayListOf<Any?>(reason), "budget" to budget,
    )

    private fun budgetMap(b: Risk.Budget): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("B" to b.B)
        if (!b.tauAbsent) m["tau"] = b.tau
        if (b.asOf != null) m["asOf"] = b.asOf // undefined (omitted) when the leak failed closed on an absent stamp
        return m
    }

    /** Decides [input]; never throws. */
    @JvmStatic
    fun decide(input: Map<String, Any?>?): Map<String, Any?> {
        val fallback = input?.get("budget") ?: budgetMap(Risk.Budget(0.0, 0.0, 0.0))
        return try {
            SafeRegex.withBudget { decideInner(input!!, fallback) }
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            denied("policy evaluation error (fail closed): ${e.message ?: "unknown"}", fallback)
        }
    }

    private fun withoutK1(cs: Any?): MutableList<Any?> = (cs as? List<*>)?.filter { !CaveatLang.isK1Caveat(it) }?.toMutableList() ?: ArrayList()

    private fun budgetOf(o: Any?): Risk.Budget? {
        val m = o as? Map<*, *> ?: return null
        val b = Risk.fin(m["B"]) ?: return null
        val tauN = IntentJs.num(m["tau"]) // a non-finite tau is still a number; an absent one leaves the stamp undefined
        return Risk.Budget(b, tauN ?: Double.NaN, IntentJs.num(m["asOf"]), tauN == null)
    }

    private fun decideInner(inp: Map<String, Any?>, fallbackBudget: Any?): Map<String, Any?> {
        val budgetIn = inp["budget"]
        val grantO = inp["grant"]
        val env = Authorize.readEnvelope(grantO) ?: return denied("grant carries no valid envelope", budgetIn)
        val grant = map(grantO)
        val now = Risk.fin(inp["now"]) ?: return denied("invalid decision time", budgetIn)
        val hasChain = inp.containsKey("chain")
        val chainO = inp["chain"]

        // an unverified capability chain is DENIED here: unless the caller vouches it was verified, decide re-verifies it
        if (inp["chainVerified"] != true) {
            val toVerify = if (chainO is List<*> && chainO.isNotEmpty()) chainO as List<Any?> else listOf<Any?>(grant)
            val issuer = grant["issuer"]
            val why = Pca.verifyChain(
                toVerify, issuer as? String ?: "", issuer is String, null,
                inp["pqPins"] as? Map<String, Any?>, inp["trustedRoot"] as? Map<String, Any?>,
            )
            if (why.isNotEmpty()) return denied("capability chain unverified: $why", budgetIn)
        }

        val pol = map(env["risk_policy"])
        val reasons = ArrayList<String>()
        val actionCtx = map(inp["action"])
        val inner = map(actionCtx["action"])

        // 1. semantic predicates (default deny)
        val denial = Predicates.denialReason(env["predicates"], actionCtx)
        val prOk = denial == null
        if (denial != null) reasons.add(denial)

        val nodeId = inp["nodeId"]
        val plan = inp["plan"] as? List<Any?>
        val risk = map(inp["risk"])

        // the class the action is bound to: its own, else the plan node it names, else unknown (fail closed)
        var revClass = inner["reversibility_class"]
        if (revClass == null && nodeId is String && plan != null) {
            plan.firstOrNull { it is Map<*, *> && nodeId == it["id"] }?.let { revClass = (it as Map<*, *>)["reversibility_class"] }
        }

        // 2. envelope caveats
        val cctx = linkedMapOf<String, Any?>("now" to now, "action" to inner, "blast_radius" to risk["blastRadius"], "reversibility_class" to revClass)
        val over = map(inp["caveatContext"])
        for ((camel, snake) in listOf(
            "blastRadius" to "blast_radius", "reversibilityClass" to "reversibility_class", "delegationDepth" to "delegation_depth",
            "recentActionTimes" to "recent_action_times",
        )) if (over.containsKey(camel)) cctx[snake] = over[camel]
        val toolCall = linkedMapOf<String, Any?>("tool" to (inner["verb"] as? String ?: ""), "args" to (inner["params"] as? Map<*, *> ?: LinkedHashMap<String, Any?>()))
        if (actionCtx["toolBinding"] is String) toolCall["toolSignatureDigest"] = actionCtx["toolBinding"]

        var chainOk = true
        var extra: List<Any?> = ArrayList()
        val gcs = grant["caveats"] as? List<*> ?: emptyList<Any?>()
        val chain = chainO as? List<Any?>
        if (hasChain) {
            if (chain == null || chain.isEmpty()) {
                chainOk = false
                reasons.add("delegation chain is empty or malformed")
            } else {
                cctx["delegation_depth"] = chain.size - 1
                val lcs = map(chain[chain.size - 1])["caveats"]
                extra = if (lcs is List<*>) ArrayList(lcs.subList(Math.min(gcs.size, lcs.size), lcs.size)) else ArrayList()
            }
        }
        val ecv = Authorize.evaluateAgentCaveats(env["caveats"], cctx, actionCtx, toolCall)
        if (!ecv.ok) reasons.add("caveat(s) not satisfied: " + ecv.failed.joinToString(", "))

        // root caveats outside the envelope are signed authority too; the caveat-language (K1) types are evaluated over the whole chain
        val leafCaveats = (if (chain != null && chain.isNotEmpty()) map(chain[chain.size - 1]) else grant)["caveats"]
        val k1In = inp["k1"] as? CaveatLang.K1Input
        val useK1 = k1In != null || (leafCaveats as? List<*>)?.any { CaveatLang.isK1Caveat(it) } == true
        val k1 = if (useK1) CaveatLang.evaluateK1(grant, chainO, k1In, now.toLong(), inner) else null
        val rcv = Authorize.evaluateAgentCaveats(withoutK1(Caveats.rootCaveats(grant)), cctx, actionCtx, toolCall)
        if (!rcv.ok) reasons.add("root caveat(s) not satisfied: " + rcv.failed.joinToString(", "))
        val cvOk = ecv.ok && rcv.ok
        val dl = withoutK1(extra)
        if (k1 != null) dl.addAll(k1.plain)
        val dcv = Authorize.evaluateAgentCaveats(dl, cctx, actionCtx, toolCall)
        var dcvOk = dcv.ok
        if (!dcv.ok) reasons.add("delegated caveat(s) not satisfied: " + dcv.failed.joinToString(", "))
        if (k1 != null && !k1.ok) {
            dcvOk = false
            for (i in k1.reasons.indices) reasons.add("caveat language: ${k1.failed[i]}: ${k1.reasons[i]}")
        }

        // 3. risk
        val budget = budgetOf(budgetIn) ?: throw IllegalArgumentException("budget is not a trust budget")
        val policy = Risk.Policy.of(pol) ?: throw IllegalArgumentException("risk_policy is not a valid policy")
        val leaked = Risk.leak(budget, now, policy.lambda)
        val inputs = LinkedHashMap<String, Any?>()
        val missing = ArrayList<String>()
        for ((i, k) in KEYS.withIndex()) {
            val v = Risk.fin(risk[k])
            if (v != null) inputs[k] = v else if (i != 5) missing.add(k)
        }
        if (plan != null && risk["semanticDistance"] == null) {
            val goal = inp["goalNodeId"] ?: if (plan.isEmpty()) null else map(plan[plan.size - 1])["id"]
            inputs["semanticDistance"] = if (nodeId is String && goal is String) Risk.planGeodesic(plan, nodeId, goal) else 1.0
            missing.remove("semanticDistance")
        }
        if (risk["age"] == null) inputs["age"] = Risk.ageSinceTouch(leaked, now, (if (inp.containsKey("ageHorizonMs")) (IntentJs.num(inp["ageHorizonMs"]) ?: Double.NaN) else 3_600_000.0)) // a present non-number is not > 0: age 1
        if (missing.isNotEmpty()) reasons.add("risk input(s) missing, assumed worst case: " + missing.joinToString(", "))
        val rFloor = Risk.fin(inp["rFloor"])?.let { Math.min(1.0, Math.max(0.0, it)) } ?: 0.0
        val r = Math.max(Risk.riskScore(inputs, policy.weights), rFloor)

        val rc = cctx["reversibility_class"]
        val irreversible = !(rc is String && rc in FAST_PATH_CLASSES)
        val rt = Risk.requiredThreshold(r, policy, irreversible)

        // 4. budget admission
        val adm = Risk.admitOf(Risk.requiredThreshold(r, policy, false).t, leaked.B.isFinite() && leaked.B >= Risk.cost(r, policy.kappa))
        if (adm.needStepUp) {
            reasons.add(if (rt.t < 3 && adm.t == 3) "trust budget depleted: human recharge required" else "risk ${Risk.toFixed3(r)} exceeds auto threshold: step-up to t=${adm.t}")
        }

        // 5. guardian release: policy AND caveats AND a well-formed chain; the human / step-up path stays available otherwise
        val release = prOk && cvOk && dcvOk && chainOk
        val thr = Risk.escalateThreshold(rt, adm.t)
        val out = if (release && adm.metered) Risk.debit(leaked, Risk.cost(r, policy.kappa)) else leaked
        val res = linkedMapOf<String, Any?>(
            "releaseGuardianShare" to release, "requiredThreshold" to linkedMapOf("t" to thr.t, "proof" to thr.proof, "optimisticAllowed" to thr.optimisticAllowed),
            "r" to r, "admit" to (release && adm.admit), "needStepUp" to (if (release) adm.needStepUp else true), "reasons" to ArrayList<Any?>(reasons),
            "budget" to budgetMap(out),
        )
        if (k1 != null) res["k1Bound"] = k1.bound.map { linkedMapOf("caveat" to it.caveat, "hop" to it.hop, "capHash" to it.capHash) }
        return res
    }

    /**
     * Assembles a [decide] input from a PCActn plus the resource server's context, so caller and verifier derive the action, node id and
     * chain identically. `ctx`: `grant` (REQUIRED: the verifier's OWN stored grant, never the artifact's chain root; it is also the chain's
     * trusted root), `plan?`, `params?` (checked by the caller against the action's params_digest), `risk`, `budget`, `chain?`, `now`,
     * `pqPins?`, `goalNodeId?`, `subject?`, `env?`, `caveatContext?`, `ageHorizonMs?`. Throws [IllegalArgumentException] when there is no grant.
     */
    @JvmStatic
    fun deriveDecideInput(p: Any?, ctx: Map<String, Any?>?): Map<String, Any?> {
        if (ctx == null) throw IllegalArgumentException("deriveDecideInput: no context")
        val grant = ctx["grant"]
        if (grant !is Map<*, *> && grant !is List<*>) throw DecideInputGrantRequired()
        if (p == null) throw IllegalArgumentException("deriveDecideInput: no PCActn")
        // a member the reference reads as undefined is absent here; a present null stays null
        val pm: Map<String, Any?> = if (p is Map<*, *>) p as Map<String, Any?> else emptyMap()
        val act: Map<String, Any?> = (pm["action"] as? Map<String, Any?>) ?: emptyMap()
        val inner = LinkedHashMap<String, Any?>()
        if (act.containsKey("verb")) inner["verb"] = act["verb"]
        if (act.containsKey("resource")) inner["resource"] = act["resource"]
        inner["params"] = ctx["params"] ?: LinkedHashMap<String, Any?>()
        if (act.containsKey("reversibility_class")) inner["reversibility_class"] = act["reversibility_class"]
        val action = linkedMapOf<String, Any?>("action" to inner)
        if (ZkJs.truthy(ctx["subject"])) action["subject"] = ctx["subject"]
        if (ZkJs.truthy(ctx["env"])) action["env"] = ctx["env"]
        val out = linkedMapOf<String, Any?>("grant" to grant, "trustedRoot" to grant)
        if (ctx.containsKey("pqPins")) out["pqPins"] = ctx["pqPins"]
        if (ctx["chain"] != null) out["chain"] = ctx["chain"] else if (pm.containsKey("cap_chain")) out["chain"] = pm["cap_chain"]
        out["action"] = action
        if (ctx.containsKey("plan")) out["plan"] = ctx["plan"]
        val plan = pm["plan"]
        if (plan is Map<*, *> && plan.containsKey("node_id")) out["nodeId"] = plan["node_id"]
        for (k in listOf("goalNodeId", "risk", "budget", "now", "caveatContext", "ageHorizonMs")) if (ctx.containsKey(k)) out[k] = ctx[k]
        return out
    }
}
