package net.atlasauth.pca.verifier

/**
 * Human approvals: standing "approve this class of action for N hours" grants, decisions, the budget effect of a human co-sign, and the
 * agent-facing half: review an intended action against a facade agent (auto / deny / step-up with its goal lineage and canonical render),
 * batch review, and time-boxing a grant. Nothing here authorizes anything; the resource server's verifier stays the authority.
 */
object Approvals {
    private fun nz(x: Double): Double = if (!x.isNaN() && !x.isInfinite() && x > 0) x else 0.0

    private fun num(o: Any?): Double = IntentJs.num(o) ?: Double.NaN

    private fun jn(d: Double): Any = Facade.jn(d)

    /**
     * A standing approval `{id, verbs, resource?, grantedAt, ttlMs, by}` for the listed verbs, optionally narrowed to a resource pattern
     * (a `*` suffix = prefix match), valid from [now] for [ttlMs].
     */
    @JvmOverloads
    fun approveClass(verbs: List<String>, ttlMs: Double, by: String, now: Double, resource: String? = null): Map<String, Any?> {
        val idBody = linkedMapOf<String, Any?>(
            "d" to "atlas-pca/class-approval/v1", "verbs" to verbs.sortedWith(Comparator { a, b -> Json.compareUtf8(a, b) }),
            "resource" to resource, "grantedAt" to jn(now), "by" to by,
        )
        val m = linkedMapOf<String, Any?>("id" to Pca.hashCanonical(idBody), "verbs" to ArrayList<Any?>(verbs))
        if (resource != null) m["resource"] = resource
        m["grantedAt"] = jn(now)
        m["ttlMs"] = jn(ttlMs)
        m["by"] = by
        return m
    }

    private fun resourceMatches(pattern: String?, resource: String): Boolean {
        if (pattern == null || pattern == "*") return true
        if (pattern.endsWith("*")) return resource.startsWith(pattern.substring(0, pattern.length - 1))
        return pattern == resource
    }

    /** True while [a] is in force (`grantedAt <= now < grantedAt + ttlMs`) and covers the verb and the resource. */
    fun classApprovalCovers(a: Map<String, Any?>, verb: String, resource: String, now: Double): Boolean {
        val granted = num(a["grantedAt"])
        val ttl = num(a["ttlMs"])
        if (!now.isFinite() || !granted.isFinite() || !ttl.isFinite()) return false
        if (!(now >= granted) || !(now < granted + ttl)) return false
        val verbs = a["verbs"] as? List<*> ?: return false
        if (!verbs.contains(verb)) return false
        return resourceMatches(a["resource"] as? String, resource)
    }

    /** True when any of the standing approvals covers the call. */
    fun coveredByAny(approvals: List<Any?>, verb: String, resource: String, now: Double): Boolean =
        approvals.any { classApprovalCovers(Pca.asMap(it), verb, resource, now) }

    /** A human decision on a step-up request: `{requestId, decision: approve|deny, by, at}`. */
    fun recordDecision(request: Map<String, Any?>, decision: String, by: String, at: Double): Map<String, Any?> =
        linkedMapOf("requestId" to request["id"], "decision" to decision, "by" to by, "at" to jn(at))

    /** The step-up requests among a batch of reviews (`{kind: step_up, request}`). */
    fun pendingRequests(reviews: List<Any?>): List<Any?> =
        reviews.filter { (it as? Map<*, *>)?.get("kind") == "step_up" }.map { (it as Map<*, *>)["request"] }

    /**
     * The budget effect of a human co-sign, the ONLY way a budget rises: [full] re-confirms the goal (`B = bMax`); otherwise
     * `B = min(bMax, B + rho)`; `tau = asOf = now` either way. [policy] carries `rho` and `bMax`.
     */
    @JvmOverloads
    fun applyCosign(budget: Map<String, Any?>, policy: Map<String, Any?>, now: Double, full: Boolean = false): Map<String, Any?> {
        val b = if (full) Risk.rechargeFull(Risk.Budget(num(budget["B"]), num(budget["tau"])), num(policy["bMax"]), now)
        else Risk.recharge(Risk.Budget(num(budget["B"]), num(budget["tau"])), num(policy["rho"]), num(policy["bMax"]), now)
        return linkedMapOf("B" to jn(b.B), "tau" to jn(now), "asOf" to jn(now))
    }

    // ---- agent-facing half ----

    /** Builds the canonical approval render of an action (what the approver must be shown); may throw, which makes the review a deny. */
    fun interface Renderer {
        fun render(verb: String, resource: String, params: Map<String, Any?>?): Map<String, Any?>
    }

    /** Options of [reviewAction]; every member is optional. */
    class ReviewOptions @JvmOverloads constructor(
        /** The clock (ms); the wall clock when null. */
        val now: Long? = null,
        /** Plaintext goal carried on a step-up request (shown to the approver). */
        val goal: String? = null,
        /** Standing class approvals that can downgrade a step-up to auto. */
        val standing: List<Any?>? = null,
        /** Without a renderer (and without [insecureUnboundApproval]) a step-up is a deny: what the approver sees is what is signed. */
        val renderer: Renderer? = null,
        /** DOCUMENTED INSECURE opt-out: keep the pre-render behaviour of an unbound request. */
        val insecureUnboundApproval: Boolean = false,
    )

    private fun jsStr(v: Any?, present: Boolean): String = if (!present) "undefined" else when (v) {
        is Map<*, *> -> "[object Object]"
        is List<*> -> v.joinToString(",") { if (it == null) "" else jsStr(it, true) }
        else -> AttestUtil.jsAnyString(v)
    }

    private fun formatLimit(limit: Facade.ParsedLimit): String {
        val amt = Json.jsNumberText(limit.amount)
        val base = if (limit.unit == "usd") "$$amt" else amt
        val ms = limit.periodMs ?: return base
        val hours = ms / 3_600_000.0
        val period = if (hours % 24 == 0.0 && hours >= 24) Json.jsNumberText(hours / 24) + "d"
        else if (hours >= 1) Json.jsNumberText(hours) + "h"
        else Json.jsNumberText(Math.floor(ms / 60_000.0 + 0.5)) + "m"
        return "$base/$period"
    }

    /** `JSON.stringify` of a parsed value: JavaScript key order (index keys first) and number spelling. */
    internal fun stringify(v: Any?): String = when {
        v == null -> "null"
        v is Boolean -> v.toString()
        v is String -> Json.canonicalize(v)
        v is Map<*, *> -> v.let { m -> keysOf(m).joinToString(",", "{", "}") { k -> Json.canonicalize(k) + ":" + stringify(m[k]) } }
        v is List<*> -> v.joinToString(",", "[", "]") { stringify(it) }
        else -> {
            val d = IntentJs.num(v)
            if (d == null || d.isNaN() || d.isInfinite()) "null" else Json.jsNumberText(d)
        }
    }

    private fun keysOf(m: Map<*, *>): List<String> = net.atlasauth.pca.evidence.EvidenceBundle.jsKeys(m)

    /** JavaScript `String(x)`: an object is "[object Object]", an array its elements joined by commas (null and undefined empty). */
    private fun jsStr(x: Any?): String = when (x) {
        is Map<*, *> -> "[object Object]"
        is List<*> -> x.joinToString(",") { if (it == null) "" else jsStr(it) }
        else -> AttestUtil.jsAnyString(x)
    }

    private fun summarizeParams(params: Map<String, Any?>?, amountField: String?): String? {
        if (params == null) return null
        if (amountField != null && params.containsKey(amountField)) return amountField + "=" + jsStr(params[amountField])
        val keys = keysOf(params)
        if (keys.isEmpty()) return null
        return keys.take(4).joinToString(", ") { k ->
            val x = params[k]
            k + "=" + (if (x == null || x is Map<*, *> || x is List<*>) stringify(x) else AttestUtil.jsAnyString(x))
        }
    }

    private fun node(kind: String, label: String, detail: String?): Map<String, Any?> {
        val n = linkedMapOf<String, Any?>("kind" to kind, "label" to label)
        if (detail != null) n["detail"] = detail
        return n
    }

    private fun specOf(agent: Facade.Handle, verb: String): Catalog.Spec? = agent.policy.actions.firstOrNull { it.verb == verb }

    /**
     * The goal lineage of one intended action ("you approved X because you asked to Y"): the grant's goal commitment, threaded through
     * the delegated authority that admits the verb, down to the action. [goal] (plaintext) is checked against the commitment with the
     * agent's salt: `goalVerified` says whether it opens it, so an inbox shows "unverified" rather than lie. Signs nothing.
     */
    @JvmOverloads
    fun buildGoalLineage(agent: Facade.Handle, verb: String, resource: String, params: Map<String, Any?>?, goal: String? = null): Map<String, Any?> {
        val env = Authorize.readEnvelope(agent.grant)
        val goalCommit = env?.get("goal_commit") as? String ?: ""
        val verified = goal != null && goalCommit.isNotEmpty() && agent.goalSalt.isNotEmpty() && Issue.goalCommit(goal, agent.goalSalt) == goalCommit
        val spec = specOf(agent, verb)
        val limit = agent.policy.limits[verb]
        val goalLabel = if (goal != null) "Pursue the goal: “$goal”" else "Pursue the grant’s committed goal"
        val goalDetail = if (goal != null) {
            if (verified) "verified: this goal opens the signed grant commitment" else "unverified: the revealed goal does not open the grant commitment"
        } else if (goalCommit.isNotEmpty()) "committed as $goalCommit" else null
        val authorityLabel = "Delegated authority to " + verb + (if (limit != null) " (up to ${formatLimit(limit)})" else "")
        val chain = ArrayList<Any?>()
        chain.add(node("goal", goalLabel, goalDetail))
        chain.add(node("authority", authorityLabel, spec?.description?.takeIf { it.isNotEmpty() }))
        chain.add(node("action", "$verb $resource", summarizeParams(params, spec?.amountField)))
        val because = if (goal != null) "Approving $verb on $resource because you asked to “$goal”."
        else "Approving $verb on $resource, authorized under the grant’s committed goal."
        val out = LinkedHashMap<String, Any?>()
        if (goal != null) out["goal"] = goal
        out["goalCommit"] = goalCommit
        out["goalVerified"] = verified
        out["chain"] = chain
        out["because"] = because
        return out
    }

    private fun truthy(v: Any?): Boolean {
        if (v == null || v == false) return false
        if (v is String) return v.isNotEmpty()
        val d = IntentJs.num(v)
        return d == null || !(d == 0.0 || d.isNaN())
    }

    /** A lineage flattened to plain text lines (SMS, plain email, Slack fallback): `label - detail`, or the label alone when a hop has no detail. */
    fun describeGoalLineage(lineage: Map<String, Any?>?): List<Any?> {
        require(lineage != null) { "describeGoalLineage: lineage required" }
        val chain = lineage["chain"] as? List<*> ?: throw IllegalArgumentException("describeGoalLineage: chain must be a list")
        val out = ArrayList<Any?>()
        for (o in chain) {
            require(o != null) { "describeGoalLineage: a hop must not be null" }
            if (o !is Map<*, *>) { out.add(null); continue } // a primitive has no label or detail
            val detail = o["detail"]
            val label = o["label"]
            if (truthy(detail)) out.add(jsStr(label, o.containsKey("label")) + " — " + AttestUtil.jsAnyString(detail)) else out.add(label)
        }
        return out
    }

    private fun riskForReview(agent: Facade.Handle, verb: String, params: Map<String, Any?>?): Double {
        val spec = specOf(agent, verb)
        val kappa = IntentJs.num(agent.policy.riskPolicy["kappa"])?.takeIf { it.isFinite() }
        val amountField = spec?.amountField
        if (agent.policy.budgetModel == "dollars" && amountField != null) {
            val amt = params?.get(amountField)?.let { IntentJs.num(it) } ?: Double.NaN
            if (!amt.isNaN() && !amt.isInfinite() && kappa != null && kappa > 0) return Math.max(0.0, Math.min(1.0, amt / kappa))
        }
        return Math.max(0.0, Math.min(1.0, spec?.blastRadius ?: 0.8))
    }

    private fun review(kind: String, reason: String?): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("kind" to kind)
        if (reason != null) m["reason"] = reason
        return m
    }

    /**
     * Review an intended action against the agent's grant. `{kind: auto}`: no human needed; `{kind: deny, reason}`: the grant's
     * predicates or caveats forbid it, or no complete approval render could be made (fail closed); `{kind: step_up, request}`:
     * admissible but needs a tier-2/3 co-sign, unless a standing class approval covers it. A step-up carries the canonical render and its
     * digest, unless `insecureUnboundApproval` is set and no renderer given.
     */
    @JvmOverloads
    fun reviewAction(agent: Facade.Handle, verb: String, resource: String, params: Map<String, Any?>? = null, opts: ReviewOptions? = null): Map<String, Any?> {
        val op = opts ?: ReviewOptions()
        val now = op.now ?: System.currentTimeMillis()
        val dr = agent.dryRun(verb, resource, params, now)
        if (!dr.allowed) return review("deny", dr.reason ?: "denied by policy")
        if (dr.t == null || dr.t == 1) return review("auto", null)
        if (op.standing != null && coveredByAny(op.standing, verb, resource, now.toDouble())) return review("auto", null)
        val tier: Int = dr.t ?: 3
        var render: Map<String, Any?>? = null
        var renderDigest: String? = null
        if (op.renderer == null && !op.insecureUnboundApproval) {
            return review("deny", "approval render required: pass a renderer (renderersFromDefs from the pinned action definitions), or insecureUnboundApproval: true")
        }
        if (op.renderer != null) {
            try {
                render = op.renderer.render(verb, resource, params)
                renderDigest = Approval.renderDigest(render)
            } catch (err: RuntimeException) {
                return review("deny", "approval render failed (fail closed): " + (err.message ?: ""))
            }
        }
        val env = Authorize.readEnvelope(agent.grant)
        val goalCommit = env?.get("goal_commit") as? String ?: ""
        val lineage = buildGoalLineage(agent, verb, resource, params, op.goal)
        val idBody = linkedMapOf<String, Any?>("d" to "atlas-pca/stepup/v1", "verb" to verb, "resource" to resource, "params" to params, "at" to now)
        val request = LinkedHashMap<String, Any?>()
        request["id"] = Pca.hashCanonical(idBody)
        request["verb"] = verb
        request["resource"] = resource
        if (params != null) request["params"] = params
        request["tier"] = tier.toLong()
        request["reason"] = dr.reason ?: "requires tier $tier co-sign"
        request["goalCommit"] = goalCommit
        if (op.goal != null) request["goal"] = op.goal
        request["lineage"] = lineage
        request["r"] = jn(riskForReview(agent, verb, params))
        request["requestedAt"] = now
        if (render != null && renderDigest != null) {
            request["render"] = render
            request["renderDigest"] = renderDigest
        }
        return linkedMapOf("kind" to "step_up", "request" to request)
    }

    /** Review a batch of intended actions (`{verb, resource, params?}` each): the inbox's "N actions waiting". */
    @JvmOverloads
    @Suppress("UNCHECKED_CAST")
    fun batchReview(agent: Facade.Handle, calls: List<Map<String, Any?>>, opts: ReviewOptions? = null): List<Any?> =
        calls.map { c -> reviewAction(agent, c["verb"] as String, c["resource"] as String, c["params"] as? Map<String, Any?>, opts) }

    /**
     * Narrow a capability to expire [ttlMs] after [now] by appending an `expires` caveat signed by the holder. Caveats are conjunctive
     * and append-only, so this can only restrict, never widen.
     */
    fun timeBox(parent: Map<String, Any?>, holder: Keys.SuiteKey, ttlMs: Double, now: Double): Map<String, Any?> {
        val at = now + ttlMs
        require(!(at.isNaN() || at.isInfinite())) { "timeBox: the expiry must be a finite number" }
        return Issue.attenuate(parent, listOf<Any?>(linkedMapOf("type" to "expires", "at" to jn(at))), holder)
    }
}
