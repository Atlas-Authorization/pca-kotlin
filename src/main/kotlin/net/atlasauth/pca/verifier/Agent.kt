package net.atlasauth.pca.verifier

/**
 * An agent that acts under a grant: it owns the leaf signing key, the capability chain and the monotonic counter, stamps a fresh
 * nonce on every action, and encodes the PCActn the way the native middleware expects (`PCA-Action` header, unpadded base64url of
 * the JSON). No TypeScript process is needed.
 *
 * ```
 * val me = Keys.ed25519(Keys.edGenerate())
 * val agent = Agent(me, "ins_123", grant)                       // chain defaults to [grant]
 * val pcactn = agent.act("pay", "invoice/7", mapOf("amount" to 1200L))
 * request.header(Agent.HEADER, Agent.header(pcactn))            // any HTTP client
 * ```
 *
 * Not thread-safe: counters are handed out in order, so use one Agent per thread or synchronize around `act`.
 */
class Agent(
    val signer: Keys.SuiteKey,
    val aud: String,
    val grant: Map<String, Any?>,
    chain: List<Any?>? = null,
    /** The last counter used; the next action uses `counter + 1`. */
    var counter: Long = 0L,
    var ttlMs: Long = Issue.DEFAULT_TTL_MS,
    var clock: () -> Long = { System.currentTimeMillis() },
    var nonces: Boolean = true,
) {
    val chain: List<Any?> = chain?.toList() ?: listOf(grant)
    private var plan: Issue.Plan? = null

    init {
        require(aud.isNotEmpty()) { "Agent: aud (the resource server / instance id) is required" }
    }

    /** Commit a plan locally; the returned root is what a server must echo if the plan is registered with it. */
    fun commitPlan(nodes: List<Map<String, Any?>>): Issue.Plan = Issue.commitPlan(nodes).also { plan = it }

    private fun build(p: Issue.Plan, nodeId: String, params: Map<String, Any?>?, slots: Map<String, Any?>?): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        fun map(k: String): Map<String, Any?>? = slots?.get(k) as? Map<String, Any?>
        val next = counter + 1
        val out = Issue.buildPCActn(
            Issue.ActSpec(
                grant = grant, chain = chain, plan = p, nodeId = nodeId, counter = next, signer = signer, aud = aud, params = params,
                iat = clock(), ttlMs = ttlMs,
                nonce = (slots?.get("nonce") as? String) ?: if (nonces) Issue.randomB64u(16) else null,
                caution = slots?.get("caution"), rationaleCommitment = slots?.get("rationale_commitment") as? String,
                toolBinding = slots?.get("tool_binding") as? String, prohibitionEvidence = slots?.get("prohibition_evidence"),
                progressStep = map("progress_step"), intent = map("intent"), intentSession = map("intent_session"), freshAt = map("fresh_at"),
                provenance = map("provenance"), attestation = map("attestation"), freshness = map("freshness"), riskClaim = map("risk_claim"),
            ),
        )
        counter = next // monotonic: a counter is never reused, even if the call later fails
        return out
    }

    /** Act on node [nodeId] of the committed plan. [slots] carries the optional signed members (caution, intent, fresh_at, ...). */
    fun actNode(nodeId: String, params: Map<String, Any?>? = null, slots: Map<String, Any?>? = null): Map<String, Any?> =
        build(checkNotNull(plan) { "commitPlan() first" }, nodeId, params, slots)

    /**
     * Act on one verb and resource with an ad-hoc single-node plan. Use [commitPlan] and [actNode] when the server requires the
     * plan to be registered first.
     */
    fun act(verb: String, resource: String, params: Map<String, Any?>? = null, slots: Map<String, Any?>? = null): Map<String, Any?> {
        val id = "n${counter + 1}"
        val node = Issue.obj("id" to id, "verb" to verb, "resource" to resource, "params_digest" to Pca.paramsDigest(params))
        return build(Issue.commitPlan(listOf(node)), id, params, slots)
    }

    /**
     * Delegate a narrower authority to a sub-agent. The child hop is signed by this agent; the returned Agent signs with [child]
     * (its counter starts at 0) over the extended chain.
     */
    fun delegate(child: Keys.SuiteKey, addedCaveats: List<Any?> = emptyList()): Agent {
        val childId = requireNotNull(child.ed) { "a delegate holder needs an Ed25519 identity" }.id()
        val hop = Issue.delegate(Pca.asMap(chain.last()), childId, addedCaveats, signer, child.pqPk())
        return Agent(child, aud, grant, chain + listOf<Any?>(hop), 0L, ttlMs, clock, nonces)
    }

    companion object {
        const val HEADER = "PCA-Action"

        /** The header value for a PCActn. */
        fun header(pcactn: Map<String, Any?>): String = Issue.header(pcactn)

        /** The JSON body `{"pcactn": ...}` that the Atlas `POST /v1/pca/actions` endpoint takes. */
        fun actionsBody(pcactn: Map<String, Any?>): String = Json.canonicalize(linkedMapOf<String, Any?>("pcactn" to pcactn))
    }
}
