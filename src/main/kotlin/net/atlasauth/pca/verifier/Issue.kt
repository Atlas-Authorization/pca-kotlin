package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * The producer side of PCA: everything an agent or an issuer needs to MAKE a proof, with the same wire as the TypeScript
 * reference (`@atlasauth/pca`). Root grants, delegation, plans, PCActns, and the signed artifacts (discharges, narrow blocks,
 * escalation answers, passports, workflow commitments and step receipts, read grants).
 *
 * Values are the verifier's JSON model: `Map<String, Any?>` / `List<Any?>` / `String` / `Boolean` / `Long` / `Int` / `null`;
 * a fractional number is a [Json.Num] (for example `Json.Num("0.5")`). Everything signed passes through the STRICT canonical form,
 * so an out-of-profile value throws instead of producing a proof no verifier would accept.
 */
@Suppress("UNCHECKED_CAST")
object Issue {
    private val RNG = SecureRandom()
    const val DEFAULT_TTL_MS = 20L * 60_000L
    const val ENVELOPE_CAVEAT = "envelope"

    /** The reference default risk policy (the same numbers as `DEFAULT_RISK_POLICY` in the TypeScript package). */
    fun defaultRiskPolicy(): Map<String, Any?> = obj(
        "weights" to obj("alpha" to Json.Num("0.25"), "beta" to Json.Num("0.2"), "gamma" to Json.Num("0.2"), "delta" to Json.Num("0.2"), "epsilon" to Json.Num("0.1"), "zeta" to Json.Num("0.05")),
        "theta1" to Json.Num("0.25"), "theta2" to Json.Num("0.6"), "kappa" to 1L, "lambda" to Json.Num("0.0005"), "rho" to Json.Num("0.5"), "bMax" to 1L,
    )

    /** Ordered map from pairs. */
    fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) r[k] = v
        return r
    }

    /** A deep copy through the strict canonical form (throws on anything out of profile); numbers come back as [Json.Num]. */
    fun <T> norm(v: T): T = Json.parse(Json.canonicalizeStrict(v)) as T

    fun randomB64u(n: Int): String = Pca.b64(ByteArray(n).also { RNG.nextBytes(it) })

    private fun utf8(s: String): ByteArray = s.toByteArray(StandardCharsets.UTF_8)

    // ---- capability chain ----------------------------------------------------------------------------------------

    private fun seal(issuer: String, holder: String, caveats: List<Any?>, parent: String?, holderPq: String?, signer: Keys.SuiteKey): LinkedHashMap<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        body["issuer"] = issuer
        body["holder"] = holder
        body["caveats"] = caveats
        body["parent"] = parent
        if (holderPq != null) body["holder_pq"] = holderPq
        val pqPk = signer.pqPk()
        if (signer.alg != "ed25519") {
            body["alg"] = signer.alg
            body["pq_pk"] = pqPk
        }
        val digest = Pca.hashCanonical(body)
        val sg = signer.sign(Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32)!!))
        val cap = LinkedHashMap<String, Any?>()
        cap["id"] = digest
        cap["issuer"] = issuer
        cap["holder"] = holder
        cap["caveats"] = caveats
        cap["body_digest"] = digest
        cap["sig"] = sg.first
        if (parent != null) cap["parent"] = parent
        if (holderPq != null) cap["holder_pq"] = holderPq
        if (signer.alg != "ed25519") {
            cap["alg"] = signer.alg
            cap["pq_pk"] = pqPk
            if (sg.second != null) cap["pq_sig"] = sg.second
        }
        return cap
    }

    private fun commitment(holderPqPk: String?): String? = holderPqPk?.let { Pca.holderPqCommitment(it) }

    /**
     * A root capability signed by the principal. [holderPqPk] (b64u, optional) is the holder's post-quantum public key, committed into
     * the body as `holder_pq`: required for a hybrid / pure-PQ agent.
     */
    fun mintRoot(principal: Keys.SuiteKey, holder: String, holderPqPk: String?, caveats: List<Any?>): Map<String, Any?> {
        val ed = requireNotNull(principal.ed) { "a root issuer needs an Ed25519 identity" }
        return seal(ed.id(), holder, norm(caveats), null, commitment(holderPqPk), principal)
    }

    class Grant(val grant: Map<String, Any?>, val goalCommit: String, val goalSalt: String)

    /** The salted goal commitment: `b64u(sha256(canonical({d, goal, salt})))`. */
    fun goalCommit(goal: String, salt: String): String = Pca.hashCanonical(obj("d" to Pca.INTENT_GOAL_COMMIT_DOMAIN, "goal" to goal, "salt" to salt))

    /**
     * A root intent grant: a root capability whose first caveat is the `envelope`. [envelope] needs `predicates`, `caveats` and
     * `risk_policy`; `agent_binding` defaults to `{}` and `objective_risk`, `progress`, `units`, `tighten`, `model_polarity`,
     * `template_ref` and `actions` (action-definition pins) pass through. Only the salted hash of [goal] goes in the grant. For an
     * approved goal use `goal = Pca.intentGoalV3(ref)`.
     */
    fun mintGrant(principal: Keys.SuiteKey, holder: String, holderPqPk: String?, envelope: Map<String, Any?>, goal: String, salt: String? = null): Grant {
        require(goal.isNotEmpty()) { "mintGrant: goal required" }
        for (k in listOf("predicates", "caveats", "risk_policy")) requireNotNull(envelope[k]) { "mintGrant: envelope.$k is required" }
        val s = salt ?: randomB64u(16)
        val commit = goalCommit(goal, s)
        val env = LinkedHashMap<String, Any?>()
        env["type"] = ENVELOPE_CAVEAT
        env["goal_commit"] = commit
        for ((k, v) in envelope) if (k != "goal_commit" && k != "type") env[k] = v
        if (!env.containsKey("agent_binding")) env["agent_binding"] = LinkedHashMap<String, Any?>()
        return Grant(mintRoot(principal, holder, holderPqPk, listOf(env)), commit, s)
    }

    /** Child capability: caveats are the parent's followed by [added] (append-only); signed by the parent's holder. */
    fun delegate(parent: Map<String, Any?>, toHolder: String, added: List<Any?>?, signer: Keys.SuiteKey, holderPqPk: String? = null): Map<String, Any?> {
        val cav = ArrayList<Any?>(norm(Pca.asList(parent["caveats"])))
        cav.addAll(norm(added ?: emptyList<Any?>()))
        val hp = if (holderPqPk != null) commitment(holderPqPk) else if (toHolder == parent["holder"]) parent["holder_pq"] as String? else null
        return seal(parent["holder"] as String, toHolder, cav, Pca.capHash(parent), hp, signer)
    }

    /** Like [delegate] with the holder unchanged: only narrows. */
    fun attenuate(parent: Map<String, Any?>, added: List<Any?>, signer: Keys.SuiteKey): Map<String, Any?> = delegate(parent, parent["holder"] as String, added, signer)

    // ---- plans ----------------------------------------------------------------------------------------------------

    private fun build(hs: List<ByteArray>): ByteArray {
        if (hs.size == 1) return hs[0]
        var k = 1
        while (k * 2 < hs.size) k *= 2
        return Pca.nodeHash(build(hs.subList(0, k)), build(hs.subList(k, hs.size)))
    }

    private fun prove(hs: List<ByteArray>, idx: Int, out: MutableList<Any?>) {
        if (hs.size == 1) return
        var k = 1
        while (k * 2 < hs.size) k *= 2
        if (idx < k) {
            prove(hs.subList(0, k), idx, out)
            out.add(obj("side" to "R", "hash" to Pca.b64(build(hs.subList(k, hs.size)))))
        } else {
            prove(hs.subList(k, hs.size), idx - k, out)
            out.add(obj("side" to "L", "hash" to Pca.b64(build(hs.subList(0, k)))))
        }
    }

    class Plan internal constructor(val root: String, val nodes: List<Map<String, Any?>>, private val leaves: List<ByteArray>) {
        fun proofFor(nodeId: String): Map<String, Any?> {
            val idx = nodes.indexOfFirst { it["id"] == nodeId }
            require(idx >= 0) { "commitPlan: unknown node $nodeId" }
            val path = ArrayList<Any?>()
            prove(leaves, idx, path)
            return obj("index" to idx.toLong(), "size" to leaves.size.toLong(), "path" to path)
        }
    }

    /** Plan node: `{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}`. */
    fun commitPlan(nodes: List<Map<String, Any?>>): Plan {
        val ids = HashSet<String>()
        val leaves = ArrayList<ByteArray>()
        for (n in nodes) {
            val id = n["id"] as? String
            require(id != null && ids.add(id)) { "commitPlan: missing or duplicate node id $id" }
            leaves.add(Pca.leafHash(Pca.planLeaf(id, n, Pca.conditionsDigest(n["pre"], n["post"]))))
        }
        require(leaves.isNotEmpty()) { "commitPlan: empty plan" }
        return Plan(Pca.b64(build(leaves)), ArrayList(nodes), leaves)
    }

    // ---- PCActn ---------------------------------------------------------------------------------------------------

    /** Inputs of [buildPCActn]. Only grant, chain, plan, nodeId, counter, signer and aud are required. */
    class ActSpec(
        val grant: Map<String, Any?>,
        val chain: List<Any?>,
        val plan: Plan,
        val nodeId: String,
        val counter: Long,
        val signer: Keys.SuiteKey,
        /** The resource server / Atlas instance this action is FOR. */
        val aud: String,
        val params: Map<String, Any?>? = null,
        val iat: Long? = null,
        val exp: Long? = null,
        val ttlMs: Long? = null,
        val nonce: String? = null,
        /** A number in [0,1] (a [Json.Num] for a fraction): can only RAISE the verifier's risk. */
        val caution: Any? = null,
        val rationaleCommitment: String? = null,
        val toolBinding: String? = null,
        val progressStep: Map<String, Any?>? = null,
        val prohibitionEvidence: Any? = null,
        val intent: Map<String, Any?>? = null,
        val intentSession: Map<String, Any?>? = null,
        val freshAt: Map<String, Any?>? = null,
        val provenance: Map<String, Any?>? = null,
        val attestation: Map<String, Any?>? = null,
        val freshness: Map<String, Any?>? = null,
        val riskClaim: Map<String, Any?>? = null,
    )

    private fun put(m: MutableMap<String, Any?>, k: String, v: Any?) { if (v != null) m[k] = v }

    fun buildPCActn(s: ActSpec): Map<String, Any?> {
        require(s.aud.isNotEmpty()) { "buildPCActn: aud (audience) is required" }
        val node = s.plan.nodes.firstOrNull { it["id"] == s.nodeId } ?: throw IllegalArgumentException("buildPCActn: unknown plan node ${s.nodeId}")
        val digest = Pca.paramsDigest(s.params)
        require(node["params_digest"] == null || node["params_digest"] == digest) { "buildPCActn: params do not match plan node ${s.nodeId}'s params_digest" }
        val iat = s.iat ?: System.currentTimeMillis()
        val exp = s.exp ?: (iat + (s.ttlMs ?: DEFAULT_TTL_MS))
        val body = LinkedHashMap<String, Any?>()
        body["ver"] = Pca.WIRE_VERSION
        body["action"] = obj("verb" to node["verb"], "resource" to node["resource"], "params_digest" to digest, "reversibility_class" to (node["reversibility_class"] ?: Pca.DEFAULT_REV))
        body["grant_ref"] = s.grant["id"]
        body["cap_chain"] = s.chain
        body["plan"] = obj("root" to s.plan.root, "inclusion_proof" to s.plan.proofFor(s.nodeId), "node_id" to s.nodeId, "conditions_digest" to Pca.conditionsDigest(node["pre"], node["post"]))
        body["attestation"] = s.attestation ?: obj("quote_digest" to "", "epoch" to 0L, "model_id" to "unattested", "measurement" to "", "operator" to "unattested")
        body["provenance"] = s.provenance ?: obj("causal_hash" to "", "taint_level" to 0L, "trusted_refs" to ArrayList<Any?>())
        body["freshness"] = s.freshness ?: obj("beacon_ref" to "", "epoch" to 0L, "accumulator_witness" to "")
        body["counter"] = s.counter
        body["risk_claim"] = s.riskClaim ?: obj("r" to 0L, "inputs" to LinkedHashMap<String, Any?>())
        body["aud"] = s.aud
        body["iat"] = iat
        body["exp"] = exp
        put(body, "nonce", s.nonce)
        put(body, "caution", s.caution)
        put(body, "rationale_commitment", s.rationaleCommitment)
        put(body, "progress_step", s.progressStep)
        put(body, "prohibition_evidence", s.prohibitionEvidence)
        put(body, "tool_binding", s.toolBinding)
        put(body, "intent", s.intent)
        put(body, "intent_session", s.intentSession)
        put(body, "fresh_at", s.freshAt)
        if (s.signer.alg != "ed25519") {
            body["alg"] = s.signer.alg
            body["pq_pk"] = s.signer.pqPk()
        }
        val sg = s.signer.sign(Pca.thresholdMessage(body))
        body["sig"] = sg.first
        if (sg.second != null) body["pq_sig"] = sg.second
        return body
    }

    /** The lenient canonical JSON text of a PCActn (what is sent). */
    fun encode(pcactn: Map<String, Any?>): String = Json.canonicalize(pcactn)

    /** The `PCA-Action` header value: the unpadded base64url of the PCActn JSON. */
    fun header(pcactn: Map<String, Any?>): String = Pca.b64(utf8(encode(pcactn)))

    // ---- signed artifacts (discharge, narrow, escalation answer, ...) ---------------------------------------------

    /**
     * Sign an artifact body under a suite: the signature covers `utf8(domain) || strictCanonical(body)` where a non-default suite
     * adds `alg` and `pq_pk` to the SIGNED body; a hybrid also returns `pq_sig`.
     */
    fun signArtifact(domain: String, body: Map<String, Any?>, signer: Keys.SuiteKey): LinkedHashMap<String, Any?> {
        val full = LinkedHashMap<String, Any?>(norm(body))
        if (signer.alg != "ed25519") {
            full["alg"] = signer.alg
            full["pq_pk"] = signer.pqPk()
        }
        val sg = signer.sign(IntentArtifacts.artifactMessage(domain, full))
        full["sig"] = sg.first
        if (sg.second != null) full["pq_sig"] = sg.second
        return full
    }

    private fun checked(what: String, signed: LinkedHashMap<String, Any?>, err: String?): Map<String, Any?> {
        require(err == null) { "$what: $err" }
        return signed
    }

    /** A third-party discharge for a `needs_discharge` caveat. Throws on a malformed body (a signer never emits a weaker artifact). */
    fun signDischarge(body: Map<String, Any?>, issuer: Keys.SuiteKey): Map<String, Any?> {
        val s = signArtifact(CaveatLang.DISCHARGE_DOMAIN, body, issuer)
        return checked("signDischarge", s, CaveatLang.dischargeShapeError(s))
    }

    /**
     * Build and sign a discharge. [bind] is `"chain_hop"` or `"action"` (then [actionDigest] is `CaveatLang.dischargeActionDigest(pcactn)`).
     * [issuerLabel] is the label the caveat names, not a key.
     */
    fun discharge(issuer: Keys.SuiteKey, caveatId: String, issuerLabel: String, hop: Map<String, Any?>, bind: String, actionDigest: String?, claims: Map<String, Any?>?, iat: Long, notAfter: Long): Map<String, Any?> {
        val b = obj("v" to 1L, "kind" to "pca-discharge", "caveat_id" to caveatId, "issuer" to issuerLabel, "cap_hash" to Pca.capHash(hop), "bind" to bind,
            "claims" to (claims ?: LinkedHashMap<String, Any?>()), "iat" to iat, "not_after" to notAfter, "nonce" to randomB64u(16))
        if (bind == "action") b["action_digest"] = actionDigest
        return signDischarge(b, issuer)
    }

    /** A holder-signed per-action self-attenuation that rides beside the PCActn (no new hop). */
    fun signNarrow(body: Map<String, Any?>, holder: Keys.SuiteKey): Map<String, Any?> {
        val s = signArtifact(CaveatLang.NARROW_DOMAIN, body, holder)
        return checked("signNarrow", s, CaveatLang.narrowShapeError(s))
    }

    fun narrow(holder: Keys.SuiteKey, leafHop: Map<String, Any?>, caveats: List<Any?>, actionDigest: String?, iat: Long, notAfter: Long): Map<String, Any?> {
        val b = obj("v" to 1L, "kind" to "pca-narrow", "cap_hash" to Pca.capHash(leafHop), "holder" to holder.ed!!.id(), "caveats" to caveats,
            "iat" to iat, "not_after" to notAfter, "nonce" to randomB64u(16))
        if (actionDigest != null) b["action_digest"] = actionDigest
        return signNarrow(b, holder)
    }

    /** The principal's signed answer to an escalation. Throws on a malformed body. */
    fun signEscalationAnswer(body: Map<String, Any?>, principal: Keys.SuiteKey): Map<String, Any?> {
        val s = signArtifact(Escalation.ANSWER_DOMAIN, body, principal)
        return checked("signEscalationAnswer", s, Escalation.answerShapeError(s))
    }

    /**
     * Answer an escalation: bound to exactly this grant (policy), this PCActn (action) and this history head. [renderDigest] (optional)
     * is the digest of the canonical approval render the principal saw.
     */
    fun escalationAnswer(principal: Keys.SuiteKey, grant: Map<String, Any?>, pcactn: Map<String, Any?>, lastCounter: Long?, allow: Boolean, iat: Long, expiresAt: Long, renderDigest: String? = null): Map<String, Any?> {
        val b = obj("v" to 1L, "kind" to "pca-escalation-answer", "principal" to principal.ed!!.id(), "policy_digest" to Escalation.policyDigest(grant),
            "action_digest" to Escalation.actionDigest(pcactn), "history_head" to Escalation.historyHead(lastCounter), "decision" to (if (allow) "allow" else "deny"),
            "iat" to iat, "expires_at" to expiresAt, "nonce" to randomB64u(16))
        if (renderDigest != null) b["render_digest"] = renderDigest
        return signEscalationAnswer(b, principal)
    }

    // ---- Ed25519 body signatures (workflow, receipts, read grants) ------------------------------------------------

    /** `b64u(Ed25519(domain || strictCanonical(body)))`. */
    fun signBody(key: Keys.EdKey, domain: String, body: Any?): String = Pca.b64(key.sign(Pca.concat(utf8(domain), utf8(Json.canonicalizeStrict(body)))))

    /** Sign a workflow commitment: `{body, sig}`. Throws on a malformed body, a cycle, or a body naming another principal. */
    fun signWorkflow(principal: Keys.EdKey, body: Map<String, Any?>): Map<String, Any?> {
        val b = norm(body)
        require(Workflow.validWorkflowBody(b) && Workflow.dagError(b) == null) { "signWorkflow: malformed workflow" }
        require(b["principal"] == principal.id()) { "signWorkflow: principal is not the signer" }
        return obj("body" to b, "sig" to signBody(principal, Workflow.WORKFLOW_DOMAIN, b))
    }

    /** Sign a step receipt (resource server). [prev] is the previous receipt of the same workflow, null for the first. */
    fun signStepReceipt(rs: Keys.EdKey, workflow: Map<String, Any?>, step: String, outcome: String, paramsDigest: String, outputs: Map<String, Any?>, issuedAt: Long, prev: Map<String, Any?>?): Map<String, Any?> {
        val base = obj("v" to 1L, "wf" to Workflow.workflowDigest(workflow), "step" to step, "seq" to (if (prev == null) 0L else Json.asLong(prev["seq"]) + 1),
            "prev" to (if (prev == null) null else Workflow.receiptRef(prev)), "outcome" to outcome, "params_digest" to paramsDigest, "outputs" to outputs,
            "issued_at" to issuedAt, "signer" to rs.id())
        val n = norm(base)
        n["sig"] = signBody(rs, Workflow.WF_RECEIPT_DOMAIN, n)
        return n
    }

    /** A receipt output for a scalar [value]; [num] is carried only for integers an edge may compare. */
    fun wfOutput(value: Any?, labels: List<String> = emptyList(), unit: String? = null, num: Boolean = false): Map<String, Any?> =
        obj("digest" to Workflow.valueDigest(value), "num" to (if (num && value is Number) value else null), "unit" to unit, "labels" to ArrayList<Any?>(labels.sorted()))

    /** Sign a read grant: `{body, sig}`. */
    fun signReadGrant(principal: Keys.EdKey, body: Map<String, Any?>): Map<String, Any?> {
        val b = norm(body)
        require(ReadSide.validReadGrantBody(b) && b["principal"] == principal.id()) { "signReadGrant: malformed grant" }
        return obj("body" to b, "sig" to signBody(principal, ReadSide.READ_GRANT_DOMAIN, b))
    }

    // ---- passports ------------------------------------------------------------------------------------------------

    /** Content fingerprint over a passport's identity fields (its `id`). */
    fun passportFingerprint(p: Map<String, Any?>): String = Pca.hashCanonical(obj("d" to "atlas-pca/passport/v1", "model_id" to p["model_id"], "weights_digest" to p["weights_digest"],
        "system_prompt_digest" to p["system_prompt_digest"], "tool_manifest_digest" to p["tool_manifest_digest"], "runtime_measurement" to p["runtime_measurement"],
        "operator" to p["operator"], "hardware_rooted" to p["hardware_rooted"]))

    /** Fill `id` from the fingerprint of the identity fields. */
    fun issuePassport(identity: Map<String, Any?>): Map<String, Any?> = LinkedHashMap(identity).also { it["id"] = passportFingerprint(identity) }

    /** Sign a passport for [subject] (the agent's Ed25519 key id). [evidence] is required for a hardware-rooted passport. */
    fun signPassport(passport: Map<String, Any?>, issuer: Keys.SuiteKey, subject: String, iat: Long, nbf: Long? = null, exp: Long, evidence: Map<String, Any?>? = null): Map<String, Any?> {
        require(passport["id"] == passportFingerprint(passport)) { "signPassport: passport.id is not the fingerprint of its identity (use issuePassport)" }
        require(passport["hardware_rooted"] != true || evidence != null) { "signPassport: hardware_rooted requires attestation evidence (fail closed)" }
        val nb = nbf ?: iat
        require(exp > nb) { "signPassport: exp must be after nbf" }
        val body = LinkedHashMap<String, Any?>()
        body["typ"] = "atlas-pca/passport"
        body["ver"] = 1L
        body["passport"] = passport
        body["iss"] = issuer.ed!!.id()
        body["sub"] = subject
        body["iat"] = iat
        body["nbf"] = nb
        body["exp"] = exp
        if (evidence != null) body["evidence"] = LinkedHashMap(evidence).also { if (!it.containsKey("at")) it["at"] = iat }
        if (issuer.alg != "ed25519") {
            body["alg"] = issuer.alg
            body["pq_pk"] = issuer.pqPk()
        }
        val n = norm(body)
        val sg = issuer.sign(Pca.concat(utf8(Passport.SIG_DOMAIN), utf8(Json.canonicalizeStrict(n))))
        n["sig"] = sg.first
        if (sg.second != null) n["pq_sig"] = sg.second
        return n
    }

    // ---- fresh_at token and aggregate grant -----------------------------------------------------------------------

    /** A signed consistency token (`fresh_at`) from the resource server. [state] holds revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest. */
    fun signFreshAt(rs: Keys.EdKey, scope: String, state: Map<String, Any?>, issuedAt: Long): Map<String, Any?> {
        val b = obj("v" to 1L, "scope" to scope)
        for (k in listOf("revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest")) b[k] = state[k]
        b["issued_at"] = issuedAt
        b["signer"] = rs.id()
        val n = norm(b)
        n["sig"] = signBody(rs, FreshAt.DOMAIN, n)
        return n
    }

    /** Sign an aggregate (differential-privacy) read grant: `{body, sig}`. */
    fun signAggregateGrant(principal: Keys.EdKey, body: Map<String, Any?>): Map<String, Any?> {
        val b = norm(body)
        require(ReadVault.validAggregateGrantBody(b) && b["principal"] == principal.id()) { "signAggregateGrant: malformed grant" }
        return obj("body" to b, "sig" to signBody(principal, ReadVault.AGGREGATE_DOMAIN, b))
    }
}
