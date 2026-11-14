package net.atlasauth.pca.verifier

/**
 * Runs one case of the shared producer vectors (the conformance files `producer-vectors.json` and `producer-pq-vectors.json`) through
 * this SDK's producers and returns the artifact in the shape of the case's `expect`. A refusal throws (its message is the reference's);
 * an op this SDK does not produce throws `unsupported_op: <op>` and a suite it cannot sign throws `unsupported_suite: <alg>`. Shared by
 * the producer tests and the cross-language driver, so both run exactly the same code.
 *
 * [keys]: name to `{seed, public}` (Ed25519); [pqKeys]: name to `{family, seed}`.
 */
@Suppress("UNCHECKED_CAST")
internal class ProducerOps(keys: Map<String, Any?>?, pqKeys: Map<String, Any?>?) {
    private val keys: Map<String, Any?> = keys ?: emptyMap()
    private val pqKeys: Map<String, Any?> = pqKeys ?: emptyMap()
    private val pqCache = HashMap<String, Keys.PqKey>()

    private fun m(o: Any?): Map<String, Any?> = Pca.asMap(o)
    private fun l(o: Any?): List<Any?> = Pca.asList(o)
    private fun s(o: Any?): String = o as String
    private fun n(o: Any?): Long = Json.asLong(o)
    private fun mOrNull(a: Map<String, Any?>, k: String): Map<String, Any?>? = a[k]?.let { m(it) }
    private fun b64(v: Any?): ByteArray = Pca.decodeB64uStrict(v, -1) ?: throw IllegalArgumentException("not canonical base64url")

    fun ed(name: Any?): Keys.EdKey {
        val e = keys[name as String] ?: throw IllegalArgumentException("unknown key '$name'")
        return Keys.edFromSeed(b64(m(e)["seed"]))
    }

    private fun edSuite(name: Any?): Keys.SuiteKey = Keys.ed25519(ed(name))

    fun pq(name: Any?): Keys.PqKey? {
        if (name == null) return null
        return pqCache.getOrPut(name as String) {
            val e = pqKeys[name] ?: throw IllegalArgumentException("unknown post-quantum key '$name'")
            Keys.pqFromSeed(prim(m(e)["family"] as String), b64(m(e)["seed"]))
        }
    }

    /** The suite key of a PQ-vector case: `alg` with the named Ed25519 key (when given) and PQ key (when given). */
    private fun suite(a: Map<String, Any?>, edMember: String): Keys.SuiteKey {
        val alg = a["alg"] as String?
        if (alg == null || alg == "ed25519") return edSuite(a[edMember])
        Pq.resolveSigAlg(alg, true) ?: throw IllegalArgumentException(Pq.refusal(alg))
        return Keys.suite(alg, a[edMember]?.let { ed(it) }, pq(a["pq"]))
    }

    /** Run [op] on [a]. */
    fun run(op: String, a: Map<String, Any?>): Any? = when (op) {
        // ---- producer-vectors.json (Ed25519) ---------------------------------------------------------------------------------
        "ed25519_sign" -> {
            val k = Keys.edFromSeed(b64(a["seed"]))
            Issue.obj("public" to k.id(), "sig" to Pca.b64(k.sign(s(a["message_utf8"]).toByteArray(Charsets.UTF_8))))
        }
        "goal_commit" -> Issue.obj("commit" to Issue.goalCommit(s(a["goal"]), s(a["salt"])))
        "params_digest" -> Issue.obj("digest" to Pca.paramsDigest(a["params"]))
        "plan_commit" -> {
            val nodes = l(a["nodes"]).map { m(it) }
            val p = Issue.commitPlan(nodes)
            val proofs = LinkedHashMap<String, Any?>()
            for (x in nodes) proofs[s(x["id"])] = p.proofFor(s(x["id"]))
            Issue.obj("root" to p.root, "proofs" to proofs)
        }
        "mint_grant" -> {
            val g = Issue.mintGrant(edSuite(a["principal"]), ed(a["holder"]).id(), null, m(a["envelope"]), s(a["goal"]), a["salt"] as String?)
            Issue.obj("grant" to g.grant, "goal_commit" to g.goalCommit, "goal_salt" to g.goalSalt)
        }
        "delegate" -> {
            val parent = m(a["parent"])
            val to = if (a["to_holder"] == null) s(parent["holder"]) else ed(a["to_holder"]).id()
            Issue.delegate(parent, to, l(a["added_caveats"]), edSuite(a["signer"]))
        }
        "act" -> {
            val p = Issue.buildPCActn(
                Issue.ActSpec(
                    grant = m(a["grant"]), chain = l(a["chain"]), plan = Issue.commitPlan(l(a["plan"]).map { m(it) }), nodeId = s(a["node_id"]),
                    counter = n(a["counter"]), signer = edSuite(a["signer"]), aud = s(a["aud"]), params = mOrNull(a, "params"),
                    iat = n(a["iat"]), exp = n(a["exp"]), nonce = a["nonce"] as String?, caution = a["caution"],
                    rationaleCommitment = a["rationale_commitment"] as String?, toolBinding = a["tool_binding"] as String?, freshAt = mOrNull(a, "fresh_at"),
                ),
            )
            Issue.obj("pcactn" to p, "threshold_message" to Pca.b64(Pca.thresholdMessage(p)), "header" to Issue.header(p))
        }
        "fresh_at" -> Issue.signFreshAt(ed(a["signer"]), s(a["scope"]), m(a["state"]), n(a["issued_at"]))
        "escalation_digests" -> Issue.obj(
            "policy_digest" to Escalation.policyDigest(a["grant"]), "action_digest" to Escalation.actionDigest(a["pcactn"]),
            "history_head" to Escalation.historyHead(a["last_counter"]?.let { n(it) }),
        )
        "sign_escalation_answer" -> Issue.signEscalationAnswer(m(a["body"]), edSuite(a["signer"]))
        "sign_discharge" -> Issue.signDischarge(m(a["body"]), edSuite(a["signer"]))
        "discharge_digest" -> Issue.obj("digest" to CaveatLang.dischargeDigest(a["discharge"]))
        "sign_narrow" -> Issue.signNarrow(m(a["body"]), edSuite(a["signer"]))
        "sign_passport" -> {
            val pp = Issue.issuePassport(m(a["identity"]))
            val signed = Issue.signPassport(pp, edSuite(a["issuer"]), ed(a["subject"]).id(), n(m(a["identity"])["issued_at"]), null, n(a["exp"]))
            Issue.obj("passport" to pp, "signed" to signed)
        }
        "sign_workflow" -> Issue.signWorkflow(ed(a["signer"]), m(a["body"]))
        "sign_step_receipt" -> Issue.signStepReceipt(
            ed(a["signer"]), m(a["workflow"]), s(a["step"]), s(a["outcome"]), s(a["params_digest"]), m(a["outputs"]), n(a["issued_at"]), mOrNull(a, "prev"),
        )
        "sign_read_grant" -> Issue.signReadGrant(ed(a["signer"]), m(a["body"]))
        "sign_aggregate_grant" -> Issue.signAggregateGrant(ed(a["signer"]), m(a["body"]))
        "sign_revocation_epoch" -> SignersMore.signRevocationEpoch(edSuite(a["signer"]), m(a["body"]))
        "sign_undo_token" -> Undo.signToken(m(a["record"]), ed(a["signer"]).seed)
        "sign_undo_receipt" -> Undo.signReceipt(m(a["body"]), ed(a["signer"]).seed)
        "sign_contract" -> Contracts.signContract(m(a["contract"]), ed(a["signer"]).seed)
        "sign_contract_reset" -> Issue.obj("sig" to ContractEnforcer.signReset(ed(a["signer"]).seed, s(a["contract_id"]), n(a["seq"])))
        "sign_constitution" -> SignersMore.signConstitution(m(a["constitution"]), ed(a["signer"]))
        "sign_safety_evidence" -> ed(a["signer"]).let { k -> Prohibitions.signSafetyEvidence(a["evidence"], k.seed, k.id()) }
        "sign_threshold_share" -> SignersMore.signThresholdShare(s(a["role"]), edSuite(a["signer"]), b64(a["message"]), a["signer_set"] as List<Any?>?, n(a["t"]).toInt())
        "sign_prepared_share" -> SignersMore.signPreparedShare(s(a["role"]), edSuite(a["signer"]), b64(a["prepared"]))
        "sign_pq_binding" -> SignersMore.signPqBinding(ed(a["signer"]), s(a["pq_pk"]), n(a["epoch"]), a["aud"] as String?)
        "sign_caution" -> SignersMore.signCaution(m(a["body"]), ed(a["signer"]))
        "sign_heartbeat" -> SignersMore.signHeartbeat(m(a["body"]), ed(a["signer"]))
        "prov_recorder" -> provRecorder(a)
        "sign_mesh_action" -> Issue.obj("sig" to SignersMore.signMeshAction(l(a["chain"]), m(a["action"]), ed(a["signer"])))
        "sign_session_root" -> SignersMore.signSessionRoot(m(a["body"]), edSuite(a["signer"]))
        "mint_session_grant" -> {
            val g = SignersMore.mintSessionGrant(edSuite(a["principal"]), ed(a["holder"]).id(), s(a["session"]), n(a["seq"]), s(a["root"]), a["prev"] as String?,
                s(a["map_digest"]), a["map_form"] as String?, l(a["predicates"]), a["caveats"]?.let { l(it) }, salt = a["salt"] as String?)
            Issue.obj("grant" to g.grant, "goal_salt" to g.goalSalt)
        }
        "sign_intent_required" -> SignersMore.signIntentRequired(m(a["body"]), s(a["kid"]), edSuite(a["signer"]))
        "sign_action_schema" -> SignersMore.signActionSchema(m(a["doc"]), s(a["kid"]), edSuite(a["signer"]))
        "sign_labels" -> SignersMore.signLabels(m(a["body"]), edSuite(a["signer"]))
        "sign_fact" -> SignersMore.signFact(m(a["body"]), edSuite(a["signer"]))
        "sign_offer_set" -> SignersMore.signOfferSet(m(a["body"]), edSuite(a["signer"]))
        "sign_progress_step" -> SignersMore.signProgressStep(m(a["step"]), ed(a["signer"]))
        "sign_read_receipt" -> SignersMore.signReadReceipt(
            ed(a["signer"]), m(a["grant"]), s(a["verb"]), s(a["resource"]), s(a["purpose"]), m(a["fields"]), l(a["labels"]), n(a["issued_at"]), mOrNull(a, "prev"),
        )
        "sign_template" -> SignersMore.signTemplate(m(a["def"]), ed(a["signer"]))
        "sign_tighten" -> SignersMore.signTighten(m(a["overlay"]), ed(a["signer"]))
        "parse_limit" -> Facade.parseLimit(a["limit"]).toJson()
        "compile_policy" -> Facade.compilePolicy(m(a["permissions"]), mOrNull(a, "limits"), null, a["budget_model"] as String?, null, n(a["now"])).toJson()
        "facade_act" -> facadeAct(a)
        // ---- producer-pq-vectors.json (every suite) --------------------------------------------------------------------------
        "pq_keygen" -> Issue.obj("public" to Keys.pqFromSeed(prim(s(a["family"])), b64(a["seed"])).pkB64u())
        "suite_sign" -> {
            val sg = suite(a, "ed").sign(s(a["message_utf8"]).toByteArray(Charsets.UTF_8))
            val o = Issue.obj("sig" to sg.first)
            if (sg.second != null) o["pq_sig"] = sg.second
            o
        }
        "mint_root_suite" -> Issue.mintRoot(suite(a, "principal"), ed(a["holder"]).id(), pq(a["holder_pq"])?.pkB64u(), l(a["caveats"]))
        "delegate_suite" -> {
            val parent = m(a["parent"])
            val to = if (a["to_holder"] == null) s(parent["holder"]) else ed(a["to_holder"]).id()
            Issue.delegate(parent, to, l(a["added_caveats"]), suite(a, "signer"), pq(a["holder_pq"])?.pkB64u())
        }
        "sign_pcactn_suite" -> Issue.obj("pcactn" to Issue.signPCActn(m(a["body"]), suite(a, "signer")))
        "sign_artifact_suite" -> {
            val k = suite(a, "signer")
            when (a["kind"]) {
                "escalation_answer" -> Issue.signEscalationAnswer(m(a["body"]), k)
                "revocation_epoch" -> SignersMore.signRevocationEpoch(k, m(a["body"]))
                else -> throw IllegalArgumentException("unsupported_op: sign_artifact_suite/${a["kind"]}")
            }
        }
        else -> throw IllegalArgumentException("unsupported_op: $op")
    }

    private fun provRecorder(a: Map<String, Any?>): Map<String, Any?> {
        val clock = l(a["clock"]).iterator()
        val r = ArgProvenance.Recorder(s(a["mediator"]), s(a["kid"]), edSuite(a["key"]), s(a["session"])) { n(clock.next()) }
        val outs = ArrayList<Any?>()
        for (stO in l(a["steps"])) {
            val st = m(stO)
            outs.add(
                when (st["kind"]) {
                    "principal" -> r.principal(s(st["text"]))
                    "tool" -> r.tool(s(st["name"]), st["output"])
                    "web" -> r.web(s(st["url"]), st["content"])
                    "retrieval" -> r.retrieval(s(st["source"]), st["content"])
                    else -> m(st["op"]).let { op -> r.forAction(Authorize.Operation(s(op["verb"]), s(op["resource"]), m(op["params"]))) }
                },
            )
        }
        return Issue.obj("pin" to LinkedHashMap(r.pin), "receipts" to ArrayList(outs.subList(0, outs.size - 1)), "bundle" to outs.last())
    }

    private fun facadeAct(a: Map<String, Any?>): Map<String, Any?> {
        val now = n(a["now"])
        val rec = ArgProvenance.Recorder("agent-harness", "k1", edSuite(a["recorder_key"]), s(a["session"])) { now }
        val base = Agent.fromPrincipal(
            Facade.AgentOptions(edSuite(a["principal"]), s(a["goal"]), m(a["permissions"]), limits = mOrNull(a, "limits"), holder = edSuite(a["holder"]),
                aud = a["aud"] as String?, now = now, goalSalt = a["goal_salt"] as String?, provenance = rec),
        )
        a["principal_messages"]?.let { msgs -> for (t in l(msgs)) base.provenance.principal(s(t)) }
        val h = a["sub_agent"]?.let { m(it) }?.let { sa -> base.subAgent(edSuite(sa["holder"]), l(sa["added_caveats"])) } ?: base
        val act = m(a["act"])
        val r = h.act(s(act["verb"]), s(act["resource"]), mOrNull(act, "params"),
            Facade.ActOptions(counter = act["counter"]?.let { n(it) }, now = act["now"]?.let { n(it) }, nonce = act["nonce"] as String?))
        return Issue.obj("grant" to base.grant, "goal_commit" to m(l(base.grant["caveats"])[0])["goal_commit"], "chain" to h.chain, "pcactn" to r.pcactn,
            "encoded" to r.encoded, "provenance" to r.provenance)
    }

    companion object {
        /** The wire's lower-case family name as this SDK's primitive; a family it cannot sign is `unsupported_suite`. */
        fun prim(family: String): Pq.Prim = when (family) {
            "ml-dsa-65" -> Pq.Prim.ML_DSA_65
            "ml-dsa-87" -> Pq.Prim.ML_DSA_87
            "slh-dsa-sha2-128f" -> Pq.Prim.SLH_DSA_SHA2_128F
            "slh-dsa-sha2-256s" -> Pq.Prim.SLH_DSA_SHA2_256S
            else -> throw IllegalArgumentException("${Pq.UNSUPPORTED_SUITE}: $family")
        }
    }
}
