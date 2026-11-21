package net.atlasauth.pca.verifier

/**
 * The resource-server verifier with the full option set (the reference's `verifyPCActn(pcactn, opts)`): stateless, deterministic,
 * offline and total. One call returns the whole verdict: `allow`, the recomputed risk `r`, the `requiredThreshold`, every check (`pass`,
 * `fail`, `not-enforced`, `unsupported`), the ordered reasons, the budget after the decision and, on request, the per-check assurance.
 *
 * The core checks come from [PcaCore.verify]; this layer adds the checks that need the server's own context: `grant_ref`, `operation`,
 * `params_digest`, `plan_root_authorized` (from the server's plan), `freshness` (a guardian-signed revocation epoch), `beacon` (the dead-man
 * liveness beacon), `risk_inputs`, `reversibility`, `delegated_caveats`, `policy` (the Policy VM), `threshold` (a step-up needs an enforced
 * threshold hook that reported at least the SERVER-derived t), the optional `assurance` requirement, then default-deny of the `require` list.
 *
 * Not offered: the reference's legacy `allowUnboundPq` (a post-quantum signer is always checked against its `holder_pq` commitment).
 * Never throws: any internal error is a fail-closed verdict (`malformed`).
 */
@Suppress("UNCHECKED_CAST")
object ServerVerify {
    /** The minimum enforcement profile a resource server should demand: every named check must be `pass`. */
    val DEFAULT_REQUIRED_CHECKS: List<String> = listOf("counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")

    /** The profile of a stateful server: the stateless profile plus `replay`. */
    val STATEFUL_REQUIRED_CHECKS: List<String> = Authorize.STATEFUL_REQUIRED_CHECKS

    private val UNSUPPORTED_SUFFIX = "unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)"

    /**
     * What the verifier is given. [grant] is the verifier's OWN stored grant (a parsed object); [context] is the server's context as a
     * parsed object: `params`, `subject`, `env`, `plan` (the principal-authorized nodes), `planAuthorized`, `reversibilityClass`, `risk`
     * (`semanticDistance, reversibility, blastRadius, taint, confidence, age`), `budget` (`{B, tau, asOf}`), `recentActionTimes`,
     * `revocationEpoch` (`{epoch, guardianPublic, lastAcceptedEpoch?, maxAgeMs?}`) and `beacon` (`{beacon, issuers, instance, pqPins?,
     * lastAcceptedSeq?}`). [operation] is a parsed `{verb, resource, params?}` (null = none given).
     */
    class Options(var grant: Any?) {
        var audience: Pca.Audience = Pca.Audience.Unset
        var hooks: PcaCore.Hooks? = null
        var nowEpoch: Long? = null
        var context: Map<String, Any?>? = null
        var require: List<String>? = null
        var allowedSuites: List<String>? = null
        var pqPins: Map<String, Any?>? = null
        var operation: Map<String, Any?>? = null
        var insecureSkipPlanRootCheck = false
        var intentPolicy: Pca.IntentPolicy? = null
        var intentV2: IntentV2.Context? = null
        var freshAt: FreshAt.Policy? = null
        var enforce: PcaCore.Enforce? = null
        var requireRiskInputs: List<String>? = null
        var assurance = false
        var requireAssurance: Map<String, Any?>? = null
        var allowUnsupported: List<String>? = null
        var k1: CaveatLang.K1Input? = null
    }

    class Verdict internal constructor(
        var allow: Boolean,
        val r: Double,
        val requiredThreshold: Map<String, Any?>,
        var checks: Map<String, String>,
        var reasons: List<String>,
        var budget: Map<String, Any?>? = null,
    ) {
        var assurance: Map<String, Map<String, Any?>>? = null
        var k1Bound: List<CaveatLang.BoundCaveat>? = null
    }

    private val WORST = linkedMapOf<String, Any?>("t" to 3, "proof" to "strong", "optimisticAllowed" to false)

    private fun failClosed(reason: String, checks: Map<String, String> = emptyMap()): Verdict {
        val c = LinkedHashMap(checks)
        c["malformed"] = "fail"
        return Verdict(false, 1.0, WORST, c, listOf(reason))
    }

    /** The reference's verdict combinator state: the check map and the ordered reasons. */
    private class Vs(checks: Map<String, String>, reasons: List<String>) {
        val checks = LinkedHashMap(checks)
        val reasons = ArrayList(reasons)
        fun get(n: String): String? = checks[n]
        fun set(n: String, s: String) { checks[n] = s }
        fun fail(n: String, why: String) { checks[n] = "fail"; reasons.add(why) }
    }

    @JvmStatic
    fun verify(pcactn: Any?, o: Options): Verdict {
        val v = verifyChecks(pcactn, o)
        // a verdict that stopped before the checks ran still reports its outcomes when asked
        if ((o.assurance || o.requireAssurance != null) && v.assurance == null) v.assurance = Assurance.report(null, v.checks, null, emptyMap())
        return v
    }

    private fun js(v: Any?, present: Boolean = true): String = if (!present) "undefined" else ZkJs.string(IntentJs.normalize(v))

    private fun isObj(v: Any?): Boolean = v is Map<*, *> || v is List<*>

    private fun verifyChecks(pcactn: Any?, o: Options): Verdict = try {
        verifyUnchecked(pcactn, o)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        failClosed("verifier error (fail closed): ${e.message ?: "unknown"}")
    }

    private fun verifyUnchecked(pcactn: Any?, o: Options): Verdict {
        val p0: Any?
        if (pcactn is String) {
            if (Pca.artifactTooLarge(pcactn)) return failClosed("undecodable PCActn: ${Pca.ARTIFACT_SIZE_REASON}")
            p0 = try {
                Json.parse(pcactn)
            } catch (e: RuntimeException) {
                return failClosed("undecodable PCActn: strict JSON: ${e.message}")
            }
            if (p0 !is Map<*, *>) return failClosed("undecodable PCActn: decodePCActn: not an object")
        } else p0 = pcactn
        if (!isObj(p0)) return failClosed("PCActn is not an object")

        val now = o.nowEpoch ?: System.currentTimeMillis()
        val grantO = o.grant
        val ctxIn: Map<String, Any?> = o.context ?: emptyMap()
        val op = o.operation
        val opHasParams = op != null && op.containsKey("params") && op["params"] != null
        val ctxHasParams = ctxIn.containsKey("params") // supplied params, even null, are a value (the reference tests for undefined)
        val ctx: Map<String, Any?> = if (opHasParams) LinkedHashMap(ctxIn).also { it["params"] = op!!["params"] } else ctxIn
        fun chas(k: String): Boolean = ctx.containsKey(k) && ctx[k] != null

        // F-1: remember the threshold the hook says it enforced, so it can be compared with the SERVER-derived t below
        var hookT: Double? = null
        val userHooks = o.hooks
        val userThreshold = userHooks?.threshold
        val hooks: PcaCore.Hooks? = if (userThreshold == null) userHooks else PcaCore.Hooks(
            userHooks!!.attestation,
            PcaCore.Hook { c -> userThreshold.run(c).also { r -> if (r.enforced) hookT = r.t } },
            userHooks.revocation, userHooks.zk,
        )

        // Rules 20 and 21 read the signed envelope of the stored grant: when it carries any, the v2 pipeline needs the plaintext params
        // and the host env even if the host configured no v2 context.
        val grantEnv = Authorize.readEnvelope(grantO)
        val needsModelRules = grantEnv != null && (grantEnv.containsKey("actions") || grantEnv.containsKey("units") || grantEnv.containsKey("tighten") ||
            grantEnv.containsKey("model_polarity") || PcaDecision.modelPathsRead(listOf(grantEnv["predicates"])).isNotEmpty())
        var v2: IntentV2.Context? = o.intentV2
        if (v2 == null && needsModelRules) v2 = IntentV2.Context.fromJson(LinkedHashMap<String, Any?>())
        if (v2 != null && v2.wellFormed) {
            if (v2.get("params") == null && ctx["params"] != null) v2 = v2.withParams(ctx["params"])
            if (v2.get("env") == null) v2 = if (ctx["env"] != null) v2.withEnv(ctx["env"]) else v2.withoutEnv()
        }
        val pm = Pca.asMap(p0)
        val grant = grantO as? Map<String, Any?>
        val v2d: IntentV2.Decision? =
            if (pm.containsKey("intent_session") || needsModelRules) IntentV2.decide(pm, grant, v2, now) else null

        val core = PcaCore.verify(
            p0,
            PcaCore.Options(grant ?: LinkedHashMap()).also {
                it.insecureSkipPlanRootCheck = true
                it.nowEpoch = now
                it.audience = o.audience
                it.hooks = hooks
                it.allowedSuites = o.allowedSuites
                it.intentPolicy = o.intentPolicy
                it.intentV2 = v2
                it.freshAt = o.freshAt
                it.enforce = o.enforce
                it.authorizedPlanRoots = null
            },
        )
        // A wire-form failure is terminal (normative): nothing else is evaluated on a malformed object.
        if (core.checks["wire"] == PcaCore.FAIL) return failClosed(core.reason ?: "wire: malformed PCActn", mapOf("wire" to "fail"))
        if (grant == null) throw IllegalStateException("grant is not an object")
        val p = pm

        val unsupported = core.checks.filter { it.value == PcaCore.UNSUPPORTED }.keys.toList()
        val vs = Vs(core.checks.mapValues { if (it.value == PcaCore.UNSUPPORTED) PcaCore.NOT_ENFORCED else it.value }, if (!core.allow && core.reason != null) listOf(core.reason) else emptyList())
        // the core keeps only its FIRST failure reason; the v2 checks are the escalate-class ones, so every failed one is reported
        if (v2d != null) {
            val fold = PcaDecision.foldV2Reasons(vs.reasons, v2d.checks.map { PcaDecision.V2Check(it.name, it.ok, it.reason) })
            for (r in fold.drop(vs.reasons.size)) vs.reasons.add(r)
        }
        fun fail(name: String, why: String) = vs.fail(name, "$name: $why")
        fun mark(name: String, s: String) = vs.set(name, s)

        // server-side PQ pin for a non-Ed25519 grant (fail closed: no pin for the issuer, or a different key, denies)
        val pins = o.pqPins
        if (pins != null) {
            val alg = if (grant["alg"] == null) "ed25519" else grant["alg"]
            val issuer = grant["issuer"]
            val pinned = issuer is String && pins.containsKey(issuer)
            val pin = if (pinned) pins[issuer as String] else null
            if (alg == "ed25519") {
                if (pinned) fail("pq_pin", Pca.PQ_PIN_CLASSICAL_REASON) else mark("pq_pin", "pass")
            } else if (pin is String && grant["pq_pk"] is String && pin == grant["pq_pk"]) mark("pq_pin", "pass")
            else fail("pq_pin", if (!pinned) "no server-side PQ pin for the grant issuer (suite ${js(alg)})" else "the grant pq_pk does not match the server-side pin")
        }

        // grant_ref binds the object to this grant
        if (p["grant_ref"] == grant["id"]) mark("grant_ref", "pass") else fail("grant_ref", "does not reference the supplied grant")

        val action = p["action"] as? Map<String, Any?>
        // the proof must be for the operation the server will execute: verb, resource and (when given) the exact params
        if (op != null) {
            val signed = "${js(action?.get("verb"), action?.containsKey("verb") == true)} on ${js(action?.get("resource"), action?.containsKey("resource") == true)}"
            val ov = op["verb"]
            val ores = op["resource"]
            if (ov !is String || ores !is String) fail("operation", "the server operation has no verb / resource (fail closed)")
            else if (action?.get("verb") != ov || action?.get("resource") != ores) fail("operation", "the proof is for $signed, but this operation is $ov on $ores")
            else if (opHasParams && Pca.hashCanonical(op["params"]) != action?.get("params_digest")) fail("operation", "the proof's params_digest does not match the params of this $ov operation")
            else if (opHasParams && ctxHasParams && Pca.hashCanonical(ctxIn["params"]) != Pca.hashCanonical(op["params"])) fail("operation", "context.params differ from the operation params")
            else mark("operation", "pass")
        }

        // params plaintext must open the committed digest
        if (ctx.containsKey("params")) {
            if (Pca.hashCanonical(ctx["params"]) == action?.get("params_digest")) mark("params_digest", "pass")
            else fail("params_digest", "supplied params do not hash to action.params_digest")
        } else mark("params_digest", "not-enforced")

        // the RS's own copy of the plan must be the committed one
        val planRaw = ctx["plan"]
        val planSupplied = ZkJs.truthy(planRaw)
        val pl = p["plan"] as? Map<String, Any?>
        val rootMatches = if (planSupplied) {
            val nodes = planRaw as List<Any?> // a plan that is not a list is a verifier error (fail closed)
            Pca.merkleRoot(nodes.map { x -> val n = x as Map<String, Any?>; Pca.planLeaf(n["id"], n, Pca.conditionsDigest(n["pre"], n["post"])) }) == pl?.get("root")
        } else false
        val authorized: Boolean? = if (ctx["planAuthorized"] == null) null else ctx["planAuthorized"] == true
        when {
            !planSupplied -> planNotEnforced(o, ::fail, ::mark)
            !rootMatches -> fail("plan_root_authorized", "known plan does not match plan.root")
            authorized == null -> planNotEnforced(o, ::fail, ::mark)
            !authorized -> fail("plan_root_authorized", "the plan root has not been authorized by the principal")
            else -> mark("plan_root_authorized", "pass")
        }

        val rev = ctx["revocationEpoch"]
        if (ZkJs.truthy(rev)) {
            val re = rev as Map<String, Any?>
            val r = Revocation.checkEpoch(
                re["epoch"], re["guardianPublic"] as? String, now.toDouble(), grant["id"] as? String, IntentJs.num(re["lastAcceptedEpoch"])?.toLong(),
                (p["freshness"] as? Map<String, Any?>)?.get("epoch"), if (re["maxAgeMs"] == null) null else IntentJs.num(re["maxAgeMs"]), null,
            )
            // an `enforce.freshness` failure from the core stands (a passing epoch never overwrites it)
            if (r.ok) { if (vs.get("freshness") != "fail") mark("freshness", "pass") } else fail("freshness", r.reason ?: "revocation epoch rejected")
        } else if (vs.get("freshness") == null) mark("freshness", "not-enforced")

        run {
            val bc = ctx["beacon"] as? Map<String, Any?>
            val bcSupplied = ZkJs.truthy(ctx["beacon"])
            val beacon = bc?.get("beacon")
            val r = if (bc != null) Beacons.verify(beacon, bc["issuers"], now, bc["instance"] as? String, grant["id"] as? String, bc["pqPins"] as? Map<String, Any?>) else null
            val last = bc?.get("lastAcceptedSeq")
            val seq = (beacon as? Map<*, *>)?.get("seq")
            val replayed = bc != null && r?.ok == true && last != null && IntentJs.num(seq).let { s -> s != null && s < (IntentJs.num(last) ?: Double.NaN) }
            val refBinds = bc != null && r?.ok == true && !replayed && (p["freshness"] as? Map<*, *>)?.get("beacon_ref") == Beacons.beaconRef(beacon)
            when (Beacons.decision(bcSupplied, r?.ok == true, replayed, refBinds)) {
                "rejected" -> fail("beacon", r?.reason ?: "beacon rejected")
                "replayed" -> fail("beacon", "beacon seq ${js(seq)} is older than the last accepted ${js(last)} (replay)")
                "unbound" -> fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon")
                "pass" -> mark("beacon", "pass")
                else -> mark("beacon", "not-enforced")
            }
        }

        // Require-when-bound: a grant whose agent_binding constrains the model / measurement / operator / weights REQUIRES a bound attestation.
        if (Authorize.requiresAttestation(grantEnv?.get("agent_binding")) && vs.get("attestation") != "pass")
            fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED")

        val chain = p["cap_chain"] as? List<Any?> ?: emptyList()
        val leaf = chain.lastOrNull()
        var k1Bound: List<CaveatLang.BoundCaveat>? = null
        val depth = maxOf(0, chain.size - 1)
        // Fail-closed default: an ABSENT budget becomes a DENY-METERED budget (B=0), so a caller that forgets `context.budget` cannot silently
        // get unlimited machine-only authority.
        val budgetSupplied = chas("budget")
        val budgetIn: Any? = if (budgetSupplied) ctx["budget"] else linkedMapOf<String, Any?>("B" to 0L, "tau" to now, "asOf" to now)
        mark("budget", if (budgetSupplied) "pass" else "not-enforced")
        if (!budgetSupplied)
            vs.reasons.add("budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge")

        // Only a server-supplied taint counts: the agent's own `provenance.taint_level` is untrusted.
        val risk: Map<String, Any?> = (ctx["risk"] as? Map<String, Any?>) ?: emptyMap()
        val need = o.requireRiskInputs
        if (!need.isNullOrEmpty()) {
            val missing = need.filter { k -> !(Risk.fin(risk[k]) != null && risk[k] !is Boolean && risk[k] !is String || (k == "semanticDistance" && ctx.containsKey("plan"))) }
            if (missing.isNotEmpty()) fail("risk_inputs", "required risk input(s) not supplied by the server: ${missing.joinToString(", ")}")
            else mark("risk_inputs", "pass")
        }

        // Reversibility: the server's authoritative class wins; the agent may only be STRICTER.
        val declared = action?.get("reversibility_class")
        var reversibility: Any? = declared
        if (ctx.containsKey("reversibilityClass") && ctx["reversibilityClass"] != null) {
            val serverClass = ctx["reversibilityClass"]
            val dr = Revocation.classRank(declared)
            val sr = Revocation.classRank(serverClass)
            if (dr < sr) fail("reversibility", "declared class '${js(declared)}' is less restrictive than the authoritative '${js(serverClass)}'")
            else mark("reversibility", "pass")
            reversibility = if (dr > sr) declared else serverClass
        }

        val inner = LinkedHashMap<String, Any?>()
        inner["verb"] = action?.get("verb")
        inner["resource"] = action?.get("resource")
        if (chas("params")) inner["params"] = ctx["params"]
        if (reversibility != null) inner["reversibility_class"] = reversibility
        val actionCtx = LinkedHashMap<String, Any?>()
        actionCtx["action"] = inner
        if (ctx["subject"] != null) actionCtx["subject"] = ctx["subject"]
        val envV = v2Env(p, v2d, ctx["env"])
        if (envV != null) actionCtx["env"] = envV
        if (p["tool_binding"] is String) actionCtx["toolBinding"] = p["tool_binding"]

        val nodeId = pl?.get("node_id")
        val k1In = o.k1
        val decideIn = linkedMapOf<String, Any?>(
            "grant" to grant, "trustedRoot" to grant, "action" to actionCtx, "risk" to risk, "budget" to budgetIn, "now" to now,
        )
        if (pins != null) decideIn["pqPins"] = pins
        if (planSupplied) decideIn["plan"] = planRaw
        if (nodeId != null) decideIn["nodeId"] = nodeId
        val cavCtx = linkedMapOf<String, Any?>("delegationDepth" to depth)
        if (ctx["recentActionTimes"] != null) cavCtx["recentActionTimes"] = ctx["recentActionTimes"]
        decideIn["caveatContext"] = cavCtx
        if (k1In != null) decideIn["k1"] = CaveatLang.K1Input(k1In.pins, k1In.discharges, CaveatLang.K1Input.ABSENT, CaveatLang.dischargeActionDigest(p), k1In.revokedDischarges, k1In.spiffeId, k1In.history)
        if (p["caution"] != null && IntentJs.num(p["caution"]) != null && p["caution"] !is Boolean && p["caution"] !is String) decideIn["rFloor"] = p["caution"]
        val d = Decide.decide(decideIn)
        val dR = IntentJs.num(d["r"]) ?: 1.0
        val dThreshold = d["requiredThreshold"] as Map<String, Any?>
        val release = d["releaseGuardianShare"] == true
        val dBudget = d["budget"] as? Map<String, Any?>

        // Caveats added by delegation hops (beyond the root's) are conjunctive too.
        if (leaf != null && !(leaf is Boolean && !leaf)) {
            val lcs = (leaf as? Map<String, Any?>)?.get("caveats") as? List<Any?> ?: throw IllegalStateException("leaf.caveats is not an array")
            val gcs = grant["caveats"] as? List<Any?> ?: throw IllegalStateException("grant.caveats is not an array")
            val extra = if (gcs.size >= lcs.size) emptyList() else lcs.subList(gcs.size, lcs.size)
            // K1 caveat types (and the caveats of a verified narrow block) are evaluated over the whole chain: the stock evaluator would refuse them
            val useK1 = lcs.any { CaveatLang.isK1Caveat(it) } || (k1In != null && k1In.narrow !== CaveatLang.K1Input.ABSENT)
            val k1r = if (useK1) CaveatLang.evaluateK1(grant, chain, k1In?.withActionDigest(CaveatLang.dischargeActionDigest(p)), now, inner) else null
            if (k1r != null) k1Bound = k1r.bound
            val plain = ArrayList<Any?>()
            for (c in extra) if (!CaveatLang.isK1Caveat(c)) plain.add(c)
            if (k1r != null) plain.addAll(k1r.plain)
            val cctx = linkedMapOf<String, Any?>("now" to now, "action" to inner, "delegation_depth" to depth)
            if (risk["blastRadius"] != null) cctx["blast_radius"] = risk["blastRadius"]
            val rc = Decide.resolveReversibilityClass(actionCtx, planRaw as? List<*>, nodeId)
            if (rc != null) cctx["reversibility_class"] = rc
            if (ctx["recentActionTimes"] != null) cctx["recent_action_times"] = ctx["recentActionTimes"]
            val cv = Authorize.evaluateAgentCaveats(plain, cctx, actionCtx, Decide.toolCallOf(actionCtx))
            if (cv.ok && (k1r?.ok ?: true)) mark("delegated_caveats", "pass")
            else {
                fail("delegated_caveats", "delegation caveat(s) not satisfied: ${(cv.failed + (k1r?.failed ?: emptyList())).joinToString(", ")}" +
                    (if (k1r != null && !k1r.ok) " (${k1r.reasons.joinToString("; ")})" else ""))
            }
        }

        // policy: the check mirrors the Policy VM's release decision; its reasons (also the informational step-up / assumed-worst-case ones
        // when released) are kept in order.
        mark("policy", if (release) "pass" else "fail")
        for (x in d["reasons"] as List<*>) vs.reasons.add("policy: ${js(x)}")

        // Threshold: t > 1 needs a proof we can only get from an enforced threshold hook (F-1: the hook must report having enforced at least
        // the SERVER-derived t; below it, or silent, the check fails).
        val tReq = (dThreshold["t"] as Number).toInt()
        val th = vs.get("threshold")
        val hT: Double? = hookT?.let { h -> if (h.isNaN()) null else if (h >= 9007199254740991.0) 9007199254740991.0 else if (h <= -9007199254740991.0) -9007199254740991.0 else Math.floor(h) }
        if (tReq > 1 && release) {
            if (th == "pass" && !(hT != null && hT >= tReq))
                fail("threshold", "threshold hook enforced t=${if (hookT == null) "unreported" else num(hookT!!)} but the server requires t=$tReq (below the server-derived threshold; derive t from server-held data)")
            else if (th != "pass") {
                if (th == "fail") fail("threshold", "t=$tReq required and the threshold proof was rejected")
                else fail("threshold", "t=$tReq (${dThreshold["proof"]}) required but no threshold verifier is enforced")
            }
        }
        val required = o.require ?: DEFAULT_REQUIRED_CHECKS
        val wantAssurance = o.assurance || o.requireAssurance != null
        val labelled = linkedMapOf<String, Any?>("attestation" to userHooks?.attestation, "zk" to userHooks?.zk, "threshold" to userHooks?.threshold, "revocation" to userHooks?.revocation)
        val attHook: Any? = o.enforce?.attestation?.verifier ?: userHooks?.attestation
        val degraded: Map<String, String> = if (v2d?.legacyModelPolarity == true) mapOf("tighten" to Authorize.LEGACY_POLARITY_DEGRADED) else emptyMap()
        fun report(checks: Map<String, String>) = Assurance.report(p, checks, degraded, labelled, attHook, hookT)
        val reqA = o.requireAssurance
        if (reqA != null) {
            val unmet = Assurance.unmetAssurance(report(LinkedHashMap(vs.checks)), reqA)
            if (unmet == null) mark("assurance", "pass") else vs.fail("assurance", unmet)
        }

        val allow = vs.checks.values.none { it == "fail" } && release && core.allow
        val checks = LinkedHashMap(vs.checks)
        for (n in unsupported) if (checks[n] == PcaCore.NOT_ENFORCED) checks[n] = PcaCore.UNSUPPORTED
        val reasons = vs.reasons
        // a feature the PCActn carries but this verifier does not implement is never a pass, and denies unless allowed
        val allowedU = o.allowUnsupported ?: emptyList()
        val refused = unsupported.filter { it !in allowedU }
        if (refused.isNotEmpty()) {
            val out = Verdict(false, dR, dThreshold, checks, reasons + refused.map { "$it: $UNSUPPORTED_SUFFIX" })
            enforce(out, required)
            if (wantAssurance) out.assurance = Assurance.refresh(LinkedHashMap(report(checks)), out.checks)
            return out
        }
        val out = if (allow) Verdict(true, dR, dThreshold, checks, reasons, if (budgetSupplied) dBudget else null) else Verdict(false, dR, dThreshold, checks, reasons)
        if (k1Bound?.any { (it.caveat as? Map<*, *>)?.get("type") == "max_uses" } == true) out.k1Bound = k1Bound
        enforce(out, required)
        // an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
        if (!out.allow && budgetSupplied && PcaDecision.decisionOf(false, out.checks, out.reasons) == "escalate") out.budget = dBudget
        if (!out.allow && out.reasons.isEmpty()) out.reasons = listOf("denied")
        if (wantAssurance) out.assurance = Assurance.refresh(LinkedHashMap(report(checks)), out.checks)
        return out
    }

    private fun num(d: Double): String = AttestUtil.jsNumString(d)

    private fun planNotEnforced(o: Options, fail: (String, String) -> Unit, mark: (String, String) -> Unit) {
        if (o.insecureSkipPlanRootCheck) mark("plan_root_authorized", "not-enforced")
        else fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)")
    }

    /** Default-deny: every required check that is not `pass` becomes a failure (the `counter` alias is resolved). Mutates [v]. */
    private fun enforce(v: Verdict, required: List<String>) {
        val r = Authorize.enforceRequired(v.allow, v.checks, v.reasons, required)
        v.allow = r.allow
        v.checks = r.checks
        v.reasons = r.reasons
    }

    /** The predicate `env`: the host's, with the verifier-computed Intent Layer v2 members (only the verifier computes them). */
    private fun v2Env(p: Map<String, Any?>, v2d: IntentV2.Decision?, env: Any?): Any? {
        if (!p.containsKey("intent_session")) return env
        val rest = LinkedHashMap<String, Any?>()
        if (env is Map<*, *>) for ((k, x) in env) rest[k as String] = x
        for (k in listOf("acc", "mon", "canon", "world", "prov", "class")) rest.remove(k)
        if (v2d != null) for ((k, x) in v2d.env) if (x != null) rest[k] = x
        return rest
    }
}
