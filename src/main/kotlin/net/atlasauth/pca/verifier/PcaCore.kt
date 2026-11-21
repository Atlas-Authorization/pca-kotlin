package net.atlasauth.pca.verifier

/**
 * The core verifier entry with the full option set: the equivalent of `verifyPCActnCore(pcactn, opts)` in the reference. Unlike
 * [Pca.verifyPcactn] it reports each check as `pass | fail | not-enforced | unsupported`, takes the verifier hooks (attestation,
 * threshold, revocation, zk) and the opt-in enforcement gates (taint, freshness, attestation), and supports the explicit audience
 * opt-out.
 *
 * Check order (normative): wire (terminal on failure), version, audience, validity, cap_chain, pq_pin, grant_ref_bound,
 * plan_inclusion, plan_root_authorized, leaf_signature, counter_format, intent, the intent v2 checks, fresh_at, taint_gate,
 * freshness, attestation, threshold, revocation, zk_compliance, bond. `allow` is "no check failed"; the reason is the first failure.
 *
 * Not offered: the reference's legacy `allowUnboundPq` (a PQ signer is always checked against its `holder_pq` commitment).
 * [Options.assurance] attaches the per-check [Assurance.report]; [Options.requireAssurance] adds the `assurance` check.
 */
object PcaCore {
    const val PASS = "pass"
    const val FAIL = "fail"
    const val NOT_ENFORCED = "not-enforced"
    const val UNSUPPORTED = "unsupported"

    /** What a hook receives: the PCActn, the verifier's grant and the verification clock. */
    class Ctx internal constructor(val pcactn: Map<String, Any?>, val grant: Map<String, Any?>, val nowEpoch: Long)

    /** `{enforced: false}` or `{enforced: true, ok, reason?, t?}`; a threshold hook reports the `t` it enforced. */
    class HookResult private constructor(val enforced: Boolean, val ok: Boolean, val reason: String?, val t: Double?) {
        companion object {
            @JvmStatic fun notEnforced() = HookResult(false, false, null, null)
            @JvmStatic @JvmOverloads fun enforced(ok: Boolean, reason: String? = null, t: Double? = null) = HookResult(true, ok, reason, t)
        }
    }

    fun interface Hook {
        fun run(ctx: Ctx): HookResult
    }

    class Hooks(var attestation: Hook? = null, var threshold: Hook? = null, var revocation: Hook? = null, var zk: Hook? = null)

    /** `enforce.freshness`: reject a missing, stub or stale signed freshness anchor. Null fields take the reference defaults. */
    class Freshness(var maxAgeMs: Double, var epochMs: Double? = null, var clockSkewMs: Double? = null, var now: Long? = null)

    /** `enforce.attestation`: the real attestation verifier; with the gate on, a not-enforced result fails unless `required` is false. */
    class AttestationGate(val verifier: Hook?, var required: Boolean = true)

    /** `enforce.taint` is a [Taint.Gate]: re-classify every declared ref from server facts and refuse above `maxTaint`. */
    class Enforce(var freshness: Freshness? = null, var taint: Taint.Gate? = null, var attestation: AttestationGate? = null)

    class Options(
        /** The verifier's OWN stored grant. */
        var grant: Map<String, Any?>,
    ) {
        /** The grant was lifted from the presented artifact: it is then not the trusted root and a PQ root verifies only under [pqPins]. */
        var grantFromArtifact = false

        /** Verifier-side pins `issuer -> pq_pk`; an issuer with a pin also refuses a classical root (`pq_pin`). */
        var pqPins: Map<String, Any?>? = null

        /** The verification clock (epoch ms); null reads the system clock. */
        var nowEpoch: Long? = null

        /** [Pca.Audience.Of] must equal, [Pca.Audience.Any] is the explicit opt-out, [Pca.Audience.Unset] fails when the PCActn carries an aud. */
        var audience: Pca.Audience = Pca.Audience.Unset
        var hooks: Hooks? = null
        var enforce: Enforce? = null
        var allowedSuites: List<String>? = null

        /** `authorizedPlanRoots`: null with [insecureSkipPlanRootCheck] false fails `plan_root_authorized`. */
        var authorizedPlanRoots: List<String>? = null
        var insecureSkipPlanRootCheck = false
        var intentPolicy: Pca.IntentPolicy? = null
        var intentV2: IntentV2.Context? = null
        var freshAt: FreshAt.Policy? = null

        /** Attach the per-check assurance report ([Result.assurance]). */
        var assurance = false

        /** A high-assurance policy (see [Assurance.unmetAssurance]); adds the `assurance` check, which fails when a dimension is unmet. */
        var requireAssurance: Map<String, Any?>? = null
    }

    class Result internal constructor(val allow: Boolean, val checks: Map<String, String>, val reason: String?, val enforcedT: Double?) {
        /** The per-check assurance report; null unless [Options.assurance] or [Options.requireAssurance] was set. */
        var assurance: Map<String, Map<String, Any?>>? = null
    }

    /** The reference's CoreState: ordered checks, first failure reason, terminal wire failure. */
    private class State {
        val checks = LinkedHashMap<String, String>()
        var reason: String? = null
        var terminal = false
        var enforcedT: Double? = null
        fun set(n: String, s: String) { checks[n] = s }
        fun fail(n: String, why: String?) {
            checks[n] = FAIL
            if (reason == null) reason = "$n: $why"
        }
        /** An exception during verification: the check `malformed` fails and the reason is the text itself (no check-name prefix). */
        fun malformed(why: String) {
            checks["malformed"] = FAIL
            if (reason == null) reason = why
        }
        fun result(): Result {
            val allow = !terminal && !checks.containsValue(FAIL)
            return Result(allow, LinkedHashMap(checks), if (allow) null else reason, enforcedT)
        }
    }

    /** Verifies [pcactn] under [o]; total: hostile input is a failed result, never an exception. */
    @JvmStatic
    fun verify(pcactn: Any?, o: Options): Result = try {
        verifyUnchecked(pcactn, o)
    } catch (ex: RuntimeException) {
        State().apply { terminal = true; fail("wire", "malformed input (${ex.javaClass.simpleName})") }.result()
    }

    private fun verifyUnchecked(pcactn: Any?, o: Options): Result {
        val st = State()
        val wire = Pca.validateWireV2(pcactn)
        if (wire != null) {
            st.terminal = true
            st.checks["wire"] = FAIL
            st.reason = "wire: $wire"
            return st.result()
        }
        val p = Pca.asMap(pcactn)
        val grant = o.grant
        val now = o.nowEpoch ?: System.currentTimeMillis()
        val ctx = Ctx(p, grant, now)
        val hooks = o.hooks
        st.set("wire", PASS)
        try {
            // version
            if (Json.asLong(p["ver"]) == Pca.WIRE_VERSION) st.set("version", PASS)
            else st.fail("version", "unsupported ver ${Json.asLong(p["ver"])} (this verifier requires ${Pca.WIRE_VERSION})")

            // audience: a string must equal, an explicit opt-out is not enforced, an omitted one fails when the PCActn carries an aud
            val hasAud = (p["aud"] as? String)?.isNotEmpty() == true
            when (val a = o.audience) {
                is Pca.Audience.Any -> st.set("audience", NOT_ENFORCED)
                is Pca.Audience.Unset ->
                    if (hasAud) st.fail("audience", "PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)")
                    else st.set("audience", NOT_ENFORCED)
                is Pca.Audience.Of -> if (a.id == p["aud"]) st.set("audience", PASS) else st.fail("audience", "aud does not match this resource server / instance")
            }

            // validity
            val iat = Json.asLong(p["iat"])
            val exp = Json.asLong(p["exp"])
            when {
                Math.abs(now) > 9007199254740991L -> st.fail("validity", "the verifier clock is not a safe integer epoch-ms")
                !(exp > iat) -> st.fail("validity", "exp must be greater than iat")
                exp - iat > Pca.MAX_LIFETIME_MS -> st.fail("validity", "lifetime exceeds ${Pca.MAX_LIFETIME_MS} ms")
                iat > now + Pca.MAX_SKEW_MS -> st.fail("validity", "iat is in the future (clock skew)")
                now > exp -> st.fail("validity", "the PCActn has expired")
                else -> st.set("validity", PASS)
            }

            // cap_chain: non-empty, rooted at the grant, then the walk
            val chain = Pca.asList(p["cap_chain"])
            if (chain.isEmpty()) st.fail("cap_chain", "empty chain")
            else if (Pca.capHash(Pca.asMap(chain[0])) != Pca.capHash(grant)) st.fail("cap_chain", "chain root is not the grant")
            else {
                val why = Pca.verifyChain(
                    chain, Pca.asStr(grant["issuer"]), grant["issuer"] is String, o.allowedSuites,
                    if (o.grantFromArtifact) o.pqPins else null, if (o.grantFromArtifact) null else grant,
                )
                if (why.isEmpty()) st.set("cap_chain", PASS) else st.fail("cap_chain", why)
            }
            // a PQ pin for the root issuer says its grants are post-quantum protected: a classical root naming it is refused
            val pins = o.pqPins
            if (pins != null && (grant["alg"] == null || grant["alg"] == "ed25519") && pins.containsKey(grant["issuer"])) st.fail("pq_pin", Pca.PQ_PIN_CLASSICAL_REASON)

            // grant_ref_bound
            val gref = p["grant_ref"]
            val rootId = (chain.firstOrNull() as? Map<*, *>)?.get("id")
            if (gref is String && gref.isNotEmpty() && rootId is String && gref == rootId) st.set("grant_ref_bound", PASS)
            else st.fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain")

            // plan inclusion + plan_root_authorized
            val plan = Pca.asMap(p["plan"])
            val action = Pca.asMap(p["action"])
            val cond = plan["conditions_digest"] as? String ?: Pca.conditionsDigest(null, null)
            val incl = try {
                Pca.verifyInclusion(Pca.asStr(plan["root"]), Pca.asMap(plan["inclusion_proof"]), Pca.planLeaf(plan["node_id"], action, cond))
            } catch (e: RuntimeException) {
                false
            }
            if (incl) st.set("plan_inclusion", PASS) else st.fail("plan_inclusion", "action is not a node of the committed plan")
            val roots = o.authorizedPlanRoots
            if (roots == null) {
                if (o.insecureSkipPlanRootCheck) st.set("plan_root_authorized", NOT_ENFORCED)
                else st.fail("plan_root_authorized", "no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)")
            } else if (roots.contains(Pca.asStr(plan["root"]))) st.set("plan_root_authorized", PASS)
            else st.fail("plan_root_authorized", "the plan root has not been authorized by the principal")

            // leaf signature (suite policy, F-2 binding, then the suite verification)
            var sigOk = false
            var leafErr: String? = null
            if (chain.isNotEmpty()) {
                val leafCap = Pca.asMap(chain[chain.size - 1])
                val holder = Pca.asStr(leafCap["holder"])
                val algPresent = p.containsKey("alg")
                leafErr = if (Pca.suitePolicyError(p["alg"], algPresent, "leaf", o.allowedSuites) != null) {
                    "signature suite '${if (algPresent) Pca.asStr(p["alg"]) else "ed25519"}' is not allowed by this verifier's suite policy"
                } else {
                    Pca.pqBindingError(p["alg"], algPresent, p["pq_pk"], leafCap["holder_pq"], "leaf")
                }
                if (leafErr == null && p["sig"] is String) {
                    sigOk = Pq.verifySuite(
                        p["alg"], algPresent, holder, PinnedPq.resolve(leafCap["holder"] as? String, p["pq_pk"], holderPq = leafCap["holder_pq"]),
                        Pca.thresholdMessage(p), p["sig"], p["pq_sig"],
                    )
                }
            }
            if (leafErr != null) st.fail("leaf_signature", leafErr)
            else if (sigOk) st.set("leaf_signature", PASS)
            else st.fail("leaf_signature", "signature does not verify under the leaf holder key / suite")

            // counter_format
            if (Json.isSafeInt(p["counter"]) && Json.asLong(p["counter"]) >= 0) st.set("counter_format", PASS)
            else st.fail("counter_format", "missing or not a non-negative safe integer")

            // intent (reported iff the PCActn carries intent or the policy is active)
            val session = if (p.containsKey("intent_session")) Pca.asMap(p["intent_session"])["session"] else null
            val mapForm = if (p.containsKey("intent_session")) Pca.asMap(p["intent_session"])["map_form"] else null
            val intentWhy = Pca.decideIntent(p["intent"], p.containsKey("intent"), grant, o.intentPolicy, session as? String, mapForm)
            if (intentWhy != null) {
                if (intentWhy.isEmpty()) st.set("intent", PASS) else st.fail("intent", intentWhy)
            }
            for (c in IntentV2.decide(p, grant, o.intentV2, now).checks) {
                if (c.ok) st.set(c.name, PASS) else st.fail(c.name, c.reason ?: "rejected")
            }
            val fa = FreshAt.decide(p["fresh_at"], p.containsKey("fresh_at"), o.freshAt, now)
            if (fa.status == FreshAt.Status.PASS) st.set("fresh_at", PASS)
            else if (fa.status == FreshAt.Status.FAIL) st.fail("fresh_at", fa.reason)

            val en = o.enforce
            // M1 taint gate
            val tg = en?.taint
            if (tg != null) {
                try {
                    val r = Taint.gate(p["provenance"], tg)
                    if (r == null) st.set("taint_gate", PASS) else st.fail("taint_gate", r)
                } catch (e: RuntimeException) {
                    st.fail("taint_gate", "taint gate error (fail closed): ${e.message}")
                }
            } else st.set("taint_gate", NOT_ENFORCED)

            // M3 freshness gate
            val g = en?.freshness
            if (g != null) {
                val epochMs = g.epochMs ?: 60_000.0
                val fnow = (g.now ?: now).toDouble()
                val skew = g.clockSkewMs?.takeIf { !it.isNaN() && !it.isInfinite() }?.let { Math.max(0.0, it) } ?: 0.0
                val fr = p["freshness"] as? Map<*, *>
                val br = fr?.get("beacon_ref")
                val epochOk = fr != null && Json.isSafeInt(fr["epoch"]) && Json.asLong(fr["epoch"]) > 0
                if (!(epochMs > 0) || g.maxAgeMs.isNaN() || g.maxAgeMs.isInfinite() || g.maxAgeMs < 0) {
                    st.fail("freshness", "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)")
                } else if (br !is String || br.isEmpty() || !epochOk) {
                    st.fail("freshness", "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
                } else {
                    val anchor = Json.asLong(fr!!["epoch"]) * epochMs
                    if (anchor > fnow + skew) st.fail("freshness", "freshness anchor is in the future")
                    else if (fnow - anchor > g.maxAgeMs) st.fail("freshness", "freshness anchor is stale (older than ${AttestUtil.jsNumString(g.maxAgeMs)} ms)")
                    else st.set("freshness", PASS)
                }
            }

            // M5 attestation (the gate's verifier takes the slot of hooks.attestation), threshold, revocation
            val attGate = en?.attestation
            runHook(st, ctx, "attestation", if (attGate != null) attGate.verifier else hooks?.attestation)
            if (attGate != null && attGate.required && st.checks["attestation"] == NOT_ENFORCED)
                st.fail("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)")
            runHook(st, ctx, "threshold", hooks?.threshold)
            runHook(st, ctx, "revocation", hooks?.revocation)

            // zk_compliance: fail closed at the core
            if (p.containsKey("zk_compliance")) {
                runHook(st, ctx, "zk_compliance", hooks?.zk)
                val c = st.checks["zk_compliance"]
                if (c != PASS && c != FAIL)
                    st.fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof")
            }
            if (p.containsKey("bond_ref")) st.set("bond", UNSUPPORTED)
        } catch (e: Exception) {
            st.malformed("malformed PCActn: ${e.message}")
        }
        val require = o.requireAssurance
        if (!o.assurance && require == null) return st.result()
        val labelled = linkedMapOf<String, Any?>("attestation" to hooks?.attestation, "zk" to hooks?.zk, "threshold" to hooks?.threshold, "revocation" to hooks?.revocation)
        val used = o.enforce?.attestation?.verifier
        if (require != null) {
            val unmet = Assurance.unmetAssurance(Assurance.report(p, st.result().checks, null, labelled, used), require)
            if (unmet == null) st.set("assurance", PASS) else st.fail("assurance", unmet.removePrefix("assurance: "))
        }
        val out = st.result()
        out.assurance = Assurance.report(p, out.checks, null, labelled, used)
        return out
    }

    private fun runHook(st: State, ctx: Ctx, name: String, hook: Hook?) {
        val res = hook?.run(ctx) ?: HookResult.notEnforced()
        if (!res.enforced) st.set(name, NOT_ENFORCED)
        else if (res.ok) {
            st.set(name, PASS)
            if (name == "threshold" && res.t != null) st.enforcedT = res.t
        } else st.fail(name, res.reason ?: "rejected")
    }
}
