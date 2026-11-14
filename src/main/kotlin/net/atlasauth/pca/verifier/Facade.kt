package net.atlasauth.pca.verifier

import java.util.Locale
import java.util.regex.Pattern

/**
 * The high-level agent API: compile human-level permissions and limits into a signed grant, then build one proof-carrying action per
 * tool call. Same output as the TypeScript reference's `agent()`, byte for byte for fixed keys, salt, session and clock.
 *
 * ```
 * val a = Agent.fromPrincipal(Facade.AgentOptions(principal, "reconcile refunds for October",
 *     mapOf("stripe" to listOf("refund"), "gmail" to listOf("send")), limits = mapOf("refund" to "$500/day"), aud = "ins_123"))
 * val r = a.act("stripe.refund", "charge:ch_123", mapOf("amount" to 42L, "currency" to "usd"))
 * // send r.headers (PCA-Action and PCA-Provenance) to the resource server; its verifier decides
 * ```
 *
 * Nothing here authorizes anything: every member the facade emits is signed, so a tampered grant or action fails verification
 * downstream. [Handle.dryRun] is a local, advisory pre-check only.
 */
object Facade {
    // ---- numbers in the reference's JSON form ------------------------------------------------------------------------------

    /** A JSON number for [d] as JavaScript writes it: a safe integer as a Long, else the shortest decimal. */
    internal fun jn(d: Double): Any = if (d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0) d.toLong() else Json.Num(Json.esNumber(d))

    /** The text JavaScript prints for a number in a template literal. */
    internal fun jsText(d: Double): String = jn(d).let { if (it is Json.Num) it.raw else it.toString() }

    // ---- limit parsing -----------------------------------------------------------------------------------------------------

    /** A parsed limit: [amount], [unit] (`usd` or `count`) and the period window in ms (null when none). */
    class ParsedLimit(val amount: Double, val unit: String, val periodMs: Long?) {
        /** `{amount, unit, periodMs?}`, the reference's member names. */
        fun toJson(): Map<String, Any?> {
            val m = Issue.obj("amount" to jn(amount), "unit" to unit)
            if (periodMs != null) m["periodMs"] = periodMs
            return m
        }
    }

    /** Longest limit string accepted (the grammar needs about 20 characters). */
    const val MAX_LIMIT_LENGTH = 64

    private val PERIODS: Map<String, Long> = LinkedHashMap<String, Long>().also { p ->
        for (k in listOf("s", "sec", "second", "seconds")) p[k] = 1000L
        for (k in listOf("m", "min", "minute", "minutes")) p[k] = 60_000L
        for (k in listOf("h", "hr", "hour", "hours")) p[k] = 3_600_000L
        for (k in listOf("d", "day", "days")) p[k] = 86_400_000L
        for (k in listOf("w", "week", "weeks")) p[k] = 604_800_000L
        for (k in listOf("mo", "month", "months")) p[k] = 2_592_000_000L
    }

    // JavaScript's \s spelled out (Android's regex has no UNICODE_CHARACTER_CLASS)
    private const val JS_WS = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]"
    private val LIMIT_RE = Pattern.compile("^(\\$)?$JS_WS*([0-9]+(?:\\.[0-9]+)?)$JS_WS*(?:/$JS_WS*([a-zA-Z]+))?$")

    // the look-behind makes the trailing alternative start only at the beginning of a run, so a long run of white space is scanned once
    private val TRIM_RE = Pattern.compile("\\A$JS_WS+|(?<!$JS_WS)$JS_WS+\\z")

    /** JavaScript `String.prototype.trim`: strips JavaScript white space and line terminators (the same set as `\s`) from both ends. */
    internal fun jsTrim(s: String): String = TRIM_RE.matcher(s).replaceAll("")

    /** Parse `"$500/day"`, `"$500"`, `"10/hour"`, `"10"`. Throws on anything malformed or longer than [MAX_LIMIT_LENGTH]. */
    fun parseLimit(sO: Any?): ParsedLimit {
        if (sO !is String || jsTrim(sO).isEmpty()) throw IllegalArgumentException("parseLimit: empty limit")
        val s: String = sO
        if (s.length > MAX_LIMIT_LENGTH) throw IllegalArgumentException("parseLimit: limit is longer than $MAX_LIMIT_LENGTH characters")
        val m = LIMIT_RE.matcher(jsTrim(s))
        if (!m.matches()) throw IllegalArgumentException("parseLimit: cannot parse limit '$s'")
        val unit = if (m.group(1) != null) "usd" else "count"
        val amount = m.group(2).toDouble()
        if (amount.isInfinite() || amount < 0) throw IllegalArgumentException("parseLimit: bad amount in '$s'")
        var periodMs: Long? = null
        val per = m.group(3)
        if (per != null) {
            periodMs = PERIODS[per.lowercase(Locale.ROOT)] ?: throw IllegalArgumentException("parseLimit: unknown period '$per' in '$s'")
        }
        return ParsedLimit(amount, unit, periodMs)
    }

    // ---- compiled policy ---------------------------------------------------------------------------------------------------

    /** The policy primitives a grant is minted from. */
    class CompiledPolicy internal constructor(
        val predicates: List<Any?>,
        val caveats: List<Any?>,
        val riskPolicy: Map<String, Any?>,
        /** The resolved action spec of each granted permission. */
        val actions: List<Catalog.Spec>,
        /** `dollars` or `risk`. */
        val budgetModel: String,
        /** The parsed limits that matched a granted action, by verb. */
        val limits: Map<String, ParsedLimit>,
        /** The raw limit input as given. */
        val inputLimits: Map<String, Any?>,
        /** Limits this offline compiler can only approximate (a `$N/period` limit is a per-call ceiling plus a one-period lifetime). */
        val approximations: List<String>,
    ) {
        /** `{predicates, caveats, riskPolicy, budgetModel, limits, approximations}`, the reference's member names. */
        fun toJson(): Map<String, Any?> {
            val l = LinkedHashMap<String, Any?>()
            for ((k, v) in limits) l[k] = v.toJson()
            return Issue.obj("predicates" to predicates, "caveats" to caveats, "riskPolicy" to riskPolicy, "budgetModel" to budgetModel, "limits" to l,
                "approximations" to ArrayList<Any?>(approximations))
        }
    }

    /** Conservative fallback for a verb not in the catalog: irreversible, blast radius 0.8; an alias of exactly one action resolves to it. */
    internal fun specFor(catalog: Catalog, verb: String): Catalog.Spec {
        catalog.get(verb)?.let { return it }
        val dot = verb.indexOf('.')
        if (dot > 0) catalog.resolve(verb.substring(0, dot), verb.substring(dot + 1))?.let { return it }
        val connector = if (dot < 0) verb else verb.substring(0, dot)
        val action = if (dot < 0) "" else verb.substring(dot + 1)
        return Catalog.Spec(connector, if (action.isEmpty()) verb else action, verb, "irreversible", 0.8, null, "(uncatalogued) $verb")
    }

    private val REVERSIBILITY_ORDER = listOf("reversible", "rate_limited", "irreversible")

    private fun sev(cls: String): Int = REVERSIBILITY_ORDER.indexOf(cls)

    /**
     * Compile permissions (`{connector: [action, ...]}`) and limits (`{action or verb: "$500/day"}`) into predicates, caveats and a risk
     * policy. Pure: no keys, no signing. [catalog] (null: [Catalog.DEFAULT]), [budgetModel] (`auto` when null, `dollars`, `risk`),
     * [riskPolicy] (members that override the derived policy) and [now] (ms) are as in the reference.
     */
    fun compilePolicy(permissions: Map<String, Any?>, limits: Map<String, Any?>? = null, catalog: Catalog? = null, budgetModel: String? = null,
                      riskPolicy: Map<String, Any?>? = null, now: Long = System.currentTimeMillis()): CompiledPolicy {
        val cat = catalog ?: Catalog.DEFAULT
        val raw: Map<String, Any?> = limits ?: LinkedHashMap()
        val actions = ArrayList<Catalog.Spec>()
        for ((k, v) in permissions) {
            if (v !is List<*>) throw IllegalArgumentException("compilePolicy: permissions.$k must be an array")
            for (a in v) actions.add(specFor(cat, "$k.$a"))
        }
        if (actions.isEmpty()) throw IllegalArgumentException("compilePolicy: no permissions granted")

        val parsed = LinkedHashMap<String, ParsedLimit>()
        val predicates = ArrayList<Any?>()
        for (s in actions) {
            var r = raw[s.verb] ?: raw[s.action]
            for (a in s.aliases) if (r == null) r = raw[a]
            var lim: ParsedLimit? = null
            if (r != null) {
                lim = parseLimit(r)
                parsed[s.verb] = lim
            }
            val where = ArrayList<Any?>()
            if (lim != null && lim.unit == "usd" && s.amountField == null)
                throw IllegalArgumentException("compilePolicy: '$' limit on '${s.verb}' but the catalog gives that verb no amount field, so the limit could not be enforced")
            if (lim != null && lim.unit == "usd") {
                where.add(Issue.obj("field" to "action.params.${s.amountField}", "op" to "lte", "value" to jn(lim.amount)))
                where.add(Issue.obj("field" to "action.params.${s.amountField}", "op" to "gte", "value" to 0L))
            }
            val p = Issue.obj("verb" to s.verb, "resource" to "*")
            if (where.isNotEmpty()) p["where"] = where
            predicates.add(p)
        }

        val caveats = ArrayList<Any?>()
        var strictest = "reversible"
        for (s in actions) if (sev(s.reversibility) > sev(strictest)) strictest = s.reversibility
        caveats.add(Issue.obj("type" to "reversibility_max", "class" to strictest))
        val minPeriod = parsed.values.mapNotNull { it.periodMs }.minOrNull()
        if (minPeriod != null) caveats.add(Issue.obj("type" to "expires", "at" to now + minPeriod))
        // one rate caveat per count limit (caveats are ANDed): a second limit can only narrow
        for (l in parsed.values)
            if (l.unit == "count" && l.periodMs != null) caveats.add(Issue.obj("type" to "rate", "max" to jn(l.amount), "per_secs" to maxOf(1L, Math.round(l.periodMs / 1000.0))))

        val dollars = parsed.values.filter { it.unit == "usd" }
        val model = when (budgetModel) { "dollars" -> "dollars"; "risk" -> "risk"; else -> if (dollars.isEmpty()) "risk" else "dollars" }
        val hasIrreversible = actions.any { it.reversibility == "irreversible" }
        var rp: Map<String, Any?> = Issue.defaultRiskPolicy()
        if (model == "dollars" && dollars.isNotEmpty()) {
            var kappa = 0.0
            var bMax = 0.0
            for (l in dollars) { kappa = maxOf(kappa, l.amount); bMax += l.amount }
            val d = Issue.defaultRiskPolicy()
            // within-cap actions auto-approve only when nothing granted is irreversible
            rp = Issue.obj("weights" to Issue.obj("alpha" to 0L, "beta" to 0L, "gamma" to 1L, "delta" to 0L, "epsilon" to 0L, "zeta" to 0L),
                "theta1" to (if (hasIrreversible) d["theta1"] else 1L), "theta2" to (if (hasIrreversible) d["theta2"] else 1L),
                "kappa" to (if (kappa > 0) jn(kappa) else 1L), "lambda" to 0L, "rho" to d["rho"], "bMax" to (if (bMax > 0) jn(bMax) else 1L))
        }
        if (riskPolicy != null) {
            val w = LinkedHashMap(Pca.asMap(rp["weights"]))
            if (riskPolicy["weights"] is Map<*, *>) w.putAll(Pca.asMap(riskPolicy["weights"]))
            val merged = LinkedHashMap(rp)
            merged.putAll(riskPolicy)
            merged["weights"] = w
            rp = merged
        }
        val bad = Authorize.riskPolicyError(rp)
        if (bad != null) throw IllegalArgumentException("compilePolicy: derived risk policy invalid: $bad")

        val approximations = ArrayList<String>()
        for ((k, v) in parsed)
            if (v.unit == "usd" && v.periodMs != null)
                approximations.add("$k: $${jsText(v.amount)}/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap")
        return CompiledPolicy(predicates, caveats, rp, actions, model, parsed, LinkedHashMap(raw), approximations)
    }

    // ---- the agent handle --------------------------------------------------------------------------------------------------

    /**
     * Inputs of [Agent.fromPrincipal]. [principal], [goal] and [permissions] are required. [limits]: per-action limits, e.g.
     * `{"refund": "$500/day"}`. [holder]: the agent key (Ed25519 generated when null; a PQ suite key commits its `pq_pk`).
     * [agentBinding]: `{}` when null. [riskPolicy]: members that override the derived policy. [budgetModel]: `auto` (default),
     * `dollars` or `risk`. [aud]: the default audience of `act`. [now]: the clock (ms) for minting and limit windows. [goalSalt]:
     * random when null (pass one only to reproduce a grant byte for byte). [provenance]: the recorder (mediator `agent-harness`,
     * kid `k1`, a fresh key and session by default); its pin is named in the grant's signed envelope.
     */
    class AgentOptions(
        val principal: Keys.SuiteKey,
        val goal: String,
        val permissions: Map<String, Any?>,
        val limits: Map<String, Any?>? = null,
        val holder: Keys.SuiteKey? = null,
        val agentBinding: Map<String, Any?>? = null,
        val riskPolicy: Map<String, Any?>? = null,
        val budgetModel: String? = null,
        val catalog: Catalog? = null,
        val aud: String? = null,
        val now: Long? = null,
        val goalSalt: String? = null,
        val provenance: ArgProvenance.Recorder? = null,
    )

    /** The local, advisory pre-check of an action. [t] is the risk tier admission would assign (1 auto, 2, 3 human co-sign). */
    class DryRun internal constructor(val allowed: Boolean, val reason: String?, val t: Int?)

    /** What [Handle.act] returns. [headers] carries `PCA-Action` and (when it fits) `PCA-Provenance`. */
    class ActResult internal constructor(
        val pcactn: Map<String, Any?>,
        val encoded: String,
        val headers: Map<String, String>,
        val dryRun: DryRun,
        val provenance: Map<String, Any?>,
    )

    /** Build an agent: compile the inputs, create the recorder, mint the grant (see [Agent.fromPrincipal]). */
    fun agent(o: AgentOptions): Handle {
        val cat = o.catalog ?: Catalog.DEFAULT
        val now = o.now ?: System.currentTimeMillis()
        val holder = o.holder ?: Keys.ed25519(Keys.edGenerate())
        val holderEd = holder.ed ?: throw IllegalArgumentException("agent: the holder needs an Ed25519 identity")
        val principalEd = o.principal.ed ?: throw IllegalArgumentException("agent: the principal needs an Ed25519 identity")
        val policy = compilePolicy(o.permissions, o.limits, cat, o.budgetModel, o.riskPolicy, now)
        val rec = o.provenance ?: ArgProvenance.Recorder("agent-harness", "k1")
        val env = Issue.obj("predicates" to policy.predicates, "caveats" to policy.caveats, "agent_binding" to (o.agentBinding ?: LinkedHashMap<String, Any?>()),
            "risk_policy" to policy.riskPolicy, "provenance" to Issue.obj("mediators" to arrayListOf<Any?>(LinkedHashMap(rec.pin))))
        val g = Issue.mintGrant(o.principal, holderEd.id(), holder.pqPk(), env, o.goal, o.goalSalt)
        return Handle(g.grant, listOf(g.grant), g.goalSalt, policy, holder, principalEd.id(), cat, o.aud, now, rec)
    }

    /** Per-call options of [Handle.act]; every member is optional. [caution]: agent uncertainty in [0,1] (a [Json.Num] for a fraction). */
    class ActOptions(
        val counter: Long? = null,
        val now: Long? = null,
        val ttlMs: Long? = null,
        val aud: String? = null,
        val nonce: String? = null,
        val caution: Any? = null,
        /** The risk claimed for this action, overriding the one derived from the catalog. */
        val risk: Double? = null,
    )

    /** An agent under a facade-minted grant: it builds one proof-carrying action per call. Not thread-safe (one counter). */
    class Handle internal constructor(
        val grant: Map<String, Any?>,
        /** The capability chain: the grant first, one more hop per sub-agent. */
        val chain: List<Any?>,
        /** The salt that opens the grant's goal commitment (keep it with the goal). */
        val goalSalt: String,
        val policy: CompiledPolicy,
        /** The agent key: it signs actions and never leaves the client. */
        val holder: Keys.SuiteKey,
        val principalPublic: String,
        private val catalog: Catalog,
        private val defaultAud: String?,
        private val startNow: Long,
        /** The provenance recorder: record the principal's messages and every tool, retrieval and web result the model reads. */
        val provenance: ArgProvenance.Recorder,
    ) {
        private var counter = 0L

        private fun kappa(): Double = Risk.fin(policy.riskPolicy["kappa"]) ?: 0.0
        private fun bMax(): Double = Risk.fin(policy.riskPolicy["bMax"]) ?: 0.0

        /** The starting trust budget `{B = bMax, tau, asOf}` (metered by the server; exposed for planning). */
        fun budget(): Map<String, Any?> = Issue.obj("B" to jn(bMax()), "tau" to startNow, "asOf" to startNow)

        /** The most this agent can do between human co-signs: `bMax / kappa * kappa`. */
        fun autonomyBound(): Double {
            val k = kappa()
            return (if (k > 0) maxOf(0.0, bMax()) / k else 0.0) * k
        }

        /** The grant as canonical JSON (for transport or inspection). */
        fun encodeGrant(): String = Json.canonicalize(grant)

        private fun riskFor(spec: Catalog.Spec, params: Map<String, Any?>?, override: Double?): Double {
            if (override != null) return Risk.clamp01(override)
            if (policy.budgetModel == "dollars" && spec.amountField != null) {
                val amt = jsNumber(params, spec.amountField)
                if (!amt.isNaN() && !amt.isInfinite() && kappa() > 0) return Risk.clamp01(amt / kappa())
            }
            return Risk.clamp01(spec.blastRadius)
        }

        /** JavaScript `Number(params[field])` for the JSON values a param can hold. */
        private fun jsNumber(params: Map<String, Any?>?, field: String): Double {
            if (params == null || !params.containsKey(field)) return Double.NaN
            val v = params[field] ?: return 0.0
            if (v is Boolean) return if (v) 1.0 else 0.0
            IntentJs.num(v)?.let { return it }
            if (v is String) {
                val t = jsTrim(v)
                if (t.isEmpty()) return 0.0
                return t.toDoubleOrNull() ?: Double.NaN
            }
            return Double.NaN
        }

        /** Local, advisory pre-check of the grant's own predicates and caveats, plus the risk tier. Never authoritative. */
        fun dryRun(verb: String, resource: String, params: Map<String, Any?>? = null, now: Long? = null): DryRun {
            val spec = specFor(catalog, verb)
            val t = now ?: System.currentTimeMillis()
            val ctx = Issue.obj("action" to Issue.obj("verb" to verb, "resource" to resource, "params" to (params ?: LinkedHashMap<String, Any?>()),
                "reversibility_class" to spec.reversibility))
            if (!Predicates.evaluatePredicates(policy.predicates, ctx)) return DryRun(false, "no predicate permits $verb on $resource", null)
            // the local handle has no admitted-action history (the server meters it), so a rate caveat is checked against none
            val cctx = Issue.obj("now" to t, "blast_radius" to jn(spec.blastRadius), "reversibility_class" to spec.reversibility,
                "delegation_depth" to (chain.size - 1).toLong(), "recent_action_times" to ArrayList<Any?>())
            val cav = Caveats.evaluateCaveats(policy.caveats, cctx)
            if (!cav.ok) return DryRun(false, "caveat(s) failed: " + cav.failed.joinToString(", "), null)
            val r = riskFor(spec, params, null)
            val tier = Risk.requiredThreshold(r, Risk.Policy.of(policy.riskPolicy)!!).t
            return DryRun(true, null, Risk.admitOf(tier, bMax() >= Risk.cost(r, kappa())).t)
        }

        /**
         * Build a proof-carrying action: a one-node plan (`n0`, the catalog's reversibility, the params digest), the risk claim, the
         * counter (the next one unless `o.counter` is given) and no nonce unless `o.nonce` is given. Records the action with the
         * provenance recorder and returns the bundle. Does NOT authorize anything.
         */
        fun act(verb: String, resource: String, params: Map<String, Any?>? = null, o: ActOptions = ActOptions()): ActResult {
            val aud = o.aud ?: defaultAud
            if (aud.isNullOrEmpty()) throw IllegalArgumentException("act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)")
            val spec = specFor(catalog, verb)
            val node = Issue.obj("id" to "n0", "verb" to verb, "resource" to resource, "reversibility_class" to spec.reversibility, "params_digest" to Pca.paramsDigest(params))
            val r = riskFor(spec, params, o.risk)
            val use: Long
            if (o.counter != null) {
                use = o.counter
                counter = maxOf(counter, o.counter)
            } else use = ++counter
            val pcactn = Issue.buildPCActn(Issue.ActSpec(
                grant = grant, chain = chain, plan = Issue.commitPlan(listOf(node)), nodeId = "n0", counter = use, signer = holder, aud = aud,
                params = params, iat = o.now ?: System.currentTimeMillis(), ttlMs = o.ttlMs, nonce = o.nonce, caution = o.caution,
                riskClaim = Issue.obj("r" to jn(r), "inputs" to Issue.obj("blastRadius" to jn(r))),
            ))
            val bundle = provenance.forAction(Authorize.Operation(verb, resource, params ?: LinkedHashMap()))
            return ActResult(pcactn, Issue.encode(pcactn), Issue.headers(pcactn, provenance = bundle), dryRun(verb, resource, params, o.now), bundle)
        }

        /**
         * A sub-agent: one more (attenuated) hop signed by this agent's key. With no [child], a key is generated: Ed25519, or for a
         * post-quantum holder a fresh key of the same suite (never this agent's PQ key), whose `pq_pk` is committed in the hop.
         */
        fun subAgent(child: Keys.SuiteKey? = null, addedCaveats: List<Any?> = emptyList()): Handle {
            val c = child ?: (holder.pq?.let { Keys.suite(holder.alg, Keys.edGenerate(), Keys.pqGenerate(it.prim)) } ?: Keys.ed25519(Keys.edGenerate()))
            val ced = c.ed ?: throw IllegalArgumentException("subAgent: the sub-agent needs an Ed25519 identity")
            val hop = Issue.delegate(Pca.asMap(chain.last()), ced.id(), addedCaveats, holder, c.pqPk())
            return Handle(grant, chain + listOf<Any?>(hop), goalSalt, policy, c, principalPublic, catalog, defaultAud, startNow, provenance)
        }
    }
}
