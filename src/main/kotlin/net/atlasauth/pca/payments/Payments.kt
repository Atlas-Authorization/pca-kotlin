package net.atlasauth.pca.payments

import net.atlasauth.pca.payments.PayJs.clamp01
import net.atlasauth.pca.payments.PayJs.copy
import net.atlasauth.pca.payments.PayJs.get
import net.atlasauth.pca.payments.PayJs.has
import net.atlasauth.pca.payments.PayJs.isFiniteNum
import net.atlasauth.pca.payments.PayJs.isSafeInteger
import net.atlasauth.pca.payments.PayJs.jn
import net.atlasauth.pca.payments.PayJs.map
import net.atlasauth.pca.payments.PayJs.nz
import net.atlasauth.pca.payments.PayJs.str
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Decide
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Payment mandates over PCA Root Intent Grants, the charge decision and the durable cumulative budget (the reference's mandate, authorize and
 * charge-action modules). A mandate, a charge and every decision are JSON-shaped maps, exactly the reference's objects: numbers are
 * [Json.Num] (or any Kotlin number), bytes are ByteArray or `{"$bytes": b64url}`.
 *
 * The policy decision (the reference's `decide`) defaults to [Decide.decide]; a caller may supply its own [Decider]: this port assembles its
 * exact input ([chargeDecideInput]) and applies everything after it (refusals, outcome, exact money arithmetic, budget threading, the atomic
 * budget store).
 */
@Suppress("UNCHECKED_CAST")
object Payments {
    /** Reversibility class every charge is minted in. */
    const val CHARGE_REVERSIBILITY_CLASS = "reversible"

    /** The action verb a charge denotes. */
    const val CHARGE_VERB = "charge"

    /** Reason on a charge whose amount is not a non-negative safe integer (minor units). */
    const val AMOUNT_NOT_MINOR_UNITS = "amount_not_integer_minor_units"

    /** Reason on a charge whose merchant is not a plain non-empty id. */
    const val MERCHANT_INVALID = "merchant_invalid"

    private const val MAX_CAS_ATTEMPTS = 8

    /** The policy decision: takes the decide input map, returns the policy decision map (releaseGuardianShare, requiredThreshold, r, admit, needStepUp, reasons, budget). */
    fun interface Decider {
        fun decide(input: Map<String, Any?>): Map<String, Any?>?
    }

    private val CORE_DECIDER = Decider { Decide.decide(it) }

    // ---- mandate ----

    /** A merchant id that cannot act as a resource pattern: a non-empty string with no `*` and no control characters. */
    @JvmStatic
    fun isPlainId(x: Any?): Boolean {
        if (x !is String || x.isEmpty()) return false
        for (c in x) if (c == '*' || c.code <= 0x1f || c.code == 0x7f) return false
        return true
    }

    private fun fin(o: Any?): Double? = if (isFiniteNum(o)) PayJs.num(o) else null

    private fun bad(msg: String): Nothing = throw IllegalArgumentException("buildPaymentMandate: $msg")

    private fun validate(p: Map<String, Any?>) {
        // -0 is a number the strict canonicalizer refuses (grant digest, hashCanonical): refuse it here instead of signing it
        for (k in listOf("perTransactionCap", "autoApproveThreshold", "cumulativeCap", "replenishPerCosign", "periodMs", "maxTransactionsPerPeriod", "periodStart", "now")) {
            val v = p[k]
            if ((v is Json.Num || v is Number) && PayJs.num(v) == 0.0 && (v.toString().startsWith("-"))) bad("$k must not be negative zero")
        }
        if (p["strictMinorUnits"] != false) {
            val rep = p["replenishPerCosign"]
            val kv = listOf(
                "perTransactionCap" to p["perTransactionCap"], "autoApproveThreshold" to p["autoApproveThreshold"],
                "cumulativeCap" to p["cumulativeCap"], "replenishPerCosign" to (rep ?: 0L),
            )
            for ((k, v) in kv) if (!isSafeInteger(v)) bad("$k must be a safe integer in minor units (strictMinorUnits)")
        }
        val ms = p["merchants"]
        if (ms !is List<*> || ms.isEmpty()) bad("at least one allowlisted merchant is required")
        for (m in ms) if (m !is String || m.isEmpty()) bad("merchant ids must be non-empty strings")
        for (m in ms) if (!isPlainId(m)) bad("merchant ids must not contain `*` or control characters")
        val cur = p["currency"]
        if (cur !is String || cur.isEmpty()) bad("currency is required")
        val x = fin(p["perTransactionCap"])
        if (x == null || x <= 0) bad("perTransactionCap (X) must be a finite number > 0")
        val y = fin(p["autoApproveThreshold"])
        if (y == null || y < 0 || y > x) bad("autoApproveThreshold (Y) must satisfy 0 ≤ Y ≤ X")
        val cap = fin(p["cumulativeCap"])
        if (cap == null || cap < x) bad("cumulativeCap must be a finite number ≥ perTransactionCap (X)")
        if (p.containsKey("periodMs")) {
            val d = fin(p["periodMs"])
            if (d == null || d <= 0) bad("periodMs must be a finite number > 0 when given")
        }
        if (p.containsKey("maxTransactionsPerPeriod")) {
            val d = fin(p["maxTransactionsPerPeriod"])
            if (d == null || d != Math.rint(d) || d <= 0) bad("maxTransactionsPerPeriod must be a positive integer when given")
        }
        if (p.containsKey("replenishPerCosign")) {
            val d = fin(p["replenishPerCosign"])
            if (d == null || d < 0) bad("replenishPerCosign must be a finite number ≥ 0 when given")
        }
    }

    private fun listOf0(o: Any?, what: String): List<Any?> = o as? List<Any?> ?: throw IllegalArgumentException("$what must be a list")

    /** The allowlist predicates: one per merchant, each carrying the currency, category and hard-ceiling guards. */
    @JvmStatic
    fun mandatePredicates(terms: Map<String, Any?>): List<Any?> {
        val merchants = listOf0(terms["merchants"], "terms.merchants")
        val out = ArrayList<Any?>()
        for (m in merchants) {
            val c1 = map("field" to "action.params.amount", "op" to "lte")
            PayJs.putTerm(c1, "value", terms, "perTransactionCap")
            val c2 = map("field" to "action.params.currency", "op" to "eq")
            PayJs.putTerm(c2, "value", terms, "currency")
            val conds = PayJs.list(c1, c2, map("field" to "action.params.amount", "op" to "gte", "value" to Json.Num("0")))
            val cats = terms["categories"] ?: throw IllegalArgumentException("terms.categories must not be null")
            if (PayJs.jsLength(cats) > 0) conds.add(map("field" to "action.params.category", "op" to "in", "value" to cats))
            out.add(map("verb" to "charge", "resource" to "merchant:" + str(m), "where" to conds))
        }
        return out
    }

    /** The envelope caveats: period window, velocity cap, and the reversibility floor. */
    @JvmStatic
    fun mandateCaveats(terms: Map<String, Any?>): List<Any?> {
        val cs = ArrayList<Any?>()
        if (PayJs.numOf(terms, "periodStart") > 0) cs.add(map("type" to "not_before", "at" to terms["periodStart"]))
        val hasEnd = terms.containsKey("periodEnd")
        if (hasEnd) cs.add(map("type" to "expires", "at" to terms["periodEnd"]))
        if (terms.containsKey("maxTransactionsPerPeriod") && hasEnd) {
            val a = PayJs.numOf(terms, "periodEnd") - PayJs.numOf(terms, "periodStart")
            var secs = Math.max(1.0, jsRound(a / 1000))
            if (a.isNaN()) secs = Double.NaN
            cs.add(map("type" to "rate", "max" to terms["maxTransactionsPerPeriod"], "per_secs" to jn(secs)))
        }
        cs.add(map("type" to "reversibility_max", "class" to "reversible"))
        return cs
    }

    private fun nzNaN(d: Double?): Double = d ?: Double.NaN

    /** Math.round of JavaScript: floor(x + 0.5), NaN and the infinities unchanged. */
    private fun jsRound(x: Double): Double {
        if (x.isNaN() || x.isInfinite()) return x
        val f = Math.floor(x)
        return if (x - f >= 0.5) f + 1 else f
    }

    /** The risk policy that makes "spend = risk" exact (only gamma is weighted; theta1 = theta2 = Y/X; kappa = X; bMax = cumulative cap). */
    @JvmStatic
    fun mandateRiskPolicy(terms: Map<String, Any?>, replenishPerCosign: Any?): Map<String, Any?> {
        val theta = jn(PayJs.numOf(terms, "autoApproveThreshold") / PayJs.numOf(terms, "perTransactionCap"))
        val out = map(
            "weights" to map("alpha" to jn(0.0), "beta" to jn(0.0), "gamma" to jn(1.0), "delta" to jn(0.0), "epsilon" to jn(0.0), "zeta" to jn(0.0)),
            "theta1" to theta, "theta2" to theta,
        )
        PayJs.putTerm(out, "kappa", terms, "perTransactionCap")
        out["lambda"] = jn(0.0)
        out["rho"] = replenishPerCosign
        PayJs.putTerm(out, "bMax", terms, "cumulativeCap")
        return out
    }

    /** The most an agent can spend autonomously between two human co-signs: safetyBound(policy) * kappa. */
    @JvmStatic
    fun autoSpendBound(mandate: Map<String, Any?>): Double {
        val pol = copy(get(mandate, "policy"))
        val kappa = nzNaN(PayJs.num(pol["kappa"]))
        val bMax = nzNaN(PayJs.num(pol["bMax"]))
        val bound = if (kappa > 0) Math.max(0.0, bMax) / kappa else 0.0
        return bound * kappa
    }

    /** Build a payment mandate: the params as a Root Intent Grant envelope plus the initial trust budget. */
    @JvmStatic
    fun buildPaymentMandate(params: Map<String, Any?>): Map<String, Any?> {
        validate(params)
        val now = if (isFiniteNum(params["now"])) PayJs.num(params["now"])!! else System.currentTimeMillis().toDouble()
        val periodStart = if (isFiniteNum(params["periodStart"])) PayJs.num(params["periodStart"])!! else now
        val cats = params["categories"]
        val terms = LinkedHashMap<String, Any?>()
        terms["merchants"] = ArrayList(params["merchants"] as List<Any?>)
        // `params.categories ? [...params.categories] : []`: a falsy value is none, a string spreads to its characters, anything else not iterable throws
        terms["categories"] = if (!PayJs.truthy(cats)) ArrayList<Any?>() else if (cats is String) ArrayList<Any?>(cats.codePoints().toArray().map { String(Character.toChars(it)) }) else ArrayList(listOf0(cats, "categories"))
        terms["currency"] = params["currency"]
        terms["perTransactionCap"] = params["perTransactionCap"]
        terms["autoApproveThreshold"] = params["autoApproveThreshold"]
        terms["cumulativeCap"] = params["cumulativeCap"]
        terms["periodStart"] = jn(periodStart)
        if (params.containsKey("periodMs")) terms["periodEnd"] = jn(periodStart + PayJs.num(params["periodMs"])!!)
        if (params.containsKey("maxTransactionsPerPeriod")) terms["maxTransactionsPerPeriod"] = params["maxTransactionsPerPeriod"]
        val rep = params["replenishPerCosign"]
        val policy = mandateRiskPolicy(terms, rep ?: params["cumulativeCap"])

        val goalO: Any? = params["goal"] ?: (
            "spend ≤ " + str(terms["autoApproveThreshold"]) + " " + str(terms["currency"]) + " autonomously / ≤ " +
                str(terms["perTransactionCap"]) + " with co-sign, ≤ " + str(terms["cumulativeCap"]) + " cumulative, at [" +
                joinStr(terms["merchants"] as List<*>) + "]"
            )
        if (goalO !is String || goalO.isEmpty()) throw IllegalArgumentException("mintGrant: goal required")

        val seed = PayJs.bytes(params["principalSecret"]) ?: throw IllegalArgumentException("buildPaymentMandate: principalSecret is required")
        val principal = Keys.ed25519(Keys.edFromSeed(seed))
        if (principal.id() != params["principalPublic"]) throw IllegalArgumentException("buildPaymentMandate: principalPublic does not match principalSecret")
        val salt = params["goalSalt"]
        val envelope = map("predicates" to mandatePredicates(terms), "caveats" to mandateCaveats(terms), "agent_binding" to map(), "risk_policy" to policy)
        val grant = Issue.mintGrant(principal, params["agentPublic"] as String, null, envelope, goalO, salt as? String)

        return map(
            "grant" to grant.grant, "policy" to policy, "budget" to map("B" to terms["cumulativeCap"], "tau" to jn(now), "asOf" to jn(now)),
            "terms" to terms, "goalCommit" to grant.goalCommit, "goalSalt" to grant.goalSalt,
        )
    }

    private fun joinStr(l: List<*>): String {
        val sb = StringBuilder()
        for (i in l.indices) {
            if (i > 0) sb.append(", ")
            if (l[i] != null) sb.append(str(l[i]))
        }
        return sb.toString()
    }

    // ---- charge action ----

    /** True for a non-negative safe integer that is not -0 (amounts are integer minor units). */
    @JvmStatic
    fun isMinorUnits(x: Any?): Boolean = isSafeInteger(x) && PayJs.num(x)!! >= 0 && !PayJs.isNegZero(x)

    private fun currencyOf(mandate: Map<String, Any?>, charge: Map<String, Any?>): Any? =
        if (has(charge, "currency")) charge["currency"] else get(get(mandate, "terms"), "currency")

    /** The action context a charge denotes (the verb, resource and params the predicates and risk read). */
    @JvmStatic
    fun chargeActionContext(mandate: Map<String, Any?>, charge: Map<String, Any?>): Map<String, Any?> =
        map("action" to map("verb" to CHARGE_VERB, "resource" to "merchant:" + (if (charge.containsKey("merchant")) str(charge["merchant"]) else "undefined"), "params" to chargeParams(mandate, charge), "reversibility_class" to CHARGE_REVERSIBILITY_CLASS))

    /** The charge params committed in both the plan node and the PCActn action. */
    @JvmStatic
    fun chargeParams(mandate: Map<String, Any?>, charge: Map<String, Any?>): Map<String, Any?> {
        val params = LinkedHashMap<String, Any?>()
        if (has(charge, "amount")) params["amount"] = charge["amount"]
        params["currency"] = currencyOf(mandate, charge)
        if (has(charge, "category")) params["category"] = charge["category"]
        return params
    }

    /** The committed plan node for a charge; its params_digest is pinned to the charge params. */
    @JvmStatic
    fun chargePlanNode(mandate: Map<String, Any?>, charge: Map<String, Any?>, id: String): Map<String, Any?> =
        map(
            "id" to id, "verb" to CHARGE_VERB, "resource" to "merchant:" + (if (charge.containsKey("merchant")) str(charge["merchant"]) else "undefined"), "reversibility_class" to CHARGE_REVERSIBILITY_CLASS,
            "params_digest" to Pca.paramsDigest(chargeParams(mandate, charge)),
        )

    /**
     * A signed PCActn for a charge: returns `{pcactn, node}`. [opts]: signerSecret (32-byte Ed25519 seed), aud, counter, and optionally chain,
     * nodeId, now.
     */
    @JvmStatic
    fun chargeToPCActn(mandate: Map<String, Any?>, charge: Map<String, Any?>, opts: Map<String, Any?>): Map<String, Any?> {
        if (!isMinorUnits(charge["amount"])) throw IllegalArgumentException("chargeToPCActn: amount must be a non-negative integer in minor units")
        val nodeId = opts["nodeId"] as String? ?: ("charge:" + str(charge["merchant"]) + ":" + str(opts["counter"]))
        val node = chargePlanNode(mandate, charge, nodeId)
        val x = PayJs.num(get(get(mandate, "terms"), "perTransactionCap")) ?: Double.NaN
        val a = PayJs.num(charge["amount"])
        val amount = if (a != null && isFiniteNum(a)) a else x
        val r = clamp01(if (x > 0) amount / x else 1.0)
        val params = chargeParams(mandate, charge)
        val chain = opts["chain"] as List<Any?>? ?: PayJs.list(get(mandate, "grant"))
        val seed = PayJs.bytes(opts["signerSecret"])
        val counter = PayJs.num(opts["counter"])!!.toLong()
        if (seed == null) throw IllegalArgumentException("chargeToPCActn: signerSecret is required")
        val inputs = LinkedHashMap<String, Any?>(params)
        inputs["blastRadius"] = jn(r)
        val s = Issue.ActSpec(
            grant = chain[0] as Map<String, Any?>,
            chain = chain,
            plan = Issue.commitPlan(listOf(node)),
            nodeId = nodeId,
            counter = counter,
            signer = Keys.ed25519(Keys.edFromSeed(seed)),
            aud = opts["aud"] as String,
            params = params,
            iat = if (opts["now"] != null) PayJs.num(opts["now"])!!.toLong() else null,
            riskClaim = map("r" to jn(r), "inputs" to inputs),
        )
        return map("pcactn" to Issue.buildPCActn(s), "node" to node)
    }

    // ---- authorize ----

    private fun numOr(x: Any?, fallback: Double): Double = if (isFiniteNum(x)) PayJs.num(x)!! else fallback

    private fun bindToVerifiedGrant(mandate: Map<String, Any?>?, verifiedGrant: Any?): Map<String, Any?> {
        if (!PayJs.isObj(verifiedGrant)) throw MandateGrantError("verified_grant_required", "a verified (or stored) grant is required; the mandate's own grant is never the authority")
        if (mandate == null || Pca.hashCanonical(mandate["grant"]) != Pca.hashCanonical(verifiedGrant)) {
            throw MandateGrantError("mandate_grant_mismatch", "the mandate grant is not the verified grant")
        }
        val env = Authorize.readEnvelope(verifiedGrant)
        var ok = env != null && PayJs.truthy(mandate["terms"]) && PayJs.truthy(mandate["policy"])
        if (ok) {
            val terms = mandate["terms"] as Map<String, Any?>
            ok = same(env!!["predicates"], mandatePredicates(terms)) && same(env["caveats"], mandateCaveats(terms)) && same(env["risk_policy"], mandate["policy"])
        }
        if (!ok) throw MandateGrantError("mandate_terms_mismatch", "the mandate terms / policy are not the ones signed into the verified grant")
        val bMax = nzNaN(PayJs.num(get(env!!["risk_policy"], "bMax")))
        val b0 = get(mandate["budget"], "B")
        val budgetB = if (isFiniteNum(b0)) Math.max(0.0, Math.min(PayJs.num(b0)!!, bMax)) else 0.0
        val budget = copy(mandate["budget"])
        budget["B"] = jn(budgetB)
        val out = copy(mandate)
        out["grant"] = verifiedGrant
        out["budget"] = budget
        return out
    }

    private fun same(a: Any?, b: Any?): Boolean = Pca.hashCanonical(a) == Pca.hashCanonical(b)

    /** The decide input for a charge: risk is collapsed to the normalized amount (spend = risk). */
    @JvmStatic
    fun chargeDecideInput(mandate0: Map<String, Any?>?, charge: Map<String, Any?>, now: Double, verifiedGrant: Any?): Map<String, Any?> {
        val mandate = bindToVerifiedGrant(mandate0, verifiedGrant)
        val x = PayJs.num(get(mandate["terms"], "perTransactionCap"))
        val amount = numOr(charge["amount"], Double.POSITIVE_INFINITY)
        val blast = if (x != null && x > 0) amount / x else 1.0
        val cav = map("reversibilityClass" to CHARGE_REVERSIBILITY_CLASS)
        if (has(charge, "recentChargeTimes")) cav["recentActionTimes"] = charge["recentChargeTimes"]
        return map(
            "grant" to verifiedGrant, "action" to chargeActionContext(mandate, charge),
            "risk" to map("semanticDistance" to jn(0.0), "reversibility" to jn(1.0), "blastRadius" to jn(blast), "taint" to jn(0.0), "confidence" to jn(1.0), "age" to jn(0.0)),
            "budget" to mandate["budget"], "now" to jn(now), "caveatContext" to cav,
        )
    }

    private fun budgetCost(r: Double, kappa: Double): Double = nz(kappa) * clamp01(if (r.isNaN() || r.isInfinite()) 1.0 else r)

    /**
     * Run a charge through the PCA decision against the grant the caller VERIFIED (or loaded from its own store). Pure: reads the mandate budget
     * (clamped to the signed bMax) and returns the next budget in `budgetAfter`. Throws [MandateGrantError] when there is no verified grant or
     * the mandate's grant, terms or policy are not that grant's; never throws on a charge. [decider] null = the core [Decide.decide].
     */
    @JvmStatic
    @JvmOverloads
    fun authorizeCharge(mandate0: Map<String, Any?>?, charge: Map<String, Any?>, verifiedGrant: Any?, decider: Decider? = null): Map<String, Any?> {
        val mandate = bindToVerifiedGrant(mandate0, verifiedGrant)
        val now = numOr(charge["now"], System.currentTimeMillis().toDouble())
        val raw: Map<String, Any?>? = (decider ?: CORE_DECIDER).decide(chargeDecideInput(mandate, charge, now, verifiedGrant))
        val refusal = if (!isMinorUnits(charge["amount"])) AMOUNT_NOT_MINOR_UNITS else if (!isPlainId(charge["merchant"])) MERCHANT_INVALID else null
        val decision: Map<String, Any?>
        if (refusal == null) {
            decision = raw ?: throw NullPointerException("the decision is null")
        } else {
            val d = copy(raw)
            d["admit"] = false
            d["releaseGuardianShare"] = false
            val reasons = ArrayList<Any?>()
            reasons.add(refusal)
            val rr = raw?.get("reasons")
            if (rr is List<*>) reasons.addAll(rr)
            d["reasons"] = reasons
            d["budget"] = mandate["budget"]
            decision = d
        }
        val outcome = if (!PayJs.truthy(decision["releaseGuardianShare"])) "deny" else if (PayJs.truthy(decision["admit"])) "auto" else "step_up"

        val kappa = get(mandate["policy"], "kappa")
        val cap = get(mandate["terms"], "perTransactionCap")
        val budget = mandate["budget"]
        val exact = outcome == "auto" && isMinorUnits(charge["amount"]) && isFiniteNum(kappa) && isFiniteNum(cap) &&
            PayJs.num(kappa)!! == PayJs.num(cap)!! && isSafeInteger(get(budget, "B"))
        val cost: Any? = if (outcome == "auto") (if (exact) charge["amount"] else jn(budgetCost(nzNaN(PayJs.num(decision["r"])), nzNaN(PayJs.num(kappa))))) else jn(0.0)
        val budgetAfter: Any? = if (exact) {
            val b = copy(decision["budget"])
            b["B"] = jn(PayJs.num(get(budget, "B"))!! - PayJs.num(charge["amount"])!!)
            b
        } else {
            decision["budget"]
        }
        val rt = decision["requiredThreshold"]
        return map(
            "outcome" to outcome, "t" to get(rt, "t"), "r" to decision["r"], "requiredThreshold" to rt, "cost" to cost, "budgetBefore" to budget,
            "budgetAfter" to budgetAfter, "reasons" to decision["reasons"], "decision" to decision,
        )
    }

    /** Advance the mandate's budget after a decision (functional): the decision's budgetAfter becomes the mandate budget. */
    @JvmStatic
    fun settleCharge(mandate: Map<String, Any?>, decision: Map<String, Any?>): Map<String, Any?> {
        val out = copy(mandate)
        out["budget"] = decision["budgetAfter"]
        return out
    }

    /** Apply a human co-sign: restore autonomous budget by rho (partial) or fully re-confirm to bMax. The ONLY way the budget goes up. */
    @JvmStatic
    fun applyHumanCosign(mandate: Map<String, Any?>, now: Double, full: Boolean): Map<String, Any?> {
        val pol = mandate["policy"]
        val bMax = nzNaN(PayJs.num(get(pol, "bMax")))
        val budget: Any?
        if (full) {
            budget = map("B" to jn(nz(bMax)), "tau" to jn(now), "asOf" to jn(now))
        } else {
            val rho = nz(nzNaN(PayJs.num(get(pol, "rho"))))
            val bo = mandate["budget"] ?: throw IllegalArgumentException("applyHumanCosign: the mandate has no budget")
            val bv = get(bo, "B")
            val absent = !has(bo, "B")
            // JavaScript '+': a string, array or object operand concatenates, anything else adds
            val sum = if (bv is String || bv is List<*> || bv is Map<*, *>) PayJs.toNumber(str(bv) + str(jn(rho)))
            else if (absent) Double.NaN else PayJs.toNumber(bv) + rho
            budget = map("B" to jn(Math.min(nz(bMax), sum)), "tau" to jn(now), "asOf" to jn(now))
        }
        val out = copy(mandate)
        out["budget"] = budget
        return out
    }

    private fun validRecord(r: ChargeBudgetStore.Record?): Boolean {
        if (r == null || !isSafeInteger(r.version) || PayJs.isNegZero(r.version)) return false
        val b = r.budget
        return b is Map<*, *> && isFiniteNum(get(b, "B")) && isFiniteNum(get(b, "tau")) && isFiniteNum(get(b, "asOf"))
    }

    private fun withBudget(mandate: Map<String, Any?>, budget: Any?): Map<String, Any?> {
        val m = copy(mandate)
        m["budget"] = budget
        return m
    }

    /**
     * [authorizeCharge] against the DURABLE cumulative budget in [store]: the debit of an auto charge is committed with an atomic compare-and-set
     * before it is returned, so two concurrent charges cannot both spend the same budget; losing the race re-reads and re-decides. A malformed
     * store throws [ChargeStoreError]; persistent contention returns a deny. [key] null = the grant hash; [decider] null = the core decision.
     */
    @JvmStatic
    @JvmOverloads
    fun authorizeChargeAtomic(mandate: Map<String, Any?>, charge: Map<String, Any?>, verifiedGrant: Any?, store: ChargeBudgetStore?, key: String?, decider: Decider? = null): Map<String, Any?> {
        if (store == null) throw ChargeStoreError("a ChargeBudgetStore with get and compareAndSet is required")
        val k = key ?: Pca.hashCanonical(verifiedGrant)
        for (i in 0 until MAX_CAS_ATTEMPTS) {
            val rec = store.get(k)
            if (rec != null && !validRecord(rec)) throw ChargeStoreError("the store returned a malformed budget record")
            val m = if (rec != null) withBudget(mandate, rec.budget) else mandate
            val d = authorizeCharge(m, charge, verifiedGrant, decider)
            if (d["outcome"] != "auto") return d
            if (store.compareAndSet(k, rec?.version, d["budgetAfter"] as Map<String, Any?>)) return d
        }
        val d = authorizeCharge(mandate, charge, verifiedGrant, decider)
        val out = copy(d)
        out["outcome"] = "deny"
        out["t"] = Json.Num("3")
        out["cost"] = jn(0.0)
        out["budgetAfter"] = d["budgetBefore"]
        val reasons = ArrayList<Any?>()
        reasons.add("budget_store_conflict")
        val dr = d["reasons"]
        if (dr is List<*>) reasons.addAll(dr)
        out["reasons"] = reasons
        return out
    }

    /**
     * [applyHumanCosign] against the DURABLE budget in [store], committed with a compare-and-set. Call it only after you have verified the human
     * co-sign. Persistent contention throws (a co-sign is never silently dropped). [key] null = the grant hash.
     */
    @JvmStatic
    fun applyHumanCosignAtomic(mandate: Map<String, Any?>, verifiedGrant: Any?, store: ChargeBudgetStore?, now: Double, full: Boolean, key: String?): Map<String, Any?> {
        if (store == null) throw ChargeStoreError("a ChargeBudgetStore with get and compareAndSet is required")
        val k = key ?: Pca.hashCanonical(verifiedGrant)
        for (i in 0 until MAX_CAS_ATTEMPTS) {
            val rec = store.get(k)
            if (rec != null && !validRecord(rec)) throw ChargeStoreError("the store returned a malformed budget record")
            val bound = bindToVerifiedGrant(if (rec != null) withBudget(mandate, rec.budget) else mandate, verifiedGrant)
            val next = applyHumanCosign(bound, now, full)["budget"] as Map<String, Any?>
            if (store.compareAndSet(k, rec?.version, next)) return next
        }
        throw ChargeStoreError("could not commit the co-sign: the budget record kept changing")
    }

    /**
     * Opens a challenge-windowed bonded claim for a charge's PCActn: if the charge is later disputed, a fraud proof slashes the bond and the
     * charge is rolled back. Thin wrapper over [ChargeBond.openOptimistic]; REFUSES (throws) an irreversible charge.
     */
    @JvmStatic
    fun openChargeBond(pcactn: Map<String, Any?>?, opts: ChargeBond.OpenOptions, signer: Keys.EdKey): Map<String, Any?> = ChargeBond.openOptimistic(pcactn, opts, signer)
}
