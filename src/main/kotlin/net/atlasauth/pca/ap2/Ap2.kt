package net.atlasauth.pca.ap2

import net.atlasauth.pca.ap2.Chain.MandateIssuer
import net.atlasauth.pca.payments.Payments
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaCore
import net.atlasauth.pca.verifier.Risk

/**
 * AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant.
 *
 * PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is the mandate wire other
 * parties verify. Settlement rails (x402, Stripe Shared Payment Tokens) move the value, fed by PCA's decision. The package is
 * split as [Sdjwt] (SD-JWT and ES256), [Mandates] (shapes, validators, minor units), [Constraints],
 * [Chain] (issue, present, verify), [Settlement] and [Ledger]; this object holds the PCA binding helpers that
 * need no PCA verifier. A PCA mandate is the JSON object `{grant, terms, ...}`; PCA terms are integer minor units of the
 * mandate currency.
 */
@Suppress("UNCHECKED_CAST")
object Ap2 {
    /** The AP2 repository commit whose schemas and documentation this package is checked against. */
    const val AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"

    const val PCA_BINDING_VERSION = 1

    private fun nm(o: Any?): Double = Ap2Js.num(o) ?: Double.NaN

    /** A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused. */
    internal fun minorTerm(v: Any?, name: String): Double {
        val d = Ap2Js.num(v)
        if (!Ap2Js.isSafeInteger(v) || d == null || d < 0 || Ap2Js.isNegZero(d)) {
            throw Ap2Error("PCA term $name must be a non-negative integer in minor units, got ${Ap2Js.str(v)}")
        }
        return d
    }

    /** `JSON.parse(JSON.stringify(v))`: a deep copy through the JSON text. */
    internal fun toJson(v: Any?): Any? {
        val s = Ap2Js.stringify(v) ?: throw IllegalArgumentException("\"undefined\" is not valid JSON")
        return Ap2Js.jsOrder(Json.parseLenient(s))
    }

    // ---------------------------------------------------------------------------------------------
    // PCA terms -> AP2 open mandates
    // ---------------------------------------------------------------------------------------------

    /** The `x_pca` claim of an open mandate: the principal-signed grant and the terms it was minted from. */
    @JvmStatic
    fun pcaOpenClaim(mandate: Map<String, Any?>): Map<String, Any?> =
        Ap2Js.m("v" to Ap2Js.n(PCA_BINDING_VERSION.toLong()), "grant" to toJson(Ap2Js.getU(mandate, "grant")), "terms" to toJson(Ap2Js.getU(mandate, "terms")))

    /** Options for issuing an open mandate from PCA terms. */
    open class FromTermsOptions {
        var issuer: MandateIssuer? = null
        var agentJwk: Map<String, Any?>? = null

        /** Descriptors for every merchant id in the PCA terms (AP2 needs a name; PCA only holds the id). */
        var merchants: List<Any?>? = null

        /** Issued-at, epoch seconds. */
        var iat: Double = Double.NaN

        /** Expiry, epoch seconds; must not exceed the PCA period end. Required when the terms have no period end. */
        var exp: Double? = null
        var salt: (() -> String)? = null
    }

    /** [FromTermsOptions] for the open payment mandate. */
    class PaymentFromTermsOptions : FromTermsOptions() {
        var checkoutReference: String? = null
    }

    /** [FromTermsOptions] for the open checkout mandate: the acceptable line items. */
    class CheckoutFromTermsOptions : FromTermsOptions() {
        var lineItems: List<Any?>? = null
    }

    private fun openExpiry(terms: Map<String, Any?>, o: FromTermsOptions): Double {
        val periodEnd: Double? = if (terms.containsKey("periodEnd")) Math.floor(nm(terms["periodEnd"]) / 1000) else null
        val exp = o.exp ?: periodEnd ?: throw Ap2Error("exp is required when the PCA terms have no period end")
        if (periodEnd != null && !(exp <= periodEnd)) throw Ap2Error("exp must not exceed the PCA period end")
        return exp
    }

    private fun merchantsFor(terms: Map<String, Any?>, merchants: List<Any?>?): List<Any?> {
        val out = ArrayList<Any?>()
        for (id in Ap2Js.arr(terms["merchants"])) {
            var found: Any? = null
            var have = false
            for (x in merchants ?: throw NullPointerException("merchants")) {
                if (Ap2Js.sEq(Ap2Js.get(x, "id"), id)) {
                    found = x
                    have = true
                    break
                }
            }
            if (!have) throw Ap2Error("no merchant descriptor supplied for PCA merchant " + Ap2Js.str(id))
            out.add(found)
        }
        return out
    }

    private fun trunc(x: Double): Double = if (x < 0) Math.ceil(x) else Math.floor(x)

    /**
     * The value of AP2 `payment.budget.max` for a PCA cap in integer minor units. The official AP2 SDK reads it as
     * `int(max * 100)` whatever the currency, while the schema calls it an amount, so two readers exist: the SDK
     * (hundredths) and a major-unit reader (`max * 10^exponent`). The value emitted never lets EITHER read more than the cap:
     * exponent 0 or 1 (JPY) and 2 (USD): `cap / 100`; exponent 3 or more (KWD): `cap / 10^exponent`. The double is
     * nudged up by at most a few ulps when `cap / divisor` falls just under the exact decimal, so that the SDK's
     * `int(max * 100)` is exact (0.29 * 100 is 28.999999999999996 in floating point).
     */
    @JvmStatic
    fun ap2BudgetMax(capMinor: Any?, currency: Any?): Double {
        val cap = minorTerm(capMinor, "cumulativeCap")
        val e = Mandates.currencyExponent(currency)
        val sdkTarget = if (e <= 2) cap else Math.floor(cap / Math.pow(10.0, (e - 2).toDouble()))
        var d = cap / Math.pow(10.0, Math.max(e, 2).toDouble())
        var i = 0
        while (i < 8 && d > 0 && trunc(d * 100) < sdkTarget) {
            d = Math.nextUp(d)
            i++
        }
        if (trunc(d * 100) != sdkTarget || Ap2Js.round(d * Math.pow(10.0, e.toDouble())) > cap) {
            throw Ap2Error("cumulativeCap " + Ap2Js.str(Ap2Js.n(cap)) + " " + Ap2Js.str(currency) + " has no exact AP2 budget.max representation")
        }
        return d
    }

    /** What the two readers of an AP2 `budget.max` read, in minor units of [currency]: `{sdk, major}`. */
    @JvmStatic
    fun ap2BudgetReads(max: Any?, currency: Any?): Map<String, Any?> {
        val e = Mandates.currencyExponent(currency)
        if (!Ap2Js.isFinite(max) || nm(max) < 0) throw Ap2Error("budget.max must be a finite non-negative number, got " + Ap2Js.str(max))
        val m = nm(max)
        return Ap2Js.m("sdk" to Ap2Js.n(trunc(m * 100)), "major" to Ap2Js.n(Ap2Js.round(m * Math.pow(10.0, e.toDouble()))))
    }

    /**
     * The AP2 open payment constraints a set of PCA terms denotes. PCA terms are INTEGER MINOR UNITS of the mandate currency (ISO
     * 4217 exponent per currency: USD 2, JPY 0, KWD 3); `amount_range` is in the same minor units. `budget.max` is
     * derived exactly by [ap2BudgetMax]; no currency is refused for its exponent.
     */
    @JvmStatic
    fun paymentConstraintsFromTerms(terms: Map<String, Any?>, merchants: List<Any?>?, checkoutReference: String?): List<Any?> {
        val cur = Ap2Js.getU(terms, "currency")
        val perTx = minorTerm(terms["perTransactionCap"], "perTransactionCap")
        val budgetMax = ap2BudgetMax(terms["cumulativeCap"], cur)
        val out = ArrayList<Any?>()
        out.add(Ap2Js.m("type" to "payment.amount_range", "currency" to cur, "min" to Ap2Js.n(0L), "max" to Ap2Js.n(perTx)))
        out.add(Ap2Js.m("type" to "payment.allowed_payees", "allowed" to merchantsFor(terms, merchants)))
        out.add(Ap2Js.m("type" to "payment.reference", "conditional_transaction_id" to checkoutReference))
        out.add(Ap2Js.m("type" to "payment.budget", "currency" to cur, "max" to Ap2Js.n(budgetMax)))
        val rec = Ap2Js.m("type" to "payment.agent_recurrence", "frequency" to "ON_DEMAND")
        if (terms.containsKey("maxTransactionsPerPeriod")) rec["max_occurrences"] = terms["maxTransactionsPerPeriod"]
        out.add(rec)
        return out
    }

    private fun fill(c: Chain.OpenMandateCommon, o: FromTermsOptions, exp: Double, pca: Map<String, Any?>) {
        c.issuer = o.issuer
        c.agentJwk = o.agentJwk
        c.iat = o.iat
        c.exp = exp
        c.pca = pca
        c.salt = o.salt
    }

    /** Issue the open payment mandate for a PCA mandate (grant + terms), chained to `checkoutReference`. */
    @JvmStatic
    fun openPaymentMandateFromPca(mandate: Map<String, Any?>, o: PaymentFromTermsOptions): String {
        val terms = Ap2Js.obj(mandate["terms"])
        val input = Chain.OpenPaymentMandateInput()
        val exp = openExpiry(terms, o)
        val pca = pcaOpenClaim(mandate)
        input.constraints = paymentConstraintsFromTerms(terms, o.merchants, o.checkoutReference)
        fill(input, o, exp, pca)
        return Chain.issueOpenPaymentMandate(input)
    }

    /** Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items. */
    @JvmStatic
    fun openCheckoutMandateFromPca(mandate: Map<String, Any?>, o: CheckoutFromTermsOptions): String {
        val terms = Ap2Js.obj(mandate["terms"])
        val input = Chain.OpenCheckoutMandateInput()
        val exp = openExpiry(terms, o)
        val pca = pcaOpenClaim(mandate)
        val constraints = ArrayList<Any?>()
        constraints.add(Ap2Js.m("type" to "checkout.line_items", "items" to o.lineItems))
        constraints.add(Ap2Js.m("type" to "checkout.allowed_merchants", "allowed" to merchantsFor(terms, o.merchants)))
        input.constraints = constraints
        fill(input, o, exp, pca)
        return Chain.issueOpenCheckoutMandate(input)
    }

    // ---------------------------------------------------------------------------------------------
    // the closed payment: binding facts
    // ---------------------------------------------------------------------------------------------

    /**
     * The value the PCActn's signed `nonce` must equal for these AP2 facts: `ap2:<hashCanonical({v, ...facts})>`.
     * [facts] is `{transactionId, payeeId, amount, currency, instrumentId, openHash, agentJkt}`
     * (`openHash`: the `sd_hash` of the open payment mandate token; `agentJkt`: RFC 7638 thumbprint of the
     * agent's AP2 key).
     */
    @JvmStatic
    fun pcaBindingNonce(facts: Map<String, Any?>): String {
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Ap2Js.n(PCA_BINDING_VERSION.toLong())
        body.putAll(facts)
        return "ap2:" + Pca.hashCanonical(body)
    }

    /**
     * amount / cap, clamped to [0, 1] and rounded UP to 12 decimals. PCA's canonical encoding refuses numbers with more than 15
     * significant digits (so 100/300 cannot be signed as-is); rounding up can only raise the risk the threshold policy sees,
     * never lower it.
     */
    @JvmStatic
    fun riskRatio(amount: Double, cap: Double): Double {
        val r = if (cap > 0) amount / cap else 1.0
        return Math.min(1.0, Math.max(0.0, Math.ceil(r * 1e12 - 1e-6) / 1e12))
    }

    // ---------------------------------------------------------------------------------------------
    // the closed payment: PCActn bound to the AP2 mandate
    // ---------------------------------------------------------------------------------------------

    /** Inputs of [buildPcaPaymentBinding]. */
    class PcaPaymentBindingInput {
        /** The PCA mandate (grant + terms + budget) the agent holds. */
        lateinit var mandate: Map<String, Any?>

        /** The open payment mandate token the closed mandate will be chained to. */
        lateinit var open: String
        var agentJwk: Map<String, Any?>? = null

        /** The agent's Ed25519 seed (the PCA grant's holder); signs the PCActn. */
        lateinit var agentSecret: ByteArray

        /** PCA audience (the resource server / Atlas instance id this action is for). */
        lateinit var audience: String
        var counter: Long = 0
        lateinit var transactionId: String
        lateinit var payee: Map<String, Any?>

        /** `{amount, currency}`: integer minor units. */
        lateinit var amount: Map<String, Any?>
        var instrumentId: String? = null
        var category: String? = null

        /** PCActn `iat`, epoch ms (default: now). */
        var now: Long? = null

        /** For a charge that needs a human co-sign: returns the threshold shares over the built PCActn. */
        var cosign: ((Map<String, Any?>) -> Map<String, Any?>)? = null
    }

    /** Build the `x_pca` claim of a closed payment mandate: a PCActn authorising exactly this charge. */
    @JvmStatic
    fun buildPcaPaymentBinding(i: PcaPaymentBindingInput): Map<String, Any?> {
        val major = minorTerm(i.amount["amount"], "amount")
        val charge = Ap2Js.m("merchant" to i.payee["id"], "amount" to Ap2Js.n(major), "currency" to i.amount["currency"])
        if (i.category != null) charge["category"] = i.category
        // an absent payee id is undefined, which the strict canonicalizer of the binding refuses
        if (!i.payee.containsKey("id")) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        val facts = Ap2Js.m(
            "transactionId" to i.transactionId, "payeeId" to i.payee["id"], "amount" to i.amount["amount"], "currency" to i.amount["currency"],
            "instrumentId" to i.instrumentId, "openHash" to Sdjwt.sdHashOf(Sdjwt.parseSdJwtHop(i.open)), "agentJkt" to Sdjwt.jwkThumbprint(i.agentJwk),
        )
        val terms = Ap2Js.obj(i.mandate["terms"])
        val risk = riskRatio(major, nm(terms["perTransactionCap"]))
        val nodeId = "ap2:" + i.transactionId
        val grant = Ap2Js.obj(i.mandate["grant"])
        val node = Payments.chargePlanNode(i.mandate, charge, nodeId)
        val params = Payments.chargeParams(i.mandate, charge)
        val inputs = LinkedHashMap<String, Any?>(params)
        inputs["blastRadius"] = Ap2Js.n(risk)
        val s = Issue.ActSpec(
            grant = grant,
            chain = Ap2Js.l(grant),
            plan = Issue.commitPlan(listOf(node)),
            nodeId = nodeId,
            counter = i.counter,
            signer = Keys.ed25519(Keys.edFromSeed(i.agentSecret)),
            aud = i.audience,
            params = params,
            iat = i.now,
            nonce = pcaBindingNonce(facts),
            riskClaim = Ap2Js.m("r" to Ap2Js.n(risk), "inputs" to inputs),
        )
        val built = Issue.buildPCActn(s)
        var pcactn: Map<String, Any?> = built
        val cosign = i.cosign
        if (cosign != null) {
            val withT = LinkedHashMap<String, Any?>(built)
            withT["threshold"] = cosign(built)
            pcactn = withT
        }
        val c2 = Ap2Js.m("amount" to Ap2Js.n(major), "currency" to i.amount["currency"])
        if (i.category != null) c2["category"] = i.category
        return Ap2Js.m("v" to Ap2Js.n(PCA_BINDING_VERSION.toLong()), "charge" to c2, "pcactn" to toJson(pcactn))
    }

    private fun findConstraint(constraints: Any?, type: String): Any? {
        for (c in Ap2Js.arr(constraints)) if (type == Ap2Js.get(c, "type")) return c
        return null
    }

    /**
     * Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant). Returns the first
     * problem, or null when every constraint is within the terms.
     */
    @JvmStatic
    fun constraintsWithinTerms(open: Map<String, Any?>, terms: Map<String, Any?>): String? {
        val cur = Ap2Js.getU(terms, "currency")
        val perTx = minorTerm(terms["perTransactionCap"], "perTransactionCap")
        val cs = open["constraints"]
        val range = findConstraint(cs, "payment.amount_range") ?: return "open mandate has no amount_range to compare with the PCA per-transaction cap"
        if (!Ap2Js.sEq(Ap2Js.get(range, "currency"), cur)) return "amount_range currency differs from the PCA terms"
        if (!(nm(Ap2Js.get(range, "max")) <= perTx)) return "amount_range.max " + Ap2Js.str(Ap2Js.getU(range, "max")) + " exceeds the PCA per-transaction cap " + Ap2Js.str(Ap2Js.n(perTx))
        val payees = findConstraint(cs, "payment.allowed_payees")
        if (payees != null) {
            for (m in Ap2Js.arr(Ap2Js.get(payees, "allowed"))) {
                var inList = false
                for (id in Ap2Js.arr(terms["merchants"])) if (Ap2Js.sEq(id, Ap2Js.get(m, "id"))) inList = true
                if (!inList) return "allowed_payees names a merchant outside the PCA allowlist"
            }
        }
        if (payees == null) return "open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side"
        val budget = findConstraint(cs, "payment.budget") ?: return "open mandate has no budget to compare with the PCA cumulative cap"
        if (!Ap2Js.sEq(Ap2Js.get(budget, "currency"), cur)) return "budget exceeds the PCA cumulative cap"
        val reads = ap2BudgetReads(Ap2Js.get(budget, "max"), cur)
        val capMinor = minorTerm(terms["cumulativeCap"], "cumulativeCap")
        if (!(nm(reads["sdk"]) <= capMinor) || !(nm(reads["major"]) <= capMinor)) return "budget exceeds the PCA cumulative cap"
        val rec = findConstraint(cs, "payment.agent_recurrence")
        if (terms.containsKey("maxTransactionsPerPeriod")) {
            val mo = Ap2Js.get(rec, "max_occurrences")
            if (rec == null || !Ap2Js.def(rec, "max_occurrences") || !(nm(mo) <= nm(terms["maxTransactionsPerPeriod"]))) return "max_occurrences is missing or exceeds the PCA transaction limit"
        }
        if (terms.containsKey("periodEnd") && (!open.containsKey("exp") || !(nm(open["exp"]) <= Math.floor(nm(terms["periodEnd"]) / 1000)))) return "open mandate outlives the PCA period"
        return null
    }

    // ---------------------------------------------------------------------------------------------
    // verification
    // ---------------------------------------------------------------------------------------------

    /** Inputs of [verifyPcaBinding]. */
    class VerifyPcaBindingInput {
        /** The parsed open payment mandate claims (from the verified AP2 chain). */
        var open: Map<String, Any?>? = null

        /** The parsed closed payment mandate claims. */
        var closed: Map<String, Any?>? = null

        /** `sd_hash` of the open payment mandate hop. */
        var openHash: String? = null

        /** The Ed25519 key (b64u) of the principal who must have signed the grant. */
        var expectedPrincipal: String? = null

        /** Verifier-side PQ pins `issuer -> pq_pk`. */
        var pqPins: Map<String, Any?>? = null

        /** This verifier's PCA audience. */
        var audience: String? = null

        /** Verification time, epoch ms (null = the clock). */
        var now: Long? = null

        /** The PCA mandate state THIS verifier holds (its live budget); required. */
        var mandate: Map<String, Any?>? = null

        /** Epoch-ms times of this holder's earlier admitted charges; required when the mandate limits the charge count. */
        var recentChargeTimes: List<Any?>? = null
        var hooks: PcaCore.Hooks? = null
        var enforce: PcaCore.Enforce? = null
    }

    private fun bindFail(reason: String): Map<String, Any?> = Ap2Js.m("ok" to false, "reason" to reason)

    /**
     * Verify the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal, consistent
     * with the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this audience,
     * committing to exactly this AP2 charge). Run it after `Chain.verifyPaymentChain`. Returns `{ok: true, pcactn, grant, terms}`
     * or `{ok: false, reason}`; throws [PcaBindingError] when the server-held mandate state is missing.
     */
    @JvmStatic
    fun verifyPcaBinding(i: VerifyPcaBindingInput?): Map<String, Any?> {
        val mandate = i?.mandate
        if (i == null || mandate == null) {
            throw PcaBindingError("mandate_required", "verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped")
        }
        if (Ap2Js.def(Ap2Js.get(mandate, "terms"), "maxTransactionsPerPeriod")) {
            var ok = i.recentChargeTimes != null
            if (ok) for (t in i.recentChargeTimes!!) if (!Ap2Js.isNumber(t) || !Ap2Js.isFinite(t)) ok = false
            if (!ok) throw PcaBindingError("charge_history_required", "the mandate limits the charge count: pass recentChargeTimes from your own records")
        }
        try {
            val oc = Ap2Js.get(i.open, "x_pca")
            if (oc !is Map<*, *> || !Ap2Js.sEq(Ap2Js.get(oc, "v"), Ap2Js.n(PCA_BINDING_VERSION.toLong())) || Ap2Js.get(oc, "grant") !is Map<*, *> || Ap2Js.get(oc, "terms") !is Map<*, *>) {
                return bindFail("open mandate carries no x_pca grant")
            }
            val grant = Ap2Js.obj(Ap2Js.get(oc, "grant"))
            val terms = Ap2Js.obj(Ap2Js.get(oc, "terms"))
            val chain = Pca.verifyChain(Ap2Js.l(grant), i.expectedPrincipal ?: return bindFail("PCA grant: no expected principal"), true, null, i.pqPins, null)
            if (chain.isNotEmpty()) return bindFail("PCA grant: $chain")
            val env = Authorize.readEnvelope(grant) ?: return bindFail("PCA grant has no envelope")
            if (Pca.hashCanonical(env["predicates"]) != Pca.hashCanonical(Payments.mandatePredicates(terms)) ||
                Pca.hashCanonical(env["caveats"]) != Pca.hashCanonical(Payments.mandateCaveats(terms))
            ) {
                return bindFail("x_pca terms do not match the grant envelope")
            }
            val pol = Ap2Js.obj(env["risk_policy"])
            if (!Ap2Js.sEq(pol["kappa"], terms["perTransactionCap"]) || !Ap2Js.sEq(pol["bMax"], terms["cumulativeCap"])) return bindFail("x_pca terms do not match the grant risk policy")
            val within = constraintsWithinTerms(i.open ?: return bindFail("open mandate carries no x_pca grant"), terms)
            if (within != null) return bindFail(within)

            val cc = Ap2Js.get(i.closed, "x_pca")
            if (cc !is Map<*, *> || !Ap2Js.sEq(Ap2Js.get(cc, "v"), Ap2Js.n(PCA_BINDING_VERSION.toLong())) || Ap2Js.get(cc, "pcactn") !is Map<*, *> || Ap2Js.get(cc, "charge") !is Map<*, *>) {
                return bindFail("closed mandate carries no x_pca PCActn")
            }
            val pcactn = Ap2Js.obj(Ap2Js.get(cc, "pcactn"))
            val charge = Ap2Js.obj(Ap2Js.get(cc, "charge"))
            val amt = Ap2Js.get(i.closed, "payment_amount")
            val payee = Ap2Js.get(i.closed, "payee")
            if (!Ap2Js.sEq(charge["currency"], Ap2Js.get(amt, "currency")) || !Ap2Js.sEq(charge["amount"], Ap2Js.get(amt, "amount"))) return bindFail("x_pca charge differs from the mandate payment_amount")
            val cats = Ap2Js.arr(terms["categories"])
            if (cats.isNotEmpty()) {
                var has = false
                if (charge["category"] is String) for (c in cats) if (Ap2Js.sEq(c, charge["category"])) has = true
                if (!has) return bindFail("x_pca charge lacks an allowed category")
            }

            // the `t` the threshold hook REPORTS it enforced (as the core verifier does): a hook built for a smaller t cannot satisfy a charge that needs more
            val co = PcaCore.Options(grant)
            co.insecureSkipPlanRootCheck = true
            co.audience = i.audience?.let { Pca.Audience.Of(it) } ?: Pca.Audience.Unset
            co.nowEpoch = i.now
            co.hooks = i.hooks
            co.enforce = i.enforce
            val core = PcaCore.verify(pcactn, co)
            if (!core.allow) return bindFail("PCActn: " + (core.reason ?: "rejected"))
            val enforcedT = core.enforcedT
            val act = Ap2Js.obj(pcactn["action"])
            if ("charge" != act["verb"] || !Ap2Js.sEq(act["resource"], "merchant:" + Ap2Js.str(Ap2Js.get(payee, "id")))) return bindFail("PCActn action is not a charge at this payee")
            val params = Ap2Js.m("amount" to charge["amount"], "currency" to charge["currency"])
            if (charge["category"] is String) params["category"] = charge["category"]
            if (!Ap2Js.sEq(act["params_digest"], Pca.paramsDigest(params))) return bindFail("PCActn params do not commit to the x_pca charge")
            val cnf = Ap2Js.get(i.open, "cnf")
            // `i.open.cnf.jwk`: a missing or null cnf throws; the refusal text is the engine's message, which this result carries as its reason
            if (cnf == null) throw IllegalStateException("Cannot read properties of " + (if ((i.open as? Map<*, *>)?.containsKey("cnf") == true) "null" else "undefined") + " (reading 'jwk')")
            val agentJwk = Ap2Js.get(cnf, "jwk")
            val facts = Ap2Js.m(
                "transactionId" to Ap2Js.get(i.closed, "transaction_id"), "payeeId" to Ap2Js.get(payee, "id"), "amount" to Ap2Js.get(amt, "amount"), "currency" to Ap2Js.get(amt, "currency"),
                "instrumentId" to Ap2Js.get(Ap2Js.get(i.closed, "payment_instrument"), "id"), "openHash" to i.openHash, "agentJkt" to Sdjwt.jwkThumbprint(agentJwk),
            )
            if (!Ap2Js.sEq(pcactn["nonce"], pcaBindingNonce(facts))) return bindFail("PCActn nonce does not bind this AP2 transaction, open mandate and agent key")
            if (!(nm(Ap2Js.get(amt, "amount")).isFinite() && nm(Ap2Js.get(amt, "amount")) <= minorTerm(terms["perTransactionCap"], "perTransactionCap"))) return bindFail("payment exceeds the PCA per-transaction cap")
            // the agent may not understate the risk of its own charge, and a charge whose risk needs a human co-sign (t > 1) is only accepted with a threshold verifier
            val recomputed = riskRatio(nm(Ap2Js.get(amt, "amount")), nm(terms["perTransactionCap"]))
            val claimed = Ap2Js.get(pcactn["risk_claim"], "r")
            if (!(Ap2Js.isNumber(claimed) && nm(claimed) >= recomputed - 1e-9)) return bindFail("PCActn understates the risk of this charge")
            val policy = Risk.Policy(emptyMap(), nm(pol["theta1"]), nm(pol["theta2"]), 0.0, 0.0, 0.0, 0.0)
            val need = Risk.requiredThreshold(nm(claimed), policy, false)
            if (need.t > 1 && i.hooks?.threshold == null) return bindFail("this charge needs a threshold of ${need.t} (human co-sign); supply hooks.threshold to verify it")
            if (need.t > 1 && !(enforcedT != null && enforcedT >= need.t)) {
                return bindFail(
                    "this charge needs a threshold of ${need.t} but the threshold hook enforced t=" + (if (enforcedT == null) "unreported" else Ap2Js.numStr(enforcedT)) +
                        "; build it with createThresholdVerifier({ t: ${need.t} })",
                )
            }
            if (!Ap2Js.sEq(Ap2Js.get(amt, "currency"), terms["currency"]) || !containsStr(terms["merchants"], Ap2Js.get(payee, "id"))) return bindFail("payment currency or payee is outside the PCA terms")

            if (Pca.hashCanonical(mandate["grant"]) != Pca.hashCanonical(grant)) return bindFail("the supplied PCA mandate is not the one in the open mandate")
            // `grant` was verified above under the caller-pinned principal; the decision is bound to it
            val ch = Ap2Js.m("merchant" to Ap2Js.get(payee, "id"), "amount" to Ap2Js.get(amt, "amount"), "currency" to Ap2Js.get(amt, "currency"))
            if (charge["category"] is String) ch["category"] = charge["category"]
            ch["recentChargeTimes"] = i.recentChargeTimes ?: ArrayList<Any?>()
            val now = i.now
            if (now != null) ch["now"] = Ap2Js.n(now)
            val decision = Payments.authorizeCharge(mandate, ch, grant)
            val outcome = decision["outcome"]
            if ("deny" == outcome) {
                val rs = ArrayList<String>()
                for (r in Ap2Js.arr(decision["reasons"])) rs.add(Ap2Js.str(r))
                return bindFail("PCA denies this charge: " + rs.joinToString("; "))
            }
            if ("step_up" == outcome && !(enforcedT != null && enforcedT >= 2)) return bindFail("PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced")
            return Ap2Js.m("ok" to true, "pcactn" to pcactn, "grant" to grant, "terms" to terms)
        } catch (e: RuntimeException) {
            return bindFail(e.message ?: e.toString())
        }
    }

    private fun containsStr(list: Any?, v: Any?): Boolean {
        if (list !is List<*>) throw IllegalStateException("terms.merchants is not an array")
        for (x in list) if (Ap2Js.sEq(x, v)) return true
        return false
    }

    /** Thrown when the PCA binding verifier lacks the server-held state the policy decision needs. */
    class PcaBindingError(
        /** `mandate_required` or `charge_history_required`. */
        val code: String,
        message: String,
    ) : RuntimeException(message)
}
