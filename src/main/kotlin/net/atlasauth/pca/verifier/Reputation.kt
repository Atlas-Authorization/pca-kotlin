package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.RoundingMode
import net.atlasauth.pca.compliance.ComplianceJs

/**
 * Reputation and underwriting (reputation.ts): an explainable score in [0,1] from a subject's activity and disputes, a transparent
 * premium curve, and signed coverage quotes whose price the verifier recomputes. Inputs and results are JSON trees (maps, lists,
 * strings, booleans, [Json.Num]).
 *
 * Advisory by construction: nothing in the verifier reads a reputation, and it must never be wired into an allow decision. The score is
 * a pure function of validated input (unusable input scores 0 and says why; a dispute counts once per id).
 */
@Suppress("UNCHECKED_CAST")
object Reputation {
    /** Upper bound on the events and on the disputes of one input. */
    const val MAX_REPUTATION_RECORDS = 100_000
    const val COVERAGE_QUOTE_DOMAIN = "atlas-pca/coverage-quote/v1\u0000"
    private val OUTCOMES = setOf("auto", "step_up", "deny", "executed")

    private fun js(x: Double): String = AttestUtil.jsNumString(x)

    /** JavaScript `x.toFixed(digits)`: the exact value rounded half away from zero (the number's own text from 1e21 and for NaN). */
    internal fun toFixed(x: Double, digits: Int): String {
        if (x.isNaN() || Math.abs(x) >= 1e21) return js(x)
        val s = BigDecimal(Math.abs(x)).setScale(digits, RoundingMode.HALF_UP).toPlainString()
        return if (x < 0) "-$s" else s
    }

    /** The member read with a default of `[]`: absent is empty, anything that is not a list (null too) is null. */
    private fun listOr(m: Map<*, *>, k: String): List<Any?>? = if (!m.containsKey(k)) emptyList() else m[k] as? List<Any?>

    /** Why `input` (`{subject, events?, disputes?}`) is unusable, or null. */
    fun validateReputationInput(input: Any?): String? {
        val m = input as? Map<*, *>
        val subject = m?.get("subject")
        if (m == null || subject !is String || subject.isEmpty()) return "subject must be a non-empty string"
        val events = listOr(m, "events")
        val disputes = listOr(m, "disputes")
        if (events == null || disputes == null) return "events and disputes must be arrays"
        if (events.size > MAX_REPUTATION_RECORDS || disputes.size > MAX_REPUTATION_RECORDS) return "too many records"
        if (events.any { e -> (e as? Map<*, *>)?.get("outcome").let { it !is String || it !in OUTCOMES } }) return "event with an unknown outcome"
        for (o in disputes) {
            val d = o as? Map<*, *>
            val id = d?.get("id")
            if (d == null || id !is String || id.isEmpty()) return "dispute without an id"
            if (d["subject"] != subject) return "dispute for another subject"
            if (d["slashed"] !is Boolean) return "dispute.slashed must be a boolean"
            if (!IntentJs.isFinite(d["at"]) || IntentJs.num(d["at"])!! < 0) return "dispute.at must be finite and >= 0"
            if (d.containsKey("amount") && (!IntentJs.isFinite(d["amount"]) || IntentJs.num(d["amount"])!! < 0)) return "dispute.amount must be finite and >= 0"
        }
        return null
    }

    private fun rep(subject: Any?, actions: Int, autos: Int, stepUps: Int, denies: Int, slashes: Int, disputes: Int, score: Double, factors: List<Any?>): Map<String, Any?> =
        linkedMapOf(
            "subject" to subject, "actions" to StoreJs.num(actions.toLong()), "autos" to StoreJs.num(autos.toLong()), "stepUps" to StoreJs.num(stepUps.toLong()),
            "denies" to StoreJs.num(denies.toLong()), "slashes" to StoreJs.num(slashes.toLong()), "disputes" to StoreJs.num(disputes.toLong()),
            "score" to StoreJs.num(score), "factors" to factors,
        )

    /**
     * The reputation of a subject `{subject, actions, autos, stepUps, denies, slashes, disputes, score, factors}`: the score starts at 1
     * and loses the deny rate (x0.6), the step-up rate (x0.15) and, dominant, 0.3 per slashed dispute (at most 0.8). A subject with no
     * history scores a neutral 0.5; unusable input fails closed to 0 with the reason in `factors`. Never throws.
     */
    fun reputation(input: Any?): Map<String, Any?> {
        val bad = validateReputationInput(input)
        if (bad != null) {
            val s = (input as? Map<*, *>)?.get("subject")
            return rep(if (s == null) "" else IntentRevocation.jsText(s, true), 0, 0, 0, 0, 0, 0, 0.0, arrayListOf<Any?>("invalid input: $bad"))
        }
        val m = input as Map<String, Any?>
        val events = listOr(m, "events")!!
        val seen = HashSet<Any?>()
        val disputes = listOr(m, "disputes")!!.map { it as Map<*, *> }.filter { seen.add(it["id"]) }
        val actions = events.size
        val outcomes = events.map { (it as Map<*, *>)["outcome"] }
        val autos = outcomes.count { it == "auto" }
        val stepUps = outcomes.count { it == "step_up" }
        val denies = outcomes.count { it == "deny" }
        val slashes = disputes.count { it["slashed"] == true }
        if (actions == 0 && disputes.isEmpty()) return rep(m["subject"], actions, autos, stepUps, denies, slashes, 0, 0.5, arrayListOf<Any?>("unproven (no history)"))

        val factors = ArrayList<Any?>()
        var score = 1.0
        if (actions > 0) {
            val denyRate = denies.toDouble() / actions
            val stepUpRate = stepUps.toDouble() / actions
            if (denyRate > 0) {
                score -= 0.6 * denyRate
                factors.add("deny rate ${toFixed(denyRate * 100, 0)}%")
            }
            if (stepUpRate > 0) {
                score -= 0.15 * stepUpRate
                factors.add("step-up rate ${toFixed(stepUpRate * 100, 0)}%")
            }
        }
        if (slashes > 0) {
            score -= Math.min(0.8, 0.3 * slashes)
            factors.add("$slashes slashed dispute${if (slashes > 1) "s" else ""}")
        }
        if (factors.isEmpty()) factors.add("clean history")
        return rep(m["subject"], actions, autos, stepUps, denies, slashes, disputes.size, Math.max(0.0, Math.min(1.0, score)), factors)
    }

    // ---- underwriting ----

    private val DEFAULTS = linkedMapOf<String, Any?>("baseRate" to Json.Num("0.01"), "riskLoad" to Json.Num("4"), "minScore" to Json.Num("0.25"))

    /** The option as given, or its default when absent or null (the reference's `??`). */
    private fun opt(opts: Map<String, Any?>?, k: String): Any? = opts?.get(k) ?: DEFAULTS[k]

    private fun pricing(declined: Boolean, premium: Double, coverage: Double, rationale: String): Map<String, Any?> =
        linkedMapOf("declined" to declined, "premium" to StoreJs.num(premium), "coverage" to StoreJs.num(coverage), "rationale" to rationale)

    /**
     * Price coverage of `exposure` for a subject with reputation `rep` (only its `score` is read): `{declined, premium, coverage,
     * rationale}` with `premium = baseRate * exposure * (1 + riskLoad * (1 - score))`, declined below `minScore` and for a score that is
     * not a number in [0,1]. `opts` may carry `baseRate` (0.01), `riskLoad` (4) and `minScore` (0.25). A non-finite exposure counts as
     * 0. Throws IllegalArgumentException when `rep` is null.
     */
    @JvmOverloads
    fun priceCoverage(rep: Any?, exposure: Double, opts: Map<String, Any?>? = null): Map<String, Any?> {
        if (rep == null) throw IllegalArgumentException("priceCoverage: no reputation")
        val baseRate = ComplianceJs.toNumber(opt(opts, "baseRate"))
        val riskLoad = ComplianceJs.toNumber(opt(opts, "riskLoad"))
        val minScore = opt(opts, "minScore")
        val score = IntentJs.num((rep as? Map<*, *>)?.get("score"))
        if (score == null || score.isNaN() || score.isInfinite() || score < 0 || score > 1) return pricing(true, 0.0, 0.0, "invalid reputation score")
        val exp = if (!exposure.isNaN() && !exposure.isInfinite()) Math.max(0.0, exposure) else 0.0
        if (score < ComplianceJs.toNumber(minScore)) {
            return pricing(true, 0.0, 0.0, "reputation ${toFixed(score, 2)} below underwriting floor ${IntentRevocation.jsText(minScore, true)}")
        }
        val load = 1 + riskLoad * (1 - score)
        return pricing(
            false, baseRate * exp * load, exp,
            "base ${IntentRevocation.jsText(opt(opts, "baseRate"), true)} × exposure ${js(exp)} × load ${toFixed(load, 2)} (score ${toFixed(score, 2)})",
        )
    }

    // ---- signed coverage quotes ----

    private fun quoteMessage(claim: Map<String, Any?>): ByteArray = Pca.concat(Json.utf8(COVERAGE_QUOTE_DOMAIN), Pca.canonicalBytesLenient(claim))

    private fun scoreOk(v: Any?): Boolean = IntentJs.isFinite(v) && IntentJs.num(v)!! >= 0 && IntentJs.num(v)!! <= 1

    /**
     * Price and sign a coverage quote for the reputation `rep`: the claim `{v, subject, score, exposure, baseRate, riskLoad, minScore,
     * declined, premium, coverage, issued_at, expires_at, underwriter}` plus `sig`. Throws IllegalArgumentException on a bad exposure,
     * time, score or a reputation without a subject (a nonsense quote is never signed).
     */
    @JvmOverloads
    fun issueCoverageQuote(rep: Map<String, Any?>, exposure: Double, underwriter: Keys.EdKey, now: Double, ttlMs: Double, opts: Map<String, Any?>? = null): Map<String, Any?> {
        require(!exposure.isNaN() && !exposure.isInfinite() && exposure >= 0) { "issueCoverageQuote: exposure must be finite and >= 0" }
        require(!now.isNaN() && !now.isInfinite() && ttlMs > 0 && !ttlMs.isInfinite()) { "issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0" }
        require(scoreOk(rep["score"])) { "issueCoverageQuote: invalid reputation score" }
        val used = linkedMapOf("baseRate" to opt(opts, "baseRate"), "riskLoad" to opt(opts, "riskLoad"), "minScore" to opt(opts, "minScore"))
        val p = priceCoverage(rep, exposure, used)
        require(rep.containsKey("subject")) { "canonicalize: unsupported type undefined" }
        val claim = linkedMapOf<String, Any?>("v" to StoreJs.num(1L), "subject" to rep["subject"], "score" to rep["score"], "exposure" to StoreJs.num(exposure))
        claim.putAll(used)
        claim["declined"] = p["declined"]
        claim["premium"] = p["premium"]
        claim["coverage"] = p["coverage"]
        claim["issued_at"] = StoreJs.num(now)
        claim["expires_at"] = StoreJs.num(now + ttlMs)
        claim["underwriter"] = underwriter.id()
        val sig = Keys.b64u(underwriter.sign(quoteMessage(claim)))
        claim["sig"] = sig
        return claim
    }

    private fun verdict(reason: String?): Map<String, Any?> = if (reason == null) linkedMapOf("ok" to true) else linkedMapOf("ok" to false, "reason" to reason)

    private val QUOTE_NUMBERS = listOf("score", "exposure", "baseRate", "riskLoad", "minScore", "premium", "coverage", "issued_at", "expires_at")

    /**
     * Verify a coverage quote: `{ok: true}` or `{ok: false, reason}` with reason `malformed`, `underwriter` (not the pinned key),
     * `signature`, `not-yet-valid`, `expired` or `price-mismatch` (the premium is recomputed from the stated inputs). Never throws.
     */
    fun verifyCoverageQuote(quote: Any?, underwriter: Any?, now: Double): Map<String, Any?> = try {
        val q = quote as? Map<String, Any?>
        when {
            q == null || IntentJs.num(q["v"]) != 1.0 || q["sig"] !is String -> verdict("malformed")
            QUOTE_NUMBERS.any { !IntentJs.isFinite(q[it]) } || q["declined"] !is Boolean || q["subject"] !is String -> verdict("malformed")
            underwriter !is String || underwriter != q["underwriter"] -> verdict("underwriter")
            !Pca.verifyB64u(underwriter, quoteMessage(LinkedHashMap(q).also { it.remove("sig") }), q["sig"] as String) -> verdict("signature")
            now.isNaN() || now.isInfinite() || now < IntentJs.num(q["issued_at"])!! -> verdict("not-yet-valid")
            now >= IntentJs.num(q["expires_at"])!! -> verdict("expired")
            else -> {
                val p = priceCoverage(q, IntentJs.num(q["exposure"])!!, linkedMapOf("baseRate" to q["baseRate"], "riskLoad" to q["riskLoad"], "minScore" to q["minScore"]))
                val same = p["declined"] == q["declined"] && IntentJs.num(p["premium"]) == IntentJs.num(q["premium"]) && IntentJs.num(p["coverage"]) == IntentJs.num(q["coverage"])
                verdict(if (same) null else "price-mismatch")
            }
        }
    } catch (e: RuntimeException) {
        verdict("malformed")
    }
}
