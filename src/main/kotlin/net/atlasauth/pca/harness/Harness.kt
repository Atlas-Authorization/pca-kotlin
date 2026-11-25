package net.atlasauth.pca.harness

import java.math.BigDecimal
import java.math.RoundingMode
import java.security.SecureRandom
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Risk

/**
 * "Attest the mediator, not the weights". The trusted computing base is this small orchestration harness, not an opaque model: the
 * model is an untrusted oracle that proposes a candidate action, and the harness enforces plan inclusion, the taint fold and the trust
 * budget before any candidate becomes a signed PCActn. The oracle holds no signing key.
 */
@Suppress("UNCHECKED_CAST")
class Harness(opts: Options) {
    /** Construction options. Fields the reference validates at runtime are `Any?` so a malformed value is refused the same way. */
    class Options {
        /** The principal-signed root capability (a JSON object); only its `id` is read. */
        @JvmField var grant: Map<String, Any?>? = null

        /** The capability chain ending at the leaf the harness signs for; null means `[grant]`. */
        @JvmField var chain: List<Any?>? = null

        /** The 32-byte Ed25519 seed of the leaf holder. The oracle never sees it. */
        @JvmField var agentSeed: ByteArray? = null

        /** The principal-authorised, committed plan: a non-empty list of nodes. */
        @JvmField var plan: Any? = null

        /** The audience the PCActns are for (a non-empty string). */
        @JvmField var audience: Any? = null

        /** The decaying trust budget `{B, tau, asOf}`. */
        @JvmField var budget: Any? = null

        /** The risk policy; null means the reference default. */
        @JvmField var policy: Map<String, Any?>? = null

        /** Base risk inputs before taint folding; null means the low, reversible default profile. */
        @JvmField var baseRisk: Map<String, Any?>? = null

        /** Clock (epoch ms); null means the system clock. */
        @JvmField var now: (() -> Long)? = null

        /** TTL stamped into each PCActn (ms); null means the default. */
        @JvmField var ttlMs: Long? = null

        /** Override of the enforced-checks manifest that feeds the measurement. */
        @JvmField var measurementManifest: List<String>? = null

        /** Nonce source; null means 16 random bytes as hex. */
        @JvmField var nonce: (() -> String)? = null

        /** When set (`operator`, optional `epoch`), the harness stamps its self-measurement into every PCActn's attestation block. */
        @JvmField var attestation: Map<String, Any?>? = null
    }

    private val grant: Map<String, Any?>
    private val chain: List<Any?>
    private val signer: Keys.SuiteKey
    private val planIndex = LinkedHashMap<String, Map<String, Any?>>()
    private val committed: Issue.Plan
    private val audience: String
    private val policy: Map<String, Any?>
    private val baseRisk: Map<String, Any?>
    private val now: () -> Long
    private val ttlMs: Long?
    private val manifest: List<String>
    private val nonce: () -> String
    private val attest: Map<String, Any?>?
    private var budget: Map<String, Any?>
    private var counter: Long = 0

    init {
        val aud = opts.audience
        if (aud !is String || aud.isEmpty()) throw IllegalArgumentException("Harness: `audience` is required (the resource-server / instance id PCActns are for)")
        val seed = opts.agentSeed
        if (seed == null || seed.size != 32) throw IllegalArgumentException("Harness: `agentSecret` must be a 32-byte Ed25519 secret key")
        val nodes = opts.plan
        if (nodes !is List<*> || nodes.isEmpty()) throw IllegalArgumentException("Harness: `plan` must be a non-empty array (an empty plan authorises nothing)")
        val ids = HashSet<Any?>()
        for (n in nodes) ids.add(Js.member(n, "id"))
        if (ids.size != nodes.size) throw IllegalArgumentException("Harness: plan node ids must be unique")
        val b = opts.budget
        if (b !is Map<*, *> || !Js.isFinite(b["B"]) || Js.num(b["B"])!! < 0 || !Js.isFinite(b["tau"]) || !Js.isFinite(b["asOf"]))
            throw IllegalArgumentException("Harness: `budget` must have finite B >= 0, tau and asOf")
        grant = opts.grant!!
        chain = opts.chain ?: arrayListOf<Any?>(opts.grant)
        signer = Keys.ed25519(Keys.edFromSeed(seed))
        val planNodes = ArrayList<Map<String, Any?>>()
        for (n in nodes) {
            if (n !is Map<*, *>) throw IllegalArgumentException("Harness: plan nodes must be objects")
            planNodes.add(n as Map<String, Any?>)
        }
        for (n in planNodes) planIndex[n["id"] as String] = n
        committed = Issue.commitPlan(planNodes)
        audience = aud
        policy = opts.policy ?: Issue.defaultRiskPolicy()
        val base = linkedMapOf<String, Any?>(
            "semanticDistance" to Json.Num("0.1"), "reversibility" to Json.Num("1"), "blastRadius" to Json.Num("0.1"),
            "taint" to Json.Num("0"), "confidence" to Json.Num("1"), "age" to Json.Num("0"),
        )
        opts.baseRisk?.let { base.putAll(it) }
        baseRisk = base
        now = opts.now ?: { System.currentTimeMillis() }
        ttlMs = opts.ttlMs
        manifest = opts.measurementManifest ?: ENFORCED_CHECKS
        nonce = opts.nonce ?: { randomHex() }
        attest = opts.attestation
        budget = LinkedHashMap(b as Map<String, Any?>)
    }

    /** The committed plan root the principal authorised. */
    fun planRoot(): String = committed.root

    /** The current (leaked-to-last-touch) trust budget `{B, tau, asOf}`. */
    fun budget(): Map<String, Any?> = budget

    /** Monotonic action counter: the number of PCActns this harness has emitted. */
    fun counter(): Long = counter

    /** The harness's self-measurement: what a remote attestation of the mediator would cover. */
    fun harnessMeasurement(): String = computeHarnessMeasurement(HARNESS_VERSION, manifest, policy)

    /**
     * Ask the untrusted oracle for a candidate action and, only if it survives the invariant gate, emit a signed PCActn. Order: plan
     * inclusion, taint fold, trust budget, sign. A throwing oracle or a malformed candidate is a refusal (`bad_candidate`), never an exception.
     * Returns `{ok:true, pcactn, inclusionProof, risk, budget}` or `{ok:false, reason, detail, requiredT?, budget?}`.
     */
    @Synchronized
    fun step(proposeAction: () -> Any?): Map<String, Any?> {
        val candidate: Any? = try {
            proposeAction()
        } catch (e: Exception) {
            return refuse("bad_candidate", "oracle failed: " + (e.message ?: "unknown error"))
        }
        // (0) the oracle is untrusted: validate the shape before use
        if (candidate !is Map<*, *> || candidate["nodeId"] !is String || candidate["verb"] !is String || candidate["resource"] !is String)
            return refuse("bad_candidate", "oracle returned a malformed candidate")
        val cand = candidate as Map<String, Any?>
        val nodeId = cand["nodeId"] as String
        // (1) plan inclusion: reject out-of-plan BEFORE signing
        val node = planIndex[nodeId] ?: return refuse("out_of_plan", "node '$nodeId' is not in the committed plan")
        if (node["verb"] != cand["verb"] || node["resource"] != cand["resource"]) {
            return refuse(
                "out_of_plan",
                "action ${cand["verb"]} ${cand["resource"]} does not match committed node '${Js.template(node["id"])}' (${strMember(node, "verb")} ${strMember(node, "resource")})",
            )
        }
        val inclusionProof = committed.proofFor(nodeId)
        // (2) taint fold: only a well-formed 'trusted' input is trusted; anything else counts as untrusted lineage
        if (cand.containsKey("inputs") && cand["inputs"] !is List<*>) return refuse("bad_candidate", "candidate.inputs is not an array")
        val inputs = ArrayList<Any?>()
        val trustedRefs = ArrayList<Any?>()
        var tainted = false
        val given = cand["inputs"] as List<Any?>?
        if (given != null) {
            for (i in given) {
                val trusted = i is Map<*, *> && "trusted" == i["provenance"] && i["ref"] is String
                val ref = Js.get(i, "ref")
                inputs.add(linkedMapOf<String, Any?>("ref" to (if (trusted) ref else if (ref is String) ref else ""), "provenance" to (if (trusted) "trusted" else "untrusted")))
                if (trusted) trustedRefs.add(ref) else tainted = true
            }
        }
        val taint = if (tainted) 1L else 0L
        val riskInputs = LinkedHashMap(baseRisk)
        riskInputs["taint"] = Json.Num(taint.toString())
        // rounded to 6 d.p. so the reported r, the signed risk_claim.r and the budget cost agree and stay canonical
        val r = Js.round(Risk.riskScore(riskInputs, policy["weights"] as Map<String, Any?>) * 1e6) / 1e6
        val rp = Risk.Policy(policy["weights"] as Map<String, Any?>, dbl(policy["theta1"]), dbl(policy["theta2"]), dbl(policy["kappa"]), dbl(policy["lambda"]), 0.0, 0.0)
        val t = Risk.requiredThreshold(r, rp, "irreversible" == node["reversibility_class"]).t
        // (3) trust budget: meter machine-only actions, leaking to now first
        val nowMs = now()
        val leaked = Risk.leak(Risk.Budget(dbl(budget["B"]), dbl(budget["tau"]), dbl(budget["asOf"])), nowMs.toDouble(), dbl(policy["lambda"]))
        val c = Risk.cost(r, dbl(policy["kappa"]))
        if (t < 3 && !(leaked.B.isFinite() && leaked.B >= c)) {
            // the budget cannot cover even a low-risk in-plan action: escalate to a human, debit nothing, produce no PCActn
            budget = budgetMap(leaked)
            val out = LinkedHashMap(refuse("over_budget", "budget ${toFixed(leaked.B, 4)} < cost ${toFixed(c, 4)}; step up to a human co-sign"))
            out["requiredT"] = 3L
            out["budget"] = budgetMap(leaked)
            return out
        }
        // (4) sign
        val provenance = linkedMapOf<String, Any?>("causal_hash" to Pca.hashCanonical(inputs), "taint_level" to taint, "trusted_refs" to trustedRefs)
        var attestation: Map<String, Any?>? = null
        if (attest != null) {
            attestation = linkedMapOf(
                "quote_digest" to "", "epoch" to (attest["epoch"] ?: 0L), "model_id" to HARNESS_MODEL_ID,
                "measurement" to harnessMeasurement(), "operator" to attest["operator"],
            )
        }
        val riskClaim = linkedMapOf<String, Any?>("r" to num(r), "inputs" to LinkedHashMap(riskInputs))
        val params = cand["params"]
        val pcactn: Map<String, Any?> = try {
            if (params != null && params !is Map<*, *>) throw IllegalArgumentException("params must be an object")
            Issue.buildPCActn(
                Issue.ActSpec(
                    grant, chain, committed, nodeId, counter + 1, signer, audience, params as Map<String, Any?>?, nowMs, null, ttlMs, nonce(),
                    provenance = provenance, attestation = attestation, riskClaim = riskClaim,
                ),
            )
        } catch (e: RuntimeException) {
            // e.g. params do not match the node's committed params_digest: still never emits an out-of-plan action
            return refuse("bad_candidate", "could not build PCActn: ${e.message}")
        }
        // debit only a metered (machine-only, t < 3) action; commit the counter
        val debited = if (t < 3) Risk.debit(leaked, c) else leaked
        budget = budgetMap(debited)
        counter += 1
        val risk = linkedMapOf<String, Any?>("r" to num(r), "inputs" to riskInputs, "taint" to taint, "t" to t.toLong())
        return linkedMapOf("ok" to true, "pcactn" to pcactn, "inclusionProof" to inclusionProof, "risk" to risk, "budget" to budget)
    }

    companion object {
        /** The ordered manifest of checks the harness enforces before signing; folded into [harnessMeasurement]. */
        @JvmField
        val ENFORCED_CHECKS: List<String> = listOf("plan_inclusion_before_signing", "taint_provenance_fold", "trust_budget_debit", "pcactn_sign")

        /** Semantic version of the harness's policy-relevant surface. Bump changes the measurement. */
        const val HARNESS_VERSION = "0.1.0"

        /** The model identifier stamped into an emitted PCActn's `attestation.model_id` when attestation is enabled. */
        const val HARNESS_MODEL_ID = "@atlasauth/pca-harness"

        /**
         * Pure, deterministic self-measurement: a SHA-256 digest (base64url) over the version, the enforced-checks manifest and the
         * risk-policy identity. [policy] must carry `weights`, `theta1`, `theta2` and `kappa` (a missing one throws, as the reference's
         * canonical form refuses an undefined member).
         */
        @JvmStatic
        fun computeHarnessMeasurement(version: Any?, enforcedChecks: Any?, policy: Any?): String {
            if (policy == null) throw JsTypeError("policy is null")
            val rp = LinkedHashMap<String, Any?>()
            for (k in listOf("weights", "theta1", "theta2", "kappa")) {
                if (!Js.own(policy, k)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
                rp[k] = Js.get(policy, k)
            }
            return Pca.hashCanonical(linkedMapOf("harness" to "@atlasauth/pca-harness", "version" to version, "enforces" to enforcedChecks, "risk_policy" to rp))
        }

        // ---- allowlisting verifier ----

        /**
         * Build the mediator attestation verifier hook: a function from the verify context (`{pcactn: {attestation: ...}}`) to a
         * hook result (`{enforced, ok?, reason?}`). Fail closed throughout: an empty allowlist accepts nothing; an absent measurement
         * fails unless `required` is false; a pinned `model_id` must match; a present measurement that is not allowlisted always fails.
         * [config]: `measurements`, `required` (default true), `expectedModelId` (true or a string).
         */
        @JvmStatic
        fun createHarnessAttestationVerifier(config: Any?): (Any?) -> Map<String, Any?> {
            val ms = Js.member(config, "measurements")
            val allow = HashSet<Any?>()
            if (ms is List<*>) for (x in ms) if (x is String && x.isNotEmpty()) allow.add(x)
            val required = Js.get(config, "required") != false
            val em = Js.get(config, "expectedModelId")
            val expected: String? = if (em == true) HARNESS_MODEL_ID else if (em is String && em.isNotEmpty()) em else null
            return { ctx ->
                if (allow.isEmpty()) hook(true, false, "harness attestation configured with an empty measurement allowlist (fail closed)")
                else {
                    val att = Js.get(Js.get(ctx, "pcactn"), "attestation")
                    val mv = Js.get(att, "measurement")
                    val measurement = if (mv is String) mv else ""
                    if (measurement.isEmpty()) {
                        if (required) hook(true, false, "harness attestation required but the PCActn carries no harness measurement (fail closed)") else linkedMapOf("enforced" to false)
                    } else if (expected != null && expected != Js.get(att, "model_id")) {
                        hook(true, false, "attestation.model_id '${strMember(att, "model_id")}' is not the required harness identity '$expected'")
                    } else if (!allow.contains(measurement)) hook(true, false, "harness measurement is not in the allowlisted set (unattested or unknown mediator)")
                    else hook(true, true, null)
                }
            }
        }

        private fun hook(enforced: Boolean, ok: Boolean, reason: String?): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["enforced"] = enforced
            m["ok"] = ok
            if (reason != null) m["reason"] = reason
            return m
        }

        private fun strMember(o: Any?, k: String): String = if (Js.own(o, k)) Js.template(Js.get(o, k)) else "undefined"

        private fun num(d: Double): Json.Num = IntentJs.normalize(d) as Json.Num

        private fun dbl(o: Any?): Double = Js.num(o) ?: Double.NaN

        private fun budgetMap(b: Risk.Budget): Map<String, Any?> = linkedMapOf("B" to num(b.B), "tau" to num(b.tau), "asOf" to num(b.asOf ?: b.tau))

        private fun refuse(reason: String, detail: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason, "detail" to detail)

        /** JavaScript `Number.prototype.toFixed` for a finite number. */
        internal fun toFixed(x: Double, digits: Int): String = BigDecimal(x).setScale(digits, RoundingMode.HALF_UP).toPlainString()

        private fun randomHex(): String {
            val r = ByteArray(16)
            SecureRandom().nextBytes(r)
            val sb = StringBuilder()
            for (x in r) sb.append(String.format("%02x", x.toInt() and 0xff))
            return sb.toString()
        }
    }
}
