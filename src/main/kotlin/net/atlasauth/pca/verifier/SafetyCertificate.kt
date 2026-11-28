package net.atlasauth.pca.verifier

/**
 * A signed safety certificate (safety-certificate.ts): a machine-readable statement of the risk-budget bound of a grant, signed by
 * the guardian that enforces the bound. From the signed risk parameters `{bMax, kappa}` it states the bound `bMax / kappa`: between
 * two consecutive human co-signs the total risk of autonomous actions is at most that. It makes no claim that the agent is safe.
 *
 * [verifySafetyCertificate] recomputes the bound from the certificate's own parameters and refuses any mismatch, so a tampered
 * certificate cannot overstate safety. Optional check rows record an external check with its outcome and a link to its evidence;
 * the certificate proves that the issuer recorded them, not that the checks are sound. Certificates are JSON trees (maps, lists,
 * strings, booleans, [Json.Num]).
 */
@Suppress("UNCHECKED_CAST")
object SafetyCertificate {
    const val SAFETY_CERT_DOMAIN = "atlas-pca/safety-cert/v1\u0000"
    const val SAFETY_CERT_VERSION = 1
    const val SAFETY_CERT_SCOPE = "risk-budget-bound"

    /** Upper bound on the check rows of one certificate. */
    const val MAX_SAFETY_CHECKS = 64
    private const val MAX_CHECK_ID = 64
    private const val MAX_EVIDENCE_URL = 2048
    private const val MAX_JSON_BYTES = 1 shl 20
    private val SHA256_HEX = Regex("[0-9a-f]{64}")
    private val STATUSES = setOf("passed", "failed", "not_run")

    private fun rec(x: Any?): Map<String, Any?>? = x as? Map<String, Any?>
    private fun no(reason: String): LinkedHashMap<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    /** A double as a JSON number (a non-finite one keeps JavaScript's text and is refused by every canonical form). */
    private fun jsonNum(d: Double): Json.Num = Json.Num(Json.jsNumberText(d))

    private fun plainHttps(ref: String): Boolean {
        if (ref.length > MAX_EVIDENCE_URL) return false
        val u = try {
            WhatwgUrl.parse(ref)
        } catch (e: RuntimeException) {
            return false
        }
        return u.protocol() == "https:" && !u.hasCredentials()
    }

    /**
     * Why `checks` is not a well-formed check list, or null when it is: at most [MAX_SAFETY_CHECKS] rows `{id, status, evidence: {kind,
     * ref}, at}` with unique 1..64 char ids, a status of `passed` / `failed` / `not_run`, a non-negative safe-integer time, and evidence
     * that is a 64 char lowercase hex `sha256` digest or a plain https `url` (no credentials, at most 2048 chars).
     */
    fun validateSafetyChecks(checks: Any?): String? {
        val list = checks as? List<Any?> ?: return "checks must be an array"
        if (list.size > MAX_SAFETY_CHECKS) return "more than $MAX_SAFETY_CHECKS checks"
        val seen = HashSet<String>()
        for (c in list) {
            if (c !is Map<*, *> && c !is List<*>) return "check is not an object"
            val k = rec(c) ?: emptyMap() // an array is an object without these members
            val id = k["id"] as? String
            if (id == null || id.isEmpty() || id.length > MAX_CHECK_ID) return "check id must be a 1..64 char string"
            if (!seen.add(id)) return "duplicate check id '$id'"
            val status = k["status"] as? String
            if (status == null || status !in STATUSES) return "check '$id' has an invalid status"
            if (!IntentJs.isNonNeg(k["at"])) return "check '$id' has an invalid time"
            val ref = rec(k["evidence"])?.get("ref") as? String ?: return "check '$id' has no evidence link"
            when (rec(k["evidence"])!!["kind"]) {
                "sha256" -> if (!SHA256_HEX.matches(ref)) return "check '$id' evidence digest is not 64 lowercase hex"
                "url" -> if (!plainHttps(ref)) return "check '$id' evidence URL must be a plain https URL"
                else -> return "check '$id' has an invalid evidence kind"
            }
        }
        return null
    }

    /** The bound of a risk policy `{bMax, kappa}`: `max(0, bMax) / kappa`, or 0 when kappa is not above zero. Throws when `policy` is not an object. */
    fun safetyCertificateBound(policy: Any?): Double {
        val p = rec(policy) ?: throw IllegalArgumentException("safetyCertificateBound: not a risk policy")
        val kappa = IntentJs.num(p["kappa"]) ?: Double.NaN
        return if (kappa > 0) Math.max(0.0, IntentJs.num(p["bMax"]) ?: Double.NaN) / kappa else 0.0
    }

    /** The fixed human statement for a bound: what is claimed, and what is not. */
    fun safetyCertificateStatement(bound: Double): String =
        "Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions " +
            "Σ r(Aᵢ) ≤ ${Json.jsNumberText(bound)} (= B_max / κ). This is not a claim that the agent or the system is safe."

    /** The canonical message signed for a certificate: the domain separator, then the lenient canonical JSON of the claim (everything but `sig` and `pq_sig`). */
    fun safetyCertificateMessage(cert: Map<String, Any?>): ByteArray {
        val claim = LinkedHashMap(cert)
        claim.remove("sig")
        claim.remove("pq_sig")
        return Pca.concat(Json.utf8(SAFETY_CERT_DOMAIN), Pca.canonicalBytesLenient(claim))
    }

    /**
     * Issue a certificate for a grant's risk policy, signed by `guardian` (its Ed25519 identity names the guardian; a post-quantum or
     * hybrid suite also binds `alg` and `pq_pk` into the signed body). `issuedAt` is epoch ms as a JSON number (null = now); `checks`
     * is an optional check list ([validateSafetyChecks]); `grantRef` and `instance` are optional labels. Throws IllegalArgumentException
     * on a malformed policy or check list, or a value that cannot be signed.
     */
    @JvmOverloads
    fun issueSafetyCertificate(
        policy: Any?, guardian: Keys.SuiteKey, issuedAt: Any? = null, grantRef: String? = null, instance: String? = null, checks: Any? = null,
    ): Map<String, Any?> {
        Authorize.riskPolicyError(policy)?.let { throw IllegalArgumentException("issueSafetyCertificate: $it") }
        val ed = requireNotNull(guardian.ed) { "issueSafetyCertificate: the guardian needs an Ed25519 identity" }
        if (checks != null) validateSafetyChecks(checks)?.let { throw IllegalArgumentException("issueSafetyCertificate: $it") }
        val p = rec(policy)!!
        val bound = jsonNum(safetyCertificateBound(p))
        val claim = linkedMapOf<String, Any?>(
            "v" to StoreJs.num(SAFETY_CERT_VERSION.toLong()), "statement" to safetyCertificateStatement(safetyCertificateBound(p)), "scope" to SAFETY_CERT_SCOPE,
        )
        if (checks != null) {
            claim["checks"] = (checks as List<Any?>).map { cO ->
                val c = cO as Map<String, Any?>
                val e = c["evidence"] as Map<String, Any?>
                linkedMapOf("id" to c["id"], "status" to c["status"], "evidence" to linkedMapOf("kind" to e["kind"], "ref" to e["ref"]), "at" to c["at"])
            }
        }
        val params = LinkedHashMap<String, Any?>()
        for (k in listOf("bMax", "kappa", "theta1", "theta2", "lambda", "rho")) params[k] = p[k]
        params["weights"] = LinkedHashMap(p["weights"] as Map<String, Any?>)
        claim["params"] = params
        claim["bound"] = bound
        claim["blastRadiusPerCheckpoint"] = bound
        if (grantRef != null) claim["grant_ref"] = grantRef
        if (instance != null) claim["instance"] = instance
        claim["issued_at"] = issuedAt ?: StoreJs.num(System.currentTimeMillis())
        claim["guardian"] = ed.id()
        if (guardian.alg != "ed25519") {
            claim["alg"] = guardian.alg
            claim["pq_pk"] = guardian.pqPk()
        }
        val sg = guardian.sign(safetyCertificateMessage(claim))
        claim["sig"] = sg.first
        if (sg.second != null) claim["pq_sig"] = sg.second
        return claim
    }

    /**
     * Verify a certificate: `{ok: true, recomputedBound}` or `{ok: false, reason, recomputedBound?}`. Never throws. The stated bound must
     * equal the bound recomputed from the certificate's own parameters, and the guardian's signature must verify (a post-quantum half
     * only under `opts.pqPins[guardian]`: the key a certificate carries is never trusted by itself, and the reference's legacy
     * `allowUnboundPq` opt-out is not offered, so it has no effect here). `opts`: `guardian` pins the guardian key; `requireChecks` lists check ids that must be present and passed; `maxAgeMs` (with `now`, default the wall clock)
     * bounds the certificate's age.
     */
    @JvmOverloads
    fun verifySafetyCertificate(cert: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> = try {
        verify(cert, opts ?: emptyMap())
    } catch (e: RuntimeException) {
        no("malformed certificate: ${e.message ?: "unknown"}")
    }

    private fun verify(certO: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val cert = rec(certO)
        if (cert == null || IntentJs.num(cert["v"]) != SAFETY_CERT_VERSION.toDouble()) return no("malformed certificate")
        val sig = cert["sig"] as? String
        val guardian = cert["guardian"] as? String
        if (sig == null || guardian == null) return no("missing guardian/signature")
        if (cert["scope"] != SAFETY_CERT_SCOPE) return no("unknown scope")
        if (cert.containsKey("checks")) validateSafetyChecks(cert["checks"])?.let { return no("invalid checks: $it") }
        val params = rec(cert["params"]) ?: emptyMap() // the reference validates a copy of the members: anything else has none
        Authorize.riskPolicyError(params)?.let { return no("invalid parameters: $it") }

        val recomputed = safetyCertificateBound(params)
        fun fail(reason: String): Map<String, Any?> = no(reason).also { it["recomputedBound"] = jsonNum(recomputed) }
        if (!IntentJs.isFinite(cert["bound"]) || IntentJs.num(cert["bound"]) != recomputed) {
            return fail("stated bound does not equal B_max/κ recomputed from the parameters")
        }
        if (IntentJs.num(cert["blastRadiusPerCheckpoint"]) != recomputed) return fail("blastRadiusPerCheckpoint does not equal the recomputed bound")
        if (opts.containsKey("guardian") && opts["guardian"] != guardian) return fail("guardian key is not the pinned key")
        val algPresent = cert.containsKey("alg")
        if (Pq.resolveSigAlg(cert["alg"], algPresent) == null) return fail("unknown signature alg")
        val signed = IntentJs.verifyPinnedSuite(
            cert["alg"], algPresent, guardian, cert["pq_pk"], safetyCertificateMessage(cert), sig, cert["pq_sig"], rec(opts["pqPins"]),
        )
        if (!signed) return fail("guardian signature does not verify")
        if (opts.containsKey("maxAgeMs")) {
            val now = if (opts["now"] == null) System.currentTimeMillis().toDouble() else IntentJs.num(opts["now"]) ?: Double.NaN
            if (!IntentJs.isFinite(opts["maxAgeMs"]) || now.isNaN() || now.isInfinite() || !IntentJs.isFinite(cert["issued_at"])) {
                return fail("invalid age policy or issue time")
            }
            val issued = IntentJs.num(cert["issued_at"])!!
            if (issued > now) return fail("certificate is issued in the future")
            if (now - issued > IntentJs.num(opts["maxAgeMs"])!!) return fail("certificate is older than maxAgeMs")
        }
        val required = opts["requireChecks"]
        if (required != null) {
            // the reference iterates the value: a list by entry, text by code point; anything else cannot be iterated and is malformed
            val ids: List<Any?> = when (required) {
                is List<*> -> required
                is String -> required.codePoints().toArray().map { String(Character.toChars(it)) }
                else -> {
                    val what = when (required) {
                        is Map<*, *> -> "object"
                        is Boolean -> "boolean $required"
                        else -> "number ${IntentRevocation.jsText(required, true)}"
                    }
                    return no("malformed certificate: $what is not iterable (cannot read property Symbol(Symbol.iterator))")
                }
            }
            val checks = cert["checks"] as? List<Any?> ?: emptyList()
            for (id in ids) {
                val text = IntentRevocation.jsText(id, true)
                val c = checks.firstOrNull { rec(it)!!["id"] == id } ?: return fail("required check '$text' is not present")
                val status = rec(c)!!["status"]
                if (status != "passed") return fail("required check '$text' is $status")
            }
        }
        return linkedMapOf("ok" to true, "recomputedBound" to jsonNum(recomputed))
    }

    /** The canonical JSON encoding (a stable string for transport or storage). */
    fun encodeSafetyCertificate(cert: Map<String, Any?>): String = Json.canonicalize(cert)

    /** Parse a certificate. Shape-checks only (null when it is not one, or larger than 1 MiB): the result MUST still go through [verifySafetyCertificate]. */
    fun decodeSafetyCertificate(text: Any?): Map<String, Any?>? {
        if (text !is String || IntentJs.u8len(text) > MAX_JSON_BYTES) return null
        val parsed = try {
            IntentJs.normalize(Json.parseLenient(text))
        } catch (e: RuntimeException) {
            return null
        }
        val v = rec(parsed) ?: return null
        if (IntentJs.num(v["v"]) != SAFETY_CERT_VERSION.toDouble() || v["sig"] !is String || v["guardian"] !is String) return null
        return if (v["params"] is Map<*, *> || v["params"] is List<*>) v else null
    }

    /**
     * The certificate as one compliance evidence row `{control, guardian, issued_at, bound, checks: [{id, status, evidence}]}` (an
     * evidence digest reads `sha256:<hex>`), or null when the certificate does not verify under `opts` ([verifySafetyCertificate]).
     */
    @JvmOverloads
    fun safetyCertificateForCompliance(cert: Any?, opts: Map<String, Any?>? = null): Map<String, Any?>? {
        if (verifySafetyCertificate(cert, opts)["ok"] != true) return null
        val c = cert as Map<String, Any?>
        val rows = (c["checks"] as? List<Any?> ?: emptyList()).map { kO ->
            val k = kO as Map<String, Any?>
            val e = k["evidence"] as Map<String, Any?>
            linkedMapOf("id" to k["id"], "status" to k["status"], "evidence" to (if (e["kind"] == "sha256") "sha256:${e["ref"]}" else e["ref"]))
        }
        return linkedMapOf(
            "control" to SAFETY_CERT_SCOPE, "guardian" to c["guardian"], "issued_at" to c["issued_at"], "bound" to c["bound"], "checks" to rows,
        )
    }
}
