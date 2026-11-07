package net.atlasauth.pca.verifier

/**
 * Signed agent passport verification (packages/pca/src/passport.ts `verifyPassport`): the same reason codes in the same check
 * order (shape, version, suite, issuer, signature, id, validity window, subject, revocation, hardware evidence). Every
 * signature suite this SDK verifies is accepted; a post-quantum / hybrid suite only under a PQ key pinned for the issuer
 * ([Options.pqPins]); a suite it does not implement is `unsupported_suite`. Fail closed, never throws.
 *
 * Hardware: `hardware_rooted` is accepted only with evidence that a hardware verifier validates, bound to the subject key and
 * this passport's id, and whose measured identity equals the claims. The verifier is [Options.attest] (the integrator's, always
 * wins) or the built-in vendor verifier of [Options.defaultHardware] (AMD SEV-SNP, Intel TDX, Azure MAA, Google Confidential
 * Space, NVIDIA GPU: see [Attest.verifierFromConfig]); with neither the passport is refused with `hardware_verifier_missing`.
 */
/**
 * What a hardware verifier is asked for a passport: verify `document` (the carried evidence); the quote's bound value must
 * equal `expected` (holder = the subject key, grant = `passport:<id>`, epoch 0, the evidence nonce).
 */
typealias HardwareAttester = (document: Map<String, Any?>, expected: Attest.Binding) -> Attest.Result

object Passport {
    const val SIG_DOMAIN = "atlas-pca/passport-sig/v1\u0000"
    const val VERSION = 1L
    const val DEFAULT_EVIDENCE_AGE_MS = 24L * 3_600_000L
    private const val MAX_SKEW_MS = 60_000L

    class Options(
        /** Issuer keys (b64u Ed25519) you trust. Empty trusts nobody. */
        val trustedIssuers: List<String>,
        val nowMs: Long,
        val clockSkewMs: Long? = null,
        val maxEvidenceAgeMs: Long? = null,
        /** When given, the passport's `sub` must equal it. */
        val subject: String? = null,
        /** The PQ public key pinned for each issuer key (required for every non-Ed25519 suite). */
        val pqPins: Map<String, Any?>? = null,
        val attest: HardwareAttester? = null,
        val defaultHardware: Attest.DefaultHardware? = null,
        /** True iff this passport (id, issuer, subject) is revoked; null = no revocation source (`revocation_unavailable`); a throw also denies. */
        val revoked: ((id: String, iss: String, sub: String) -> Boolean)? = null,
    )

    /** The verdict: `reason` is null when the passport verifies, else the reason code; `detail` is optional text. */
    class Verdict(val ok: Boolean, val reason: String?, val detail: String? = null, val passport: Map<String, Any?>? = null, val hardwareVerified: Boolean = false) {
        override fun toString(): String = "Passport.Verdict(ok=$ok, reason=$reason, detail=$detail)"
    }

    private fun bad(reason: String, detail: String? = null) = Verdict(false, reason, detail)

    private fun isStr(x: Any?): Boolean = x is String && x.isNotEmpty()

    /** Content fingerprint over the identity fields (the passport `id`). */
    fun fingerprint(p: Map<String, Any?>): String {
        val fp = LinkedHashMap<String, Any?>()
        fp["d"] = "atlas-pca/passport/v1"
        for (k in listOf("model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement", "operator", "hardware_rooted"))
            fp[k] = if (p.containsKey(k)) p[k] else null
        return Pca.hashCanonical(fp)
    }

    private fun strictEq(a: Any?, b: Any?): Boolean = a !is Map<*, *> && a !is List<*> && b !is Map<*, *> && b !is List<*> && IntentJs.jsonEquals(a, b)

    fun verify(sp: Any?, o: Options): Verdict = try {
        verifyUnchecked(sp, o)
    } catch (e: RuntimeException) {
        bad("malformed", e.javaClass.simpleName)
    } catch (e: StackOverflowError) {
        bad("malformed", "StackOverflowError")
    }

    @Suppress("UNCHECKED_CAST")
    private fun verifyUnchecked(sp: Any?, o: Options): Verdict {
        if (sp !is Map<*, *>) return bad("malformed")
        val s = sp as Map<String, Any?>
        val pRaw = s["passport"]
        if (s["typ"] != "atlas-pca/passport" || pRaw == null) return bad("malformed")
        if (!IntentJs.isSafeInteger(s["ver"]) || IntentJs.num(s["ver"]) != VERSION.toDouble()) return bad("unsupported_version", IntentRevocation.jsText(IntentJs.normalize(s["ver"]), s.containsKey("ver")))
        val algPresent = s.containsKey("alg")
        if (algPresent && Pq.resolveSigAlg(s["alg"], true) == null) return bad("unsupported_suite", IntentRevocation.jsText(IntentJs.normalize(s["alg"]), true))
        val p = pRaw as? Map<String, Any?> ?: return bad("malformed")
        if (!isStr(s["iss"]) || !isStr(s["sub"]) || !isStr(s["sig"]) || !isStr(p["id"]) || !isStr(p["model_id"]) || !isStr(p["operator"]) || p["hardware_rooted"] !is Boolean) return bad("malformed")
        val iss = s["iss"] as String
        val sub = s["sub"] as String
        val id = p["id"] as String
        if (!listOf(s["iat"], s["nbf"], s["exp"]).all { IntentJs.isSafeInteger(it) } || Math.abs(o.nowMs) > 9007199254740991L || IntentJs.lng(s["exp"]) <= IntentJs.lng(s["nbf"])) return bad("malformed", "times")
        if (iss !in o.trustedIssuers) return bad("unknown_issuer")
        val body = LinkedHashMap(s)
        body.remove("sig")
        body.remove("pq_sig")
        if (!IntentJs.verifyPinnedSuite(s["alg"], algPresent, iss, s["pq_pk"], IntentJs.message(SIG_DOMAIN, body), s["sig"], s["pq_sig"], o.pqPins)) return bad("bad_signature")
        if (id != fingerprint(p)) return bad("id_mismatch")
        val skew = Math.min(Math.max(o.clockSkewMs ?: 0L, 0L), MAX_SKEW_MS)
        val nbf = IntentJs.lng(s["nbf"])
        val exp = IntentJs.lng(s["exp"])
        if (o.nowMs + skew < nbf) return bad("not_yet_valid")
        if (o.nowMs - skew >= exp) return bad("expired")
        if (o.subject != null && o.subject != sub) return bad("subject_mismatch")
        val rev = o.revoked ?: return bad("revocation_unavailable", "no revocation source")
        val isRevoked = try { rev(id, iss, sub) } catch (e: Exception) { return bad("revocation_unavailable") }
        if (isRevoked) return bad("revoked")
        val hw = p["hardware_rooted"] == true
        if (hw) {
            val ev = s["evidence"] as? Map<String, Any?> ?: emptyMap()
            val doc = ev["document"] as? Map<String, Any?>
            if (doc == null || !isStr(doc["nonce"])) return bad("hardware_evidence_missing")
            if (!IntentJs.isSafeInteger(ev["at"])) return bad("hardware_evidence_missing", "evidence.at")
            val at = IntentJs.lng(ev["at"])
            val maxAge = o.maxEvidenceAgeMs ?: DEFAULT_EVIDENCE_AGE_MS
            if (maxAge < 0 || o.nowMs - at > maxAge || at - o.nowMs > skew) return bad("hardware_evidence_stale")
            var attester: HardwareAttester? = o.attest
            val dh = o.defaultHardware
            if (attester == null && dh != null) attester = dh.attester(o.nowMs)
            if (attester == null) return bad("hardware_verifier_missing")
            val nonce = doc["nonce"] as String
            val r = try {
                attester(doc, Attest.Binding(sub, "passport:$id", 0.0, nonce))
            } catch (e: Exception) {
                return bad("hardware_attestation_failed", e.message ?: "error")
            }
            if (!r.ok || !r.bound) return bad("hardware_attestation_failed", r.reason)
            if (!identityMatches(p, r.measured)) return bad("hardware_identity_mismatch")
        }
        return Verdict(true, null, null, p, hw)
    }

    /** The hardware-measured identity equals the claims: model and operator always; the optional digests / runtime measurement when stated; measured weights when claimed. */
    private fun identityMatches(p: Map<String, Any?>, m: Map<String, Any?>?): Boolean {
        if (m == null) return false
        if (!strictEq(m["model_id"], p["model_id"]) || !strictEq(m["operator"], p["operator"])) return false
        for (k in listOf("weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"))
            if (p.containsKey(k) && !strictEq(m[k], p[k])) return false
        if (p["weights_measured"] == true && m["weights_measured"] != true) return false
        return true
    }
}
