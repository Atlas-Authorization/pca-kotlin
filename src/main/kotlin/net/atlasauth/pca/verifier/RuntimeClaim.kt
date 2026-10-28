package net.atlasauth.pca.verifier

/**
 * Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class. Valid
 * only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
 * `verifiedEvidence`), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is
 * "none". Total.
 */
object RuntimeClaim {
    const val DOMAIN = "atlas-pca/runtime-class-claim/v1\u0000"
    private val CLASSES = listOf("none", "os_confined", "egress_default_deny", "wasi_no_ambient")
    private val KEYS = setOf("v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig")

    @JvmStatic
    fun verifiedClass(v: Any?, pinnedAttestors: List<String>, passportDigest: String, verifiedEvidence: List<String>, now: Any?): String {
        try {
            val c = K3Sig.map(v) ?: return "none"
            if (c.keys != KEYS || !IntentJs.isSafeInteger(c["v"]) || IntentJs.lng(c["v"]) != 1L) return "none"
            val cls = c["class"] as? String ?: return "none"
            if (cls !in CLASSES) return "none"
            if (!K3Sig.isStr(c["attestor"], 128) || !K3Sig.isStr(c["passport_digest"], 128) || !K3Sig.isStr(c["evidence_digest"], 128)) return "none"
            if (!K3Sig.isSafeInt(c["iat"]) || !K3Sig.isSafeInt(c["exp"]) || !K3Sig.isSafeInt(now)) return "none"
            val t = IntentJs.lng(now)
            if (c["attestor"] !in pinnedAttestors || c["passport_digest"] != passportDigest || c["evidence_digest"] !in verifiedEvidence) return "none"
            if (!(IntentJs.lng(c["iat"]) <= t && t < IntentJs.lng(c["exp"]))) return "none"
            val body = LinkedHashMap<String, Any?>(c)
            body.remove("sig")
            return if (K3Sig.verifyBody(DOMAIN, body, c["attestor"], c["sig"])) cls else "none"
        } catch (e: RuntimeException) {
            return "none"
        }
    }
}
