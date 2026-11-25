package net.atlasauth.pca.sandbox

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * A signed statement that a sandbox instance runs at a class, bound to the signed passport (by digest) of the agent it contains.
 * The signer is an attestor the verifier pins (a platform or attestation key); an operator saying so is not enough. Anything that
 * does not verify is treated as `none`.
 */
@Suppress("UNCHECKED_CAST")
object RuntimeClaims {
    /** Signed bytes: `domain || canonical(claim without sig)`, the construction of the other signed records. */
    const val RUNTIME_CLAIM_DOMAIN = "atlas-pca/runtime-class-claim/v1\u0000"

    private val KEYS = setOf("v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig")

    private fun body(claimWithoutSig: Any?): ByteArray = IntentJs.message(RUNTIME_CLAIM_DOMAIN, claimWithoutSig)

    /**
     * Sign a claim (`class, passport_digest, evidence_digest, iat, exp`) with the attestor's Ed25519 key (a 32-byte seed).
     * Returns the claim with `v`, `attestor` and `sig`.
     */
    @JvmStatic
    fun signRuntimeClaim(secretKey: ByteArray, publicKey: ByteArray, c: Map<String, Any?>): Map<String, Any?> {
        val unsigned = LinkedHashMap<String, Any?>()
        unsigned["v"] = 1L
        unsigned.putAll(c)
        unsigned["attestor"] = Keys.b64u(publicKey)
        val sig = Keys.edFromSeed(secretKey).sign(body(unsigned))
        val out = LinkedHashMap(unsigned)
        out["sig"] = Keys.b64u(sig)
        return out
    }

    /** A safe integer >= 0, never -0: a negative time is never valid. */
    private fun nat(o: Any?): Boolean = IntentJs.isNonNeg(o)

    /** A non-empty string of at most 128 UTF-16 code units. */
    private fun str(o: Any?): Boolean = o is String && o.isNotEmpty() && o.length <= 128

    private fun includes(list: Any?, x: Any?): Boolean = list is List<*> && list.contains(x)

    /**
     * The class the claim proves, or `"none"` for anything missing, unsigned, unpinned, expired, for another passport or
     * malformed. [trust] carries `pinnedAttestors`, `passportDigest`, `verifiedEvidenceDigests` and `now`.
     */
    @JvmStatic
    fun verifiedRuntimeClass(claim: Any?, trust: Any?): String {
        try {
            if (claim !is Map<*, *> || trust !is Map<*, *>) return "none"
            val c = claim as Map<String, Any?>
            val t = trust as Map<String, Any?>
            if (c.keys != KEYS) return "none"
            val v = IntentJs.num(c["v"])
            if (v == null || v != 1.0 || c["class"] !is String || c["class"] !in Receipts.RUNTIME_CLASSES) return "none"
            if (c["sig"] !is String || !str(c["attestor"]) || !str(c["passport_digest"]) || !str(c["evidence_digest"]) ||
                !includes(t["pinnedAttestors"], c["attestor"])) return "none"
            val now = t["now"]
            if (c["passport_digest"] != t["passportDigest"] || !nat(c["iat"]) || !nat(c["exp"]) || !nat(now) ||
                IntentJs.num(now)!! < IntentJs.num(c["iat"])!! || IntentJs.num(now)!! >= IntentJs.num(c["exp"])!!) return "none"
            if (!includes(t["verifiedEvidenceDigests"], c["evidence_digest"])) return "none"
            val rest = LinkedHashMap(c)
            rest.remove("sig")
            return if (IntentJs.verifyEd(c["attestor"], body(rest), c["sig"])) c["class"] as String else "none"
        } catch (e: RuntimeException) {
            return "none"
        }
    }

    /** hashCanonical of the signed passport a claim is about. */
    @JvmStatic
    fun passportDigest(signedPassport: Any?): String = Pca.hashCanonical(signedPassport)

    /** The digest a claim's `evidence_digest` must equal for this attestation document. */
    @JvmStatic
    fun evidenceDigest(document: Any?): String = Pca.hashCanonical(document)

    /**
     * Run an attestation verifier over the evidence; only if it answers `{ok: true, bound: true}` is the evidence's digest admitted
     * into the trust. Anything else (a throw, a malformed answer, not bound) leaves the list empty, so every claim is `none`.
     */
    @JvmStatic
    fun trustFromAttestation(document: Any?, verify: () -> Any?, nowMs: Long, pinnedAttestors: List<String>, passportDigest: String?): Map<String, Any?> {
        val ok = try {
            val h = verify()
            h is Map<*, *> && h["ok"] == true && h["bound"] == true
        } catch (e: Exception) {
            false
        }
        val digests = ArrayList<Any?>()
        if (ok) digests.add(evidenceDigest(document))
        return linkedMapOf("pinnedAttestors" to ArrayList<Any?>(pinnedAttestors), "passportDigest" to passportDigest, "verifiedEvidenceDigests" to digests, "now" to nowMs)
    }
}
