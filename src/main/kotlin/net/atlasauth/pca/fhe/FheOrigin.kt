package net.atlasauth.pca.fhe

import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Origin authentication of an encrypted risk claim (scheme-independent): the encryptor signs the ciphertext, the binding to one action, the
 * gate policy, a context and a one-time nonce; the verifier checks the signature, the context, the binding, the policy and a replay guard
 * BEFORE spending any evaluator work; the key holder signs the verdict over the exact claim and gate output it opened. A claim and an
 * attestation are parsed JSON objects (maps).
 */
object FheOrigin {
    private const val CLAIM_DOMAIN = "atlas-pca-fhe/signed-claim/v1\u0000"
    private const val VERDICT_DOMAIN = "atlas-pca-fhe/verdict-attestation/v1\u0000"
    private const val NONCE_BYTES = 16
    private const val MAX_CONTEXT_LEN = 512

    private fun utf8(s: String) = Json.utf8(s)
    private fun bytesDigest(s: String) = Keys.b64u(MessageDigest.getInstance("SHA-256").digest(utf8(s)))
    private fun prefixed(domain: String, body: Any?) = utf8(domain) + utf8(Json.canonicalizeStrict(body))

    @Suppress("UNCHECKED_CAST")
    private fun obj(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun isObject(o: Any?) = o is Map<*, *> || o is List<*>

    private fun claimStatement(claim: Map<String, Any?>, context: String, nonce: String, signer: String): ByteArray = prefixed(
        CLAIM_DOMAIN,
        linkedMapOf(
            "v" to 1L, "context" to context, "nonce" to nonce, "signer" to signer, "binding" to claim["binding"],
            "policy" to Pca.hashCanonical(claim["policy"]), "enc_inputs" to bytesDigest(claim["encInputs"] as String),
        ),
    )

    /** The content digest of a signed claim (what the key holder's attestation commits to). */
    fun signedClaimDigest(signed: Any?): String = Pca.hashCanonical(signed)

    private fun key(secret: ByteArray?): Keys.EdKey {
        require(secret != null && secret.size == 32) { "signing key must be a 32-byte Ed25519 secret key" }
        return Keys.edFromSeed(secret)
    }

    /** Signs an encrypted risk claim; a fresh random one-time nonce unless one is supplied (tests and replay of recorded vectors). */
    fun signRiskClaim(claim: Map<String, Any?>, signerSecretKey: ByteArray, context: String, nonce: ByteArray = ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }): Map<String, Any?> {
        require(context.isNotEmpty() && context.length <= MAX_CONTEXT_LEN) { "context must be a non-empty string of at most $MAX_CONTEXT_LEN characters" }
        check(nonce.any { it.toInt() != 0 }) { "signRiskClaim: random source returned all zeros (RNG failure)" }
        val k = key(signerSecretKey)
        val signer = Keys.b64u(k.pub)
        val n = Keys.b64u(nonce)
        return linkedMapOf("claim" to claim, "context" to context, "nonce" to n, "signer" to signer, "sig" to Keys.b64u(k.sign(claimStatement(claim, context, n, signer))))
    }

    /** A bounded set of nonces already seen; claim(key) is false when the key was seen or the window is full. */
    fun interface NonceGuard { fun claim(key: String): Boolean }

    fun memoryNonceGuard(maxEntries: Int = 100_000): NonceGuard {
        val seen = HashSet<String>()
        return NonceGuard { k -> if (k in seen || seen.size >= maxEntries) false else { seen.add(k); true } }
    }

    /** What the verifier expects: trusted encryptor keys, the grant context, the action binding, the gate policy and the replay guard. */
    class ClaimExpectations(val trustedSigners: List<String>, val context: String, val binding: Any?, val policy: Any?, val nonces: NonceGuard)

    /** ok with the claim and its digest, or not ok with a reason. */
    data class ClaimCheck(val ok: Boolean, val claim: Map<String, Any?>?, val digest: String?, val reason: String?)

    private fun fail(reason: String) = ClaimCheck(false, null, null, reason)

    /** Verifies a signed claim; never throws (a malformed or hostile input is a not-ok result). */
    fun verifySignedRiskClaim(s: Any?, exp: ClaimExpectations): ClaimCheck {
        try {
            if (s !is Map<*, *>) return fail("claim is not signed: malformed envelope")
            val c = obj(s)
            val claimO = c["claim"]
            if (c["context"] !is String || c["nonce"] !is String || c["signer"] !is String || c["sig"] !is String ||
                claimO !is Map<*, *> || obj(claimO)["encInputs"] !is String || !isObject(obj(claimO)["binding"]) || !isObject(obj(claimO)["policy"])
            ) return fail("claim is not signed: malformed envelope")
            val claim = obj(claimO)
            val context = c["context"] as String
            val nonce = c["nonce"] as String
            val signer = c["signer"] as String
            val sig = c["sig"] as String
            if (Pca.decodeB64uStrict(nonce, NONCE_BYTES) == null) return fail("malformed nonce")
            val signerBytes = Pca.decodeB64uStrict(signer, 32)
            val sigBytes = Pca.decodeB64uStrict(sig, 64)
            if (signerBytes == null || sigBytes == null) return fail("malformed signer key or signature")
            if (signer !in exp.trustedSigners) return fail("signer is not a trusted encryptor")
            if (!Jose.verifyEd25519Strict(signerBytes, claimStatement(claim, context, nonce, signer), sigBytes)) {
                return fail("signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)")
            }
            if (context != exp.context) return fail("context mismatch: claim was signed for a different grant/policy")
            if (Pca.hashCanonical(claim["binding"]) != Pca.hashCanonical(exp.binding)) return fail("binding mismatch: claim is bound to a different action")
            if (Pca.hashCanonical(claim["policy"]) != Pca.hashCanonical(exp.policy)) return fail("policy mismatch: claim was signed for a different gate policy")
            if (!exp.nonces.claim("$signer:$nonce")) return fail("replay: nonce already used (or the replay window is full)")
            return ClaimCheck(true, claim, signedClaimDigest(s), null)
        } catch (e: RuntimeException) {
            return fail("claim could not be verified (malformed)")
        }
    }

    /** The outcome of [evalSignedRiskClaim]: ok with the evaluator's `gate` and the claim digest, or not ok with a reason. */
    data class SignedEval(val ok: Boolean, val gate: Any?, val claimDigest: String?, val reason: String?)

    /**
     * The evaluator: verify the signed claim, then run the gate. The ciphertext reaches [evalGate] (the SEAL gate of the `pca-fhe-seal`
     * module: `(encInputs, policy) -> gate`) only after the signature, signer, context, binding, policy and nonce all check out. A claim
     * that fails verification, or a gate that throws, is a not-ok result, never a throw.
     */
    fun evalSignedRiskClaim(signed: Any?, exp: ClaimExpectations, evalGate: (String, Map<String, Any?>) -> Any?): SignedEval {
        val chk = verifySignedRiskClaim(signed, exp)
        if (!chk.ok) return SignedEval(false, null, null, chk.reason)
        return try {
            val claim = chk.claim!!
            SignedEval(true, evalGate(claim["encInputs"] as String, obj(claim["policy"])), chk.digest, null)
        } catch (e: RuntimeException) {
            SignedEval(false, null, null, "evaluation failed: " + (e.message ?: "unknown error"))
        }
    }

    private fun verdictStatement(claimDigest: String, gateDigest: Any?, admit: Boolean, holder: String): ByteArray =
        prefixed(VERDICT_DOMAIN, linkedMapOf("v" to 1L, "claim" to claimDigest, "gate" to gateDigest, "admit" to admit, "holder" to holder))

    /** The key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output. */
    fun attestVerdict(holderSecretKey: ByteArray, signed: Map<String, Any?>, gate: Map<String, Any?>, admit: Boolean): Map<String, Any?> {
        val gateDigest = linkedMapOf<String, Any?>("encRiskRaw" to bytesDigest(gate["encRiskRaw"] as String), "encSlack" to bytesDigest(gate["encSlack"] as String))
        val claimDigest = signedClaimDigest(signed)
        val k = key(holderSecretKey)
        val holder = Keys.b64u(k.pub)
        return linkedMapOf(
            "claimDigest" to claimDigest, "gateDigest" to gateDigest, "admit" to admit, "holder" to holder,
            "sig" to Keys.b64u(k.sign(verdictStatement(claimDigest, gateDigest, admit, holder))),
        )
    }

    /** ok with the attested admit bit, or not ok with a reason. */
    data class AttestationCheck(val ok: Boolean, val admit: Boolean, val reason: String?)

    private fun afail(reason: String) = AttestationCheck(false, false, reason)

    /** Verifies an attestation: trusted holder, signature, the expected claim digest and (when given) the expected gate output. */
    fun verifyVerdictAttestation(a: Any?, trustedHolders: List<String>, claimDigest: String, gate: Map<String, Any?>?): AttestationCheck {
        try {
            if (a !is Map<*, *>) return afail("malformed attestation")
            val x = obj(a)
            val gd = x["gateDigest"]
            if (x["claimDigest"] !is String || x["holder"] !is String || x["sig"] !is String || x["admit"] !is Boolean ||
                gd !is Map<*, *> || obj(gd)["encRiskRaw"] !is String || obj(gd)["encSlack"] !is String
            ) return afail("malformed attestation")
            val holderS = x["holder"] as String
            if (holderS !in trustedHolders) return afail("attestation holder is not trusted")
            val holder = Pca.decodeB64uStrict(holderS, 32)
            val sig = Pca.decodeB64uStrict(x["sig"], 64)
            if (holder == null || sig == null) return afail("malformed holder key or signature")
            val admit = x["admit"] as Boolean
            if (!Jose.verifyEd25519Strict(holder, verdictStatement(x["claimDigest"] as String, gd, admit, holderS), sig)) return afail("attestation signature does not verify")
            if (x["claimDigest"] != claimDigest) return afail("attestation is for a different claim")
            if (gate != null) {
                if (obj(gd)["encRiskRaw"] != bytesDigest(gate["encRiskRaw"] as String) || obj(gd)["encSlack"] != bytesDigest(gate["encSlack"] as String)) {
                    return afail("attestation is for a different gate output")
                }
            }
            return AttestationCheck(true, admit, null)
        } catch (e: RuntimeException) {
            return afail("attestation could not be verified (malformed)")
        }
    }
}
