package net.atlasauth.pca.ratchet

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Verifier-side bindings that the stateless primitives cannot give on their own: a spent-leaf store so a SECOND signature at the same leaf is
 * detected (replay) and a different message at the same leaf is flagged as equivocation, and action-bound risk commitments, created by the
 * party that COMPUTES the risk and signed together with the action digest, so a prover cannot commit 0 for a 1.0-risk action or move a
 * commitment between actions.
 */
object Binding {
    /** The outcome of a [SpentLeafStore.claim]: first claim, or the record stored earlier. */
    class Claim private constructor(val first: Boolean, val record: String?) {
        companion object {
            @JvmStatic fun first(): Claim = Claim(true, null)
            @JvmStatic fun seen(record: String): Claim = Claim(false, record)
        }
    }

    /** Atomic first-claim store keyed by leaf nullifier. */
    fun interface SpentLeafStore {
        /** Atomically record [record] under [nullifier] if absent; return [Claim.first] or the earlier record. */
        fun claim(nullifier: String, record: String): Claim
    }

    /** In-process [SpentLeafStore]. Per process: use a shared store for a verifier fleet. */
    @JvmStatic
    fun memorySpentLeafStore(): SpentLeafStore {
        val seen = HashMap<String, String>()
        return SpentLeafStore { nullifier, record ->
            synchronized(seen) {
                val prev = seen[nullifier]
                if (prev != null) Claim.seen(prev)
                else {
                    seen[nullifier] = record
                    Claim.first()
                }
            }
        }
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun result(vararg kv: Pair<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) m[k] = v
        return m
    }

    /**
     * Verify a leaf signature AND enforce one-time use at the verifier: the first valid signature at a leaf is accepted and its message digest
     * recorded; a later signature at that leaf is refused as `replay` (same message) or `equivocation` (a different message: the evidence of a
     * holder that kept an old state). Fail closed: a store that throws denies. Returns `{ok}` or `{ok: false, reason, ...}`.
     */
    @JvmStatic
    fun verifyLeafSignatureOnce(rootCommitment: String, leafIndex: Any?, message: ByteArray, signature: Any?, store: SpentLeafStore): Map<String, Any?> {
        if (!Ratchet.verifyLeafSignature(rootCommitment, leafIndex, message, signature)) return result("ok" to false, "reason" to "invalid")
        val nullifier = Ratchet.leafNullifier(rootCommitment, leafIndex)
        val idx = (IntentJs.normalize(Ratchet.jsNum(leafIndex)!!) as Json.Num).raw
        val mine = Keys.b64u(sha256(message)) + "@" + idx
        return try {
            val r = store.claim(nullifier, mine)
            if (r.first) result("ok" to true)
            else if (mine == r.record) result("ok" to false, "reason" to "replay", "nullifier" to nullifier)
            else result("ok" to false, "reason" to "equivocation", "nullifier" to nullifier, "firstMessageDigest" to r.record, "secondMessageDigest" to mine)
        } catch (e: RuntimeException) {
            result("ok" to false, "reason" to "store-error")
        }
    }

    private val ATTEST_DOMAIN = "atlas-pca-ratchet/risk-attestation/v1\u0000".toByteArray(Charsets.UTF_8)

    private fun attestMessage(actionDigest: String, commitment: String): ByteArray {
        val a = Json.utf8(actionDigest)
        val c = Json.utf8(commitment)
        val out = ByteBuffer.allocate(ATTEST_DOMAIN.size + 4 + a.size + 4 + c.size)
        out.put(ATTEST_DOMAIN).putInt(a.size).put(a).putInt(c.size).put(c)
        return out.array()
    }

    /** What [issueRiskCommitment] returns; hand [blinding] privately to the prover, publish the rest. [attestation] is `{actionDigest, sig}`. */
    class Issued internal constructor(val commitment: String, val blinding: BigInteger, val rangeProof: Map<String, Any?>, val attestation: Map<String, Any?>)

    /**
     * RISK AUTHORITY side: commit to the risk it computed for [actionDigest], prove the range, and sign (actionDigest, commitment) with the
     * authority's 32-byte Ed25519 secret.
     */
    @JvmStatic
    fun issueRiskCommitment(risk: Any?, actionDigest: String, authoritySecretKey: ByteArray): Issued {
        val c = Accumulator.commitRisk(risk, null)
        val rangeProof = Accumulator.proveRiskRange(risk, c.blinding)
        val sig = Keys.b64u(Keys.edFromSeed(authoritySecretKey).sign(attestMessage(actionDigest, c.commitment)))
        return Issued(c.commitment, c.blinding, rangeProof, result("actionDigest" to actionDigest, "sig" to sig))
    }

    /** Verify one attestation against the risk authority's public key (b64u). Never throws. */
    @JvmStatic
    fun verifyRiskAttestation(commitment: Any?, attestation: Any?, authorityPublicKey: Any?): Boolean = try {
        if (attestation !is Map<*, *>) false
        else {
            val ad = attestation["actionDigest"]
            val sig = attestation["sig"]
            val pk = Pca.decodeB64uStrict(authorityPublicKey, 32)
            val sg = Pca.decodeB64uStrict(sig, 64)
            if (ad !is String || sig !is String || pk == null || sg == null) false
            else Pca.ed25519Strict(pk, attestMessage(ad, commitment as String), sg)
        }
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Sound end-to-end budget check over ATTESTED commitments. For the verifier's own list of action digests (in order), every item must carry a
     * valid authority attestation for exactly that digest and commitment, then [Accumulator.verifyBoundedBudget] must hold. Never throws.
     */
    @JvmStatic
    fun verifyAttestedBudget(items: Any?, expectedActionDigests: Any?, authorityPublicKey: Any?, bMax: Any?, budgetProof: Any?): Boolean {
        try {
            if (items !is List<*> || expectedActionDigests !is List<*> || items.size != expectedActionDigests.size) return false
            val commitments = ArrayList<Any?>()
            val proofs = ArrayList<Any?>()
            for (i in items.indices) {
                val item = items[i] as Map<*, *>
                val att = item["attestation"]
                val ad = if (att is Map<*, *>) att["actionDigest"] else null
                if (ad == null || ad != expectedActionDigests[i]) return false
                if (!verifyRiskAttestation(item["commitment"], att, authorityPublicKey)) return false
                commitments.add(item["commitment"])
                proofs.add(item["rangeProof"])
            }
            return Accumulator.verifyBoundedBudget(commitments, proofs, bMax, budgetProof)
        } catch (e: RuntimeException) {
            return false
        }
    }
}
