package net.atlasauth.pca.frost

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.ZkJs
import java.security.MessageDigest

/**
 * Post-quantum agility for the FROST guardian-quorum co-sign (interim hybrid). The quorum's FROST aggregate is an ordinary Ed25519 signature, so the whole
 * guardian path rests on the discrete log of Ed25519. The interim hybrid attaches an ML-DSA-65 co-signature by the long-lived guardian key over a representative
 * that binds the group key, the SHA-256 of the message, the signer set and the suite, so it cannot be lifted to another group, message, quorum or suite;
 * verification is fail closed `edOk && pqOk`. It is not a post-quantum THRESHOLD signature: the threshold property rides on the classical aggregate and the
 * ML-DSA half is minted by one guardian key. The artifact is self-describing through `groupAlg` (absent: `ed25519`, just `{sig}`, byte-identical in shape to the
 * raw aggregate); a hybrid artifact whose co-signature is missing or invalid is DENIED, and a verifier that pins hybrid refuses a classical-only artifact.
 *
 * The ML-DSA co-signer QUORUM (pqT-of-m, format version 2) lives in `PqThreshold`.
 */
@Suppress("UNCHECKED_CAST")
object FrostPq {
    const val DEFAULT_FROST_GROUP_ALG = "ed25519"
    const val HYBRID_GROUP_ALG = "hybrid-ed25519-ml-dsa-65"
    private const val FROST_COSIGN_DOMAIN = "atlas-pca/frost-pq-cosign/v1\u0000"
    private const val FROST_SIGNER_SET_DOMAIN = "atlas-pca/frost-signer-set/v1\u0000"

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun concat(vararg parts: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (p in parts) out.write(p)
        return out.toByteArray()
    }

    private fun known(x: Any?): Boolean = x == DEFAULT_FROST_GROUP_ALG || x == HYBRID_GROUP_ALG

    /** The artifact's `groupAlg` (absent: `ed25519`); null for an unknown value (fail closed). `absent` is true when the member is missing. */
    @JvmStatic
    fun resolveFrostGroupAlg(groupAlg: Any?, absent: Boolean = false): String? = if (absent) DEFAULT_FROST_GROUP_ALG else if (known(groupAlg)) groupAlg as String else null

    /**
     * The canonical digest of the signer set: `sha256(DOMAIN || canonical(sorted distinct ids))`. Order-insensitive and duplicate-free; an empty set or an
     * identifier that is not a positive safe integer throws.
     */
    @JvmStatic
    fun frostSignerSetDigest(signerSet: Any?): ByteArray {
        if (signerSet !is List<*> || signerSet.isEmpty()) throw IllegalArgumentException("frostSignerSetDigest: empty signer set")
        val ids = LinkedHashSet<Double>()
        for (x in signerSet) {
            val d = IntentJs.num(x)
            if (d == null || !IntentJs.isSafeInteger(x) || d <= 0) {
                throw IllegalArgumentException("frostSignerSetDigest: participant identifiers must be positive safe integers")
            }
            ids.add(d)
        }
        val sorted = ids.sorted().map { IntentJs.ofLong(it.toLong()) }
        return sha256(concat(FROST_SIGNER_SET_DOMAIN.toByteArray(Charsets.UTF_8), Pca.canonBytes(sorted)))
    }

    /** The bytes the guardian ML-DSA-65 co-signature covers: `DOMAIN || groupAlg || 0x00 || groupPublicKey(32) || sha256(message) || signerSetDigest(32)`. */
    @JvmStatic
    fun frostCosignRepresentative(groupPublicKeyB64u: Any?, message: ByteArray, signerSet: Any?, groupAlg: String): ByteArray {
        val gpk = Pca.decodeB64uStrict(groupPublicKeyB64u, 32) ?: throw IllegalArgumentException("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point")
        return concat(
            FROST_COSIGN_DOMAIN.toByteArray(Charsets.UTF_8), groupAlg.toByteArray(Charsets.UTF_8), byteArrayOf(0), gpk, sha256(message), frostSignerSetDigest(signerSet),
        )
    }

    /**
     * Produce the co-sign artifact over `message`: the classical FROST aggregate of `quorum` (every safety check on; an invalid or sub-threshold aggregate
     * throws) and, for the hybrid suite, the guardian ML-DSA-65 co-signature (`guardianMlDsa`, required: a hybrid suite without it throws). `{sig}` for
     * `ed25519`, `{sig, groupAlg, pq_sig, pq_pk}` for the hybrid.
     */
    @JvmStatic @JvmOverloads
    fun signHybridFrostCosign(
        groupPublicKey: ByteArray, quorum: List<Frost.FrostParticipantShare>, message: ByteArray, groupAlg: String? = null, guardianMlDsa: Keys.PqKey? = null, threshold: Int? = null,
    ): Map<String, Any?> {
        val alg = groupAlg ?: DEFAULT_FROST_GROUP_ALG
        if (!known(alg)) throw IllegalArgumentException("signHybridFrostCosign: unknown groupAlg '$alg'")
        val aggregate = Frost.cosign(groupPublicKey, quorum, message, threshold)
        val sig = Keys.b64u(aggregate)
        if (alg == DEFAULT_FROST_GROUP_ALG) return linkedMapOf("sig" to sig)
        if (guardianMlDsa == null) throw IllegalArgumentException("signHybridFrostCosign: '$alg' requires a guardian ML-DSA-65 key pair")
        val rep = frostCosignRepresentative(Keys.b64u(groupPublicKey), message, quorum.map { IntentJs.ofLong(it.identifier) }, alg)
        val pq = Keys.suite("ml-dsa-65", null, guardianMlDsa).sign(rep)
        return linkedMapOf("sig" to sig, "groupAlg" to alg, "pq_sig" to pq.first, "pq_pk" to guardianMlDsa.pkB64u())
    }

    private fun deny(reason: String, groupAlg: String? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("ok" to false, "edOk" to false, "pqOk" to false)
        if (groupAlg != null) m["groupAlg"] = groupAlg
        m["reason"] = reason
        return m
    }

    /**
     * Verify a co-sign artifact over `message`. FAIL CLOSED HYBRID: for the hybrid suite BOTH the FROST Ed25519 group signature (under `groupPublicKeyB64u`) AND the
     * guardian ML-DSA-65 co-signature (over the representative, under the REGISTERED guardian key `guardianPqPublicKey`, never the artifact's own `pq_pk`) must
     * verify. `expectGroupAlg` pins the suite: a classical-only artifact is then refused (no silent downgrade). Total: never throws.
     * `{ok, groupAlg?, edOk, pqOk, reason?}`.
     */
    @JvmStatic @JvmOverloads
    fun verifyHybridFrostCosign(
        artifact: Any?, message: ByteArray, groupPublicKeyB64u: Any?, signerSet: Any?, guardianPqPublicKey: Any? = null, expectGroupAlg: Any? = null, hasExpect: Boolean = false,
    ): Map<String, Any?> {
        if (artifact !is Map<*, *> || artifact["sig"] !is String) return deny("malformed artifact")
        if (groupPublicKeyB64u !is String || Pca.decodeB64uStrict(groupPublicKeyB64u, 32) == null) return deny("malformed group public key")
        val groupAlg = resolveFrostGroupAlg(artifact["groupAlg"], !artifact.containsKey("groupAlg")) ?: return deny("unknown groupAlg '${ZkJs.string(artifact["groupAlg"])}'")
        if (hasExpect) {
            if (!known(expectGroupAlg)) return deny("unknown expected groupAlg '${ZkJs.string(expectGroupAlg)}'")
            if (expectGroupAlg != groupAlg) return deny("groupAlg '$groupAlg' does not match the required '$expectGroupAlg'", groupAlg)
        }
        val edOk = try {
            Pca.verifyB64u(groupPublicKeyB64u, message, artifact["sig"] as String)
        } catch (e: RuntimeException) {
            false
        }
        if (groupAlg == DEFAULT_FROST_GROUP_ALG) {
            if (!edOk) return deny("FROST Ed25519 group signature did not verify", groupAlg)
            return linkedMapOf("ok" to true, "groupAlg" to groupAlg, "edOk" to true, "pqOk" to false)
        }
        if (guardianPqPublicKey !is String || Pca.decodeB64uStrict(guardianPqPublicKey, Pq.ML_DSA_65_PUBLIC_KEY_BYTES) == null) {
            return deny("hybrid groupAlg requires a registered guardian ML-DSA-65 public key", groupAlg)
        }
        if (artifact.containsKey("pq_pk") && artifact["pq_pk"] != guardianPqPublicKey) return deny("artifact pq_pk does not match the registered guardian ML-DSA key", groupAlg)
        val pqSig = artifact["pq_sig"]
        if (pqSig !is String) return deny("hybrid groupAlg declared but the guardian ML-DSA co-signature is missing", groupAlg)
        val pqOk = try {
            Pq.mlDsa65VerifyB64u(guardianPqPublicKey, frostCosignRepresentative(groupPublicKeyB64u, message, signerSet, groupAlg), pqSig)
        } catch (e: RuntimeException) {
            false
        }
        if (!edOk || !pqOk) {
            return linkedMapOf("ok" to false, "groupAlg" to groupAlg, "edOk" to edOk, "pqOk" to pqOk, "reason" to if (!edOk) "FROST Ed25519 group signature did not verify" else "guardian ML-DSA-65 co-signature did not verify")
        }
        return linkedMapOf("ok" to true, "groupAlg" to groupAlg, "edOk" to true, "pqOk" to true)
    }
}
