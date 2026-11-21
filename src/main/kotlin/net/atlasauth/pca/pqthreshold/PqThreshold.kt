package net.atlasauth.pca.pqthreshold

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.pqthreshold.GroupDescriptor.isInteger
import net.atlasauth.pca.pqthreshold.GroupDescriptor.member
import net.atlasauth.pca.pqthreshold.GroupDescriptor.numOf
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq

/**
 * Post-quantum threshold step-up for PCActn: a hybrid of a classical FROST(Ed25519) aggregate (verified as the plain Ed25519 signature it is,
 * under the verifier's pinned group key, with the threshold bound by a signed [GroupDescriptor]) AND a pqT-of-m ML-DSA-65 co-signature quorum
 * over the same action digest. Both must hold; either short fails closed.
 *
 * Scope of this port: the verifier side and the quorum signer. The FROST signing protocol (dealer, nonces, cosign) lives in a FROST
 * implementation this SDK does not carry yet, so [hybridThresholdAssemble] takes an aggregate produced elsewhere and refuses one that does not
 * verify. The research lattice-threshold prototype of the reference (labelled not-for-production) is [LatticeThresholdExperimental].
 */
object PqThreshold {
    const val HYBRID_ARTIFACT_VERSION = 2
    const val PQ_QUORUM_VERSION = 2
    const val MAX_PQ_QUORUM_ENTRIES = 256
    const val HYBRID_CLASSICAL_ALG = "frost-ed25519"
    const val PQ_QUORUM_ALG = "ml-dsa-65"
    private val PQ_QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\u0000".toByteArray(Charsets.UTF_8)

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun verdict(ok: Boolean, count: Any?, need: Any?, reason: String?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        m["count"] = count
        if (need != null) m["need"] = need
        if (reason != null) m["reason"] = reason
        return m
    }

    /** The bytes every quorum co-signature covers: DOMAIN || sha256(message). */
    @JvmStatic
    fun pqQuorumRepresentative(message: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(PQ_QUORUM_DOMAIN, 0, PQ_QUORUM_DOMAIN.size)
        val h = sha256(message)
        o.write(h, 0, h.size)
        return o.toByteArray()
    }

    /** The trusted pool as canonical b64u strings (String or byte[] entries); anything that is not a well-formed ML-DSA-65 public key is ignored. */
    @JvmStatic
    fun normalizePqQuorumPool(pks: List<*>): Set<String> {
        val pool = LinkedHashSet<String>()
        for (p in pks) {
            val s = GroupDescriptor.asB64u(p)
            if (s != null && Pca.decodeB64uStrict(s, Pq.ML_DSA_65_PUBLIC_KEY_BYTES) != null) pool.add(s)
        }
        return pool
    }

    private fun mlDsa65VerifyB64u(pk: Any?, msg: ByteArray, sig: Any?): Boolean {
        val p = Pca.decodeB64uStrict(pk, Pq.ML_DSA_65_PUBLIC_KEY_BYTES)
        val s = Pca.decodeB64uStrict(sig, Pq.ML_DSA_65_SIGNATURE_BYTES)
        return p != null && s != null && Pq.mlDsa65Verify(p, msg, s)
    }

    /** An ML-DSA-65 co-signer key pair (FIPS 204 encodings). */
    class MlDsaKeyPair(val publicKey: ByteArray, val secretKey: ByteArray)

    private fun mlDsa65Sign(sk: ByteArray, msg: ByteArray): ByteArray = Pq.mlDsa65Sign(sk, msg)

    /** One ML-DSA-65 co-signature per key pair over the representative; pqT defaults to the signer count. */
    @JvmStatic
    @JvmOverloads
    fun signPqQuorum(message: ByteArray, keyPairs: List<MlDsaKeyPair>, pqT: Int? = null): Map<String, Any?> {
        val rep = pqQuorumRepresentative(message)
        val signers = ArrayList<Any?>()
        for (k in keyPairs) {
            val e = LinkedHashMap<String, Any?>()
            e["pk"] = Keys.b64u(k.publicKey)
            e["sig"] = Keys.b64u(mlDsa65Sign(k.secretKey, rep))
            signers.add(e)
        }
        val b = LinkedHashMap<String, Any?>()
        b["v"] = Js.n(PQ_QUORUM_VERSION.toLong())
        b["alg"] = PQ_QUORUM_ALG
        b["pqT"] = Js.n((pqT ?: signers.size).toLong())
        b["signers"] = signers
        return b
    }

    /**
     * Count DISTINCT trusted keys whose co-signature verifies over [message]; ok iff the count reaches [pqT]. Total: never throws. A key
     * outside the pool, a repeated key, a signature over another message and every malformed entry count for nothing; a block whose version
     * is missing (pre-0.5), 1 or unknown is refused before any verification. Returns {ok, count, need, reason?}.
     */
    @JvmStatic
    fun verifyPqQuorum(block: Any?, message: ByteArray, trustedPool: Set<String>, pqT: Any?): Map<String, Any?> {
        val zero = Js.n(0)
        if (!isInteger(pqT) || numOf(pqT)!! < 1) return verdict(false, zero, pqT, "pqT must be a positive integer")
        if (!GroupDescriptor.isObject(block)) return verdict(false, zero, pqT, "malformed pq block")
        val b: Map<*, *> = if (block is Map<*, *>) block else emptyMap<Any?, Any?>()
        if (!b.containsKey("v")) return verdict(false, zero, pqT, "pq quorum version missing (pre-0.5 format is refused)")
        val v = numOf(b["v"])
        if (v != null && v == 1.0) return verdict(false, zero, pqT, "pq quorum version 1 is no longer accepted (pre-0.5 format)")
        if (v == null || v != PQ_QUORUM_VERSION.toDouble()) return verdict(false, zero, pqT, "unsupported pq quorum version")
        val signers = b["signers"]
        if (PQ_QUORUM_ALG != b["alg"] || signers !is List<*>) return verdict(false, zero, pqT, "malformed pq block")
        val rep = pqQuorumRepresentative(message)
        val counted = HashSet<String>()
        var seen = 0
        for (entry in signers) {
            if (seen++ >= MAX_PQ_QUORUM_ENTRIES) break
            val pk = member(entry, "pk")
            val sig = member(entry, "sig")
            if (pk !is String || sig !is String) continue
            if (!trustedPool.contains(pk) || counted.contains(pk)) continue
            if (!mlDsa65VerifyB64u(pk, rep, sig)) continue
            counted.add(pk)
        }
        val count = counted.size.toLong()
        if (count >= numOf(pqT)!!) return verdict(true, Js.n(count), pqT, null)
        return verdict(false, Js.n(count), pqT, "post-quantum quorum short: $count of ${GroupDescriptor.fmt(pqT)} required ML-DSA co-signatures")
    }

    // ---- hybrid ----

    private fun normalizeGroupKeyB64u(k: Any?): String? {
        val s = GroupDescriptor.asB64u(k)
        return if (s != null && Pca.decodeB64uStrict(s, 32) != null) s else null
    }

    /** The FROST aggregate is a plain strict Ed25519 signature under the TRUSTED group key (never one the artifact declares). */
    private fun verifyFrostAggregate(sig: Any?, message: ByteArray, trustedGroupKey: String): Boolean = sig is String && Pca.verifyB64u(trustedGroupKey, message, sig)

    /** Options for [verifyHybridThreshold]; every field is a wire/config value as parsed JSON (keys may be String or byte[]). */
    class HybridVerifyOpts {
        var groupKey: Any? = null
        var pqPublicKeys: Any? = null
        var t: Any? = null
        var pqT: Any? = null
        var groupDescriptor: Any? = null
        var trustedAuthorities: Any? = null
        var signerSetCommitment: String? = null
    }

    private fun malformed(): Map<String, Any?> {
        val reason = "malformed action or verifier options"
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = false
        m["frost"] = false
        m["pq"] = verdict(false, Js.n(0), Js.n(0), reason)
        m["reason"] = reason
        return m
    }

    /**
     * Verify a standalone hybrid artifact over [action] (a PCActn or body as a JSON object). BOTH the classical aggregate and the pqT-of-m
     * quorum must hold; the declared classical threshold must not be below the required t (downgrade). Never throws: malformed input is a
     * refusal. Returns {ok, frost, pq, reason?}.
     */
    @JvmStatic
    fun verifyHybridThreshold(action: Map<String, Any?>, artifact: Any?, opts: HybridVerifyOpts): Map<String, Any?> = try {
        verifyInner(action, artifact, opts)
    } catch (e: RuntimeException) {
        malformed()
    }

    private fun verifyInner(action: Map<String, Any?>, artifact: Any?, opts: HybridVerifyOpts): Map<String, Any?> {
        val hasV = artifact is Map<*, *> && artifact.containsKey("v")
        val vn = numOf(member(artifact, "v"))
        if (!hasV || vn == null || vn != HYBRID_ARTIFACT_VERSION.toDouble()) {
            val reason = if (!hasV) "artifact version missing (pre-0.5 format is refused)"
            else if (vn != null && vn == 1.0) "artifact version 1 is no longer accepted (pre-0.5 format)" else "unsupported artifact version"
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = false
            m["frost"] = false
            m["pq"] = verdict(false, Js.n(0), opts.pqT, reason)
            m["reason"] = reason
            return m
        }
        val message = Pca.thresholdMessage(action)
        val trustedGroupKey = normalizeGroupKeyB64u(opts.groupKey)
        val keys = opts.pqPublicKeys
        if (keys !is List<*>) throw IllegalArgumentException("pqPublicKeys is not iterable")
        val pool = normalizePqQuorumPool(keys)

        var frostOk = false
        var frostReason: String? = null
        val dr = GroupDescriptor.verifyGroupDescriptor(opts.groupDescriptor, opts.trustedAuthorities, opts.groupKey, opts.t, opts.signerSetCommitment)
        val descriptorReason = if (dr["ok"] == true) null else dr["reason"] as String?
        val frost = member(artifact, "frost")
        if (!isInteger(opts.t) || numOf(opts.t)!! < 1) {
            frostReason = "t must be a positive integer"
        } else if (trustedGroupKey == null) {
            frostReason = "trusted FROST group key is not a canonical b64u(32) point"
        } else if (!GroupDescriptor.isObject(frost) || HYBRID_CLASSICAL_ALG != member(frost, "alg")) {
            frostReason = "malformed or missing FROST part"
        } else if (descriptorReason != null) {
            frostReason = descriptorReason
        } else if (!isInteger(member(frost, "t")) || numOf(member(frost, "t"))!! < numOf(opts.t)!!) {
            frostReason = "FROST declared threshold ${GroupDescriptor.fmt(member(frost, "t"))} is below the required t=${GroupDescriptor.fmt(opts.t)} (downgrade)"
        } else if (!verifyFrostAggregate(member(frost, "sig"), message, trustedGroupKey)) {
            frostReason = "FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)"
        } else {
            frostOk = true
        }
        val pq = verifyPqQuorum(member(artifact, "pq"), message, pool, opts.pqT)
        val ok = frostOk && pq["ok"] == true
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = ok
        out["frost"] = frostOk
        out["pq"] = pq
        if (!ok) {
            val r = if (frostOk) pq["reason"] else frostReason
            if (r != null) out["reason"] = r
        }
        return out
    }

    /**
     * Assemble a hybrid artifact from a FROST aggregate produced by a FROST implementation (the signing protocol is not carried here) and the
     * ML-DSA co-signers. Fails closed: a sub-threshold quorum count, no co-signer, a non-canonical group key, or an aggregate that does not
     * verify under the group key all throw.
     */
    @JvmStatic
    @JvmOverloads
    fun hybridThresholdAssemble(
        action: Map<String, Any?>, groupPublicKey: ByteArray?, frostAggregate: ByteArray?, t: Int, quorum: Int, pqSigners: List<MlDsaKeyPair>, pqT: Int? = null,
    ): Map<String, Any?> {
        require(t >= 1) { "hybridThresholdAssemble: t must be a positive integer (got $t)" }
        require(quorum >= t) { "hybridThresholdAssemble: FROST quorum of $quorum is below the threshold t=$t" }
        require(pqSigners.isNotEmpty()) { "hybridThresholdAssemble: at least one ML-DSA co-signer is required" }
        require(!(groupPublicKey == null || groupPublicKey.size != 32)) { "hybridThresholdAssemble: FROST group public key must be 32 bytes" }
        val message = Pca.thresholdMessage(action)
        require(frostAggregate != null && Pca.verifyB64u(Keys.b64u(groupPublicKey), message, Keys.b64u(frostAggregate))) {
            "hybridThresholdAssemble: the FROST aggregate does not verify under the group key"
        }
        val frost = LinkedHashMap<String, Any?>()
        frost["alg"] = HYBRID_CLASSICAL_ALG
        frost["group_pk"] = Keys.b64u(groupPublicKey)
        frost["sig"] = Keys.b64u(frostAggregate!!)
        frost["t"] = Js.n(t.toLong())
        frost["quorum"] = Js.n(quorum.toLong())
        val a = LinkedHashMap<String, Any?>()
        a["v"] = Js.n(HYBRID_ARTIFACT_VERSION.toLong())
        a["digest"] = Keys.b64u(sha256(message))
        a["frost"] = frost
        a["pq"] = signPqQuorum(message, pqSigners, pqT)
        return a
    }
}
