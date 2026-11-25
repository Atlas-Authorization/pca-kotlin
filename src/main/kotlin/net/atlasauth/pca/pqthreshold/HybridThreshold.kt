package net.atlasauth.pca.pqthreshold

import net.atlasauth.pca.frost.Frost
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaCore

/**
 * The PCActn-verifier side of the hybrid post-quantum threshold step-up: fold the classical aggregate into a PCActn's threshold container,
 * and enforce both halves through the core verifier's threshold hook. The artifact formats and the standalone verifier live in [PqThreshold].
 */
@Suppress("UNCHECKED_CAST")
object HybridThreshold {
    /** The classical FROST quorum supplied to [hybridThresholdSign]; [groupPublicKey] is 32 bytes or canonical b64u(32). */
    class FrostQuorumInput(val groupPublicKey: Any?, val quorum: List<Frost.FrostParticipantShare>, val t: Int)

    private fun groupKeyBytes(k: Any?): ByteArray {
        if (k is ByteArray) {
            require(k.size == 32) { "hybridThresholdSign: FROST group public key must be 32 bytes" }
            return k
        }
        return (if (k is String) Pca.decodeB64uStrict(k, 32) else null) ?: throw IllegalArgumentException("hybridThresholdSign: FROST group public key is not canonical b64u(32)")
    }

    /**
     * A hybrid artifact for [action]: the FROST t-of-n aggregate over `thresholdMessage(action)` (produced here by [Frost.cosign], which throws
     * on a short quorum or an invalid share) plus one ML-DSA-65 co-signature per signer over the same message.
     */
    @JvmStatic
    @JvmOverloads
    fun hybridThresholdSign(action: Map<String, Any?>, frost: FrostQuorumInput, pqSigners: List<PqThreshold.MlDsaKeyPair>, pqT: Int? = null): Map<String, Any?> {
        require(frost.t >= 1) { "hybridThresholdSign: frost.t must be a positive integer (got ${frost.t})" }
        require(frost.quorum.size >= frost.t) { "hybridThresholdSign: FROST quorum of ${frost.quorum.size} is below the threshold t=${frost.t}" }
        require(pqSigners.isNotEmpty()) { "hybridThresholdSign: at least one ML-DSA co-signer is required" }
        val message = Pca.thresholdMessage(action)
        val groupKey = groupKeyBytes(frost.groupPublicKey)
        val aggregate = Frost.cosign(groupKey, frost.quorum, message, frost.t)
        return PqThreshold.hybridThresholdAssemble(action, groupKey, aggregate, frost.t, frost.quorum.size, pqSigners, pqT)
    }

    /** The PCActn with the classical aggregate folded into its threshold container, and the PQ block that travels alongside it. */
    class StepUp(val pcactn: Map<String, Any?>, val pq: Map<String, Any?>?)

    /**
     * Fold a hybrid artifact into a PCActn step-up: the FROST aggregate becomes a 'guardian' share (publicKey = the group key, sig = the
     * aggregate) in `threshold.shares`; `thresholdMessage` excludes `threshold`, so neither quorum's signed bytes change. The PQ block cannot
     * live in the signed body and rides alongside.
     */
    @JvmStatic
    fun foldHybridStepUp(action: Map<String, Any?>, artifact: Map<String, Any?>): StepUp {
        val f = artifact["frost"] as? Map<String, Any?> ?: throw IllegalArgumentException("foldHybridStepUp: artifact has no FROST part")
        val share = LinkedHashMap<String, Any?>()
        share["role"] = "guardian"
        if (f.containsKey("group_pk")) share["publicKey"] = f["group_pk"] // an absent member stays absent (JSON drops undefined)
        if (f.containsKey("sig")) share["sig"] = f["sig"]
        val shares = ArrayList<Any?>()
        val th = action["threshold"]
        if (th is Map<*, *> && th["shares"] is List<*>) shares.addAll(th["shares"] as List<Any?>)
        shares.add(share)
        val threshold = LinkedHashMap<String, Any?>()
        threshold["shares"] = shares
        val pcactn = LinkedHashMap(action)
        pcactn["threshold"] = threshold
        return StepUp(pcactn, artifact["pq"] as Map<String, Any?>?)
    }

    /** Configuration of [createHybridThresholdVerifier]; values are wire/config values (keys may be String or byte[]). */
    class VerifierOpts {
        var groupKey: Any? = null
        var pqPublicKeys: Any? = null
        var t: Any? = null
        var pqT: Any? = null
        var groupDescriptor: Any? = null
        var trustedAuthorities: Any? = null
        var pqBlock: Any? = null
        var signerSetCommitment: String? = null
    }

    private fun deepCopy(v: Any?): Any? = when (v) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { o -> for ((k, x) in v) o[k as String] = deepCopy(x) }
        is List<*> -> ArrayList<Any?>().also { o -> for (x in v) o.add(deepCopy(x)) }
        is ByteArray -> v.clone()
        else -> v
    }

    private fun normalizeGroupKeyB64u(k: Any?): String? {
        val s = GroupDescriptor.asB64u(k)
        return if (s != null && Pca.decodeB64uStrict(s, 32) != null) s else null
    }

    private fun checkDescriptor(o: VerifierOpts): String? {
        val r = GroupDescriptor.verifyGroupDescriptor(o.groupDescriptor, o.trustedAuthorities, o.groupKey, o.t, o.signerSetCommitment)
        return if (r["ok"] == true) null else r["reason"] as String?
    }

    /**
     * The core verifier's threshold hook enforcing the hybrid step-up: the FROST aggregate folded into `pcactn.threshold` (a plain Ed25519
     * signature under the TRUSTED group key) AND the ML-DSA quorum block. The configuration is copied, so later edits by the caller change
     * nothing. Enforced and ok only when both hold; every other outcome is an enforced refusal.
     */
    @JvmStatic
    fun createHybridThresholdVerifier(inp: VerifierOpts): PcaCore.Hook {
        val o = VerifierOpts()
        o.groupKey = deepCopy(inp.groupKey)
        o.pqPublicKeys = deepCopy(inp.pqPublicKeys)
        o.t = inp.t
        o.pqT = inp.pqT
        o.pqBlock = deepCopy(inp.pqBlock)
        o.groupDescriptor = deepCopy(inp.groupDescriptor)
        o.trustedAuthorities = deepCopy(inp.trustedAuthorities)
        o.signerSetCommitment = inp.signerSetCommitment
        val trustedGroupKey = normalizeGroupKeyB64u(o.groupKey)
        val keys = o.pqPublicKeys
        if (keys !is List<*>) throw IllegalArgumentException("pqPublicKeys is not iterable")
        val pool = PqThreshold.normalizePqQuorumPool(keys)
        return PcaCore.Hook { ctx ->
            val descriptorReason = checkDescriptor(o)
            if (descriptorReason != null) return@Hook PcaCore.HookResult.enforced(false, descriptorReason, null)
            val message = Pca.thresholdMessage(ctx.pcactn)
            if (trustedGroupKey == null) return@Hook PcaCore.HookResult.enforced(false, "trusted FROST group key is not a canonical b64u(32) point", null)
            var sig: String? = null
            val th = ctx.pcactn["threshold"]
            if (th is Map<*, *> && th["shares"] is List<*>) {
                for (s in th["shares"] as List<*>) {
                    if (s is Map<*, *> && s["sig"] is String && trustedGroupKey == s["publicKey"]) { sig = s["sig"] as String; break }
                }
            }
            if (sig == null) return@Hook PcaCore.HookResult.enforced(false, "no FROST aggregate for the trusted group key in the step-up", null)
            if (!Pca.verifyB64u(trustedGroupKey, message, sig)) {
                return@Hook PcaCore.HookResult.enforced(false, "FROST aggregate does not verify under the trusted group key (quorum short or forged)", null)
            }
            val pq = PqThreshold.verifyPqQuorum(o.pqBlock, message, pool, o.pqT)
            if (pq["ok"] != true) return@Hook PcaCore.HookResult.enforced(false, (pq["reason"] as String?) ?: "post-quantum quorum short", null)
            PcaCore.HookResult.enforced(true)
        }
    }

    /** Options of [verifyHybridStepUp]; [t] is the step-up tier (the classical threshold). */
    class StepUpVerifyOpts {
        var grant: Map<String, Any?> = LinkedHashMap()
        var groupKey: Any? = null
        var pqPublicKeys: Any? = null
        var t: Any? = null
        var pqT: Any? = null
        var groupDescriptor: Any? = null
        var trustedAuthorities: Any? = null
        var signerSetCommitment: String? = null

        /** Audience: [audience] (must equal), [audienceAny] (explicit opt-out), or unset (fails when the PCActn carries an aud). */
        var audience: String? = null
        var audienceGiven: Boolean = false
        var nowEpoch: Long? = null
        fun audience(a: String): StepUpVerifyOpts { audience = a; audienceGiven = true; return this }
        fun audienceAny(): StepUpVerifyOpts { audience = null; audienceGiven = true; return this }
    }

    class StepUpResult internal constructor(
        val allow: Boolean,
        /** The full PCActn verification (wire, audience, validity, chain, leaf signature, counter, threshold hook). */
        val core: PcaCore.Result,
        /** The post-quantum quorum verdict, also computed standalone for the audit surface. */
        val pq: Map<String, Any?>,
        val reason: String?,
    )

    /** Verify a folded hybrid step-up end to end: the whole PCActn must verify AND both the FROST threshold and the ML-DSA quorum must hold. */
    @JvmStatic
    fun verifyHybridStepUp(stepUp: StepUp, opts: StepUpVerifyOpts): StepUpResult {
        val keys = opts.pqPublicKeys
        if (keys !is List<*>) throw IllegalArgumentException("pqPublicKeys is not iterable")
        val pool = PqThreshold.normalizePqQuorumPool(keys)
        val pq = PqThreshold.verifyPqQuorum(stepUp.pq, Pca.thresholdMessage(stepUp.pcactn), pool, opts.pqT)
        val v = VerifierOpts()
        v.groupKey = opts.groupKey
        v.pqPublicKeys = opts.pqPublicKeys
        v.t = opts.t
        v.pqT = opts.pqT
        v.pqBlock = stepUp.pq
        v.groupDescriptor = opts.groupDescriptor
        v.trustedAuthorities = opts.trustedAuthorities
        v.signerSetCommitment = opts.signerSetCommitment
        val o = PcaCore.Options(opts.grant)
        o.insecureSkipPlanRootCheck = true
        if (opts.audienceGiven) o.audience = if (opts.audience == null) Pca.Audience.Any else Pca.Audience.Of(opts.audience!!)
        o.nowEpoch = opts.nowEpoch
        o.hooks = PcaCore.Hooks(threshold = createHybridThresholdVerifier(v))
        val core = PcaCore.verify(stepUp.pcactn, o)
        return StepUpResult(core.allow, core, pq, if (core.allow) null else core.reason)
    }
}
