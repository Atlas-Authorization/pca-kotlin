package net.atlasauth.pca.pqthreshold

import java.math.BigDecimal
import net.atlasauth.pca.frost.Frost
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaCore
import net.atlasauth.pca.verifier.Pq
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the hybrid-threshold signer / step-up oracle (sign, fold, hook, verify), plus a native FROST-to-verifier round trip. */
@Suppress("UNCHECKED_CAST")
class HybridThresholdDiffTest {
    private val M = "ref-pq-threshold-java-extra"

    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("expected object")

    /** {"$bytes"} objects become byte[] everywhere (the reference wrapper's `un`). */
    private fun un(v: Any?): Any? {
        if (v is List<*>) return v.map { un(it) }
        if (v is Map<*, *>) {
            if (v.size == 1 && v["\$bytes"] is String) return Keys.unb64u(v["\$bytes"] as String)
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) out[k as String] = un(x)
            return out
        }
        return v
    }

    @Test fun foldHybridStepUp() = OracleCases.each(M, "fold") { a ->
        val s = HybridThreshold.foldHybridStepUp(map(a[0]), map(a[1]))
        val m = LinkedHashMap<String, Any?>()
        m["pcactn"] = s.pcactn
        if (s.pq != null) m["pq"] = s.pq
        m
    }

    @Test fun thresholdHook() = OracleCases.each(M, "hook") { a ->
        val o = map(un(a[0]))
        val v = HybridThreshold.VerifierOpts()
        v.groupKey = o["groupKey"]
        v.pqPublicKeys = o["pqPublicKeys"]
        v.t = o["t"]
        v.pqT = o["pqT"]
        v.pqBlock = o["pqBlock"]
        v.groupDescriptor = o["groupDescriptor"]
        v.trustedAuthorities = o["trustedAuthorities"]
        v.signerSetCommitment = o["signerSetCommitment"] as? String
        val r = HybridThreshold.createHybridThresholdVerifier(v).run(PcaCore.Ctx(map(a[1]), LinkedHashMap(), 1_800_000_000_000L))
        val m = LinkedHashMap<String, Any?>()
        m["enforced"] = r.enforced
        m["ok"] = r.ok
        if (r.reason != null) m["reason"] = r.reason
        m
    }

    @Test fun verifyHybridStepUp() = OracleCases.each(M, "stepUp") { a ->
        val su = map(a[0])
        val o = map(un(a[1]))
        val v = HybridThreshold.StepUpVerifyOpts()
        v.grant = map(o["grant"])
        v.groupKey = o["groupKey"]
        v.pqPublicKeys = o["pqPublicKeys"]
        v.t = o["t"]
        v.pqT = o["pqT"]
        v.groupDescriptor = o["groupDescriptor"]
        v.trustedAuthorities = o["trustedAuthorities"]
        v.signerSetCommitment = o["signerSetCommitment"] as? String
        if (o.containsKey("audience")) { if (o["audience"] == null) v.audienceAny() else v.audience(o["audience"] as String) }
        if (o.containsKey("nowEpoch")) v.nowEpoch = IntentJs.num(o["nowEpoch"])!!.toLong()
        val pq = su["pq"]
        val r = HybridThreshold.verifyHybridStepUp(HybridThreshold.StepUp(map(su["pcactn"]), if (pq == null) null else map(pq)), v)
        val m = LinkedHashMap<String, Any?>()
        m["allow"] = r.allow
        m["pq"] = r.pq
        if (r.reason != null) m["reason"] = r.reason
        m["checks"] = LinkedHashMap<String, Any?>(r.core.checks)
        m
    }

    private fun whole(o: Any?): Long {
        if (o !is Json.Num) throw IllegalArgumentException("expected number")
        return BigDecimal(o.raw).toBigIntegerExact().toLong()
    }

    private fun list(o: Any?): List<Any?> = o as? List<Any?> ?: throw IllegalArgumentException("expected array")

    @Test fun hybridSign() = OracleCases.each(M, "hybridSign") { a ->
        val x = map(un(a[0]))
        val t = whole(x["t"]).toInt()
        val n = whole(x["n"]).toInt()
        val ko = Frost.FrostKeygenOpts()
        ko.secret = x["secret"] as ByteArray?
        ko.coefficients = list(x["coefficients"]).map { it as ByteArray }
        val kg = Frost.trustedDealerKeygen(t, n, ko)
        val quorum = list(x["quorum"]).map { id -> kg.participantShares.last { it.identifier == whole(id) } }
        val keys = list(x["pqSeeds"]).map { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, it as ByteArray) }
        val signers = list(x["pq"]).map { i -> val k = keys[whole(i).toInt()]; PqThreshold.MlDsaKeyPair(k.pk, k.sk) }
        val pqT = if (x["pqT"] == null) null else whole(x["pqT"]).toInt()
        val signT = if (x["signT"] == null) t else whole(x["signT"]).toInt()
        val group: Any = if (x["groupAsString"] == true) Keys.b64u(kg.groupPublicKey) else kg.groupPublicKey
        val action = map(x["action"])
        val artifact = HybridThreshold.hybridThresholdSign(action, HybridThreshold.FrostQuorumInput(group, quorum, signT), signers, pqT)

        val parts = kg.participantShares.map { linkedMapOf<String, Any?>("identifier" to it.identifier, "publicKey" to Keys.b64u(it.publicKey)) }
        val authSeed = x["authSeed"] as ByteArray
        val descriptor = GroupDescriptor.issueGroupDescriptor(authSeed, Keys.b64u(kg.groupPublicKey), t.toLong().let { net.atlasauth.pca.jose.Js.n(it) }, parts)
        val vo = PqThreshold.HybridVerifyOpts()
        vo.groupKey = Keys.b64u(kg.groupPublicKey)
        vo.pqPublicKeys = keys.map { Keys.b64u(it.pk) }
        vo.t = net.atlasauth.pca.jose.Js.n(t.toLong())
        vo.pqT = net.atlasauth.pca.jose.Js.n((pqT ?: signers.size).toLong())
        vo.groupDescriptor = descriptor
        vo.trustedAuthorities = listOf(Keys.b64u(Keys.edFromSeed(authSeed).pub))
        val verdict = PqThreshold.verifyHybridThreshold(action, artifact, vo)

        val frost = LinkedHashMap(map(artifact["frost"]))
        val sig = frost.remove("sig") as String
        frost["sigLen"] = sig.length.toLong()
        val shown = LinkedHashMap(artifact)
        shown["frost"] = frost
        linkedMapOf("artifact" to shown, "verdict" to verdict)
    }

    /** A native FROST quorum folded into a PCActn-shaped action verifies through the standalone hybrid verifier, and a sub-threshold one cannot be signed. */
    @Test fun signFoldRoundTrip() {
        val ko = Frost.FrostKeygenOpts()
        ko.secret = byteArrayOf(9, 8, 7, 6, 5, 4, 3, 2, 1)
        ko.coefficients = listOf(byteArrayOf(1, 1, 2, 3, 5, 8, 13))
        val kg = Frost.trustedDealerKeygen(2, 3, ko)
        val k = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32))
        val signers = listOf(PqThreshold.MlDsaKeyPair(k.pk, k.sk))
        val action = linkedMapOf<String, Any?>("ver" to net.atlasauth.pca.jose.Js.n(2), "aud" to "rs", "counter" to net.atlasauth.pca.jose.Js.n(1))
        val artifact = HybridThreshold.hybridThresholdSign(action, HybridThreshold.FrostQuorumInput(kg.groupPublicKey, kg.participantShares.subList(1, 3), 2), signers, null)
        assertTrue(Pca.ed25519Strict(kg.groupPublicKey, Pca.thresholdMessage(action), Keys.unb64u(map(artifact["frost"])["sig"] as String)))
        val folded = HybridThreshold.foldHybridStepUp(action, artifact)
        assertTrue(Pca.thresholdMessage(action).contentEquals(Pca.thresholdMessage(folded.pcactn))) // folding does not change the signed bytes
        assertFalse((map(folded.pcactn["threshold"])["shares"] as List<*>).isEmpty())
        assertThrows(IllegalArgumentException::class.java) {
            HybridThreshold.hybridThresholdSign(action, HybridThreshold.FrostQuorumInput(kg.groupPublicKey, kg.participantShares.subList(0, 1), 2), signers, null)
        }
    }
}
