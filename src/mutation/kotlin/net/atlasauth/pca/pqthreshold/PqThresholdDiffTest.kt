package net.atlasauth.pca.pqthreshold

import java.security.MessageDigest
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

@Suppress("UNCHECKED_CAST")
class PqThresholdDiffTest {
    private val M = "ref-pq-threshold"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

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

    private fun by(o: Any?): ByteArray = un(o) as? ByteArray ?: throw IllegalArgumentException("expected bytes")

    @Test fun signerSetCommitment() = OracleCases.each(M, "signerSetCommitment") { a ->
        if (a[0] !is List<*>) throw IllegalArgumentException("participants must be an array")
        GroupDescriptor.signerSetCommitment(un(a[0]) as List<*>)
    }

    @Test fun issueGroupDescriptor() = OracleCases.each(M, "issueGroupDescriptor") { a ->
        val inp = map(a[0])
        val seed = un(inp["authoritySeed"])
        if (inp["participants"] !is List<*>) throw IllegalArgumentException("participants must be an array")
        GroupDescriptor.issueGroupDescriptor(seed as? ByteArray, inp["groupPublicKey"], inp["t"], un(inp["participants"]) as List<*>)
    }

    @Test fun verifyGroupDescriptor() = OracleCases.each(M, "verifyGroupDescriptor") { a ->
        val e = map(a[1])
        GroupDescriptor.verifyGroupDescriptor(a[0], e["trustedAuthorities"], e["groupKey"], e["t"], e["signerSetCommitment"] as? String)
    }

    @Test fun normalizePqQuorumPool() = OracleCases.each(M, "normalizePqQuorumPool") { a -> PqThreshold.normalizePqQuorumPool(un(a[0]) as List<*>).sorted() }

    @Test fun pqQuorumRepresentative() = OracleCases.each(M, "pqQuorumRepresentative") { a -> PqThreshold.pqQuorumRepresentative(by(a[0])) }

    @Test fun verifyPqQuorum() = OracleCases.each(M, "verifyPqQuorum") { a ->
        val v = PqThreshold.verifyPqQuorum(a[0], by(a[1]), PqThreshold.normalizePqQuorumPool(un(a[2]) as List<*>), a[3])
        // the corpus always passes the threshold: a JSON null is echoed as need: null (only an absent one is omitted)
        if (a[3] == null) LinkedHashMap(v).also { it["need"] = null } else v
    }

    @Test fun verifyHybridThreshold() = OracleCases.each(M, "verifyHybridThreshold") { a ->
        val o = map(un(a[2]))
        val opts = PqThreshold.HybridVerifyOpts()
        opts.groupKey = o["groupKey"]
        opts.pqPublicKeys = o["pqPublicKeys"]
        opts.t = o["t"]
        opts.pqT = o["pqT"]
        opts.groupDescriptor = o["groupDescriptor"]
        opts.trustedAuthorities = o["trustedAuthorities"]
        opts.signerSetCommitment = o["signerSetCommitment"] as? String
        PqThreshold.verifyHybridThreshold(map(a[0]), un(a[1]), opts)
    }

    // ---- signing round trip (the co-signers and the assembled artifact) ----

    private fun seed(l: String): ByteArray = MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/ref-pqt-java/$l".toByteArray(Charsets.UTF_8))

    @Test fun signAssembleAndVerifyRoundTrip() {
        val k1 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("pq1"))
        val k2 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("pq2"))
        val k3 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed("pq3"))
        val signers = listOf(PqThreshold.MlDsaKeyPair(k1.pk, k1.sk), PqThreshold.MlDsaKeyPair(k2.pk, k2.sk))
        val group = Keys.edFromSeed(seed("group"))
        val authority = Keys.edFromSeed(seed("authority"))
        val parts = ArrayList<Any?>()
        for (i in 1..3) parts.add(linkedMapOf<String, Any?>("identifier" to Js.n(i.toLong()), "publicKey" to Keys.edFromSeed(seed("share$i")).id()))
        val descriptor = GroupDescriptor.issueGroupDescriptor(seed("authority"), group.id(), Js.n(2), parts)

        val action = linkedMapOf<String, Any?>("ver" to Js.n(2), "aud" to "rs", "counter" to Js.n(7))
        val msg = Pca.thresholdMessage(action)
        val aggregate = group.sign(msg)
        val artifact = PqThreshold.hybridThresholdAssemble(action, group.pub, aggregate, 2, 3, signers, null)

        val opts = PqThreshold.HybridVerifyOpts()
        opts.groupKey = group.id()
        opts.pqPublicKeys = listOf(Keys.b64u(k1.pk), Keys.b64u(k2.pk), Keys.b64u(k3.pk))
        opts.t = Js.n(2)
        opts.pqT = Js.n(2)
        opts.groupDescriptor = descriptor
        opts.trustedAuthorities = listOf(authority.id())
        val ok = PqThreshold.verifyHybridThreshold(action, artifact, opts)
        assertEquals(ok.toString(), true, ok["ok"])
        opts.pqT = Js.n(3)
        assertEquals(false, PqThreshold.verifyHybridThreshold(action, artifact, opts)["ok"])
        opts.pqT = Js.n(2)
        val other = LinkedHashMap(action)
        other["counter"] = Js.n(8)
        assertEquals(false, PqThreshold.verifyHybridThreshold(other, artifact, opts)["ok"])
        assertThrows(IllegalArgumentException::class.java) { PqThreshold.hybridThresholdAssemble(other, group.pub, aggregate, 2, 3, signers, null) }
        assertThrows(IllegalArgumentException::class.java) { PqThreshold.hybridThresholdAssemble(action, group.pub, aggregate, 3, 2, signers, null) }
        assertTrue(GroupDescriptor.signerSetCommitment(parts).isNotEmpty())
        assertFalse(PqThreshold.normalizePqQuorumPool(listOf("x")).iterator().hasNext())
    }
}
