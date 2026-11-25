package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the reference oracle of the in-core post-quantum quorum sets, quorum proofs and rotation chains: 389 cases, every fn
 * dispatched. The sign cases derive Ed25519 and ML-DSA keys from the corpus' seed labels and compare the signature bytes, which also
 * pins this SDK's ML-DSA signer to the deterministic FIPS 204 variant. Five cases pass the reference a value of another type that it
 * happens to tolerate (a string index, a string for bytes or for a list, string arithmetic on an epoch); a typed API cannot receive
 * them, so they are skipped by name and the skip is asserted.
 */
@Suppress("UNCHECKED_CAST")
class PqQuorumDiffTest {
    private val mod = "ref-pq-threshold-quorum"

    private class Unrepresentable(m: String) : RuntimeException(m)

    private val skipped = setOf(
        "quorumActionDigest/string (throws)", "signQuorumShare/index string", "assembleQuorumProof/shares not array",
        "buildRotationCert/epoch string concatenates", "quorumProofSize/chosen index string",
    )

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null
    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw Unrepresentable("not an object")
    private fun list(o: Any?): List<Any?> = o as? List<Any?> ?: throw Unrepresentable("not an array")

    private fun bytesOrNull(o: Any?): ByteArray? {
        val b = (o as? Map<*, *>)?.get("\$bytes")
        return if (o is Map<*, *> && o.size == 1 && b is String) Keys.unb64u(b) else null
    }

    private fun int(o: Any?): Int {
        val d = IntentJs.num(o)
        if (d == null || d != Math.rint(d) || Math.abs(d) > Int.MAX_VALUE) throw Unrepresentable("not an integer")
        return d.toInt()
    }

    /** The loader has replaced each {"$seed": label} by the base64url seed. */
    private fun seed(o: Any?): ByteArray? = if (o == null) null else Pca.decodeB64uStrict(o, 32) ?: throw Unrepresentable("not a key")

    private fun ed(keys: Map<String, Any?>): Keys.EdKey? = seed(keys["edSecret"])?.let { Keys.edFromSeed(it) }

    /** The post-quantum key the slot's suite needs, from the corpus key bag {edSecret?, mlDsa?, mlDsa87?}. */
    private fun pq(set: Map<String, Any?>, index: Int, keys: Map<String, Any?>): Keys.PqKey? {
        val alg = ((set["signers"] as? List<*>)?.getOrNull(index) as? Map<*, *>)?.get("alg") as? String ?: return null
        val is87 = alg.endsWith("ml-dsa-87")
        val s = seed(keys[if (is87) "mlDsa87" else "mlDsa"]) ?: return null
        return Keys.pqFromSeed(if (is87) Pq.Prim.ML_DSA_87 else Pq.Prim.ML_DSA_65, s)
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf("PQ_QUORUM_MAX_SIGNERS" to PqQuorum.PQ_QUORUM_MAX_SIGNERS, "PQ_QUORUM_MAX_CHAIN" to PqQuorum.PQ_QUORUM_MAX_CHAIN)
        "buildQuorumSet" -> if (a.size > 2) PqQuorum.buildQuorumSet(arg(a, 0), arg(a, 1), a[2]) else PqQuorum.buildQuorumSet(arg(a, 0), arg(a, 1))
        "loadQuorumSet" -> PqQuorum.loadQuorumSet(arg(a, 0))
        "quorumMessage" -> PqQuorum.quorumMessage(arg(a, 0), arg(a, 1), arg(a, 2))
        "quorumActionDigest" -> PqQuorum.quorumActionDigest(bytesOrNull(arg(a, 0)) ?: throw Unrepresentable("not bytes"))
        "signQuorumShare" -> {
            val set = map(arg(a, 0))
            val keys = map(arg(a, 4))
            val i = int(arg(a, 1))
            PqQuorum.signQuorumShare(set, i, arg(a, 2), arg(a, 3), ed(keys), pq(set, i, keys))
        }
        "assembleQuorumProof" -> PqQuorum.assembleQuorumProof(map(arg(a, 0)), list(arg(a, 1)))
        "verifyQuorum" -> PqQuorum.verifyQuorum(arg(a, 0))
        "verifyQuorumApproval" -> PqQuorum.verifyQuorumApproval(arg(a, 0), arg(a, 1), bytesOrNull(arg(a, 2)), arg(a, 3), arg(a, 4) as? Map<String, Any?>)
        "rotationActionDigest" -> PqQuorum.rotationActionDigest(arg(a, 0), arg(a, 1))
        "buildRotationCert" -> PqQuorum.buildRotationCert(map(arg(a, 0)), arg(a, 1), arg(a, 2), list(arg(a, 3)))
        "signRotationShare" -> {
            val from = map(arg(a, 0))
            val keys = map(arg(a, 4))
            val i = int(arg(a, 1))
            PqQuorum.signRotationShare(from, i, arg(a, 2), map(arg(a, 3)), ed(keys), pq(from, i, keys))
        }
        "verifyRotationChain" -> PqQuorum.verifyRotationChain(arg(a, 0), arg(a, 1), arg(a, 2))
        "isRotationFork" -> PqQuorum.isRotationFork(arg(a, 0), arg(a, 1))
        "quorumProofSize" -> PqQuorum.quorumProofSize(map(arg(a, 0)), if (a.size > 1) list(a[1]) else null)
        else -> throw AssertionError("unhandled fn $fn")
    }

    private val handled = setOf(
        "constants", "buildQuorumSet", "loadQuorumSet", "quorumMessage", "quorumActionDigest", "signQuorumShare", "assembleQuorumProof", "verifyQuorum",
        "verifyQuorumApproval", "rotationActionDigest", "buildRotationCert", "signRotationShare", "verifyRotationChain", "isRotationFork", "quorumProofSize",
    )

    @Test fun replayAllCases() {
        assertEquals(handled, BaseOracle.fns("$mod.json.gz"))
        var total = 0
        val skippedSeen = HashSet<String>()
        val bad = ArrayList<String>()
        for (fn in handled) for (c in OracleCases.of(mod, fn)) {
            total++
            val name = c["name"] as String
            if (name in skipped) { skippedSeen.add(name); continue }
            OracleCases.diff(c, c["out"]) { a -> call(fn, a) }?.let { bad.add(it) }
        }
        assertEquals(389, total)
        assertEquals(skipped, skippedSeen)
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }
}
