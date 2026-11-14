package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for Ledger: freshly signed guardian heads, witness cosignatures and witnessed heads, each varied in exactly one
 * member, so every refusal (missing member, wrong type, untrusted / duplicate witness, epoch binding, consistency size guards) is
 * pinned to false, and every refusal that must not throw is called with the shape that reaches it.
 */
class Kill05StoreLedgerTest {
    private val g = "k05/ledger/guardian"
    private val w1 = "k05/ledger/w1"
    private val w2 = "k05/ledger/w2"
    private val x32 = Pca.b64(ByteArray(32))

    private fun signed(m: Map<String, Any?>, keyField: String, label: String, domain: String, body: Map<String, Any?>): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap(m)
        out[keyField] = pub(label)
        out["sig"] = sign(label, IntentJs.message(domain, body))
        return out
    }

    private fun sthBody(root: String = "r1", prev: Any? = "p0", size: Long = 1L) =
        jm("instance_id", "ins", "principal", "pr", "size", size, "root", root, "prev_root", prev, "timestamp", 5L)

    /** A genuine head for [g]. */
    private fun sth(root: String = "r1"): LinkedHashMap<String, Any?> = sthBody(root).let { signed(it, "guardian", g, Ledger.STH_DOMAIN, it) }

    private fun cosig(head: Map<String, Any?>, label: String, epoch: Any? = 0L): LinkedHashMap<String, Any?> {
        val body = jm(
            "instance_id", head["instance_id"], "principal", head["principal"], "size", head["size"], "root", head["root"],
            "prev_root", head["prev_root"], "guardian_epoch", epoch,
        )
        return jm("key", pub(label), "sig", sign(label, IntentJs.message(Ledger.STH_WITNESS_DOMAIN, body)))
    }

    private fun witnessed(root: String, label: String = w1): LinkedHashMap<String, Any?> =
        jm("principal", "pr", "size", 3L, "root", root).let { signed(it, "witness", label, Ledger.LEDGER_HEAD_DOMAIN, it) }

    private fun proof(old: Long, new: Long) = jm("oldSize", old, "newSize", new, "path", jl())

    @Test
    fun treeHeadMembersAndSignatureInput() {
        assertTrue(Ledger.verifyTreeHead(sth(), pub(g)))
        // a member the signature covered as null but the wire omits: refused, not read as null
        val body = sthBody()
        body["timestamp"] = null
        val noTs = signed(body, "guardian", g, Ledger.STH_DOMAIN, body)
        noTs.remove("timestamp")
        assertFalse(Ledger.verifyTreeHead(noTs, pub(g)))
        // a member that cannot be canonicalized: the signature input cannot be built, so false (never true, never a throw)
        val odd = sth()
        odd["root"] = Any()
        assertFalse(Ledger.verifyTreeHead(odd, pub(g)))
        // a non-string guardian is false, not a ClassCastException
        val ng = sth()
        ng["guardian"] = 5L
        assertFalse(Ledger.verifyTreeHead(ng, pub(g)))
        assertFalse(Ledger.same(Any(), Any()))
        assertTrue(Ledger.same(5L, IntentJs.ofLong(5)))
    }

    @Test
    fun checkpointChainOfOneAndItsVerdict() {
        val v = Ledger.verifyCheckpointChain(jl(jm("sth", sth())), pub(g))
        assertTrue(v.ok)
        assertEquals(0, v.at)
        assertEquals("CheckpointVerdict(ok=true, at=0)", v.toString())
        assertEquals("CheckpointVerdict(ok=false, at=1)", Ledger.CheckpointVerdict(false, 1).toString())
    }

    @Test
    fun witnessedHeadsAndEquivocation() {
        val a = witnessed("r1")
        val b = witnessed("r2")
        assertTrue(Ledger.verifyWitnessedHead(a, pub(w1)))
        assertTrue(Ledger.detectEquivocation(a, b, pub(w1)))
        val noRoot = LinkedHashMap(a)
        noRoot.remove("root")
        assertFalse(Ledger.verifyWitnessedHead(noRoot, pub(w1)))
        assertFalse(Ledger.verifyWitnessedHead(jm("witness", 5L), pub(w1)))
        // either side not a genuine head: no equivocation
        val forged = LinkedHashMap(b)
        forged["sig"] = a["sig"]
        assertFalse(Ledger.detectEquivocation(forged, a, pub(w1)))
        assertFalse(Ledger.detectEquivocation(a, forged, pub(w1)))
        assertFalse(Ledger.detectEquivocation(a, "x", pub(w1)))
        assertFalse(Ledger.detectEquivocation("x", a, pub(w1)))
    }

    @Test
    fun oneCosignatureIsBoundToTheHeadAndTheEpoch() {
        val head = sth()
        assertTrue(Ledger.verifyWitnessCosignature(head, cosig(head, w1), pub(w1)))
        assertFalse(Ledger.verifyWitnessCosignature("x", jm("key", pub(w1), "sig", "s"), pub(w1)))
        assertFalse(Ledger.verifyWitnessCosignature(head, "x", pub(w1)))
        val noPrev = LinkedHashMap(head)
        noPrev.remove("prev_root")
        assertFalse(Ledger.verifyWitnessCosignature(noPrev, jm("key", pub(w1), "sig", "s"), pub(w1)))
        // absent or null guardian_epoch = 0; a present one is bound as it is
        val nullEpoch = LinkedHashMap(head)
        nullEpoch["guardian_epoch"] = null
        assertTrue(Ledger.verifyWitnessCosignature(nullEpoch, cosig(head, w1, 0L), pub(w1)))
        val e3 = LinkedHashMap(head)
        e3["guardian_epoch"] = 3L
        assertTrue(Ledger.verifyWitnessCosignature(e3, cosig(head, w1, 3L), pub(w1)))
        assertFalse(Ledger.verifyWitnessCosignature(e3, cosig(head, w1, 0L), pub(w1)))
        assertFalse(Ledger.verifyWitnessCosignature(head, cosig(head, w1, 3L), pub(w1)))
    }

    private fun withWitnesses(vararg labels: String): LinkedHashMap<String, Any?> {
        val head = sth()
        head["witnesses"] = jl(*labels.map { cosig(head, it) }.toTypedArray())
        return head
    }

    @Test
    fun theThresholdCountsDistinctTrustedWitnessesOnly() {
        val keys = jl(pub(w1), pub(w2))
        assertTrue(Ledger.verifyWitnessCosignatures(withWitnesses(w1, w2), jm("threshold", 2L, "witnessKeys", keys)))
        assertFalse(Ledger.verifyWitnessCosignatures(withWitnesses(w1, w1), jm("threshold", 2L, "witnessKeys", keys)))
        assertFalse(Ledger.verifyWitnessCosignatures(withWitnesses(w2), jm("threshold", 1L, "witnessKeys", jl(pub(w1)))))
        // a non-string key in the trusted list is skipped, not cast
        assertTrue(Ledger.verifyWitnessCosignatures(withWitnesses(w1), jm("threshold", 1L, "witnessKeys", jl(5L, pub(w1)))))
        assertFalse(Ledger.verifyWitnessCosignatures(withWitnesses(w1), jm("threshold", 1L, "witnessKeys", "x")))
        assertFalse(Ledger.verifyWitnessCosignatures(withWitnesses(w1), jm("threshold", 1L)))
        assertFalse(Ledger.verifyWitnessCosignatures(withWitnesses(w1), null))
        assertFalse(Ledger.verifyWitnessCosignatures(null, jm("threshold", 0L)))
        assertFalse(Ledger.verifyWitnessCosignatures("x", jm("threshold", 0L)))
        // threshold 0 is vacuously met; a non-object pqPins is no pins
        assertTrue(Ledger.verifyWitnessCosignatures(sth(), jm("threshold", 0L, "pqPins", "x")))
    }

    @Test
    fun consistencyGuards() {
        val e = Ledger.EMPTY_TREE_ROOT
        // a non-string new root is refused even where the empty-tree rule would be vacuous
        assertTrue(Ledger.verifyConsistency(e, "x", proof(0, 5)))
        assertFalse(Ledger.verifyConsistency(e, null, proof(0, 5)))
        assertFalse(Ledger.verifyConsistency(e, 5L, proof(0, 5)))
        // negative sizes and a shrinking tree are refused before the path is walked
        assertFalse(Ledger.verifyConsistency("a", "a", proof(-1, -1)))
        assertFalse(Ledger.verifyConsistency(x32, x32, proof(2, 1)))
        // a power-of-two old size whose old root does not decode
        assertFalse(Ledger.verifyConsistency("!!", "x", proof(2, 3)))
        // a proof whose members cannot be read is false, not an exception
        val hostile = object : AbstractMap<String, Any?>() {
            override val entries: Set<Map.Entry<String, Any?>> get() = throw IllegalStateException("hostile")
        }
        assertFalse(Ledger.verifyConsistency("a", "b", hostile))
    }
}
