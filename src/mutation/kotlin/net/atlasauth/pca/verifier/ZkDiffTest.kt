package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.zkreplay.ZkReplay
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Replays the reference oracle of the zk module: 1429 cases, every fn dispatched (an fn the replay does not know fails the run), every
 * case's outcome asserted. The core library has no pairing engine, so the pairing question is answered by the reference's recorded
 * verdict of the case; a case the reference refuses at a gate must never ask it. The real pairing runs in the native module's test.
 */
class ZkDiffTest {
    private val corpus = BaseOracle.corpusPath("ref-zk.json.gz")

    @After fun reset() = Zk.unregisterGroth16()

    @Test fun replayAllCases() {
        ZkReplay.Recorded.reached.clear()
        Zk.registerGroth16(ZkReplay.Recorded)
        val o = ZkReplay.run(corpus)
        assertEquals(ZkReplay.FNS, o.fns)
        assertEquals(1429, o.total)
        assertTrue("${o.divergent.size} divergent case(s):\n" + o.divergent.take(40).joinToString("\n"), o.divergent.isEmpty())
        val reached = ZkReplay.Recorded.reached
        assertTrue("the valid sample proofs must reach the pairing check", reached.containsAll(listOf("verifyPolicyVmProof/bn/valid", "verifyPolicyVmProof/bls/valid")))
        assertTrue("a pinned backend must reach the pairing check", "createPolicyVmSnarkBackend/bn/valid-bound" in reached)
        // the one prove case needs the proving key and witness calculator, which are build outputs
        assertTrue(o.artifacts.isEmpty() || o.artifacts == listOf("provePolicyVmCompliance/roundtrip"))
    }

    /** Without an engine a well-formed proof is never reported invalid: verification refuses to answer. */
    @Test fun noEngineIsNotAVerdict() {
        Zk.unregisterGroth16()
        val env = ZkReplay.args(corpus, "verifyPolicyVmProof/bn/valid")[0]
        try {
            Zk.verifyPolicyVmProof(env)
            fail("a missing engine must not produce a verdict")
        } catch (e: Zk.ZkBackendMissing) {
            assertEquals(Zk.NO_GROTH16_ENGINE_MESSAGE, e.message)
        }
        // a malformed envelope needs no engine: it is refused at the gate
        assertFalse(Zk.verifyPolicyVmProof(mapOf("system" to "groth16-bn254", "circuit" to "pca-policyvm-v1")))
    }
}
