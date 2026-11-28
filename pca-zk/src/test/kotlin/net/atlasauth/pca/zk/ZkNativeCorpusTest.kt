package net.atlasauth.pca.zk

import java.nio.file.Paths
import net.atlasauth.pca.verifier.Zk
import net.atlasauth.pca.verifier.zkreplay.ZkReplay
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * The reference oracle of the zk module with the real Groth16 engine: all 1429 cases, none left to a stand-in (both curves: valid
 * proofs, every tampered signal and proof point, off-subgroup points, wrong and mutated keys, the backends and the verifier hook's
 * SNARK mode). Set ATLAS_PCA_LIBPCAZK (or -Dpca.zk.lib); ATLAS_PCA_LIBPCAZK_REQUIRED=1 fails instead of skipping.
 */
@Suppress("UNCHECKED_CAST")
class ZkNativeCorpusTest {
    private val corpus = Paths.get("../test-data/ref-zk.json.gz")

    // a leaked registration would change every later test in this JVM
    @After fun reset() = ZkNative.unregister()

    @Before fun native() {
        val ok = ZkNative.available()
        if (System.getenv("ATLAS_PCA_LIBPCAZK_REQUIRED") == "1") assertTrue("libpcazk must load (ATLAS_PCA_LIBPCAZK)", ok)
        assumeTrue("libpcazk not available", ok)
        ZkNative.register()
    }

    @Test fun replayAllCasesWithTheRealEngine() {
        val o = ZkReplay.run(corpus)
        assertEquals(ZkReplay.FNS, o.fns)
        assertEquals(1429, o.total)
        assertTrue("${o.divergent.size} divergent case(s):\n" + o.divergent.take(40).joinToString("\n"), o.divergent.isEmpty())
        // the one prove case runs only with the proving key and witness calculator (PCA_ZK_POLICYVM_ZKEY / PCA_ZK_POLICYVM_WASM)
        assertTrue(o.artifacts.isEmpty() || o.artifacts == listOf("provePolicyVmCompliance/roundtrip"))
    }

    /** snarkjs ignores the key's nPublic, its protocol tag and extra IC entries: the default mode agrees with it, strict refuses. */
    @Test fun strictModeRefusesWhatSnarkjsLetsThrough() {
        for (name in listOf("bn/quirk-vkey-nPublic-14", "bn/quirk-vkey-protocol-plonk", "bn/quirk-vkey-ic-long", "bls/quirk-vkey-nPublic-14")) {
            val a = ZkReplay.args(corpus, "verifyPolicyVmProof/$name")
            val env = a[0] as Map<String, Any?>
            val vkey = (a[1] as Map<String, Any?>)["verificationKey"]
            val signals = env["publicSignals"] as List<Any?>
            assertTrue("$name (snarkjs rules)", ZkNative.verify(vkey, signals, env["proof"]))
            assertFalse("$name (strict)", ZkNative.verify(vkey, signals, env["proof"], true))
        }
        val a = ZkReplay.args(corpus, "verifyPolicyVmProof/bn/valid")
        val env = a[0] as Map<String, Any?>
        assertTrue(ZkNative.verify(Zk.policyVmVerificationKey(), env["publicSignals"] as List<Any?>, env["proof"], true))
    }

    /** The key's curve name is read by the library as snarkjs reads it: an alias verifies, a name snarkjs does not know does not, strict wants the exact name. */
    @Test fun theKeysCurveNameIsTheLibrarysBusiness() {
        val a = ZkReplay.args(corpus, "verifyPolicyVmProof/bn/valid")
        val env = a[0] as Map<String, Any?>
        val vkey = LinkedHashMap((a[1] as Map<String, Any?>)["verificationKey"] as Map<String, Any?>)
        val signals = env["publicSignals"] as List<Any?>
        for (alias in listOf("bn128", "BN254", "alt_bn128", "Bn-128")) {
            vkey["curve"] = alias
            assertTrue("alias $alias", ZkNative.verify(vkey, signals, env["proof"]))
        }
        vkey["curve"] = "alt_bn128"
        assertFalse("strict wants the exact name", ZkNative.verify(vkey, signals, env["proof"], true))
        vkey["curve"] = "bls12-377"
        assertFalse("an unknown name", ZkNative.verify(vkey, signals, env["proof"]))
    }
}
