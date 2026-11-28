package net.atlasauth.pca.fndsa

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.util.Base64
import net.atlasauth.pca.Keys
import net.atlasauth.pca.verifier.Pq
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * The Kotlin face over libfndsa: the keyless known-answer file (keygen and sign byte for byte, verify of every vector), refusals, and the Java PCA leaf
 * framing and hybrid through the registered backend. Set ATLAS_PCA_LIBFNDSA (or -Dpca.fndsa.lib); ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping.
 */
class FnDsaNativeTest {
    // a leaked registration would change every later test in this JVM: each test starts from, and returns to, "no backend"
    @After fun reset() = FnDsaNative.unregister()

    @Before fun native() {
        val ok = FnDsaNative.available()
        if (System.getenv("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1") assertTrue("libfndsa must load (ATLAS_PCA_LIBFNDSA)", ok)
        assumeTrue("libfndsa not available", ok)
        FnDsaNative.register()
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // the KAT carries seed labels, not seed bytes: the 32-byte seed is SHAKE256(UTF-8 label) cut to 32 bytes
    private fun labelSeed(label: String): ByteArray {
        val d = org.bouncycastle.crypto.digests.SHAKEDigest(256)
        val b = label.toByteArray(Charsets.UTF_8)
        d.update(b, 0, b.size)
        return ByteArray(32).also { d.doFinal(it, 0, 32) }
    }

    private fun kat(): JsonObject = JsonParser.parseString(File("test-data/ref-fndsa-kat.json").readText()).asJsonObject

    private fun str(o: JsonObject, k: String) = o.get(k).asString

    @Test fun knownAnswers() {
        val k = kat()
        val wasm = k.getAsJsonArray("wasm_signed")
        val c = k.getAsJsonArray("c_signed")
        assertTrue(wasm.size() > 0 && c.size() > 0)
        for (e in wasm) {
            val v = e.asJsonObject
            val variant = str(v, "variant")
            val vk = hex(str(v, "vk")); val msg = hex(str(v, "msg")); val sig = hex(str(v, "sig"))
            val kp = FnDsaNative.keygen(variant, labelSeed(str(v, "keygen_seed_label")))
            assertArrayEquals("keygen $variant", vk, kp.pk)
            assertArrayEquals("sign $variant", sig, FnDsaNative.sign(variant, kp.sk, msg, labelSeed(str(v, "sign_seed_label"))))
            assertTrue("verify $variant", FnDsaNative.verify(variant, vk, msg, sig))
        }
        for (e in c) {
            val v = e.asJsonObject
            assertTrue("c-signed verify", FnDsaNative.verify(str(v, "variant"), hex(str(v, "vk")), hex(str(v, "msg")), hex(str(v, "sig"))))
        }
    }

    @Test fun tamperAndRefusals() {
        val v = kat().getAsJsonArray("wasm_signed")[0].asJsonObject
        val variant = str(v, "variant")
        val vk = hex(str(v, "vk")); val msg = hex(str(v, "msg")); val sig = hex(str(v, "sig"))
        fun flip(b: ByteArray) = b.clone().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
        assertFalse(FnDsaNative.verify(variant, vk, msg, flip(sig)))
        assertFalse(FnDsaNative.verify(variant, flip(vk), msg, sig))
        assertFalse(FnDsaNative.verify(variant, vk, byteArrayOf(1, 2), sig))
        assertFalse(FnDsaNative.verify(variant, vk.copyOf(vk.size - 1), msg, sig))
        assertFalse(FnDsaNative.verify(variant, vk, ByteArray(8193), sig))
        for (bad in listOf<() -> Any>(
            { FnDsaNative.verify("fn-dsa-768", vk, msg, sig) },
            { FnDsaNative.keygen("fn-dsa-768") },
            { FnDsaNative.keygen(variant, ByteArray(31)) },
            { FnDsaNative.sign(variant, FnDsaNative.keygen(variant).sk, ByteArray(8193)) },
        )) {
            try { bad(); throw AssertionError("expected a refusal") } catch (e: IllegalArgumentException) { /* refused before the library call */ }
        }
    }

    @Test fun framingThroughTheSeam() {
        assertSame(NativeFnDsa.BACKEND, FnDsa.getFalconBackend())
        val edSecret = ByteArray(32) { 7 }
        val holder = Keys.edFromSeed(edSecret).id()
        for (alg in listOf("fn-dsa-512", "fn-dsa-1024", "hybrid-ed25519-fn-dsa-512", "hybrid-ed25519-fn-dsa-1024")) {
            val suite = FnDsa.resolveFnDsaAlg(alg)
            val kp = FnDsaNative.keygen(suite.variant)
            val leaf = linkedMapOf<String, Any>("iss" to "issuer", "aud" to "audience", "n" to "1")
            val w = FnDsa.signPcaWithFndsa(alg, leaf, kp.pk, kp.sk, if (suite.hasEd25519) edSecret else null)
            assertEquals(alg, w["alg"])
            assertTrue(alg, FnDsa.verifyPcaFndsa(alg, leaf, holder, w["pq_pk"], w["sig"], w["pq_sig"]))
            val other = LinkedHashMap(leaf).also { it["n"] = "2" }
            assertFalse("$alg tampered leaf", FnDsa.verifyPcaFndsa(alg, other, holder, w["pq_pk"], w["sig"], w["pq_sig"]))
        }
    }

    private fun b64u(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    /** The registered backend makes fn-dsa-* real suites of the Kotlin core dispatch; tamper and wrong-length pq_pk are denied. */
    @Test fun coreSuiteDispatch() {
        assertTrue(Pq.supportedSuites().containsAll(listOf("fn-dsa-512", "fn-dsa-1024")))
        val seen = HashSet<String>()
        for (e in kat().getAsJsonArray("c_signed")) {
            val v = e.asJsonObject
            val alg = str(v, "variant"); seen += alg
            val vk = hex(str(v, "vk")); val msg = hex(str(v, "msg")); val sig = hex(str(v, "sig"))
            fun leaf(m: ByteArray, k: ByteArray, s: ByteArray) = Pq.verifyLeafSuite(alg, true, null, b64u(k), m, b64u(s), null)
            assertTrue("$alg verifies", leaf(msg, vk, sig))
            assertFalse("$alg tampered sig", leaf(msg, vk, sig.clone().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }))
            assertFalse("$alg tampered msg", leaf(byteArrayOf(*msg, 0), vk, sig))
            assertFalse("$alg tampered pq_pk", leaf(msg, vk.clone().also { it[5] = (it[5].toInt() xor 1).toByte() }, sig))
            assertFalse("$alg short pq_pk", leaf(msg, vk.copyOf(vk.size - 1), sig))
        }
        assertEquals(setOf("fn-dsa-512", "fn-dsa-1024"), seen)
    }

    /** With the hook removed the same vectors are denied and the suite is `unsupported_suite`. */
    @Test fun noBackendDenies() {
        FnDsaNative.unregister()
        for (e in kat().getAsJsonArray("c_signed")) {
            val v = e.asJsonObject
            val alg = str(v, "variant")
            assertFalse(Pq.verifyLeafSuite(alg, true, null, b64u(hex(str(v, "vk"))), hex(str(v, "msg")), b64u(hex(str(v, "sig"))), null))
            assertEquals("unsupported_suite: $alg", Pq.refusal(alg))
        }
    }
}
