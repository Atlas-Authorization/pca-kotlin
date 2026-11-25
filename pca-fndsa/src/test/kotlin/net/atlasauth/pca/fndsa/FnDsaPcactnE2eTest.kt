package net.atlasauth.pca.fndsa

import java.io.File
import java.security.MessageDigest
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * End to end over the shared FN-DSA PCActn fixture (12 cases, both variants): keys derive from the fixture's seed labels, the valid body signed through the
 * public Issue/Keys path equals the TypeScript reference byte for byte, and every case verifies through Pca.verifyPcactn to exactly the expected verdict.
 * With no backend registered every case is denied (the valid one as unsupported_suite). ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping.
 */
@Suppress("UNCHECKED_CAST")
class FnDsaPcactnE2eTest {
    @After fun reset() = FnDsaNative.unregister()

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun cases(): List<Map<String, Any?>> =
        (m(Json.parseLenient(File("test-data/ref-fndsa-pcactn.json").readText(Charsets.UTF_8)))["cases"] as List<Any?>).map { m(it) }

    private fun seed(label: String): ByteArray = MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/$label".toByteArray(Charsets.UTF_8))

    private fun verify(c: Map<String, Any?>): Pca.Verdict =
        Pca.verifyPcactn(c["pcactn"], m(c["grant"]), Json.asLong(c["now_epoch"]), Pca.Audience.Of(c["audience"] as String), insecureSkipPlanRootCheck = true)

    private fun needNative() {
        val ok = FnDsaNative.available()
        if (System.getenv("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1") assertTrue("libfndsa must load (ATLAS_PCA_LIBFNDSA)", ok)
        assumeTrue("libfndsa not available", ok)
        FnDsaNative.register()
    }

    @Test fun signedBodyEqualsTheReference() {
        needNative()
        val valid = cases().filter { (it["name"] as String).endsWith("/valid") }
        assertEquals(2, valid.size)
        for (c in valid) {
            val alg = c["alg"] as String
            val labels = m(c["key_labels"])
            val prim = if (alg == "fn-dsa-512") Pq.Prim.FN_DSA_512 else Pq.Prim.FN_DSA_1024
            val pq = Keys.pqFromSeed(prim, seed(labels["fndsa_keygen"] as String), seed(labels["fndsa_sign_seed"] as String))
            val signed = Issue.signPCActn(m(c["body"]), Keys.suite(alg, null, pq))
            assertEquals(alg, Json.canonicalize(c["pcactn"]), Json.canonicalize(signed))
        }
    }

    @Test fun everyCaseVerifiesToTheExpectedVerdict() {
        needNative()
        val all = cases()
        assertEquals(12, all.size)
        for (c in all) assertEquals(c["name"] as String, c["expect_allow"] as Boolean, verify(c).allow)
    }

    @Test fun withoutABackendNothingIsAllowed() {
        FnDsaNative.unregister()
        for (c in cases()) {
            val v = verify(c)
            assertFalse(c["name"] as String, v.allow)
            if ((c["name"] as String).endsWith("/valid")) assertTrue(v.reason, v.reason.contains("unsupported_suite"))
        }
    }
}
