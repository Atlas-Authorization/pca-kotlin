package net.atlasauth.pca.fndsa

import java.io.File
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pq
import net.atlasauth.pca.verifier.ProducerOps
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Replays the FN-DSA cases of the shared producer-pq-vectors.json byte for byte through the Kotlin signers (pq_keygen, suite_sign, mint_root, delegate,
 * PCActn, escalation answer, revocation epoch) with libfndsa registered; without a backend every one is refused `unsupported_suite`.
 * ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails (not skips) when the library is missing.
 */
@Suppress("UNCHECKED_CAST")
class FnDsaProducerVectorsTest {
    @After fun reset() = FnDsaNative.unregister()

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>

    private fun doc(): Map<String, Any?> {
        var d: File? = File(System.getProperty("user.dir")).absoluteFile
        while (d != null) {
            val f = listOf("packages/pca/conformance/producer-pq-vectors.json", "conformance/producer-pq-vectors.json").map { File(d, it) }.firstOrNull { it.exists() }
            if (f != null) return m(Json.parseLenient(f.readText(Charsets.UTF_8)))
            d = d.parentFile
        }
        throw IllegalStateException("producer-pq-vectors.json is missing: the shared corpus must be present (never skipped)")
    }

    private fun fnCases(d: Map<String, Any?>) = l(d["cases"]).map { m(it) }.filter { c ->
        val a = m(c["args"])
        (a["alg"] as? String)?.startsWith("fn-dsa") == true || (a["family"] as? String)?.startsWith("fn-dsa") == true
    }

    private fun ops(d: Map<String, Any?>) = ProducerOps(m(d["ed_keys"]), m(d["pq_keys"]))

    @Test fun everyFnDsaCaseIsReproducedByteForByte() {
        val ok = FnDsaNative.available()
        if (System.getenv("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1") assertTrue("libfndsa must load (ATLAS_PCA_LIBFNDSA)", ok)
        assumeTrue("libfndsa not available", ok)
        FnDsaNative.register()
        val d = doc()
        val cases = fnCases(d)
        assertTrue("the fn-dsa corpus shrank: ${cases.size}", cases.size >= 14)
        val p = ops(d)
        for (c in cases) {
            val name = c["name"].toString()
            assertEquals(name, Json.canonicalize(c["expect"]), Json.canonicalize(p.run(c["op"] as String, m(c["args"]))))
        }
    }

    @Test fun withoutABackendEveryCaseIsRefusedUnsupportedSuite() {
        FnDsaNative.unregister()
        val d = doc()
        val p = ops(d)
        for (c in fnCases(d)) {
            try { p.run(c["op"] as String, m(c["args"])); throw AssertionError("${c["name"]}: expected a refusal") }
            catch (e: IllegalArgumentException) { assertTrue("${c["name"]}: ${e.message}", e.message!!.startsWith("${Pq.UNSUPPORTED_SUITE}: ")) }
        }
    }
}
