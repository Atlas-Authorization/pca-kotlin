package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * LESS suites through libatlas_less ([LessNative]): with a Java 22+ runtime and the library (sdks/pca-less-c/build.sh, or
 * ATLAS_PCA_LIBLESS) the known answers of packages/pca/conformance/less-vectors.json, incl. the seed-padding malleation every
 * verifier must refuse; otherwise both suites are out of the manifest and refused with `unsupported_suite`.
 */
class LessNativeTest {
    private fun vectors(): Path {
        var d: Path? = Paths.get("").toAbsolutePath()
        while (d != null) {
            val p = d.resolve("packages/pca/conformance/less-vectors.json")
            if (Files.isRegularFile(p)) return p
            d = d.parent
        }
        throw IllegalStateException("less-vectors.json not found")
    }

    @Test
    fun manifestListsBothOrNeither() {
        assertEquals(LessNative.available, "less-cat1" in Pq.supportedSuites())
        assertEquals(LessNative.available, "hybrid-ed25519-less-cat1" in Pq.supportedSuites())
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun knownAnswersOrRefusal() {
        if (!LessNative.available) {
            assertEquals("unsupported_suite: less-cat1", Pq.validateSignatureWire(mapOf("alg" to "less-cat1", "sig" to "AA")))
            return
        }
        val doc = Json.parseLenient(String(Files.readAllBytes(vectors()), Charsets.UTF_8)) as Map<String, Any?>
        val keys = doc["keys"] as Map<String, Any?>
        val vs = doc["vectors"] as List<Any?>
        assertTrue(vs.size >= 25)
        for (o in vs) {
            val v = o as Map<String, Any?>
            val key = keys[v["key"]] as Map<String, Any?>
            val pk = if (v.containsKey("pq_pk_override")) v["pq_pk_override"] else key["pq_pk"]
            val msg = Pca.decodeB64uStrict(v["message"], -1)!!
            val got = Pq.verifyArtifactSignature(v["alg"] as String, key["ed_pub"] as String, pk, msg, v["sig"], v["pq_sig"])
            assertEquals(v["name"] as String, (v["expect"] as Map<String, Any?>)["allow"], got)
        }
    }
}
