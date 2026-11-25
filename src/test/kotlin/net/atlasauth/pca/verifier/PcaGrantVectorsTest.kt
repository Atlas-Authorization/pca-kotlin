package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The `pca_grant` authorization-details corpus (`pca-grant-vectors.json`). A missing file fails; the corpus may not shrink. */
@Suppress("UNCHECKED_CAST")
class PcaGrantVectorsTest {
    private val doc = ParityVectors.load("pca-grant-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(k: String): List<Any?> = doc[k] as List<Any?>

    @Test
    fun digests() {
        for (x in l("digest")) assertEquals(m(x)["digest"], PcaGrant.chainDigest(m(x)["ids"] as List<String>))
    }

    @Test
    fun details() {
        assertTrue(l("detail").size >= 40)
        for (x in l("detail")) {
            val v = m(x)
            val code = PcaGrant.validate(v["input"])
            val exp = m(v["expect"])
            assertEquals("${v["name"]}: ok", exp["ok"], code == null)
            if (code != null) assertEquals("${v["name"]}: code", exp["code"], code)
        }
    }

    @Test
    fun arrays() {
        for (x in l("array")) {
            val v = m(x)
            val r = PcaGrant.parse(v["input"])
            val exp = m(v["expect"])
            assertEquals("${v["name"]}: ok", exp["ok"], r.code == null)
            if (r.code == null) assertEquals("${v["name"]}: count", IntentJs.lng(exp["count"]), r.details.size.toLong())
            else assertEquals("${v["name"]}: code", exp["code"], r.code)
        }
    }

    @Test
    fun presentations() {
        for (x in l("presentation")) {
            val v = m(x)
            val p = m(v["presented"])
            val r = PcaGrant.check((v["details"] as List<Any?>).map { m(it) }, p["resource"] as String, p["chain_ids"] as List<String>, p["proof_verified"] as Boolean)
            val exp = m(v["expect"])
            assertEquals("${v["name"]}: allow", exp["allow"], r.code == null)
            if (r.code == null) assertEquals("${v["name"]}: index", IntentJs.lng(exp["index"]), r.index.toLong())
            else assertEquals("${v["name"]}: code", exp["code"], r.code)
        }
    }
}
