package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Offline Sigstore bundle verification (`sigstore-vectors.json`, track K9): every case replayed. A missing file fails. */
@Suppress("UNCHECKED_CAST")
class SigstoreVectorsTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private val doc = ParityVectors.load("sigstore-vectors.json")
    private val roots = m(doc["roots"]).mapValues { Sigstore.parseTrustedRoot(it.value) }
    private val cases = doc["cases"] as List<Any?>

    @Test
    fun everyCase() {
        assertTrue(cases.size >= 35)
        var accepted = 0
        for (x in cases) {
            val c = m(x)
            val want = m(c["expect"])
            val r = Sigstore.verifySigstoreBundleCore(c["bundle"], roots[c["roots"]])
            val name = c["name"]
            assertEquals("$name: ${r.code} ${r.detail}", want["ok"], r.ok)
            if (r.ok) {
                accepted++
                assertTrue("$name: want ${want["core"]}, got ${r.core}", IntentJs.jsonEquals(want["core"], r.core))
            } else {
                assertEquals("$name: ${r.detail}", want["code"], r.code) // the reference's reason (informative, matched here)
            }
        }
        assertTrue("accepted $accepted", accepted >= 9)
    }

    @Test
    fun factsFeedTheGate() {
        val c = m(cases.first { m(it)["name"] == "npm/sigstore-5.0.0" })
        val r = Sigstore.verifySigstoreBundle(c["bundle"], roots[c["roots"]])
        assertTrue("${r.code} ${r.detail}", r.ok)
        assertNull(r.facts.toString(), ProvenanceGate.provenanceFactsError(r.facts))
    }

    @Test
    fun hostileInputIsRefusedNotThrown() {
        val any = roots.values.first()
        val bad = Json.parseLenient(
            "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MAA=\"}}," +
                "\"dsseEnvelope\":{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"\",\"signatures\":[{\"sig\":\"\"}]}}",
        )
        for (b in listOf(null, "x", emptyList<Any?>(), mapOf("verificationMaterial" to emptyMap<String, Any?>()), bad)) {
            assertFalse(Sigstore.verifySigstoreBundleCore(b, any).ok)
        }
    }
}
