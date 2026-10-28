package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The runtime-class claim corpus (`runtime-claim-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class RuntimeClaimVectorsTest {
    @Test
    fun cases() {
        val doc = ParityVectors.load("runtime-claim-vectors.json")
        val t = doc["trust"] as Map<String, Any?>
        val pinned = (t["pinnedAttestors"] as List<Any?>).map { it as String }
        val ev = (t["verifiedEvidenceDigests"] as List<Any?>).map { it as String }
        val pd = t["passportDigest"] as String
        val cases = doc["cases"] as List<Any?>
        assertTrue(cases.size >= 8)
        for (x in cases) {
            val c = x as Map<String, Any?>
            assertEquals(c["name"] as String, c["expect"], RuntimeClaim.verifiedClass(c["claim"], pinned, pd, ev, c["now"]))
        }
        val first = cases[0] as Map<String, Any?>
        assertEquals("none", RuntimeClaim.verifiedClass(first["claim"], emptyList(), pd, ev, first["now"]))
        assertEquals("none", RuntimeClaim.verifiedClass(first["claim"], pinned, pd, emptyList(), first["now"]))
        assertEquals("none", RuntimeClaim.verifiedClass(null, pinned, pd, ev, null))
    }
}
