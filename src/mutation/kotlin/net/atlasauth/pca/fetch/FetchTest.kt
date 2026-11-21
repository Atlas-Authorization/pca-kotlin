package net.atlasauth.pca.fetch

import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.PcaGuardConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The request guard: plumbing and the default-deny shapes (the decisions themselves are the core's). */
class FetchTest {
    private val sc = GuardFixtures.within()

    @Test fun headersRoundTrip() {
        val h = Fetch.pcaHeaders("{\"a\":\"é\"}")
        assertEquals(listOf("PCA-Action"), h.keys.toList())
        assertFalse(h["PCA-Action"]!!.contains("="))
    }

    @Test fun noProofIsRefusedWithAChallengeAndTheHandlerNeverRuns() {
        var calls = 0
        val f = Fetch.withPCA(Fetch.Options(sc.config(null, signatureOnly = true))) { _, _ -> calls++; Fetch.FetchResponse(200, emptyMap(), "") }
        val res = f(Fetch.FetchRequest("POST", "https://rs.example/x", emptyMap(), null))
        assertEquals(401, res.status)
        assertEquals("PCA realm=\"pca\"", res.headers["WWW-Authenticate"]!!.substringBefore(","))
        assertEquals("application/json", res.headers["content-type"])
        assertEquals(0, calls)
    }

    @Test fun aValidProofReachesTheHandlerInSignatureOnlyMode() {
        val ok = Fetch.FetchResponse(200, emptyMap(), "ok")
        val headers = mapOf("pca-action" to sc.header)
        val f = Fetch.withPCA(Fetch.Options(sc.config(null, signatureOnly = true))) { _, _ -> ok }
        assertSame(ok, f(Fetch.FetchRequest("POST", "https://rs.example/x", headers, null)))
        val other = PcaGuardConfig("someone-else", { ref -> if (ref == sc.grant["id"]) sc.grant else null }, null, null, true, { sc.now })
        assertEquals(403, Fetch.withPCA(Fetch.Options(other)) { _, _ -> ok }(Fetch.FetchRequest("POST", "u", headers, null)).status)
    }

    @Test fun anUnknownGrantIsRefused() {
        val cfg = PcaGuardConfig(sc.audience, { null }, null, null, true, { sc.now })
        val r = Fetch.createPcaFetchGuard(Fetch.Options(cfg))(Fetch.FetchRequest("POST", "u", mapOf("PCA-ACTION" to sc.header), null))
        assertFalse(r.allowed)
    }

    @Test fun aCustomDenyBodyIsUsed() {
        val f = Fetch.withPCA(Fetch.Options(sc.config(null, signatureOnly = true), denyBody = { "{\"no\":true}" })) { _, _ -> error("never") }
        assertEquals("{\"no\":true}", f(Fetch.FetchRequest("GET", "u", null, null)).body)
    }

    @Test fun authorizedModeNeedsOptionsAndAMapper() {
        var threw = false
        try { Fetch.Options(sc.config(GuardFixtures.options())) } catch (e: IllegalArgumentException) { threw = true }
        assertTrue(threw)
    }
}
