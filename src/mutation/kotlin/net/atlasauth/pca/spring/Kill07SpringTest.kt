package net.atlasauth.pca.spring

import jakarta.servlet.http.HttpServletResponse
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.GuardOutcome
import net.atlasauth.pca.guard.PcaGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/** The refusal writer must not touch the challenge header at all when there is none; the interceptor's refusal stops the handler. */
class Kill07SpringTest {
    private class Recording : MockHttpServletResponse() {
        val touched = ArrayList<String>()
        override fun setHeader(name: String, value: String?) { touched.add(name); super.setHeader(name, value) }
        override fun addHeader(name: String, value: String) { touched.add(name); super.addHeader(name, value) }
    }

    private fun writeRefusal(res: HttpServletResponse, out: GuardOutcome) {
        val m = Class.forName("net.atlasauth.pca.spring.PcaSpringKt")
            .getDeclaredMethod("writeRefusal", HttpServletResponse::class.java, GuardOutcome::class.java)
        m.isAccessible = true
        m.invoke(null, res, out)
    }

    @Test
    fun noChallengeMeansNoWwwAuthenticateCallAtAll() {
        for (st in listOf(404, 409, 500)) {
            val res = Recording()
            writeRefusal(res, GuardOutcome(false, st, null, "{}", "deny"))
            assertFalse("status $st: ${res.touched}", res.touched.any { it.equals("WWW-Authenticate", true) })
            assertFalse(res.headerNames.contains("WWW-Authenticate"))
        }
        for (st in listOf(401, 403)) {
            val res = Recording()
            writeRefusal(res, GuardOutcome(false, st, null, "{}", "deny"))
            assertEquals(1, res.touched.count { it.equals("WWW-Authenticate", true) })
        }
    }

    @Test
    fun theInterceptorRefusalStopsTheHandlerAndWritesTheOutcome() {
        val sc = GuardFixtures.overLimit()
        val r = MockHttpServletRequest("POST", "/pay/send")
        r.addHeader(PcaGuard.HEADER, sc.header)
        r.addHeader(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader)
        val res = MockHttpServletResponse()
        val i = PcaInterceptor(sc.config(GuardFixtures.options()), PcaOperationMapper { _, _ -> sc.operation })
        assertFalse(i.preHandle(r, res, Any()))
        assertEquals(403, res.status)
        assertTrue(res.contentAsString, res.contentAsString.contains("insufficient_authority"))
        assertEquals(null, r.getAttribute(PCA_ATTRIBUTE))
        val ok = GuardFixtures.within()
        val r2 = MockHttpServletRequest("POST", "/pay/send")
        r2.addHeader(PcaGuard.HEADER, ok.header)
        r2.addHeader(PcaGuard.PROVENANCE_HEADER, ok.provenanceHeader)
        val i2 = PcaInterceptor(ok.config(GuardFixtures.options()), PcaOperationMapper { _, _ -> ok.operation })
        assertTrue(i2.preHandle(r2, MockHttpServletResponse(), Any()))
        assertTrue(r2.getAttribute(PCA_ATTRIBUTE) is GuardOutcome)
    }
}
