package net.atlasauth.pca.spring

import jakarta.servlet.http.HttpServletResponse
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.RecordedResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/** The interceptor's body is empty (not one zero byte); the replay never writes a content type it does not have. */
class Kill07SpringRound2Test {
    private class TypeWatch : MockHttpServletResponse() {
        val typeCalls = ArrayList<String?>()
        override fun setContentType(contentType: String?) { typeCalls.add(contentType); super.setContentType(contentType) }
    }

    private fun writeRecorded(res: HttpServletResponse, rec: RecordedResponse, replayed: Boolean) {
        val m = Class.forName("net.atlasauth.pca.spring.PcaSpringKt")
            .getDeclaredMethod("writeRecorded", HttpServletResponse::class.java, RecordedResponse::class.java, java.lang.Boolean.TYPE)
        m.isAccessible = true
        m.invoke(null, res, rec, replayed)
    }

    @Test
    fun theInterceptorMapsAndDecidesOverAnEmptyBody() {
        val sc = GuardFixtures.within()
        var opBody = -1
        var wfBody = -1
        val i = PcaInterceptor(
            sc.config(GuardFixtures.options()),
            PcaOperationMapper { _, b -> opBody = b.size; sc.operation },
            PcaWorkflowStepMapper { _, b -> wfBody = b.size; null },
        )
        val res = MockHttpServletResponse()
        assertFalse(i.preHandle(MockHttpServletRequest("POST", "/pay/send"), res, Any()))
        assertEquals(0, opBody)
        assertEquals(0, wfBody)
        assertEquals(401, res.status)
        assertTrue(res.contentAsString, res.contentAsString.contains("no PCA-Action header and no PCActn body"))
        assertFalse(res.contentAsString, res.contentAsString.contains("not strict JSON"))
    }

    @Test
    fun aRecordWithoutAContentTypeNeverTouchesTheResponsesContentType() {
        val none = TypeWatch()
        writeRecorded(none, RecordedResponse(200, null, linkedMapOf<String, List<String>>(), "x".toByteArray()), false)
        assertTrue(none.typeCalls.toString(), none.typeCalls.isEmpty())
        val kept = TypeWatch()
        kept.contentType = "application/xml"
        kept.typeCalls.clear()
        writeRecorded(kept, RecordedResponse(200, "text/plain", linkedMapOf<String, List<String>>(), "x".toByteArray()), false)
        assertTrue(kept.typeCalls.toString(), kept.typeCalls.isEmpty())
        val fresh = TypeWatch()
        writeRecorded(fresh, RecordedResponse(200, "text/plain", linkedMapOf<String, List<String>>(), "x".toByteArray()), false)
        assertEquals(listOf<String?>("text/plain"), fresh.typeCalls)
    }
}
