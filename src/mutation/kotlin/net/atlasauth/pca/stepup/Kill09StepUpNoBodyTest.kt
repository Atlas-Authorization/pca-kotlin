package net.atlasauth.pca.stepup

import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okio.Timeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * A Call may return a Response with NO body (OkHttp's own interceptor chain refuses one: "interceptor ... returned a response with no body",
 * so the Call is replaced instead of an interceptor) (Response.body is null). `call` then reads the body as the empty string
 * (`resp.body?.string().orEmpty()`) and the `use` block's closing of such a response throws IllegalStateException ("response is not
 * eligible for a body and must not be closed", Response.close pc 11-26) on the success path, while an error status is thrown as its
 * StepUpError with the close failure only suppressed. These pin exactly that: the body read must not dereference a null body (a
 * NullPointerException would replace the close failure) and the close on the success path must run (a skipped close returns normally).
 */
class Kill09StepUpNoBodyTest {
    private fun client(code: Int): StepUpClient {
        val http = object : OkHttpClient() {
            override fun newCall(request: Request): Call = object : Call {
                override fun request(): Request = request
                override fun execute(): Response = Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(code).message("m").build()
                override fun enqueue(responseCallback: Callback) { throw UnsupportedOperationException() }
                override fun cancel() {}
                override fun isExecuted(): Boolean = true
                override fun isCanceled(): Boolean = false
                override fun timeout(): Timeout = Timeout.NONE
                override fun clone(): Call = this
            }
        }
        return StepUpClient(
            "https://dash.example/", "https://inst.example/", "acc", "ins",
            PrincipalDeviceKey(InMemorySecretStore()).also { it.generate() }, { "tok" }, http, { 0L },
        )
    }

    private val su = PendingStepUp("su_1", "g", "v", "r", 3, "AAEC", 0)

    private fun thrown(block: suspend () -> Unit): Throwable? = runBlocking {
        try {
            block()
            null
        } catch (t: Throwable) {
            t
        }
    }

    @Test
    fun aBodylessSuccessIsReadAsEmptyAndClosingItFails() {
        val c = client(200)
        for (t in listOf(thrown { c.deny(su) }, thrown { c.approve(su) }, thrown { c.pending() })) {
            assertTrue(t.toString(), t is IllegalStateException)
            assertTrue(t.toString(), t!!.message!!.contains("must not be closed"))
        }
    }

    @Test
    fun aBodylessErrorStatusIsItsStepUpErrorWithTheDefaultMessage() {
        val forbidden = thrown { client(403).deny(su) }
        assertTrue(forbidden.toString(), forbidden is StepUpError.PrincipalMismatch)
        assertEquals("The request failed.", forbidden!!.message)
        val server = thrown { client(500).deny(su) }
        assertTrue(server.toString(), server is StepUpError.Api)
        assertEquals(500, (server as StepUpError.Api).status)
        assertEquals("HTTP 500: The request failed.", server.message)
        if (thrown { client(404).approve(su) } !is StepUpError.Api) fail("approve on a bodyless 404")
    }
}
