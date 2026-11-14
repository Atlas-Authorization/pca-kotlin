package net.atlasauth.pca.stepup

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

/** deny returns only after its request went out (no blocking takeRequest: a mutant that sends nothing or returns early fails at once). */
class Kill07StepUpDenyTest {
    @Test fun denyHasSentItsRequestWhenItReturns() = runBlocking {
        MockWebServer().use { d ->
            MockWebServer().use { i ->
                d.enqueue(MockResponse().setBody("{}"))
                val c = StepUpClient(
                    d.url("/").toString(), i.url("/").toString(), "acc", "ins",
                    PrincipalDeviceKey(InMemorySecretStore()).also { it.generate() }, { delay(20); "tok" }, OkHttpClient(), { 0L },
                )
                val r: Any? = c.deny(PendingStepUp("su_1", "g", "v", "r", 3, "AAEC", 0))
                assertSame(Unit, r)
                assertEquals(1, d.requestCount)
            }
        }
    }
}
