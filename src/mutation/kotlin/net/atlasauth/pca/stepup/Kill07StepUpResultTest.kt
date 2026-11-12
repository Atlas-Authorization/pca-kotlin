package net.atlasauth.pca.stepup

import kotlinx.coroutines.delay
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.intrinsics.COROUTINE_SUSPENDED

/**
 * The value `deny` delivers to its own continuation is Unit. A Kotlin caller coerces a Unit-returning suspend call to Unit, so it
 * cannot see a null; the raw continuation (reached through the JVM signature) can.
 */
class Kill07StepUpResultTest {
    @Test fun denyDeliversUnitToItsContinuation() {
        MockWebServer().use { d ->
            MockWebServer().use { i ->
                d.enqueue(MockResponse().setBody("{}"))
                val c = StepUpClient(
                    d.url("/").toString(), i.url("/").toString(), "acc", "ins",
                    PrincipalDeviceKey(InMemorySecretStore()).also { it.generate() }, { delay(20); "tok" }, OkHttpClient(), { 0L },
                )
                val done = CompletableFuture<Result<Any?>>()
                val cont = object : Continuation<Any?> {
                    override val context: CoroutineContext = EmptyCoroutineContext
                    override fun resumeWith(result: Result<Any?>) { done.complete(result) }
                }
                val m = StepUpClient::class.java.getDeclaredMethod("deny", PendingStepUp::class.java, String::class.java, Continuation::class.java)
                val direct = m.invoke(c, PendingStepUp("su_1", "g", "v", "r", 3, "AAEC", 0), null, cont)
                val value = if (direct === COROUTINE_SUSPENDED) done.get(30, TimeUnit.SECONDS).getOrThrow() else direct
                assertSame(Unit, value)
                assertEquals(1, d.requestCount)
            }
        }
    }
}
