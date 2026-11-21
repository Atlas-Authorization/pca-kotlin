package net.atlasauth.pca.stepup

import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.atlasauth.pca.verifier.Deadline
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The paths Kill06StepUpClientTest cannot reach: it always runs on runBlocking's own dispatcher, so withContext(Dispatchers.IO)
 * inside StepUpClient.call always suspends. Here the caller is already on Dispatchers.IO, so call() returns without suspending
 * (the "== COROUTINE_SUSPENDED" fast exit of pending / approve / deny), and a cancelled caller must not send its request.
 * A mutant that returns COROUTINE_SUSPENDED for a finished call never resumes: Deadline turns that hang into a failure.
 */
class Kill07StepUpClientTest {
    private fun client(
        d: MockWebServer, i: MockWebServer,
        token: suspend () -> String = { "tok" },
    ) = StepUpClient(
        d.url("/").toString(), i.url("/").toString(), "acc", "ins",
        PrincipalDeviceKey(InMemorySecretStore()).also { it.generate() }, token, now = { 0L },
    )

    private fun entry(id: String) =
        """{"id":"$id","grant_ref":"g1","action":{"verb":"pay","resource":"order/1"},"required_t":3,"threshold_message":"AAEC","expires_at":"2099-01-01T00:00:00.250Z"}"""

    private fun su(id: String = "su_1") = PendingStepUp(id, "g", "v", "r", 3, "AAEC", 0)

    /** Runs [block] on Dispatchers.IO (so withContext(IO) takes its no-suspension fast path) under a deadline. */
    private fun <T> onIo(block: suspend () -> T): T = Deadline.within { runBlocking(Dispatchers.IO) { block() } }

    private fun withServers(block: (MockWebServer, MockWebServer) -> Unit) {
        MockWebServer().use { d -> MockWebServer().use { i -> block(d, i) } }
    }

    @Test fun pendingFinishesWhenTheCallDoesNotSuspend() = withServers { d, i ->
        d.enqueue(MockResponse().setBody("""{"stepups":[${entry("su_a")}]}"""))
        d.enqueue(MockResponse().setBody("""{"stepups":[${entry("su_b")}]}"""))
        val plain = onIo { client(d, i).pending() }
        assertEquals(listOf("su_a"), plain.map { it.id })
        assertEquals(4_070_908_800_250L, plain[0].expiresAt)
        // a token that really suspends, then a call that does not
        val slow = onIo { client(d, i, token = { delay(2); "tok" }).pending() }
        assertEquals(listOf("su_b"), slow.map { it.id })
        assertEquals(0, i.requestCount)
    }

    @Test fun approveFinishesWhenTheCallDoesNotSuspend() = withServers { d, i ->
        i.enqueue(MockResponse().setBody("""{"status":"approved","allow":true}"""))
        i.enqueue(MockResponse().setResponseCode(202).setBody("""{"status":"awaiting"}"""))
        val c = client(d, i)
        assertEquals(ApproveResult("approved", true, 200), onIo { c.approve(su()) })
        assertEquals(ApproveResult("awaiting", false, 202), onIo { c.approve(su()) })
        assertEquals(0, d.requestCount)
    }

    @Test fun approveStillRaisesServerErrorsWhenTheCallDoesNotSuspend() = withServers { d, i ->
        i.enqueue(MockResponse().setResponseCode(403).setBody("""{"errors":[{"code":"forbidden","message":"wrong key"}]}"""))
        val e = onIo { runCatching { client(d, i).approve(su()) }.exceptionOrNull() }
        assertTrue(e is StepUpError.PrincipalMismatch)
        assertEquals("wrong key", e!!.message)
    }

    @Test fun denyFinishesWithUnitWhenTheCallDoesNotSuspend() = withServers { d, i ->
        d.enqueue(MockResponse().setBody("{}"))
        d.enqueue(MockResponse().setBody("{}"))
        val c = client(d, i)
        val direct: Any? = onIo { c.deny(su("su_x"), "no") }
        assertSame(Unit, direct)
        val afterSuspend: Any? = onIo { client(d, i, token = { delay(2); "tok" }).deny(su("su_y")) }
        assertSame(Unit, afterSuspend)
        assertEquals("/v1/dashboard/accounts/acc/instances/ins/pca/stepups/su_x/deny", d.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!.path)
        assertEquals("/v1/dashboard/accounts/acc/instances/ins/pca/stepups/su_y/deny", d.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!.path)
    }

    @OptIn(DelicateCoroutinesApi::class)
    @Test fun aCallCancelledWhileItsIoTaskIsQueuedNeverSendsTheRequest() = withServers { d, i ->
        d.enqueue(MockResponse().setBody("{}"))
        val release = CountDownLatch(1)
        val reached = CountDownLatch(1)
        // Dispatchers.IO runs at most max(64, cores) tasks at once: far more blockers than that keep call()'s task queued.
        val blockers = List(1024) { GlobalScope.launch(Dispatchers.IO) { release.await() } }
        try {
            val c = client(d, i, token = { reached.countDown(); "tok" })
            Deadline.within(20_000) {
                runBlocking {
                    val job = launch(Dispatchers.Default) { c.deny(su()) }
                    assertTrue(reached.await(10, TimeUnit.SECONDS))
                    // withContext(IO) attaches its coroutine to the caller's job before it dispatches, and the 1024 blockers queued
                    // ahead of it keep that task from starting until release: this wait replaces any timing guess
                    val until = System.nanoTime() + 10_000_000_000L
                    while (job.children.none() && System.nanoTime() < until) Thread.yield()
                    assertTrue("the IO call never attached to the caller's job", job.children.any())
                    job.cancel()
                    release.countDown()
                    job.join()
                    assertTrue(job.isCancelled)
                }
            }
            assertEquals(0, d.requestCount)
        } finally {
            release.countDown()
            blockers.forEach { it.cancel() }
        }
    }
}
