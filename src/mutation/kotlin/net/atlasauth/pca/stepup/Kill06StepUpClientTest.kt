package net.atlasauth.pca.stepup

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Instant
import java.util.TimeZone

/** StepUpClient against two MockWebServers (dashboard + instance). */
class Kill06StepUpClientTest {
    private fun withServers(block: suspend (MockWebServer, MockWebServer) -> Unit) {
        runBlocking { MockWebServer().use { d -> MockWebServer().use { i -> block(d, i) } } }
    }

    private fun client(
        d: MockWebServer, i: MockWebServer,
        key: PrincipalDeviceKey = PrincipalDeviceKey(InMemorySecretStore()).also { it.generate() },
        now: () -> Long = { 0L },
        http: OkHttpClient = OkHttpClient(),
        token: suspend () -> String = { "tok" },
    ) = StepUpClient(d.url("/").toString(), i.url("/").toString(), "acc", "ins", key, token, http, now)

    private fun entry(
        id: String, exp: String, tm: String = "AAEC", verb: String = "pay", res: String = "order/1",
        grant: String = "g1", t: Int = 3,
    ) = """{"id":"$id","grant_ref":"$grant","action":{"verb":"$verb","resource":"$res"},"required_t":$t,"threshold_message":"$tm","expires_at":"$exp"}"""

    private fun list(vararg entries: String) = """{"stepups":[${entries.joinToString(",")}]}"""

    private suspend fun thrown(block: suspend () -> Unit): Throwable =
        unrecovered(runCatching { block() }.exceptionOrNull() ?: throw AssertionError("expected a throw"))

    /** kotlinx-coroutines stack-trace recovery (on under -ea) rethrows a copy whose cause is the original: compare the original. */
    private fun unrecovered(e: Throwable): Throwable {
        val c = e.cause
        return if (c != null && c.javaClass == e.javaClass && c.message == e.message) c else e
    }

    private fun su(id: String = "su_1", tm: String = "AAEC") = PendingStepUp(id, "g", "v", "r", 3, tm, 0)

    private fun verify(pubB64: String, msg: ByteArray, sigB64: String): Boolean {
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(Base64Url.decode(pubB64)!!, 0))
        v.update(msg, 0, msg.size)
        return v.verifySignature(Base64Url.decode(sigB64)!!)
    }

    // ---- pending ----

    @Test fun pendingSendsAnAuthenticatedGetAndMapsEveryField() = withServers { d, i ->
        d.enqueue(MockResponse().setBody(list(entry("su_9", "2026-10-06T18:00:00.123Z", tm = "QUJD", verb = "refund", res = "order/77", grant = "grant-5", t = 7))))
        val c = client(d, i, token = { delay(3); "dsk_abc" })
        val l = c.pending()
        assertEquals(1, l.size)
        assertEquals(PendingStepUp("su_9", "grant-5", "refund", "order/77", 7, "QUJD", Instant.parse("2026-10-06T18:00:00.123Z").toEpochMilli()), l[0])
        assertEquals("refund on order/77", l[0].summary)
        val r = d.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!
        assertEquals("GET", r.method)
        assertEquals("/v1/dashboard/accounts/acc/instances/ins/pca/stepups?status=pending", r.path)
        assertEquals("Bearer dsk_abc", r.getHeader("Authorization"))
        assertEquals(0, i.requestCount)
    }

    @Test fun pendingReturnsAnEmptyListNotNull() = withServers { d, i ->
        d.enqueue(MockResponse().setBody(list()))
        assertEquals(emptyList<PendingStepUp>(), client(d, i).pending())
    }

    @Test fun anEntryExpiringAtOrBeforeNowIsDropped() = withServers { d, i ->
        d.enqueue(MockResponse().setBody(list(
            entry("before", "1970-01-01T00:00:00.999Z"),
            entry("at", "1970-01-01T00:00:01.000Z"),
            entry("after", "1970-01-01T00:00:01.001Z"),
        )))
        val l = client(d, i, now = { 1000L }).pending()
        assertEquals(listOf("after"), l.map { it.id })
        assertEquals(1001L, l[0].expiresAt)
    }

    @Test fun timestampsAreParsedAsUtcWithOptionalFraction() = withServers { d, i ->
        val stamps = listOf(
            "2026-10-06T18:00:00.123Z", "2026-10-06T18:00:00.5Z", "2026-10-06T18:00:00.12Z",
            "2026-10-06T18:00:00.123456Z", "2026-10-06T18:00:00Z", "2026-01-02T03:04:05.007Z", "2026-07-01T00:00:00.999Z",
        )
        d.enqueue(MockResponse().setBody(list(*stamps.mapIndexed { n, s -> entry("e$n", s) }.toTypedArray())))
        val saved = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("America/Los_Angeles"))
        try {
            val l = client(d, i).pending()
            assertEquals(stamps.size, l.size)
            stamps.forEachIndexed { n, s -> assertEquals(s, Instant.parse(s).toEpochMilli(), l[n].expiresAt) }
        } finally {
            TimeZone.setDefault(saved)
        }
    }

    @Test fun anUnreadableListIsATransportError() = withServers { d, i ->
        d.enqueue(MockResponse().setBody("not json"))
        d.enqueue(MockResponse().setBody("{}"))
        val c = client(d, i)
        repeat(2) {
            val e = thrown { c.pending() }
            assertTrue(e is StepUpError.Transport)
            assertEquals("Unreadable step-up list.", e.message)
            assertNotNull(e.cause)
        }
    }

    @Test fun anUnreadableEntryIsATransportError() = withServers { d, i ->
        d.enqueue(MockResponse().setBody("""{"stepups":[{"id":"x"}]}"""))
        d.enqueue(MockResponse().setBody("""{"stepups":[{"id":"x","grant_ref":"g","action":{"verb":"v","resource":"r"},"threshold_message":"AA","expires_at":"2099-01-01T00:00:00Z"}]}"""))
        val c = client(d, i)
        repeat(2) {
            val e = thrown { c.pending() }
            assertTrue(e is StepUpError.Transport)
            assertEquals("Unreadable step-up entry.", e.message)
            assertNotNull(e.cause)
        }
    }

    @Test fun httpFailuresCarryTheEnvelopeMessage() = withServers { d, i ->
        d.enqueue(MockResponse().setResponseCode(401).setBody("""{"errors":[{"code":"unauthorized","message":"bad token"}]}"""))
        d.enqueue(MockResponse().setResponseCode(500).setBody("<html>oops</html>"))
        d.enqueue(MockResponse().setResponseCode(409).setBody("""{"errors":[]}"""))
        val c = client(d, i)
        val a = thrown { c.pending() } as StepUpError.Api
        assertEquals(401, a.status)
        assertEquals("HTTP 401: bad token", a.message)
        val b = thrown { c.pending() } as StepUpError.Api
        assertEquals(500, b.status)
        assertEquals("HTTP 500: The request failed.", b.message)
        val e = thrown { c.pending() } as StepUpError.Api
        assertEquals("HTTP 409: The request failed.", e.message)
    }

    @Test fun aTokenThatFailsAfterSuspendingSurfacesItsOwnError() = withServers { d, i ->
        val e = thrown { client(d, i, token = { delay(2); throw IllegalStateException("tok-boom") }).pending() }
        assertTrue(e is IllegalStateException)
        assertEquals("tok-boom", e.message)
        assertEquals(0, d.requestCount)
        val e2 = thrown { client(d, i, token = { delay(2); throw IllegalStateException("tok-boom2") }).deny(su()) }
        assertEquals("tok-boom2", e2.message)
        assertEquals(0, d.requestCount)
    }

    // ---- transport ----

    @Test fun aNetworkFailureIsATransportErrorKeepingTheCauseMessage() = withServers { d, i ->
        val c = StepUpClient("http://127.0.0.1:1/", i.url("/").toString(), "a", "b", PrincipalDeviceKey(InMemorySecretStore()), { "t" })
        val e = thrown { c.pending() }
        assertTrue(e is StepUpError.Transport)
        assertTrue(e.cause is IOException)
        assertNotNull(e.cause!!.message)
        assertEquals(e.cause!!.message, e.message)
    }

    @Test fun aNetworkFailureWithoutAMessageGetsTheDefault() = withServers { d, i ->
        val http = OkHttpClient.Builder().addInterceptor(Interceptor { throw IOException() }).build()
        val e = thrown { client(d, i, http = http).pending() }
        assertTrue(e is StepUpError.Transport)
        assertEquals("Network error.", e.message)
        assertTrue(e.cause is IOException)
    }

    // ---- approve ----

    @Test fun approveRejectsAMalformedThresholdMessageBeforeAnyRequest() = withServers { d, i ->
        val e = thrown { client(d, i).approve(su(tm = "A")) }
        assertTrue(e is StepUpError.InvalidThresholdMessage)
        assertEquals("The step-up's threshold message is not valid base64url.", e.message)
        assertEquals(0, i.requestCount)
        assertEquals(0, d.requestCount)
    }

    @Test fun approveSignsTheMessageAndPostsToTheInstanceUnauthenticated() = withServers { d, i ->
        val key = PrincipalDeviceKey(InMemorySecretStore())
        val pub = key.generate()
        val msg = byteArrayOf(1, 2, 3, -6, -5, 9)
        i.enqueue(MockResponse().setBody("""{"status":"approved","allow":true}"""))
        val res = client(d, i, key = key).approve(su("su_4", Base64Url.encode(msg)))
        assertEquals(ApproveResult("approved", true, 200), res)
        val r = i.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!
        assertEquals("POST", r.method)
        assertEquals("/v1/pca/stepups/su_4/cosign", r.path)
        assertNull(r.getHeader("Authorization"))
        assertTrue(r.getHeader("Content-Type")!!.startsWith("application/json"))
        val body = Json.parseToJsonElement(r.body.readUtf8()).jsonObject
        assertEquals(setOf("role", "publicKey", "sig"), body.keys)
        assertEquals("principal", body["role"]!!.jsonPrimitive.content)
        assertEquals(pub, body["publicKey"]!!.jsonPrimitive.content)
        assertTrue(verify(pub, msg, body["sig"]!!.jsonPrimitive.content))
        assertEquals(0, d.requestCount)
    }

    @Test fun approveReadsStatusAnchoredAndHttpStatusFromTheAnswer() = withServers { d, i ->
        i.enqueue(MockResponse().setResponseCode(202).setBody("""{"status":"awaiting"}"""))
        i.enqueue(MockResponse().setBody("not json"))
        i.enqueue(MockResponse().setBody(""))
        i.enqueue(MockResponse().setBody("""{"status":"x","allow":false}"""))
        i.enqueue(MockResponse().setBody("""{"status":null,"allow":null}"""))
        i.enqueue(MockResponse().setBody("[]"))
        i.enqueue(MockResponse().setBody("""{"allow":"yes"}"""))
        i.enqueue(MockResponse().setBody("""{"allow":true}"""))
        i.enqueue(MockResponse().setBody("""{"status":5,"allow":true}"""))
        val c = client(d, i)
        assertEquals(ApproveResult("awaiting", false, 202), c.approve(su()))
        assertEquals(ApproveResult("", false, 200), c.approve(su()))
        assertEquals(ApproveResult("", false, 200), c.approve(su()))
        assertEquals(ApproveResult("x", false, 200), c.approve(su()))
        assertEquals(ApproveResult("", false, 200), c.approve(su()))
        assertEquals(ApproveResult("", false, 200), c.approve(su()))
        assertEquals(ApproveResult("", false, 200), c.approve(su()))
        assertEquals(ApproveResult("", true, 200), c.approve(su()))
        assertEquals(ApproveResult("5", true, 200), c.approve(su()))
    }

    @Test fun approveMapsErrorsFromTheEnvelope() = withServers { d, i ->
        i.enqueue(MockResponse().setResponseCode(403).setBody("""{"errors":[{"code":"forbidden","message":"not this grant's principal key"}]}"""))
        i.enqueue(MockResponse().setResponseCode(403).setBody("garbage"))
        i.enqueue(MockResponse().setResponseCode(409).setBody("""{"errors":[{"code":"conflict","message":"already approved"}]}"""))
        val c = client(d, i)
        val m = thrown { c.approve(su()) }
        assertTrue(m is StepUpError.PrincipalMismatch)
        assertEquals("not this grant's principal key", m.message)
        val g = thrown { c.approve(su()) }
        assertTrue(g is StepUpError.PrincipalMismatch)
        assertEquals("The request failed.", g.message)
        val a = thrown { c.approve(su()) } as StepUpError.Api
        assertEquals(409, a.status)
        assertEquals("HTTP 409: already approved", a.message)
    }

    // ---- deny ----

    @Test fun denyPostsTheReasonToTheDashboardWithTheBearerToken() = withServers { d, i ->
        d.enqueue(MockResponse().setBody("{}"))
        val r0: Any? = client(d, i, token = { delay(2); "dsk_z" }).deny(su("su_7"), "no way")
        assertSame(Unit, r0)
        val r = d.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!
        assertEquals("POST", r.method)
        assertEquals("/v1/dashboard/accounts/acc/instances/ins/pca/stepups/su_7/deny", r.path)
        assertEquals("Bearer dsk_z", r.getHeader("Authorization"))
        assertTrue(r.getHeader("Content-Type")!!.startsWith("application/json"))
        assertEquals("""{"reason":"no way"}""", r.body.readUtf8())
        assertEquals(0, i.requestCount)
    }

    @Test fun denyWithoutAReasonSendsAnEmptyObjectAndAnEmptyReasonIsKept() = withServers { d, i ->
        d.enqueue(MockResponse().setBody("{}"))
        d.enqueue(MockResponse().setBody("{}"))
        val c = client(d, i)
        c.deny(su())
        assertEquals("{}", d.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!.body.readUtf8())
        c.deny(su(), "")
        assertEquals("""{"reason":""}""", d.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS)!!.body.readUtf8())
    }

    @Test fun denyMapsServerErrors() = withServers { d, i ->
        d.enqueue(MockResponse().setResponseCode(403).setBody("""{"errors":[{"code":"forbidden","message":"owner or admin only"}]}"""))
        d.enqueue(MockResponse().setResponseCode(409).setBody("""{"errors":[{"code":"conflict","message":"already denied"}]}"""))
        val c = client(d, i)
        val m = thrown { c.deny(su()) }
        assertTrue(m is StepUpError.PrincipalMismatch)
        assertEquals("owner or admin only", m.message)
        val a = thrown { c.deny(su()) } as StepUpError.Api
        assertEquals("HTTP 409: already denied", a.message)
    }
}
