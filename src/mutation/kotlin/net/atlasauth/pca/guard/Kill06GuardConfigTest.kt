package net.atlasauth.pca.guard

import net.atlasauth.pca.guard.Kill06GuardKit.cfg
import net.atlasauth.pca.guard.Kill06GuardKit.decide
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Operations
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The guard value types: config, executor config, recorded response, outcome and run. */
@Suppress("UNCHECKED_CAST")
class Kill06GuardConfigTest {
    private val none: (String) -> Map<String, Any?>? = { null }

    private fun iae(f: () -> Unit): String? = try {
        f()
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Test
    fun defaultsAreAuthorizeModeWithNoExecutorAndTheSystemClock() {
        val c = PcaGuardConfig("a", none)
        assertEquals("a", c.audience)
        assertSame(none, c.resolveGrant)
        assertNull(c.authorize)
        assertNull(c.intentPolicy)
        assertFalse(c.signatureOnly)
        assertNull(c.executor)
        val t0 = System.currentTimeMillis()
        val v = c.clock()
        val t1 = System.currentTimeMillis()
        assertTrue("$t0 <= $v <= $t1", v in t0..t1)
        assertTrue(v > 1_000_000_000_000L)
    }

    @Test
    fun theDefaultConfigRefusesEveryRequestWithAuthorizeConfig() {
        val sc = GuardFixtures.within()
        val c = PcaGuardConfig(sc.audience, { ref -> if (ref == sc.grant["id"]) sc.grant else null }, null, null, false, { sc.now })
        val o = decide(sc, c)
        assertFalse(o.allowed)
        assertEquals(403, o.status)
    }

    @Test
    fun theMembersAreWhatWasGiven() {
        val sc = GuardFixtures.within()
        val az = GuardFixtures.options()
        val ip = Pca.IntentPolicy(require = true)
        val ex = GuardFixtures.executor()
        val clock: () -> Long = { 7L }
        val c = PcaGuardConfig("aud", none, az, ip, false, clock, ex)
        assertSame(az, c.authorize)
        assertSame(ip, c.intentPolicy)
        assertSame(ex, c.executor)
        assertSame(clock, c.clock)
        assertEquals(7L, c.clock())
        assertTrue(sc.now > 0)
    }

    @Test
    fun signatureOnlyWithAuthorizeIsRefused() {
        assertEquals("signatureOnly cannot be combined with authorize options", iae { PcaGuardConfig("a", none, GuardFixtures.options(), null, true) })
        // the same options without signatureOnly are fine
        PcaGuardConfig("a", none, GuardFixtures.options(), null, false)
    }

    @Test
    fun anExecutorNeedsAuthorizeOptionsAndNoSignatureOnly() {
        assertEquals(
            "an executor needs authorize options and cannot be combined with signatureOnly",
            iae { PcaGuardConfig("a", none, null, null, false, { 0L }, GuardFixtures.executor()) },
        )
        assertEquals(
            "an executor needs authorize options and cannot be combined with signatureOnly",
            iae { PcaGuardConfig("a", none, null, null, true, { 0L }, GuardFixtures.executor()) },
        )
        // authorize + executor is the supported pair; no executor at all is fine in either mode
        PcaGuardConfig("a", none, GuardFixtures.options(), null, false, { 0L }, GuardFixtures.executor())
        PcaGuardConfig("a", none, null, null, false, { 0L }, null)
        PcaGuardConfig("a", none, null, null, true, { 0L }, null)
    }

    @Test
    fun signatureOnlyNeedsAnAudienceAndAResolver() {
        val msg = "signatureOnly needs an audience and a resolveGrant"
        assertEquals(msg, iae { PcaGuardConfig(null, none, null, null, true) })
        assertEquals(msg, iae { PcaGuardConfig("", none, null, null, true) })
        assertEquals(msg, iae { PcaGuardConfig("a", null, null, null, true) })
        val ok = PcaGuardConfig("a", none, null, null, true)
        assertTrue(ok.signatureOnly)
        // without signatureOnly an absent audience / resolver is accepted (the guard then refuses with authorize_config)
        PcaGuardConfig(null, null)
        PcaGuardConfig("", none)
    }

    @Test
    fun theExecutorConfigDefaultsAndMembers() {
        val store = Operations.MemoryStore()
        val d = PcaExecutorConfig(store)
        assertSame(store, d.operations)
        assertNull(d.recheck)
        assertEquals("irreversible", d.recheckFor)
        assertNull(d.reversibilityClassOf)
        assertEquals(300000.0, d.pendingTimeoutMs, 0.0)
        assertEquals(Operations.PENDING_TIMEOUT_MS.toDouble(), d.pendingTimeoutMs, 0.0)

        val rc: (Operations.ExecutionHandle) -> Operations.Recheck = { Operations.Recheck.OK }
        val cls: (Authorize.Operation) -> String? = { "reversible" }
        val e = PcaExecutorConfig(store, rc, "always", cls, 42.5)
        assertSame(rc, e.recheck)
        assertEquals("always", e.recheckFor)
        assertSame(cls, e.reversibilityClassOf)
        assertEquals(42.5, e.pendingTimeoutMs, 0.0)
    }

    // ---- RecordedResponse ----

    @Test
    fun aRecordedResponseKeepsItsMembersAndWritesARecord() {
        val r = RecordedResponse(201, "text/plain", linkedMapOf("X-A" to listOf("1", "2")), byteArrayOf(1, 2, 3))
        assertEquals(201, r.status)
        assertEquals("text/plain", r.contentType)
        assertEquals(mapOf("X-A" to listOf("1", "2")), r.headers)
        assertArrayEquals(byteArrayOf(1, 2, 3), r.body)
        val rec = r.toRecord()
        assertEquals(setOf("status", "contentType", "headers", "body"), rec.keys)
        assertEquals(201L, rec["status"])
        assertEquals("text/plain", rec["contentType"])
        assertEquals(mapOf("X-A" to listOf("1", "2")), rec["headers"])
        assertEquals("AQID", rec["body"])
        assertNull(RecordedResponse(200, null, emptyMap(), ByteArray(0)).contentType)
    }

    @Test
    fun theFrameworkOwnedHeadersAreNeverRecorded() {
        for (n in listOf("content-length", "Content-Length", "TRANSFER-ENCODING", "Connection", "keep-alive", "Keep-Alive", "content-type", "Content-Type"))
            assertFalse(n, RecordedResponse.recorded(n))
        for (n in listOf("X-Foo", "set-cookie", "Location", "content-language", "contentlength"))
            assertTrue(n, RecordedResponse.recorded(n))
    }

    private fun rec(status: Any? = 200L, headers: Any? = linkedMapOf<String, Any?>(), ct: Any? = "t", body: Any? = "AQID"): Map<String, Any?> =
        linkedMapOf("status" to status, "contentType" to ct, "headers" to headers, "body" to body)

    @Test
    fun aValidRecordIsReadBack() {
        val hs = linkedMapOf<String, Any?>(
            "X-B" to listOf("1", "2"), "Content-Length" to listOf("3"), "X-A" to listOf("z"), "content-type" to listOf("x"), "Connection" to listOf("close"),
        )
        val r = RecordedResponse.of(rec(headers = hs))!!
        assertEquals(200, r.status)
        assertEquals("t", r.contentType)
        assertEquals(listOf("X-B", "X-A"), r.headers.keys.toList())
        assertEquals(listOf("1", "2"), r.headers["X-B"])
        assertEquals(listOf("z"), r.headers["X-A"])
        assertArrayEquals(byteArrayOf(1, 2, 3), r.body)
        // a Json number and an Int status are safe integers too; a null content type is kept
        assertEquals(204, RecordedResponse.of(rec(status = Json.Num("204"), ct = null))!!.status)
        assertNull(RecordedResponse.of(rec(status = Json.Num("204"), ct = null))!!.contentType)
        assertEquals(7, RecordedResponse.of(rec(status = 7))!!.status)
        // a record written by toRecord reads back as the same response
        val orig = RecordedResponse(418, "a/b", linkedMapOf("X-Q" to listOf("v")), byteArrayOf(9, 8))
        val back = RecordedResponse.of(orig.toRecord())!!
        assertEquals(418, back.status)
        assertEquals("a/b", back.contentType)
        assertEquals(orig.headers, back.headers)
        assertArrayEquals(orig.body, back.body)
    }

    @Test
    fun anUnreadableRecordIsNull() {
        assertNull(RecordedResponse.of(null))
        assertNull(RecordedResponse.of("x"))
        assertNull(RecordedResponse.of(listOf(1)))
        assertNull(RecordedResponse.of(rec(status = 1.5)))
        assertNull(RecordedResponse.of(rec(status = Json.Num("1.5"))))
        assertNull(RecordedResponse.of(rec(status = 9007199254740992L)))
        assertNull(RecordedResponse.of(rec(status = "200")))
        assertNull(RecordedResponse.of(rec(status = null)))
        assertNull(RecordedResponse.of(rec(headers = null)))
        assertNull(RecordedResponse.of(rec(headers = "x")))
        assertNull(RecordedResponse.of(rec(headers = linkedMapOf<String, Any?>("X-A" to "v"))))
        assertNull(RecordedResponse.of(rec(headers = linkedMapOf<String, Any?>("X-A" to listOf(1)))))
        assertNull(RecordedResponse.of(rec(ct = 5)))
        assertNull(RecordedResponse.of(rec(body = "***")))
        assertNull(RecordedResponse.of(rec(body = null)))
        assertNull(RecordedResponse.of(rec(body = 5)))
        assertNull(RecordedResponse.of(linkedMapOf<String, Any?>("status" to 200L)))
    }

    // ---- GuardOutcome / GuardRun ----

    @Test
    fun anOutcomeKeepsEveryMember() {
        val bo = Authorize.AuthorizedOperation("v", "r", "d", "id")
        val pc = mapOf<String, Any?>("a" to 1)
        val o = GuardOutcome(true, 200, null, "", "allow", null, null, pc, bo, "idem")
        assertTrue(o.allowed)
        assertEquals(200, o.status)
        assertNull(o.wwwAuthenticate)
        assertEquals("", o.body)
        assertEquals("allow", o.decision)
        assertNull(o.authorization)
        assertNull(o.verdict)
        assertSame(pc, o.pcactn)
        assertSame(bo, o.boundOperation)
        assertEquals("idem", o.idempotencyKey)
        assertSame(bo, o.operation)
        // only an allow is bound to an operation
        assertNull(GuardOutcome(false, 403, "c", "b", "deny", null, null, null, bo, "idem").operation)
        val d = GuardOutcome(false, 403, "c", "b", "deny")
        assertNull(d.authorization)
        assertNull(d.pcactn)
        assertNull(d.boundOperation)
        assertNull(d.idempotencyKey)
        assertNull(d.verdict)
        assertEquals("c", d.wwwAuthenticate)
        assertEquals("b", d.body)
    }

    @Test
    fun anAuthorizeAllowIsBoundToTheAuthorizedOperation() {
        val sc = GuardFixtures.within()
        val allow = decide(sc, cfg(sc, GuardFixtures.options()))
        assertTrue(allow.allowed)
        val az = allow.authorization!!
        assertNotNull(az.operation)
        assertEquals(sc.operation.verb, az.operation!!.verb)
        assertEquals(az.operation, allow.operation)
        assertNull(allow.boundOperation)
        // the authorization's operation wins over a bound one; a non-allow has none at all
        val bo = Authorize.AuthorizedOperation("other", "other", "d", "id")
        assertEquals(az.operation, GuardOutcome(true, 200, null, "", "allow", az, null, null, bo, null).operation)
        assertNull(GuardOutcome(false, 403, "c", "b", "deny", az, null, null, bo, null).operation)
        assertNull(GuardOutcome(false, 403, "c", "b", "deny", az, null, null, null, null).operation)
    }

    @Test
    fun aRunKeepsItsMembers() {
        val d = GuardRun(null)
        assertNull(d.refusal)
        assertFalse(d.replayed)
        assertNull(d.result)
        val ref = GuardOutcome(false, 403, "c", "b", "deny")
        val r = GuardRun(ref, true, "x")
        assertSame(ref, r.refusal)
        assertTrue(r.replayed)
        assertEquals("x", r.result)
    }
}
