package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * k05 survivors in ArgProvenance: the public label lists, the read-only / action-info / envelope edges, token boundaries at
 * every class edge, the leaf and content-size bounds, the operation / observation / pin refusals, the fail-closed handlers
 * (a RuntimeException and a StackOverflowError raised while reading the operation), header / body decoding, and the
 * Recorder's accessors, clock, random session, source clipping, non-JSON output and constructor refusals.
 */
class Kill05SchemaArgProvenanceTest {
    private val sess = Pca.b64(ByteArray(32) { 3 })
    private fun rec(now: Long = 1_700_000_000_000L) = ArgProvenance.Recorder("m", "k", Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 7 })), sess, { now })
    private fun op(verb: Any? = "pay.send", resource: Any? = "acct", params: Any? = linkedMapOf<String, Any?>("to" to "bob")): Map<String, Any?> =
        linkedMapOf("verb" to verb, "resource" to resource, "params" to params)

    /** A map whose every read throws [t] (the decision must answer, never throw). */
    private class Boom(val t: Throwable) : AbstractMap<String, Any?>() {
        override val entries: Set<Map.Entry<String, Any?>> get() = throw t
        override fun get(key: String): Any? = throw t
    }

    @Test fun publicLists() {
        assertEquals(listOf("principal", "tool", "retrieval", "web", "action"), ArgProvenance.ORIGINS)
        assertEquals(listOf("trusted", "first_party", "tool", "web", "agent"), ArgProvenance.LEVELS)
        assertEquals(listOf("pca.financial_data_read", "pca.pii_access", "pca.regulated_data"), ArgProvenance.READ_SAFE_TRAITS)
    }

    @Test fun decisionToString() {
        val d = ArgProvenance.decide(null, op(), emptyList<Any?>())
        assertEquals("escalate", d.outcome)
        assertEquals("ArgProvenance.Decision(outcome=${d.outcome}, code=${d.code}, reason=${d.reason})", d.toString())
    }

    @Test fun readOnlyAction() {
        assertFalse(ArgProvenance.isReadOnlyAction(null))
        assertFalse(ArgProvenance.isReadOnlyAction("x"))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to "read")))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("traits" to listOf<Any?>())))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf<Any?>())))
        assertTrue(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"))))
        assertTrue(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read", "read"))))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read", "write"))))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("write", "read"))))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"), "traits" to "x")))
        assertTrue(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"), "traits" to listOf<Any?>())))
        assertTrue(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"), "traits" to ArgProvenance.READ_SAFE_TRAITS)))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"), "traits" to listOf("x"))))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"), "traits" to listOf("pca.pii_access", "x"))))
    }

    @Test fun actionInfo() {
        for (k in listOf("effects", "traits")) {
            val bad = "action info '$k' must be a list of strings"
            assertNull(ArgProvenance.actionInfoError(mapOf(k to listOf<Any?>())))
            assertNull(ArgProvenance.actionInfoError(mapOf(k to List(64) { "e".repeat(128) })))
            assertEquals(bad, ArgProvenance.actionInfoError(mapOf(k to List(65) { "e" })))
            assertEquals(bad, ArgProvenance.actionInfoError(mapOf(k to listOf("e".repeat(129)))))
            assertEquals(bad, ArgProvenance.actionInfoError(mapOf(k to listOf(""))))
            assertEquals(bad, ArgProvenance.actionInfoError(mapOf(k to listOf("a", 5))))
            assertEquals(bad, ArgProvenance.actionInfoError(mapOf(k to "read")))
        }
        assertNull(ArgProvenance.actionInfoError(mapOf("params" to mapOf("a" to "tool", "b" to "first_party", "c" to "agent"))))
        assertEquals("action info param 'a' must map to first_party | tool | agent", ArgProvenance.actionInfoError(mapOf("params" to mapOf("a" to "trusted"))))
        assertEquals("action info 'params' must be an object", ArgProvenance.actionInfoError(mapOf("params" to listOf<Any?>())))
    }

    @Test fun envelope() {
        val pin = rec().pin
        val bad = "provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}"
        assertNull(ArgProvenance.envelopeError(mapOf("mediators" to listOf<Any?>())))
        assertNull(ArgProvenance.envelopeError(mapOf("mode" to "enforce", "mediators" to List(16) { pin })))
        assertNull(ArgProvenance.envelopeError(mapOf("mode" to "insecure_off")))
        assertEquals(bad, ArgProvenance.envelopeError(mapOf("mediators" to List(17) { pin })))
        assertEquals(bad, ArgProvenance.envelopeError(mapOf("mediators" to listOf(mapOf<String, Any?>()))))
        assertEquals(bad, ArgProvenance.envelopeError(mapOf("mediators" to listOf(pin, mapOf<String, Any?>()))))
        assertEquals(bad, ArgProvenance.envelopeError(mapOf("mediators" to pin)))
        assertEquals("provenance.mode must be 'enforce' or 'insecure_off'", ArgProvenance.envelopeError(mapOf("mode" to "x")))
    }

    @Test fun tokenBoundariesAtEveryClassEdge() {
        for (c in "/09:@AZ[_`az{\u007f\u0080ÿ一") {
            val word = c in '0'..'9' || c in 'A'..'Z' || c in 'a'..'z' || c == '_' || c.code >= 0x80
            assertEquals("before '$c'", !word, ArgProvenance.occursAsToken("${c}x", "x"))
            assertEquals("after '$c'", !word, ArgProvenance.occursAsToken("x$c", "x"))
            assertEquals("needle '$c'", true, ArgProvenance.occursAsToken("$c", "$c"))
        }
        assertTrue(ArgProvenance.occursAsToken("ab-c", "-c"))
        assertTrue(ArgProvenance.occursAsToken("xab ab", "ab"))
        assertFalse(ArgProvenance.occursAsToken("xab abx", "ab"))
        assertFalse(ArgProvenance.occursAsToken("ab", ""))
    }

    @Test fun leafBound() {
        val l = ArrayList<Any?>()
        repeat(ArgProvenance.MAX_LEAVES) { l.add("s") }
        // an empty member after exactly MAX_LEAVES leaves adds nothing: still within the bound
        l.add(ArrayList<Any?>())
        l.add(LinkedHashMap<String, Any?>())
        assertEquals(ArgProvenance.MAX_LEAVES, ArgProvenance.provLeaves(l)!!.size)
        l.add("s")
        assertNull(ArgProvenance.provLeaves(l))
    }

    @Test fun contentSizeBound() {
        for ((len, outcome) in listOf(ArgProvenance.MAX_CONTENT_BYTES to "pass", ArgProvenance.MAX_CONTENT_BYTES + 1 to "deny")) {
            val r = rec()
            val text = "a".repeat(len)
            r.principal(text)
            @Suppress("UNCHECKED_CAST")
            val b = r.forAction("pay.send", "acct", linkedMapOf("to" to "bob")) as MutableMap<String, Any?>
            b["contents"] = linkedMapOf<String, Any?>("0" to text)
            val d = ArgProvenance.decide(b, op(), listOf(r.pin))
            assertEquals("$len", outcome, d.outcome)
            if (outcome == "deny") {
                assertEquals("malformed_bundle", d.code)
                assertEquals("contents '0' must be a string of at most 65536 bytes", d.reason)
            }
        }
    }

    @Test fun operationObservationAndPinRefusals() {
        val opMsg = "the operation needs a verb, a resource and a params object"
        for (o in listOf(op(resource = 5), op(params = "x"), op(params = null), op(verb = 5), op(verb = ""), op(verb = "v".repeat(257)), op(resource = null))) {
            val d = ArgProvenance.decide(null, o, emptyList<Any?>())
            assertEquals("deny", d.outcome)
            assertEquals("malformed_operation", d.code)
            assertEquals(opMsg, d.reason)
        }
        assertEquals("escalate", ArgProvenance.decide(null, op(verb = "v".repeat(256)), emptyList<Any?>()).outcome)
        val obsMsg = "observations must be a list of {origin, source}"
        for (obs in listOf<Any?>(
            "x", listOf(mapOf("origin" to "tool", "source" to "s".repeat(257))), listOf(mapOf("origin" to "principal", "source" to "s")),
            listOf(mapOf("origin" to "tool", "source" to "")), listOf(mapOf("origin" to "web", "source" to "s"), "x"),
        )) {
            val d = ArgProvenance.decide(null, op(), emptyList<Any?>(), null, false, false, obs)
            assertEquals("$obs", "malformed_config", d.code)
            assertEquals(obsMsg, d.reason)
        }
        val ok = ArgProvenance.decide(null, op(), emptyList<Any?>(), null, false, false, listOf(mapOf("origin" to "tool", "source" to "s".repeat(256))))
        assertEquals("escalate", ok.outcome)
        assertEquals(listOf("tool:" + "s".repeat(256), "unlabelled"), ok.path)
        val pinMsg = "mediator pins must be a list of {mediator, kid, pk, pq_pk?}"
        for (pins in listOf<Any?>("x", null, listOf(mapOf<String, Any?>()), listOf(rec().pin, "x"))) {
            val d = ArgProvenance.decide(null, op(), pins)
            assertEquals("malformed_config", d.code)
            assertEquals(pinMsg, d.reason)
        }
    }

    @Test fun failsClosedOnThrowingInput() {
        val rt = ArgProvenance.decide(null, Boom(IllegalStateException("boom")), emptyList<Any?>())
        assertEquals("deny", rt.outcome)
        assertEquals("malformed_config", rt.code)
        assertEquals("evaluation error (fail closed): IllegalStateException", rt.reason)
        val so = ArgProvenance.decide(null, Boom(StackOverflowError()), emptyList<Any?>())
        assertEquals("deny", so.outcome)
        assertEquals("malformed_config", so.code)
        assertEquals("evaluation error (fail closed): StackOverflowError", so.reason)
    }

    @Test fun headerAndBody() {
        fun header(h: String): String? = try { ArgProvenance.bundleFromHeader(h); null } catch (e: IllegalArgumentException) { e.message }
        assertEquals("PCA-Provenance is not UTF-8", header(Pca.b64(byteArrayOf(0xff.toByte()))))
        assertEquals("PCA-Provenance is not UTF-8", header(Pca.b64(byteArrayOf(0xc3.toByte()))))
        assertEquals("PCA-Provenance is not canonical base64url", header("!!"))
        assertNull(header(Pca.b64("{\"a\":1}".toByteArray())))
        assertTrue(ArgProvenance.bundleFromHeader(Pca.b64("{\"a\":1}".toByteArray())) is Map<*, *>)
        assertNull(ArgProvenance.bundleFromBody(null))
        assertNull(ArgProvenance.bundleFromBody(ByteArray(0)))
        assertNull(ArgProvenance.bundleFromBody(byteArrayOf(0xff.toByte())))
        assertNull(ArgProvenance.bundleFromBody("{".toByteArray()))
        assertNull(ArgProvenance.bundleFromBody("[1]".toByteArray()))
        assertNull(ArgProvenance.bundleFromBody("{\"x\":1}".toByteArray()))
        assertNotNull(ArgProvenance.bundleFromBody("{\"pca_provenance\":{\"v\":1}}".toByteArray()))
    }

    @Test fun recorderAccessorsClockClipAndText() {
        val r = rec(0L)
        assertEquals("m", r.mediator)
        assertEquals("k", r.kid)
        assertEquals(sess, r.session)
        val a = r.principal("hi")
        assertEquals(0L, IntentJs.lng(a["issued_at"]))
        val t = r.tool("a".repeat(300), object { override fun toString() = "hello" })
        assertEquals("a".repeat(150), t["source"])
        assertEquals(Pca.hashCanonical("hello"), t["content_digest"])
        assertEquals("-", r.web("", "x")["source"])
        assertEquals(listOf(a["sig"], t["sig"]), r.receipts().take(2).map { it["sig"] })
        assertEquals(3, r.receipts().size)
        val before = System.currentTimeMillis()
        val d1 = ArgProvenance.Recorder("m", "k")
        val x = d1.principal("hi")
        val after = System.currentTimeMillis()
        assertTrue(IntentJs.lng(x["issued_at"]) in before..after)
        val d2 = ArgProvenance.Recorder("m", "k")
        assertNotEquals(d1.session, d2.session)
        assertNotEquals(Pca.b64(ByteArray(32)), d1.session)
    }

    @Test fun recorderRefusals() {
        fun iae(want: String, f: () -> Unit) {
            try {
                f()
            } catch (e: IllegalArgumentException) {
                assertEquals(want, e.message)
                return
            }
            fail("expected IllegalArgumentException: $want")
        }
        val names = "ArgProvenance.Recorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required"
        iae(names) { ArgProvenance.Recorder("", "k") }
        iae(names) { ArgProvenance.Recorder("m", "") }
        iae(names) { ArgProvenance.Recorder("m".repeat(257), "k") }
        iae(names) { ArgProvenance.Recorder("m", "k".repeat(65)) }
        assertEquals("k".repeat(64), ArgProvenance.Recorder("m".repeat(256), "k".repeat(64)).kid)
        iae("ArgProvenance.Recorder: session must be canonical base64url of 32 bytes") { ArgProvenance.Recorder("m", "k", null, "AA") }
        iae("ArgProvenance.Recorder: the key needs an Ed25519 identity") {
            ArgProvenance.Recorder("m", "k", Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32))), null)
        }
    }
}
