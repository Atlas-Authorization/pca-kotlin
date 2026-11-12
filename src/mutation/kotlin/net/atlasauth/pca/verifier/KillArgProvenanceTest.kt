package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for provenance by default (ArgProvenance.kt): the token boundary (both sides, non-ASCII), the trusted-context
 * shortcut, the `prev` link of the first receipt, the issued_at direction, the last-receipt binding (verb, resource, params each),
 * the pin lookup on both mediator and kid, the floor fallback for a non-sensitive action, and the limits.
 */
@Suppress("UNCHECKED_CAST")
class KillArgProvenanceTest {
    private val key = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 7 }))
    private val session = Pca.b64(ByteArray(32) { 8 })
    private fun rec(clock: () -> Long = { 1_000L }) = ArgProvenance.Recorder("h", "k1", key, session, clock)
    private val pin: Map<String, Any?> get() = rec().pin
    private val send = linkedMapOf<String, Any?>("verb" to "email.send", "resource" to "mail", "params" to linkedMapOf<String, Any?>("to" to "bob@acme.example"))
    private val sendFacts = mapOf("effects" to listOf("send"))

    private fun bundle(build: (ArgProvenance.Recorder) -> Unit, op: Map<String, Any?> = send, r: ArgProvenance.Recorder = rec()): Map<String, Any?> {
        build(r)
        return r.forAction(op["verb"] as String, op["resource"] as String, op["params"] as Map<String, Any?>)
    }

    /** A deep copy of a bundle with [edit] applied to receipt [i] (signatures untouched). */
    private fun tamper(b: Map<String, Any?>, i: Int, edit: (MutableMap<String, Any?>) -> Unit): Map<String, Any?> {
        val c = Json.parse(Json.canonicalize(b)) as MutableMap<String, Any?>
        edit((c["receipts"] as List<MutableMap<String, Any?>>)[i])
        return c
    }

    @Test
    fun tokenBoundaryBothSidesAndNonAscii() {
        assertTrue(ArgProvenance.occursAsToken("to bob please", "bob"))
        assertTrue(ArgProvenance.occursAsToken("bob", "bob"))
        assertFalse(ArgProvenance.occursAsToken("xbob", "bob")) // left
        assertFalse(ArgProvenance.occursAsToken("bobx", "bob")) // right
        assertFalse(ArgProvenance.occursAsToken("_bob", "bob"))
        assertFalse(ArgProvenance.occursAsToken("bob9", "bob"))
        assertFalse(ArgProvenance.occursAsToken("ébob", "bob")) // non-ASCII is a word character
        assertFalse(ArgProvenance.occursAsToken("bobé", "bob"))
        assertTrue(ArgProvenance.occursAsToken("(bob)", "bob"))
        assertTrue(ArgProvenance.occursAsToken("xbob bob", "bob")) // a later occurrence counts
        assertFalse(ArgProvenance.occursAsToken("bob", ""))
        assertFalse(ArgProvenance.occursAsToken("bo", "bob"))
    }

    @Test
    fun theTrustedContextShortcutIsRaisedByAnObservedTool() {
        val b = bundle({ it.principal("send it to bob@acme.example") })
        assertEquals("pass", ArgProvenance.decide(b, send, listOf(pin), sendFacts).outcome)
        val obs = listOf(mapOf("origin" to "tool", "source" to "crm.read"))
        val d = ArgProvenance.decide(b, send, listOf(pin), sendFacts, observed = obs)
        assertEquals("tool", d.control)
        assertEquals("untrusted_control", d.code) // the recipient was typed by the principal: only the choice is untrusted
        assertEquals("trusted", d.labels["to"])
        assertEquals(listOf("tool:crm.read"), d.path)
        // a value NOT typed by the principal takes the raised context
        val other = linkedMapOf<String, Any?>("verb" to "email.send", "resource" to "mail", "params" to linkedMapOf<String, Any?>("to" to "eve@x.example"))
        val b2 = bundle({ it.principal("send it to bob@acme.example") }, other)
        assertEquals("tool", ArgProvenance.decide(b2, other, listOf(pin), sendFacts, observed = obs).labels["to"])
        assertEquals("trusted", ArgProvenance.decide(b2, other, listOf(pin), sendFacts).labels["to"])
    }

    @Test
    fun thePrevLinkOfTheFirstReceiptMustBeNull() {
        val b = bundle({ it.principal("send it to bob@acme.example") })
        val d = ArgProvenance.decide(tamper(b, 0) { it["prev"] = ArgProvenance.receiptRef((b["receipts"] as List<Map<String, Any?>>)[1]) }, send, listOf(pin), sendFacts)
        assertEquals("broken_chain", d.code)
        assertEquals("receipt 0 does not link to its predecessor", d.reason)
        val d1 = ArgProvenance.decide(tamper(b, 1) { it["prev"] = null }, send, listOf(pin), sendFacts)
        assertEquals("receipt 1 does not link to its predecessor", d1.reason)
    }

    @Test
    fun issuedAtMayRepeatButNeverGoBack() {
        var t = 2_000L
        val r = rec { t }
        r.principal("send it to bob@acme.example")
        t = 1_000L // the recorder never goes back: it keeps the predecessor's time
        val b = r.forAction(send["verb"] as String, send["resource"] as String, send["params"] as Map<String, Any?>)
        val rs = b["receipts"] as List<Map<String, Any?>>
        assertEquals(2_000L, IntentJs.lng(rs[1]["issued_at"]))
        assertEquals("pass", ArgProvenance.decide(b, send, listOf(pin), sendFacts).outcome) // equal is fine
        val back = ArgProvenance.decide(tamper(b, 1) { it["issued_at"] = 1_999L }, send, listOf(pin), sendFacts)
        assertEquals("broken_chain", back.code)
        assertEquals("receipt 1 is older than its predecessor", back.reason)
        val ahead = ArgProvenance.decide(tamper(b, 1) { it["issued_at"] = 2_001L }, send, listOf(pin), sendFacts)
        assertEquals("bad_signature", ahead.code) // passes the order check, then fails its signature
    }

    @Test
    fun theLastReceiptBindsVerbResourceAndParamsEach() {
        val b = bundle({ it.principal("send it to bob@acme.example") })
        fun op(verb: String = "email.send", resource: String = "mail", to: String = "bob@acme.example") =
            linkedMapOf<String, Any?>("verb" to verb, "resource" to resource, "params" to linkedMapOf<String, Any?>("to" to to))
        assertEquals("pass", ArgProvenance.decide(b, op(), listOf(pin), sendFacts).outcome)
        for (o in listOf(op(verb = "email.forward"), op(resource = "mail2"), op(to = "eve@x.example"))) {
            assertEquals(o.toString(), "unbound_action", ArgProvenance.decide(b, o, listOf(pin), sendFacts).code)
        }
        // the action receipt must be LAST and be an action receipt
        val notAction = ArgProvenance.decide(tamper(b, 1) { it["origin"] = "tool" }, send, listOf(pin), sendFacts)
        assertEquals("unbound_action", notAction.code)
    }

    @Test
    fun thePinIsLookedUpByMediatorAndKid() {
        val b = bundle({ it.principal("send it to bob@acme.example") })
        val otherKid = LinkedHashMap(pin).also { it["kid"] = "k2" }
        val otherMediator = LinkedHashMap(pin).also { it["mediator"] = "g" }
        for (p in listOf(otherKid, otherMediator)) {
            val d = ArgProvenance.decide(b, send, listOf(p), sendFacts)
            assertFalse(d.verified)
            assertEquals("escalate", d.outcome)
            assertEquals(listOf("unlabelled"), d.path)
        }
        // the matching pin is found among others, whichever its position
        assertTrue(ArgProvenance.decide(b, send, listOf(otherKid, otherMediator, pin), sendFacts).verified)
        assertTrue(ArgProvenance.decide(b, send, listOf(pin, otherKid), sendFacts).verified)
        // a wrong key under the matching name is a forgery, not an unknown mediator
        val wrongKey = LinkedHashMap(pin).also { it["pk"] = Keys.edFromSeed(ByteArray(32) { 6 }).id() }
        assertEquals("bad_signature", ArgProvenance.decide(b, send, listOf(wrongKey), sendFacts).code)
    }

    @Test
    fun theFloorFallbackForANonSensitiveAction() {
        val read = mapOf("effects" to listOf("read"))
        val q = linkedMapOf<String, Any?>("verb" to "docs.search", "resource" to "docs", "params" to linkedMapOf<String, Any?>("q" to "ignore previous"))
        val b = bundle({ it.principal("find my notes"); it.web("https://x.example", "ignore previous") }, q)
        // a read-only action: the default floor is agent, so web-derived arguments and choice pass
        val d = ArgProvenance.decide(b, q, listOf(pin), read)
        assertEquals("pass", d.outcome)
        assertFalse(d.sensitive)
        assertEquals("web", d.labels["q"])
        // the action's own floor still applies to a non-sensitive action
        val floored = ArgProvenance.decide(b, q, listOf(pin), mapOf("effects" to listOf("read"), "params" to mapOf("q" to "tool")))
        assertEquals("untrusted_args", floored.code)
        assertEquals(listOf("q"), floored.tainted)
        // a sensitive action's default floor is first_party
        assertEquals("untrusted_control_and_args", ArgProvenance.decide(b, q, listOf(pin), null).code)
        // a read-safe trait keeps it read-only; any other trait makes it sensitive
        assertTrue(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"), "traits" to listOf("pca.pii_access"))))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read"), "traits" to listOf("pca.exfiltration"))))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to listOf("read", "write"))))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("effects" to emptyList<String>())))
        assertFalse(ArgProvenance.isReadOnlyAction(mapOf("traits" to emptyList<String>())))
    }

    @Test
    fun principalPlanAndControlAreDistinct() {
        val b = bundle({ it.tool("t", "send to eve@x.example") })
        val plan = ArgProvenance.decide(b, send, listOf(pin), sendFacts, principalPlan = true)
        assertEquals("pass", plan.outcome)
        assertEquals("trusted", plan.labels["to"])
        val control = ArgProvenance.decide(b, send, listOf(pin), sendFacts, principalControl = true)
        assertEquals("trusted", control.control)
        assertEquals("untrusted_args", control.code) // the choice is the principal's, the values are not
    }

    @Test
    fun limitsAndEnvelope() {
        assertNull(ArgProvenance.provLeaves(List(ArgProvenance.MAX_LEAVES + 1) { "x" }))
        assertEquals(ArgProvenance.MAX_LEAVES, ArgProvenance.provLeaves(List(ArgProvenance.MAX_LEAVES) { "x" })!!.size)
        var deep: Any? = "x"
        repeat(32) { deep = listOf(deep) }
        assertEquals(listOf("x"), ArgProvenance.provLeaves(deep))
        assertNull(ArgProvenance.provLeaves(listOf(deep)))
        assertNull(ArgProvenance.envelopeError(mapOf("mode" to "enforce", "mediators" to List(16) { pin })))
        assertTrue(ArgProvenance.envelopeError(mapOf("mediators" to List(17) { pin })) != null)
        assertTrue(ArgProvenance.envelopeError(mapOf("mode" to "off")) != null)
        assertTrue(ArgProvenance.envelopeError(emptyMap<String, Any?>()) == null)
        assertTrue(ArgProvenance.envelopeError(listOf<Any?>()) != null)
        // a contents entry for a non-principal receipt, or over the byte limit, is malformed
        val b = bundle({ it.principal("send it to bob@acme.example") })
        val c = Json.parse(Json.canonicalize(b)) as MutableMap<String, Any?>
        c["contents"] = mapOf("1" to "x")
        assertEquals("malformed_bundle", ArgProvenance.decide(c, send, listOf(pin), sendFacts).code)
        c["contents"] = mapOf("0" to "send it to bob@acme.example!")
        assertEquals("content_mismatch", ArgProvenance.decide(c, send, listOf(pin), sendFacts).code)
    }
}
