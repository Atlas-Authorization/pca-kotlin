package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Surface the differential oracle cannot pin: the exception class name in a fail-closed reason, the receipt suite refusal of a
 * runner without the suite, the Context factories on a malformed context. Fixtures are the oracle cases of [IntentV2DiffTest].
 */
@Suppress("UNCHECKED_CAST")
class K042IntentV2UnitTest {
    private fun caseNamed(name: String): Map<String, Any?> = IntentV2DiffTest.cases.first { it["name"] == name }
    private fun obj(o: Any?) = o as MutableMap<String, Any?>
    private fun list(o: Any?) = o as MutableList<Any?>
    private fun parse(text: Any?) = obj(Json.parseLenient(text as String))
    private fun now(c: Map<String, Any?>) = (c["now"] as Json.Num).raw.toLong()
    private fun render(d: IntentV2.Decision) = d.checks.map { "${it.name}|${it.ok}|${it.reason}" }

    @Test fun aThrowingStepFailsClosedWithTheExceptionClass() {
        val c = caseNamed("vec/session-g0")
        val p = parse(c["p"])
        obj(p["intent_session"])["seq"] = "x"
        val d = IntentV2.decide(p, parse(c["grant"]), IntentV2.Context.fromJsonText(c["ctx"] as String), now(c))
        val r = render(d)
        assertEquals(3, r.size)
        assertEquals("schema|true|null", r[0]); assertEquals("accumulators|true|null", r[2])
        assertEquals("intent_session|false|intent_session error (fail closed): NullPointerException", r[1])
        assertEquals("{\"acc\":{\"trip_spend\":{\"post\":38900}},\"canon\":{\"add_ons\":\"[\\\"none\\\"]\",\"refundable\":\"false\"},\"mon\":{}}", Json.canonicalize(d.env))
    }

    @Test fun receiptSuiteRefusal() {
        val c = caseNamed("vec/acc-receipt")
        val base = "the reservation receipt for 'trip_spend'"
        val unsigned = "$base is not signed by a key the session sequencer's root-signed key set lists for its issue time"
        val algs = listOf<Pair<Any?, String?>>("fn-dsa-512" to "$base: unsupported_suite", "rot13" to "$base: unsupported_suite", Json.Num("7") to unsigned, "ml-dsa-65" to unsigned, "ed25519" to null)
        for ((alg, want) in algs) {
            val p = parse(c["p"]); val ctx = parse(c["ctx"])
            val rc = obj(list(obj(ctx["acc"])["receipts"])[0])
            rc["alg"] = alg
            obj(list(obj(p["intent_session"])["acc"])[0])["receipt"] = IntentAcc.receiptDigest(rc)
            val d = IntentV2.decide(p, parse(c["grant"]), IntentV2.Context.fromJson(ctx), now(c))
            assertEquals(alg.toString(), "accumulators|${want == null}|$want", render(d)[2])
        }
        val p = parse(c["p"]); val ctx = parse(c["ctx"])
        val rc = obj(list(obj(ctx["acc"])["receipts"])[0])
        rc.remove("alg")
        val sg = rc["sig"].toString()
        rc["sig"] = sg.substring(0, 10) + "A" + sg.substring(11).replace('A', 'B')
        obj(list(obj(p["intent_session"])["acc"])[0])["receipt"] = IntentAcc.receiptDigest(rc)
        val d = IntentV2.decide(p, parse(c["grant"]), IntentV2.Context.fromJson(ctx), now(c))
        assertEquals("accumulators|false|$unsigned", render(d)[2])
    }

    @Test fun malformedContextFactories() {
        val c = caseNamed("vec/session-g0")
        val params = linkedMapOf<String, Any?>("total" to Json.Num("1"))
        for (ctx in listOf(IntentV2.Context.fromJson(Json.Num("7")).withParams(params), IntentV2.Context.fromJsonText("[1]").withParams(params), IntentV2.Context.fromJsonText("null").withParams(null))) {
            val d = IntentV2.decide(parse(c["p"]), parse(c["grant"]), ctx, now(c))
            val r = "malformed v2 context: the v2 verifier context must be an object"
            assertEquals(listOf("schema|false|$r", "intent_session|false|$r", "accumulators|false|$r"), render(d))
            assertTrue(d.env.isEmpty()); assertFalse(ctx.wellFormed)
            assertEquals(listOf("params"), ctx.raw.keys.toList())
        }
        val ctx = IntentV2.Context.fromJsonText(c["ctx"] as String)
        val w = ctx.withParams(Json.parseLenient("{\"total\":3.89e4}"))
        assertTrue(w.wellFormed)
        assertEquals("{\"total\":38900}", Json.canonicalize(w.raw["params"]))
        assertEquals("38900", Json.canonicalize(obj(ctx.raw["params"])["total"]))
        assertNotSame(ctx.raw, w.raw)
        assertEquals(ctx.raw.keys, w.raw.keys)
        assertNull(IntentV2.Context.fromJsonText("{\"a\":1}").get("b"))
    }
}
