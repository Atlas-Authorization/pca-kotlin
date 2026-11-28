package net.atlasauth.pca.testing

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference oracle for the testing kit (constants, route mapping, fake verifier, tamper, state store). */
@Suppress("UNCHECKED_CAST")
class TestingKitDiffTest {
    private val MODULE = "ref-testing"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun opts(o: Any?): TestingKit.FakeVerifyOptions {
        val src = m(o)
        val r = TestingKit.FakeVerifyOptions()
        if (src.containsKey("audience")) r.audience(src["audience"] as String?)
        if (src["now"] != null) r.now(src["now"].toString().toLong())
        if (src["grant"] != null) r.grant(m(src["grant"]))
        return r
    }

    @Test fun consts() = OracleCases.each(MODULE, "consts") {
        linkedMapOf("aud" to TestingKit.ADAPTER_ACCEPTANCE_AUDIENCE, "expected" to TestingKit.adapterAcceptanceExpected())
    }

    @Test fun acceptanceOperation() = OracleCases.each(MODULE, "acceptanceOperation") { a -> TestingKit.acceptanceOperation(m(a[0])) }

    @Test fun fakeVerify() = OracleCases.each(MODULE, "fakeVerifyAllow") { a -> TestingKit.fakeVerify(a[0], opts(a[1])).allow }

    @Test fun expectVerifies() = OracleCases.each(MODULE, "expectVerifies") { a -> TestingKit.expectVerifies(a[0], opts(a[1])).allow }

    @Test fun expectDenied() = OracleCases.each(MODULE, "expectDenied") { a -> TestingKit.expectDenied(a[0], opts(a[1])).allow }

    @Test fun tamper() = OracleCases.each(MODULE, "tamper") { a ->
        val mut = m(a[1])
        TestingKit.tamper(a[0] as String) { rec ->
            val op = mut["op"] as String
            if (op != "none") {
                val path = l(mut["path"])
                var cur: Any? = rec
                for (i in 0 until path.size - 1) cur = m(cur)[path[i] as String]
                val holder = (cur as Map<String, Any?>?)!! as MutableMap<String, Any?> // a missing parent is null here: the reference throws, so does this
                val last = path[path.size - 1] as String
                if (op == "set") holder[last] = mut["value"] else holder.remove(last)
            }
        }
    }

    @Test fun memoryStateStore() = OracleCases.each(MODULE, "memorySession") { a ->
        val s = TestingKit.memoryStateStore()
        val out = ArrayList<Any?>()
        for (op in l(a[0])) {
            val o = l(op)
            if (o[0] == "put") s.put(o[1] as String, m(o[2])) else out.add(s.get(o[1] as String))
        }
        out
    }

    /** A real agent built with the defaults verifies, a tampered one does not. */
    @Test fun roundTrip() {
        val a = TestingKit.testAgent()
        val made = TestingKit.makePCActn(a, "stripe.refund", "charge:ch_1", linkedMapOf("amount" to Json.Num("42")))
        assertTrue(TestingKit.expectVerifies(made.pcactn).allow)
        val bad = TestingKit.tamper(made.encoded) { rec -> (rec["action"] as MutableMap<String, Any?>)["verb"] = "stripe.payout" }
        var threw = false
        try { TestingKit.expectVerifies(Json.parse(bad)) } catch (e: IllegalStateException) { threw = true }
        assertTrue(threw)
        assertFalse(TestingKit.expectDenied(Json.parse(bad)).allow)
    }
}
