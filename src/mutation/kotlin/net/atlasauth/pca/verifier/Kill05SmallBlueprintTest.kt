package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kill tests for Blueprint (k05 small group): every shape guard on a VALIDLY signed record, the registry codes and the chain gate. */
class Kill05SmallBlueprintTest {
    private val label = "k05-blueprint-operator"
    private val op = IntentTestKit.pub(label)
    private fun n(s: String) = Json.Num(s)
    private val keys = listOf("v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator")

    private fun record(vararg over: Pair<String, Any?>, drop: String? = null): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        b["v"] = n("1"); b["id"] = "bp1"; b["key"] = "K1"; b["ceiling"] = ArrayList<Any?>(); b["epoch"] = n("1")
        b["status"] = "active"; b["issued_at"] = n("100"); b["operator"] = op
        for ((k, v) in over) b[k] = v
        if (drop != null) b.remove(drop)
        val body = LinkedHashMap<String, Any?>()
        for (k in keys) if (b.containsKey(k)) body[k] = b[k]
        b["sig"] = IntentTestKit.sign(label, IntentJs.message(Blueprint.DOMAIN, body))
        return b
    }

    private fun ceiling(size: Int): ArrayList<Any?> = ArrayList<Any?>(List(size) { LinkedHashMap<String, Any?>(mapOf("type" to "t")) })

    @Test fun verifyEveryShapeGuard() {
        assertTrue(Blueprint.verify(record()))
        assertFalse(Blueprint.verify("x"))
        val good = listOf(
            record("id" to "i".repeat(128)), record("key" to "k".repeat(128)), record("max_depth" to n("1")), record("expires_at" to n("5")),
            record("ceiling" to ceiling(32)), record("status" to "disabled"),
        )
        for (r in good) assertTrue(r.toString(), Blueprint.verify(r))
        val bad = listOf(
            record("v" to n("2")), record("v" to "1"), record("id" to ""), record("id" to "i".repeat(129)), record("key" to ""),
            record("key" to "k".repeat(129)), record("epoch" to n("-1")), record("issued_at" to n("-1")), record("status" to "paused"),
            record("max_depth" to n("0")), record("max_depth" to "1"), record("expires_at" to n("-1")), record(drop = "ceiling"),
            record("ceiling" to "x"), record("ceiling" to ceiling(33)), record("ceiling" to arrayListOf<Any?>("x")),
            record("ceiling" to arrayListOf<Any?>(LinkedHashMap<String, Any?>(mapOf("type" to n("1"))))),
            record("ceiling" to arrayListOf<Any?>(LinkedHashMap<String, Any?>())),
        )
        for (r in bad) assertFalse(r.toString(), Blueprint.verify(r))
    }

    @Test fun registryCodes() {
        val reg = Blueprint.Registry(listOf(op))
        assertEquals(0L, reg.epoch())
        val bad = reg.accept(record("v" to n("2")))
        assertEquals("bad_record", bad.code)
        assertFalse(bad.replaced)
        val unknown = Blueprint.Registry(listOf("someone-else")).accept(record())
        assertEquals("unknown_operator", unknown.code)
        assertFalse(unknown.replaced)
        val first = reg.accept(record("epoch" to n("3")))
        assertNull(first.code)
        assertTrue(first.replaced)
        assertEquals(3L, reg.epoch())
        val stale = reg.accept(record("epoch" to n("2")))
        assertEquals("stale_epoch", stale.code)
        assertFalse(stale.replaced)
        assertEquals("epoch_fork", reg.accept(record("epoch" to n("3"), "issued_at" to n("101"))).code)
        reg.accept(record("key" to "K2", "epoch" to n("7")))
        assertEquals(7L, reg.epoch())
    }

    private fun hop(i: String, h: String) = LinkedHashMap<String, Any?>(mapOf("issuer" to i, "holder" to h))

    private fun pins(vararg p: Any?) = arrayListOf(*p)
    private fun pin(vararg kv: Pair<String, Any?>) = LinkedHashMap<String, Any?>(mapOf(*kv))

    /** blueprint.ts:86-91: the shape of runtime_pins (a record carrying them is signed over them, and accepted). */
    @Test fun runtimePinShapes() {
        for (k in listOf("runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id")) assertTrue(k, Blueprint.verify(record("runtime_pins" to pins(pin(k to "x")))))
        assertTrue(Blueprint.verify(record("runtime_pins" to ArrayList<Any?>(List(16) { pin("model_id" to "m") }))))
        assertTrue(Blueprint.verify(record("runtime_pins" to pins(pin("model_id" to "m".repeat(256))))))
        for (bad in listOf<Any?>(
            "x", ArrayList<Any?>(), ArrayList<Any?>(List(17) { pin("model_id" to "m") }), pins("x"), pins(pin()), pins(pin("other" to "x")),
            pins(pin("model_id" to "")), pins(pin("model_id" to n("1"))), pins(pin("model_id" to "m".repeat(257))), pins(pin("model_id" to "m"), pin("other" to "x")),
        )) assertFalse("$bad", Blueprint.verify(record("runtime_pins" to bad)))
        // the signature covers the pins
        val r = record("runtime_pins" to pins(pin("model_id" to "m")))
        assertFalse(Blueprint.verify(LinkedHashMap(r).also { it["runtime_pins"] = pins(pin("model_id" to "n")) }))
        assertFalse(Blueprint.verify(LinkedHashMap(r).also { it.remove("runtime_pins") }))
    }

    /** blueprint.ts:202-205: admission is not implemented here, so a pinned blueprint denies; status, expiry and depth come first, the ceiling after. */
    @Test fun aPinnedBlueprintDeniesAtTheCheck() {
        val two = listOf(hop("P", "K1"), hop("K1", "inst"))
        val thePins = pins(pin("model_id" to "m"))
        fun check(vararg over: Pair<String, Any?>, mode: String = "any", chain: List<Any?> = two): Blueprint.Decision {
            val reg = Blueprint.Registry(listOf(op))
            assertNull(reg.accept(record("runtime_pins" to thePins, *over)).code)
            return Blueprint.check(chain, reg, n("999"), mode)
        }
        val denied = check()
        assertEquals("deny", denied.decision)
        assertEquals("admission_required", denied.code)
        assertEquals("bp1", denied.blueprint)
        assertEquals("admission_required", check(mode = "require").code)
        assertEquals("blueprint_disabled", check("status" to "disabled", "epoch" to n("2")).code) // a group kill keeps the pins
        assertEquals("blueprint_expired", check("expires_at" to n("999")).code)
        assertEquals("too_deep", check("max_depth" to n("1"), chain = listOf(hop("P", "K1"), hop("K1", "i"), hop("i", "j"))).code)
        assertEquals("admission_required", check("ceiling" to ceiling(1)).code)
        // a chain the blueprint does not govern is untouched
        assertEquals("allow", check(chain = listOf(hop("P", "Q"))).decision)
    }

    /** One atomic update per key: of racing forks exactly one is taken, the rest are refused, nothing is lost. */
    @Test fun racingAcceptsNeverLoseForkDetection() {
        val reg = Blueprint.Registry(listOf(op))
        val records = List(32) { record("epoch" to n("1"), "issued_at" to n("${100 + it}")) }
        val pool = java.util.concurrent.Executors.newFixedThreadPool(8)
        try {
            val codes = pool.invokeAll(records.map { r -> java.util.concurrent.Callable { reg.accept(r).code } }).map { it.get() }
            assertEquals(1, codes.count { it == null })
            assertEquals(31, codes.count { it == "epoch_fork" })
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun chainGate() {
        val reg = Blueprint.Registry(listOf(op))
        assertNull(reg.accept(record("max_depth" to n("1"), "expires_at" to n("1000"))).code)
        val two = listOf(hop("P", "K1"), hop("K1", "inst"))
        val ok = Blueprint.check(two, reg, n("999"), "require")
        assertEquals("allow", ok.decision)
        assertEquals(listOf("bp1"), ok.governed)
        assertNull(ok.code)
        val expired = Blueprint.check(two, reg, n("1000"), "require")
        assertEquals("deny", expired.decision)
        assertEquals("blueprint_expired", expired.code)
        assertEquals("bp1", expired.blueprint)
        assertEquals("too_deep", Blueprint.check(listOf(hop("P", "K1"), hop("K1", "inst"), hop("inst", "sub")), reg, n("999"), "require").code)

        fun badInput(chain: Any?, now: Any? = n("999")) {
            val d = Blueprint.check(chain, reg, now, "any")
            assertEquals("deny", d.decision)
            assertEquals("bad_input", d.code)
            assertNull(d.blueprint)
        }
        badInput(null)
        badInput(emptyList<Any?>())
        badInput(two, "999")
        badInput(two, n("-1"))
        badInput(listOf<Any?>("x"))
        badInput(listOf(hop("P", "K1"), hop("", "inst")))
        badInput(listOf(hop("P", "K1"), hop("K1", "h".repeat(129))))
        assertEquals("allow", Blueprint.check(listOf(hop("P", "K1"), hop("K1", "h".repeat(128))), reg, n("999"), "any").decision)

        val esc = Blueprint.check(two, reg, n("999"), "require", 5L)
        assertEquals("escalate", esc.decision)
        assertEquals("stale_blueprint_state", esc.code)
        assertEquals(1L, esc.have)
        assertEquals(5L, esc.need)
    }
}
