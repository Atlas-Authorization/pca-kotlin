package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for Blueprint.kt (durable Registry over AtomicKv): the running maximum epoch, a store that throws or never runs the
 * update function, a fatal error, and a record of the wrong shape.
 */
class Kill08K1BlueprintTest {
    private val labelA = "k08k1-blueprint-a"
    private val labelB = "k08k1-blueprint-b"
    private val opA = IntentTestKit.pub(labelA)
    private val opB = IntentTestKit.pub(labelB)
    private fun n(s: String) = Json.Num(s)
    private val keys = listOf("v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator")

    private fun record(key: String, epoch: Long, operator: String = opA, label: String = labelA, issued: Long = 100L): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        b["v"] = n("1"); b["id"] = "bp-$key"; b["key"] = key; b["ceiling"] = ArrayList<Any?>(); b["epoch"] = n("$epoch")
        b["status"] = "active"; b["issued_at"] = n("$issued"); b["operator"] = operator
        val body = LinkedHashMap<String, Any?>()
        for (k in keys) if (b.containsKey(k)) body[k] = b[k]
        b["sig"] = IntentTestKit.sign(label, IntentJs.message(Blueprint.DOMAIN, body))
        return b
    }

    private fun hop(i: String, h: String) = LinkedHashMap<String, Any?>(mapOf("issuer" to i, "holder" to h))

    @Test fun theMaximumEpochOnlyRisesAndOnlyOnATakenRecord() {
        val reg = Blueprint.Registry(listOf(opA, opB), MemoryAtomicKv())
        assertEquals(0L, reg.epoch())
        assertTrue(reg.accept(record("K1", 5)).replaced)
        assertEquals(5L, reg.epoch())
        // a new key with a lower epoch is taken but does not lower the maximum
        assertTrue(reg.accept(record("K2", 3)).replaced)
        assertEquals(5L, reg.epoch())
        // an equal epoch on a new key leaves it
        assertTrue(reg.accept(record("K3", 5)).replaced)
        assertEquals(5L, reg.epoch())
        assertTrue(reg.accept(record("K4", 9)).replaced)
        assertEquals(9L, reg.epoch())
        assertTrue(reg.accept(record("K5", 6)).replaced)
        assertEquals(9L, reg.epoch())
        // refused records never move it, whatever epoch they carry
        val changed = reg.accept(record("K1", 20, opB, labelB))
        assertEquals("operator_changed", changed.code)
        assertFalse(changed.replaced)
        assertEquals(9L, reg.epoch())
        assertEquals("epoch_fork", reg.accept(record("K1", 5, issued = 101L)).code)
        assertEquals("stale_epoch", reg.accept(record("K4", 2)).code)
        assertEquals(9L, reg.epoch())
    }

    @Test fun aStoreThatNeverRunsTheUpdateFunctionIsUnreachableAndNotReplaced() {
        val reg = Blueprint.Registry(listOf(opA), Kill08K1NoopKv)
        val a = reg.accept(record("K1", 5))
        assertNotNull(a)
        assertEquals("store_unreachable", a.code)
        assertFalse(a.replaced)
        assertEquals(0L, reg.epoch())
    }

    @Test fun aStoreThatThrowsIsUnreachableAndAFatalErrorIsRethrown() {
        val down = Blueprint.Registry(listOf(opA), Kill08K1ThrowingKv { IllegalStateException("down") })
        val a = down.accept(record("K1", 5))
        assertEquals("store_unreachable", a.code)
        assertFalse(a.replaced)
        val c = Blueprint.check(listOf(hop("P", "K1"), hop("K1", "inst")), down, n("999"), "require")
        assertEquals("deny", c.decision)
        assertEquals("store_unreachable", c.code)
        val fatal = Blueprint.Registry(listOf(opA), Kill08K1ThrowingKv { OutOfMemoryError("fatal") })
        assertThrows(OutOfMemoryError::class.java) { fatal.accept(record("K1", 5)) }
        assertThrows(OutOfMemoryError::class.java) { Blueprint.check(listOf(hop("P", "K1"), hop("K1", "inst")), fatal, n("999"), "require") }
    }

    @Test fun aRecordKeyHoldingSomethingThatIsNotAnObjectIsNoRecord() {
        val kv = MemoryAtomicKv()
        kv.set("blueprint/record/K1", "junk")
        val reg = Blueprint.Registry(listOf(opA), kv)
        assertNull(reg.get("K1"))
    }
}
