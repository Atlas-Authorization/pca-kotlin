package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** A break-glass entry whose stored shape is not an object is an unknown grant, never a fault. */
class BreakGlassStoreShapeTest {
    private fun registryOver(grants: Map<String, Any?>): BreakGlass.Registry {
        val kv = MemoryAtomicKv()
        kv.set("breakglass/holder/agent", linkedMapOf<String, Any?>("grants" to grants))
        return BreakGlass.Registry(BreakGlass.Policy(listOf("authority"), listOf("reviewer")), kv)
    }

    @Test fun aStoredEntryThatIsNotAnObjectIsUnknown() {
        val reg = registryOver(linkedMapOf("junk" to "not-an-object", "empty" to null, "list" to arrayListOf<Any?>()))
        for (id in listOf("junk", "empty", "list", "absent")) {
            val d = reg.use(id, "agent", "act", IntentJs.ofLong(1), true)
            assertEquals(id, "deny", d.decision)
            assertEquals(id, "unknown_break_glass", d.code)
            assertEquals(id, id, d.id)
        }
    }
}
