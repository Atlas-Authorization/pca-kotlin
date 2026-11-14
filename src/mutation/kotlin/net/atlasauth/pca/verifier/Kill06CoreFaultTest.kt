package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.NOW
import net.atlasauth.pca.verifier.KUtil.valid
import net.atlasauth.pca.verifier.KUtil.validGrant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A fault anywhere in core verification denies, including after every core check passed (TS pcactn.ts catch:
 * CoreMalformed sets checks.malformed = fail). Each top-level read of a valid PCActn is made to throw in turn.
 */
class Kill06CoreFaultTest {
    /** Counts every read; throws on read number [at] (0 = never). */
    private class FaultAt(private val base: Map<String, Any?>, private val at: Int) : Map<String, Any?> by base {
        var reads = 0
        private fun tick() { reads++; if (reads == at) throw IllegalStateException("fault") }
        override val entries: Set<Map.Entry<String, Any?>> get() { tick(); return base.entries }
        override val keys: Set<String> get() { tick(); return base.keys }
        override val values: Collection<Any?> get() { tick(); return base.values }
        override val size: Int get() { tick(); return base.size }
        override fun get(key: String): Any? { tick(); return base[key] }
        override fun containsKey(key: String): Boolean { tick(); return base.containsKey(key) }
        override fun isEmpty(): Boolean { tick(); return base.isEmpty() }
    }

    @Test fun everyInjectedFaultDenies() {
        val clean = FaultAt(valid(), 0)
        assertTrue(Pca.verifyPcactn(clean, validGrant(), NOW, KUtil.Of, insecureSkipPlanRootCheck = true).allow)
        assertTrue(clean.reads > 10)
        for (k in 1..clean.reads) assertFalse("fault at read $k", Pca.verifyPcactn(FaultAt(valid(), k), validGrant(), NOW, KUtil.Of, insecureSkipPlanRootCheck = true).allow)
    }

    /** The intent read is the last step in the core block: every core check has passed, and the fault still denies as malformed. */
    @Test fun aFaultAfterEveryCoreCheckIsMalformed() {
        val p = object : java.util.LinkedHashMap<String, Any?>(valid()) {
            override fun get(key: String): Any? = if (key == "intent") throw IllegalStateException("late") else super.get(key)
        }
        val v = Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of, insecureSkipPlanRootCheck = true)
        assertFalse(v.allow)
        for (c in listOf("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"))
            assertEquals(c, true, v.checks[c])
        assertEquals(false, v.checks["malformed"])
        assertEquals("malformed PCActn: java.lang.IllegalStateException: late", v.reason)
    }
}
