package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 0.5 mutation kill for the restored resolveLink guard: a registry with no `templates` member (or one that is not an object) is
 * the plain "not in the registry" refusal, never the generic fail-closed catch (a null dereference).
 */
class Kill07RestoredGuardsTest {
    @Test
    fun registryWithoutTemplatesRefusesAsNotInTheRegistry() {
        val ref = linkedMapOf<String, Any?>("template_id" to "t", "version_digest" to "d", "slots" to emptyMap<String, Any?>())
        val regs = listOf<Any?>(
            emptyMap<String, Any?>(), mapOf("templates" to null), mapOf("templates" to "x"), mapOf("templates" to listOf<Any?>()),
            mapOf("templates" to emptyMap<String, Any?>()), mapOf("templates" to mapOf("other" to mapOf<String, Any?>())),
        )
        for (reg in regs) {
            val r = PolicyAuthoring.resolveLink(ref, reg)
            assertNull("$reg", r.policy)
            assertEquals("$reg", "template version is not in the registry", r.reason)
            assertEquals(0, r.overlays)
        }
    }
}
