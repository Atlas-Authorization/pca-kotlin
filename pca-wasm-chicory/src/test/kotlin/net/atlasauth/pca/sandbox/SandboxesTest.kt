package net.atlasauth.pca.sandbox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class SandboxesTest {
    @Test fun withoutAProvenClaimTheTableIsClassNone() {
        val sb = createSandbox(SandboxOptions(emptyMap()))
        assertEquals("none", sb.table.runtimeClass())
        assertEquals(0, sb.table.size())
        val bad = createSandbox(SandboxOptions(emptyMap(), runtimeClaim = Pair(linkedMapOf<String, Any?>("class" to "wasi_no_ambient"), linkedMapOf<String, Any?>())))
        assertEquals("none", bad.table.runtimeClass())
    }

    @Test fun anEmptyOrOversizedModuleIsRefusedBeforeAnythingRuns() {
        val sb = createSandbox(SandboxOptions(emptyMap(), maxModuleBytes = 16))
        assertEquals("module_size", sb.run(ByteArray(0)).reason)
        assertEquals("module_size", sb.run(ByteArray(17)).reason)
        assertFalse(sb.runAsync(ByteArray(0)).get().ok)
    }
}
