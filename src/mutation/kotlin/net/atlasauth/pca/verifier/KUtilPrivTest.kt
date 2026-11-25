package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** KUtil.priv reaches the internal function itself, never a private helper the compiler hoisted out of it (requiresAttestation has a local function). */
class KUtilPrivTest {
    @Test fun anInternalFunctionIsFoundBesideItsHoistedLocalFunction() {
        assertEquals(true, KUtil.priv<Boolean>(Authorize, "requiresAttestation", mapOf("operator" to "acme")))
        assertEquals(true, KUtil.priv<Boolean>(Authorize, "requiresAttestation", mapOf("model_allowlist" to listOf("m"))))
        assertEquals(false, KUtil.priv<Boolean>(Authorize, "requiresAttestation", emptyMap<String, Any?>()))
    }
}
