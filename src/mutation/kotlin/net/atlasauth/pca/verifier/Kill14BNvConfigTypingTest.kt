package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** NVIDIA config typing: a present collateral / firmware that is not an object is refused (it used to drop the collateral or firmware policy). */
class Kill14BNvConfigTypingTest {
    private fun err(cfg: Map<String, Any?>): String? = try { AttestNvidia.create(cfg); null } catch (e: IllegalArgumentException) { e.message }

    private val base: Map<String, Any?> = mapOf("rootSpkiSha256" to listOf("aa"), "policy" to mapOf("measurements" to mapOf("1" to "aa")))

    @Test fun collateralMustBeAnObject() {
        for (bad in listOf<Any?>("x", "", 5, 0, true, false, listOf<Any?>(), listOf("a"))) {
            assertEquals("$bad", "createNvidiaSpdmVerifier: collateral must be an object", err(base + ("collateral" to bad)))
        }
        assertEquals(null, err(base + ("collateral" to null)))
    }

    @Test fun firmwareMustBeAnObject() {
        val col = mapOf<String, Any?>("rimRootSpkiSha256" to listOf("aa"))
        for (bad in listOf<Any?>("x", 5, true, listOf<Any?>())) {
            assertEquals("$bad", "nvidiaCollateralHook: firmware must be an object", err(base + ("collateral" to (col + ("firmware" to bad)))))
        }
        for (falsy in listOf<Any?>(null, "", 0, false)) assertEquals("$falsy", null, err(base + ("collateral" to (col + ("firmware" to falsy)))))
        assertEquals(null, err(base + ("collateral" to (col + ("firmware" to emptyMap<String, Any?>())))))
        assertThrows(IllegalArgumentException::class.java) { AttestNvidia.create(base + ("collateral" to (col + ("requireCrlIssuers" to listOf("a", 1))))) }
    }
}
