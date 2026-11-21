package net.atlasauth.pca.attesteat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Hand-built inputs fail closed: a present dbgstat that is not an RFC 9711 value is unknown, and a minTcb that is not a number, string or object is not comparable. */
class AttestEatHardeningTest {
    private fun appraise(evidence: Map<String, Any?>, rv: Map<String, Any?>) = AttestEat.appraise(evidence, rv, emptyMap(), emptyMap())

    @Test fun invalidDbgstatIsUnknown() {
        for (bad in listOf<Any?>("bogus", "", 1L, true, null)) {
            val r = appraise(linkedMapOf("dbgstat" to bad), linkedMapOf("requireDebugDisabled" to true))
            assertEquals(bad.toString(), false, r["trustworthy"])
            assertEquals(bad.toString(), "rejected", r["tier"])
            assertTrue((r["reasons"] as List<*>).any { it.toString().startsWith("debug status unknown") })
        }
    }

    @Test fun nonObjectMinTcbIsNotComparable() {
        for (bad in listOf<Any?>(true, false, listOf<Any?>(), null)) {
            assertNull(bad.toString(), AttestEat.packTcb(bad))
            val r = appraise(linkedMapOf<String, Any?>(), linkedMapOf("minTcb" to bad))
            assertEquals(bad.toString(), "rejected", r["tier"])
            assertTrue((r["reasons"] as List<*>).any { it == "reference minTcb is not a comparable TCB version" })
        }
    }
}
