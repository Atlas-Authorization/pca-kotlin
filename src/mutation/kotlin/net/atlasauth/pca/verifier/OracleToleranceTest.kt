package net.atlasauth.pca.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The diagnostic statistics compare to 1e-12 relative (1e-15 absolute floor); everything else, and every other shape, stays exact. */
class OracleToleranceTest {
    @Test fun aLastDigitDifferenceIsCloseButARealOneIsNot() {
        assertTrue(OracleCases.jsonClose(Json.Num("0.1"), Json.Num("0.10000000000000002")))
        assertTrue(OracleCases.jsonClose(Json.Num("1e300"), Json.Num("1.0000000000001e300")))
        assertFalse(OracleCases.jsonClose(Json.Num("1"), Json.Num("1.000000001")))
        assertTrue(OracleCases.jsonClose(Json.Num("0"), Json.Num("1e-16")))
        assertFalse(OracleCases.jsonClose(Json.Num("0"), Json.Num("1e-14")))
    }

    @Test fun shapeStaysExact() {
        assertFalse(OracleCases.jsonClose("a", "b"))
        assertFalse(OracleCases.jsonClose(listOf(Json.Num("1")), listOf(Json.Num("1"), Json.Num("1"))))
        assertFalse(OracleCases.jsonClose(null, Json.Num("0")))
        assertFalse(OracleCases.jsonClose(Json.Num("NaN"), Json.Num("NaN")))
        assertTrue(OracleCases.jsonClose(linkedMapOf<String, Any?>("a" to listOf(Json.Num("2"), true)), linkedMapOf<String, Any?>("a" to listOf(Json.Num("2.0000000000001"), true))))
    }

    @Test fun onlyTheDiagnosticFunctionsAreTolerant() {
        for (f in listOf("binomialCdf", "hoeffdingHalfWidth", "wilsonInterval", "lnGamma", "betacf", "betaInc", "betaQuantile")) assertTrue(f, f in OracleCases.DIAGNOSTIC_FNS)
        for (f in listOf("clopperPearsonUpper", "clopperPearsonCertified", "proportionCutoff", "admissionPolicy", "etaUnderLoad")) assertFalse(f, f in OracleCases.DIAGNOSTIC_FNS)
    }
}
