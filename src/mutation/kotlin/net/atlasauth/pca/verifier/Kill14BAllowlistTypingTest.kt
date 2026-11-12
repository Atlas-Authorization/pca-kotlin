package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** Policy allowlists (MAA, Intel DCAP): a present non-array is refused, non-string entries are refused, an absent list stays empty. */
class Kill14BAllowlistTypingTest {
    private val x = Kill05IntelMeshKit

    private fun intel(g: Kill05IntelMeshKit.G, extra: Map<String, Any?>): Map<String, Any?> {
        val pol = KUtil.m("mrtds" to KUtil.l(x.hex(g.mrTd)))
        pol.putAll(extra)
        return KUtil.m("binding" to "report-data", "trustAnchorRootCaSpkiSha256" to g.pin(), "allowMissingCollateral" to true, "policy" to pol)
    }

    @Test fun intelFmspcsAndRtmrsMustBeStringArrays() {
        val g = Kill05IntelMeshKit.G()
        for (name in listOf("fmspcs", "rtmrs")) {
            for (bad in listOf<Any?>("aa", 5, true, KUtil.m())) {
                val e = assertThrows(IllegalArgumentException::class.java) { AttestIntel.create(intel(g, KUtil.m(name to bad))) }
                assertEquals("$name $bad", "createIntelDcapVerifier: policy.$name must be an array of strings", e.message)
            }
            val e = assertThrows(IllegalArgumentException::class.java) { AttestIntel.create(intel(g, KUtil.m(name to KUtil.l("aa", 1)))) }
            assertEquals("createIntelDcapVerifier: policy.$name must list only strings", e.message)
            AttestIntel.create(intel(g, KUtil.m(name to null)))
            AttestIntel.create(intel(g, KUtil.m(name to KUtil.l())))
        }
    }

    private fun maa(pol: String): String? = try {
        Attest.verifierFromConfig("azure-maa", Json.parse("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":$pol}""") as Map<String, Any?>)
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Test fun maaMeasurementAllowlistsMustBeStringArrays() {
        val p = "createAzureMaaVerifier: policy."
        for (name in listOf("sevSnpMeasurements", "tdxMrtds")) {
            for (bad in listOf("\"aa\"", "5", "true", "{}")) {
                assertEquals("$name $bad", "$p$name must be an array of strings", maa("""{"$name":$bad}"""))
            }
            assertEquals("$p$name must list only strings", maa("""{"$name":["aa",1]}"""))
        }
        assertEquals(null, maa("""{"tdxMrtds":["aa"]}"""))
    }
}
