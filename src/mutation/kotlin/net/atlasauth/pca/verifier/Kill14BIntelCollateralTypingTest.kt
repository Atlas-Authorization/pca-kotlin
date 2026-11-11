package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Intel DCAP collateral typing: a policy.collateral that is present and not an object is refused at construction (it used to drop the accepted
 * statuses and the evaluation floor); a truthy evidence.collateral that is not an object is never "missing" and fails before the
 * allowMissingCollateral branch.
 */
class Kill14BIntelCollateralTypingTest {
    private val k = Kill05GcpAmdKit
    private val x = Kill05IntelMeshKit
    private val now = Kill05GcpAmdKit.NOW

    private fun config(g: Kill05IntelMeshKit.G, polExtra: Map<String, Any?> = emptyMap(), allowMissing: Boolean = true): Map<String, Any?> {
        val pol = KUtil.m("mrtds" to KUtil.l(x.hex(g.mrTd)))
        pol.putAll(polExtra)
        return KUtil.m("binding" to "report-data", "trustAnchorRootCaSpkiSha256" to g.pin(), "allowMissingCollateral" to allowMissing, "policy" to pol)
    }

    @Test fun aNonObjectPolicyCollateralRefusesTheConfig() {
        val g = Kill05IntelMeshKit.G()
        for (bad in listOf<Any?>("x", "", 5, 0, true, false, ArrayList<Any?>(), ArrayList<Any?>(listOf("a")))) {
            val e = assertThrows(IllegalArgumentException::class.java) { AttestIntel.create(config(g, KUtil.m("collateral" to bad))) }
            assertEquals("$bad", "createIntelDcapVerifier: policy.collateral must be an object", e.message)
        }
        AttestIntel.create(config(g, KUtil.m("collateral" to null)))
        AttestIntel.create(config(g, KUtil.m("collateral" to KUtil.m())))
        AttestIntel.create(config(g, KUtil.m("collateral" to KUtil.m("minTcbEvaluationDataNumber" to Json.Num("7")))))
    }

    @Test fun aTruthyNonObjectEvidenceCollateralFailsInsteadOfBeingMissing() {
        val g = Kill05IntelMeshKit.G()
        val quote = k.b64(g.quote())
        fun run(collateral: Any?, withKey: Boolean = true): Attest.Result {
            val ev = KUtil.m("quote" to quote)
            if (withKey) ev["collateral"] = collateral
            return AttestIntel.create(config(g)).verify(ev, Kill05GcpAmdKit.BINDING, now)
        }
        for (bad in listOf<Any?>("x", 5, ArrayList<Any?>(), true, Json.Num("1"))) {
            val r = run(bad)
            assertEquals("$bad", false, r.ok)
            assertEquals("$bad", "Intel collateral: collateral incomplete (fail closed)", r.reason)
        }
        for (missing in listOf<Any?>(null, 0, "", false, Json.Num("0"))) {
            val r = run(missing)
            assertTrue("$missing: ${r.reason}", r.ok)
            assertEquals("unevaluated", r.hostAsserted!!["tcb_status"])
        }
        assertTrue(run(null, withKey = false).ok)
    }
}
