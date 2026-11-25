package net.atlasauth.pca.policybridge

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference oracle for the policy bridge (Cedar, Rego, OpenFGA and CEL translators and the deny-overrides decision). */
class PolicyBridgeDiffTest {
    private val module = "ref-policy-bridge"

    @Suppress("UNCHECKED_CAST")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun items(o: Any?): List<Map<String, Any?>> = o as List<Map<String, Any?>>

    @Test fun cedarToPca() = OracleCases.each(module, "cedarToPca") { a -> Cedar.cedarToPca(a[0] as String) }

    @Test fun translateCedar() = OracleCases.each(module, "translateCedar") { a -> Cedar.translateCedar(a[0] as String, a[1] as Boolean) }

    @Test fun regoToPca() = OracleCases.each(module, "regoToPca") { a -> Rego.regoToPca(a[0] as String) }

    @Test fun openfgaToPca() = OracleCases.each(module, "openfgaToPca") { a -> OpenFga.openfgaToPca(a[0], a[1]) }

    @Test fun decide() = OracleCases.each(module, "decide") { a -> PolicyBridge.decide(m(a[0]), m(a[1])) }

    @Test fun celToCondition() = OracleCases.each(module, "celToCondition") { a -> Cel.celToCondition(a[0] as String?, a[1]) }

    @Test fun parseCel() = OracleCases.each(module, "parseCel") { a -> Cel.parseCel(a[0] as String?) }

    @Test fun celToPredicate() = OracleCases.each(module, "celToPredicate") { a ->
        val scope = m(a[2])
        Cel.celToPredicate(a[0] as String?, a[1], scope["verb"], scope["resource"] as String?)
    }

    @Test fun celConditionsToPca() = OracleCases.each(module, "celConditionsToPca") { a -> Cel.celConditionsToPca(items(a[0]), a[1]) }

    /** A forbid that matches overrides a matching permit; an incomplete translation denies everything. */
    @Test fun denyOverridesPermit() {
        val r = Cedar.cedarToPca("permit (principal, action, resource); forbid (principal, action == Action::\"delete\", resource);")
        val read = mapOf("subject" to mapOf("id" to "u"), "action" to mapOf("verb" to "read", "resource" to "r"))
        val del = mapOf("subject" to mapOf("id" to "u"), "action" to mapOf("verb" to "delete", "resource" to "r"))
        assertEquals(true, PolicyBridge.decide(r, read)["allowed"])
        assertEquals("forbidden by deny policy", PolicyBridge.decide(r, del)["reason"])
        val bad = Cedar.cedarToPca("forbid (principal, action, resource) when { resource.a + 1 < 2 };")
        assertTrue((m(bad["report"])["errors"] as List<*>).isNotEmpty())
        assertEquals("translation incomplete (fail closed)", PolicyBridge.decide(bad, read)["reason"])
    }
}
