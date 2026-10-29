package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Workflow admission inside `Authorize.authorize` (K5, C-308), replayed over `authorize-workflow-fixtures.json`. Each case threads its steps
 * through ONE replay store. A missing file FAILS (ParityVectors.load throws).
 */
@Suppress("UNCHECKED_CAST")
class K5AuthorizeWorkflowTest {
    private val f = ParityVectors.load("authorize-workflow-fixtures.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test
    fun fixtures() {
        assertEquals("pca-authorize-workflow-fixtures/1", f["format"])
        assertTrue(l(f["cases"]).size >= 14)
        val grant = m(f["grant"])
        for (cx in l(f["cases"])) {
            val c = m(cx)
            val store = Authorize.MemoryStateStore()
            for ((n, sx) in l(c["steps"]).withIndex()) {
                val s = m(sx)
                val w = s["workflow"]?.let { m(it) }
                val call = w?.let {
                    Authorize.WorkflowStep(it["commitment"], it["receipts"], it["step"] as String?, (it["units"] as Map<String, Any?>?) ?: emptyMap(), it["goal_digest"] as String?)
                }
                val r = Authorize.authorize(
                    s["pcactn"],
                    Authorize.Input(
                        operation = Authorize.Operation.fromJson(s["operation"]), audience = f["audience"] as String,
                        resolveGrant = { ref -> if (ref == grant["id"]) grant else null }, stateStore = store, isRevoked = { _, _ -> false },
                        now = Json.asLong(f["now"]), context = { _ -> mapOf("plan" to f["plan"], "plan_authorized" to true) },
                        workflow = Authorize.WorkflowGate(f["principal"] as String, f["rs_signer"] as String, c["required"] == true), workflowCall = call,
                        provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(Authorize.Operation.fromJson(s["operation"])),
                    ),
                )
                val e = m(s["expect"])
                val where = "${c["name"]} step $n: ${r.reasons}"
                assertEquals(where, e["allow"], r.allow)
                assertEquals(where, e["decision"], r.decision)
                assertEquals(where, Json.asLong(e["status"]).toInt(), r.status)
                assertEquals(where, (e["failed"] as List<*>).map { it as String }, r.checks.filterValues { it == "fail" }.keys.sorted())
                val why = e["reason"] as String?
                if (why != null) assertTrue(where, (if (r.allow) "" else r.reason ?: "").contains(why))
            }
        }
    }

    @Test
    fun absentOptionChangesNothing() {
        // no workflow option: a call that carries a workflow step is decided exactly as without it
        val grant = m(f["grant"])
        val s = m(m(l(m(l(f["cases"])[0])["steps"])[0]))
        val r = Authorize.authorize(
            s["pcactn"],
            Authorize.Input(
                operation = Authorize.Operation.fromJson(s["operation"]), audience = f["audience"] as String,
                resolveGrant = { ref -> if (ref == grant["id"]) grant else null }, stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false },
                now = Json.asLong(f["now"]), context = { _ -> mapOf("plan" to f["plan"], "plan_authorized" to true) },
                workflowCall = Authorize.WorkflowStep(null, null, "quote"),
                provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(Authorize.Operation.fromJson(s["operation"])),
            ),
        )
        assertTrue(r.reasons.toString(), r.allow)
    }
}
