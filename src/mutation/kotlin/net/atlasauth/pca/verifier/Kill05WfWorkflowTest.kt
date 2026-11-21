package net.atlasauth.pca.verifier

import java.util.TreeMap
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PCA 0.5 mutation kills for [Workflow]: a differential test against the TS reference (packages/pca/src/workflow.ts) through the
 * shared oracle test-data/k05-workflow.json.gz (tools/pca-audit/k05-oracles/workflow-oracle.mts; the java-pca K05WorkflowDiffTest
 * replays the same file). Every body member deleted / retyped / at its limit and RE-SIGNED, every receipt member (re-signed and
 * not), every request member, the clock and the pinned keys at their boundaries, budgets, freshness, edge operators and labels,
 * promise binding, random DAGs, plan-root authorization and the digests. Admission results compare in full (decision, code, step,
 * at, pending), through toMap() AND through the public getters. Plus the fail-closed handlers (a member read that throws).
 */
@Suppress("UNCHECKED_CAST")
class Kill05WfWorkflowTest {
    companion object {
        const val FILE = "k05-workflow.json.gz"
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun isThrow(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
        fun show(o: Any?): String = if (isThrow(o)) "THROWS" else Json.canonicalize(o)

        /** A map whose every read throws (a hostile Map implementation): the entry points must deny, never throw or allow. */
        val BOOM: Map<String, Any?> = object : AbstractMap<String, Any?>() {
            override val entries: Set<Map.Entry<String, Any?>> get() = throw IllegalStateException("boom")
        }

        fun input(a: List<Any?>) = Workflow.AdmitInput(a[0], a[1], a[2], a[3], a[4], a[5])

        /** The result through its public getters (toMap() reads the fields directly). */
        fun viaGetters(r: Workflow.WfResult): Map<String, Any?> =
            linkedMapOf("decision" to r.decision, "code" to r.code, "step" to r.step, "at" to r.at?.toLong(), "pending" to r.pending.map { it.toLong() })
    }

    private fun diff(fn: String, f: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        val cs = of(fn)
        for (c in cs) {
            val want = show(c["out"])
            val got = try { Json.canonicalize(f(args(c))) } catch (t: Throwable) { "THROWS" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        assertTrue("$fn: ${bad.size}/${cs.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    private fun admission(fn: String, f: (Workflow.AdmitInput) -> Workflow.WfResult) {
        val bad = ArrayList<String>()
        val cs = of(fn)
        for (c in cs) {
            val want = show(c["out"])
            val r = try { f(input(args(c))) } catch (t: Throwable) { bad.add("${c["name"]}: THROWS $t"); continue }
            val got = Json.canonicalize(r.toMap())
            val getters = Json.canonicalize(viaGetters(r))
            if (want != got || want != getters) bad.add("${c["name"]}\n  want: $want\n  got:  $got\n  getters: $getters")
        }
        assertTrue("$fn: ${bad.size}/${cs.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    @Test fun admit() = admission("admit") { Workflow.admitStep(it) }

    @Test fun bind() = admission("bind") { Workflow.bindPromises(it) }

    @Test fun validBody() = diff("validBody") { Workflow.validWorkflowBody(it[0]) }

    @Test fun dag() = diff("dag") { Workflow.dagError(it[0] as Map<String, Any?>) }

    @Test fun ancestors() = diff("ancestors") { a ->
        Workflow.ancestors(a[0] as Map<String, Any?>)?.let { m ->
            val out = TreeMap<String, Any?>()
            for ((k, v) in m) out[k] = v.sorted()
            out
        }
    }

    @Test fun planRoot() = diff("planRoot") { Workflow.planRootAuthorized(it[0], it[1], it[2], it[3]) }

    @Test fun valueDigest() = diff("valueDigest") { Workflow.valueDigest(it[0]) }

    @Test fun workflowDigest() = diff("workflowDigest") { Workflow.workflowDigest(it[0]) }

    @Test fun receiptRef() = diff("receiptRef") { Workflow.receiptRef(it[0]) }

    // ---- fail closed: an exception inside the evaluation denies (admitStep / bindPromises) or answers false (planRootAuthorized) ----

    @Test fun admitStepThatThrowsDenies() {
        for (r in listOf(
            Workflow.admitStep(Workflow.AdmitInput(BOOM, null, null, emptyList<Any?>(), 1L, null)),
            Workflow.bindPromises(Workflow.AdmitInput(BOOM, null, null, emptyList<Any?>(), 1L, null)),
        )) {
            assertEquals("deny", r.decision)
            assertEquals("bad_workflow", r.code)
            assertNull(r.step)
            assertNull(r.at)
            assertEquals(emptyList<Int>(), r.pending)
        }
    }

    @Test fun planRootThatThrowsIsNotAuthorized() {
        assertFalse(Workflow.planRootAuthorized(BOOM, "p", 1L, "r"))
    }
}
