package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PCA 0.5 mutation kills for [Workflow], round 2 (full run 41911466407, shard 15): the shared validators member by member and at
 * every limit (onlyKeys, isScalarMap, uintMap, the receipt and request shapes, the body limits), memoised ancestors on a ladder DAG,
 * and admissions over workflows and receipts signed here: edge taint, promise binding with a pending edge, deps_unmet before
 * dep_failed in binding, receipt chains (duplicate step, a receipt before an unpromised dependency) and the pinned inputs.
 * Expectations follow packages/pca/src/workflow.ts.
 */
@Suppress("UNCHECKED_CAST")
class Kill05R2WorkflowTest {
    private fun m(vararg kv: Pair<String, Any?>) = KUtil.m(*kv)
    private fun l(vararg v: Any?) = KUtil.l(*v)
    private val b32 = KUtil.B32

    private fun receiptShape(r: Any?): Boolean = KUtil.priv(Workflow, "validReceiptShape", r)
    private fun request(r: Any?): Boolean = KUtil.priv(Workflow, "validRequest", r)
    private fun uintMap(x: Any?, max: Int): Boolean = KUtil.priv(Workflow, "uintMap", x, max)

    private fun names(prefix: String, n: Int): ArrayList<Any?> = ArrayList((0 until n).map { prefix + it.toString().padStart(2, '0') })
    private fun fields(n: Int, v: Any?): LinkedHashMap<String, Any?> { val r = LinkedHashMap<String, Any?>(); for (k in names("f", n)) r[k as String] = v; return r }

    // ---- onlyKeys / isScalarMap / uintMap -----------------------------------------------------------------------------------

    @Test
    fun onlyKeysIsExactlyTheseMembers() {
        assertTrue(Workflow.onlyKeys(m("a" to 1L, "b" to null), listOf("a", "b")))
        assertTrue(Workflow.onlyKeys(m(), emptyList()))
        assertFalse(Workflow.onlyKeys(m("a" to 1L, "c" to 2L), listOf("a", "b"))) // same size, one member renamed
        assertFalse(Workflow.onlyKeys(m("a" to 1L, "b" to 2L, "c" to 3L), listOf("a", "b"))) // every member present plus one more
        assertFalse(Workflow.onlyKeys(m("a" to 1L), listOf("a", "b")))
        assertFalse(Workflow.onlyKeys(m("a" to 1L), emptyList()))
    }

    @Test
    fun isScalarMapAcceptsOnlyNamedScalars() {
        assertFalse(Workflow.isScalarMap(null))
        assertFalse(Workflow.isScalarMap("x"))
        assertFalse(Workflow.isScalarMap(l()))
        assertTrue(Workflow.isScalarMap(m()))
        assertTrue(Workflow.isScalarMap(m("a" to 1L, "b" to "x", "c" to true)))
        assertTrue(Workflow.isScalarMap(fields(32, 1L)))
        assertFalse(Workflow.isScalarMap(fields(33, 1L)))
        assertFalse(Workflow.isScalarMap(m("a b" to 1L)))
        assertFalse(Workflow.isScalarMap(m("a" to 1L, "b" to l(1L))))
        assertFalse(Workflow.isScalarMap(m("a" to null)))
        assertFalse(Workflow.isScalarMap(m("a" to KUtil.n("1.5"))))
    }

    @Test
    fun uintMapIsNamedUnsignedIntegersUpToItsSize() {
        assertFalse(uintMap(null, 8))
        assertFalse(uintMap("x", 8))
        assertTrue(uintMap(m(), 8))
        assertTrue(uintMap(fields(8, 0L), 8))
        assertFalse(uintMap(fields(9, 0L), 8))
        assertTrue(uintMap(m("a" to 7L), 8))
        assertFalse(uintMap(m("a b" to 7L), 8))
        assertFalse(uintMap(m("a" to -1L), 8))
        assertFalse(uintMap(m("a" to "7"), 8))
        assertFalse(uintMap(m("a" to 1L, "b" to -1L), 8))
    }

    // ---- the body at its limits ----------------------------------------------------------------------------------------------

    private val pk = Keys.edFromSeed(ByteArray(32) { 7 })
    private val rs = Keys.edFromSeed(ByteArray(32) { 8 })
    private val t0 = 1_800_000_000_000L
    private val now = t0 + 10_000L

    private fun step(id: String, deps: List<Any?> = emptyList(), deny: List<Any?> = emptyList(), escalate: List<Any?> = emptyList(), cost: Map<String, Any?> = m()) =
        m("id" to id, "verb" to "do", "resource" to "r/$id", "params_digest" to null, "deps" to ArrayList(deps), "sink" to null, "deny_labels" to ArrayList(deny),
            "escalate_labels" to ArrayList(escalate), "fresh_ms" to null, "cost" to LinkedHashMap(cost))

    private fun edge(from: String, to: String, promise: String? = null, deny: List<Any?> = emptyList(), op: Any? = "eq") =
        m("from" to m("step" to from, "field" to "x"), "to" to m("step" to to, "param" to "x"), "op" to op, "unit" to null, "deny_labels" to ArrayList(deny), "promise" to promise)

    private fun body(steps: List<Any?>, edges: List<Any?> = emptyList(), caps: Map<String, Any?> = m()) =
        m("v" to 1L, "id" to "wf-1", "principal" to pk.id(), "goal_digest" to null, "plan_root" to null, "issued_at" to t0, "expires_at" to t0 + 3_600_000L,
            "steps" to ArrayList(steps), "edges" to ArrayList(edges), "budget" to m("max_steps" to 16L, "caps" to LinkedHashMap(caps)))

    @Test
    fun theBodyAtEveryLimit() {
        assertTrue(Workflow.validWorkflowBody(body(names("s", 64).map { step(it as String) })))
        assertFalse(Workflow.validWorkflowBody(body(names("s", 65).map { step(it as String) })))
        val two = listOf(step("a"), step("b", listOf("a")))
        assertTrue(Workflow.validWorkflowBody(body(two, List(256) { edge("a", "b") })))
        assertFalse(Workflow.validWorkflowBody(body(two, List(257) { edge("a", "b") })))
        assertTrue(Workflow.validWorkflowBody(body(listOf(step("z", deps = names("a", 16))))))
        assertFalse(Workflow.validWorkflowBody(body(listOf(step("z", deps = names("a", 17))))))
        assertTrue(Workflow.validWorkflowBody(body(listOf(step("z", deny = names("l", 16))))))
        assertFalse(Workflow.validWorkflowBody(body(listOf(step("z", deny = names("l", 17))))))
        assertTrue(Workflow.validWorkflowBody(body(listOf(step("z", escalate = names("l", 16))))))
        assertFalse(Workflow.validWorkflowBody(body(listOf(step("z", escalate = names("l", 17))))))
        assertTrue(Workflow.validWorkflowBody(body(two, listOf(edge("a", "b", deny = names("l", 16))))))
        assertFalse(Workflow.validWorkflowBody(body(two, listOf(edge("a", "b", deny = names("l", 17))))))
        // budget caps: at most 8 names, and every cost name capped
        assertTrue(Workflow.validWorkflowBody(body(listOf(step("z", cost = fields(8, 1L))), caps = fields(8, 2L))))
        assertFalse(Workflow.validWorkflowBody(body(listOf(step("z")), caps = fields(9, 2L))))
        assertFalse(Workflow.validWorkflowBody(body(listOf(step("z", cost = m("f00" to 1L, "f01" to 1L))), caps = m("f00" to 2L))))
        assertTrue(Workflow.validWorkflowBody(body(listOf(step("y", cost = m("f00" to 1L)), step("z", cost = m("f01" to 1L))), caps = m("f00" to 2L, "f01" to 2L))))
        assertFalse(Workflow.validWorkflowBody(body(listOf(step("y", cost = m("f00" to 1L)), step("z", cost = m("f01" to 1L))), caps = m("f00" to 2L))))
        // an edge operator is one of five strings
        for (op in listOf("eq", "le", "ge", "lt", "gt")) assertTrue(op, Workflow.validWorkflowBody(body(two, listOf(edge("a", "b", op = op)))))
        for (op in listOf<Any?>("xx", "EQ", 5L, null, l("eq"))) assertFalse("$op", Workflow.validWorkflowBody(body(two, listOf(edge("a", "b", op = op)))))
    }

    // ---- ancestors are memoised -------------------------------------------------------------------------------------------

    /** Each step depends on the two before it: without the memo the walk is exponential (Fibonacci in the depth). */
    @Test(timeout = 30_000)
    fun ancestorsOfALadderAreComputedOnce() {
        val ids = names("s", 64)
        val steps = ArrayList<Any?>()
        for (i in ids.indices) steps.add(m("id" to ids[i], "deps" to ArrayList(ids.subList(maxOf(0, i - 2), i))))
        val anc = Workflow.ancestors(m("steps" to steps))!!
        assertEquals(63, anc["s63"]!!.size)
        assertEquals(0, anc["s00"]!!.size)
        assertEquals(setOf("s00"), anc["s01"])
        assertNull(Workflow.dagError(body(ids.indices.map { i -> step(ids[i] as String, ids.subList(maxOf(0, i - 2), i)) })))
    }

    // ---- receipt and request shapes ---------------------------------------------------------------------------------------

    private fun out(vararg kv: Pair<String, Any?>) = m("digest" to b32, "num" to null, "unit" to null, "labels" to l()).also { it.putAll(kv) }

    private fun receipt(vararg kv: Pair<String, Any?>) =
        m("v" to 1L, "wf" to b32, "step" to "s1", "seq" to 0L, "prev" to null, "outcome" to "ok", "params_digest" to b32, "outputs" to m(), "issued_at" to 0L,
            "signer" to b32, "sig" to "x").also { it.putAll(kv) }

    @Test
    fun theReceiptShapeMemberByMember() {
        assertTrue(receiptShape(receipt()))
        assertTrue(receiptShape(receipt("outcome" to "failed")))
        assertTrue(receiptShape(receipt("seq" to 1L, "prev" to b32)))
        assertFalse(receiptShape(receipt("x" to 1L)))
        assertFalse(receiptShape(KUtil.mm(receipt()).also { it.remove("sig") }))
        assertFalse(receiptShape(receipt("v" to 2L)))
        assertFalse(receiptShape(receipt("wf" to "x")))
        assertFalse(receiptShape(receipt("step" to "bad id!")))
        assertFalse(receiptShape(receipt("step" to 5L)))
        assertFalse(receiptShape(receipt("seq" to -1L)))
        assertFalse(receiptShape(receipt("seq" to KUtil.n("1.5"), "prev" to b32)))
        assertFalse(receiptShape(receipt("seq" to 1L, "prev" to "x")))
        assertFalse(receiptShape(receipt("seq" to 1L)))
        assertFalse(receiptShape(receipt("prev" to b32)))
        assertFalse(receiptShape(receipt("outcome" to "x")))
        assertFalse(receiptShape(receipt("params_digest" to "x")))
        assertFalse(receiptShape(receipt("issued_at" to -1L)))
        assertFalse(receiptShape(receipt("signer" to "x")))
        assertFalse(receiptShape(receipt("sig" to 5L)))
        assertFalse(receiptShape(receipt("outputs" to "x")))
        assertTrue(receiptShape(receipt("outputs" to fields(32, out()))))
        assertFalse(receiptShape(receipt("outputs" to fields(33, out()))))
        assertTrue(receiptShape(receipt("outputs" to m("x" to out("num" to 5L, "unit" to "cents", "labels" to names("l", 16))))))
        assertFalse(receiptShape(receipt("outputs" to m("bad key" to out()))))
        assertFalse(receiptShape(receipt("outputs" to m("x" to "x"))))
        assertFalse(receiptShape(receipt("outputs" to m("x" to out("y" to 1L)))))
        assertFalse(receiptShape(receipt("outputs" to m("x" to out("digest" to "x")))))
        assertFalse(receiptShape(receipt("outputs" to m("x" to out("num" to -1L)))))
        assertFalse(receiptShape(receipt("outputs" to m("x" to out("unit" to "x y")))))
        assertFalse(receiptShape(receipt("outputs" to m("x" to out("labels" to l("b", "a"))))))
        assertFalse(receiptShape(receipt("outputs" to m("x" to out("labels" to names("l", 17))))))
    }

    private fun req(step: String = "s1", vararg kv: Pair<String, Any?>) =
        m("step" to step, "verb" to "do", "resource" to "r/$step", "params" to m("x" to 400L), "units" to m(), "goal_digest" to null, "plan_root" to null).also { it.putAll(kv) }

    @Test
    fun theRequestShapeMemberByMember() {
        assertFalse(request(null))
        assertFalse(request("x"))
        assertTrue(request(req()))
        assertTrue(request(req("s1", "units" to m("x" to "cents"), "goal_digest" to b32, "plan_root" to b32)))
        assertFalse(request(req("s1", "y" to 1L)))
        assertFalse(request(req("s1", "units" to "x")))
        assertFalse(request(req("s1", "units" to m("bad key" to "cents"))))
        assertFalse(request(req("s1", "units" to m("x" to "bad unit!"))))
        assertFalse(request(req("s1", "units" to m("x" to 5L))))
        assertFalse(request(req("s1", "goal_digest" to "x")))
        assertFalse(request(req("s1", "plan_root" to "x")))
        assertFalse(request(req("s1", "params" to "x")))
        assertFalse(request(req("bad id!")))
        assertFalse(request(req("s1", "verb" to "")))
        assertFalse(request(req("s1", "resource" to "r".repeat(513))))
    }

    // ---- admissions over signed workflows and receipts -----------------------------------------------------------------------

    private val pd = Pca.hashCanonical(m("x" to 400L))

    private fun signed(steps: List<Any?>, edges: List<Any?> = emptyList()) = Issue.signWorkflow(pk, body(steps, edges))

    private fun bodyOf(sw: Map<String, Any?>) = sw["body"] as Map<String, Any?>

    private fun rcpt(sw: Map<String, Any?>, step: String, prev: Map<String, Any?>?, outcome: String = "ok", labels: List<String> = emptyList()) =
        Issue.signStepReceipt(rs, bodyOf(sw), step, outcome, pd, m("x" to Issue.wfOutput(400L, labels)), t0 + 1_000L, prev)

    private fun input(sw: Any?, receipts: Any?, step: String, principal: Any? = pk.id(), rsSigner: Any? = rs.id(), at: Any? = now, request: Any? = req(step)) =
        Workflow.AdmitInput(sw, principal, rsSigner, receipts, at, request)

    private fun exp(decision: String, code: String?, step: String?, at: Long? = null, pending: List<Long> = emptyList()): Map<String, Any?> =
        linkedMapOf<String, Any?>("decision" to decision, "code" to code, "step" to step, "at" to at, "pending" to pending)

    @Test
    fun anEdgeDenyLabelStopsTheFlow() {
        val sw = signed(listOf(step("s1"), step("s2", listOf("s1"))), listOf(edge("s1", "s2"), edge("s1", "s2", deny = listOf("pii"))))
        val tainted = rcpt(sw, "s1", null, labels = listOf("pii"))
        assertEquals(exp("deny", "taint_flow", "s2", 1L), Workflow.admitStep(input(sw, l(tainted), "s2")).toMap())
        val clean = rcpt(sw, "s1", null, labels = listOf("ok"))
        assertEquals(exp("allow", null, "s2"), Workflow.admitStep(input(sw, l(clean), "s2")).toMap())
    }

    /** s2 ran first on a promise from s1; s3 reads s1 too, so its edge from s1 stays pending until s1's receipt exists. */
    @Test
    fun aPendingEdgeAllowsAdmissionButNeverBinding() {
        val sw = signed(listOf(step("s1"), step("s2", listOf("s1")), step("s3", listOf("s2"))), listOf(edge("s1", "s2", promise = "p1"), edge("s1", "s3")))
        // s2 before s1: every edge from s1 is a promise, so it is admitted (not escalated) with that edge pending
        assertEquals(exp("allow", null, "s2", null, listOf(0L)), Workflow.admitStep(input(sw, l(), "s2")).toMap())
        val r0 = rcpt(sw, "s2", null)
        assertEquals(exp("allow", null, "s3", null, listOf(1L)), Workflow.admitStep(input(sw, l(r0), "s3")).toMap())
        val r1 = rcpt(sw, "s3", r0)
        assertEquals(exp("deny", "deps_unmet", "s3"), Workflow.bindPromises(input(sw, l(r0, r1), "s3")).toMap())
    }

    /** Binding refuses a missing dependency before it looks at the next one (here a failed one). */
    @Test
    fun bindingRefusesAMissingDependencyFirst() {
        val sw = signed(listOf(step("a"), step("b"), step("s", listOf("a", "b"))), listOf(edge("a", "s", promise = "p1")))
        val r0 = rcpt(sw, "b", null, outcome = "failed")
        val r1 = rcpt(sw, "s", r0)
        assertEquals(exp("deny", "deps_unmet", "s"), Workflow.bindPromises(input(sw, l(r0, r1), "s")).toMap())
    }

    @Test
    fun theReceiptChainRefusesDuplicatesAndUnpromisedOrder() {
        val dup = signed(listOf(step("s1"), step("s2", listOf("s1"))))
        val d0 = rcpt(dup, "s1", null)
        assertEquals(exp("deny", "bad_receipt", "s2", 1L), Workflow.admitStep(input(dup, l(d0, rcpt(dup, "s1", d0)), "s2")).toMap())
        // s3's receipt comes before its dependency s2: refused with no edge from s2, and with an edge that is not a promise
        for (edges in listOf(emptyList<Any?>(), listOf<Any?>(edge("s2", "s3")))) {
            val sw = signed(listOf(step("s1"), step("s2"), step("s3", listOf("s2"))), edges)
            val r0 = rcpt(sw, "s1", null)
            assertEquals(exp("deny", "bad_receipt", "s2", 1L), Workflow.admitStep(input(sw, l(r0, rcpt(sw, "s3", r0)), "s2")).toMap())
        }
        // with a promise it stands
        val ok = signed(listOf(step("s1"), step("s2"), step("s3", listOf("s2"))), listOf(edge("s2", "s3", promise = "p1")))
        val o0 = rcpt(ok, "s1", null)
        assertEquals(exp("allow", null, "s2"), Workflow.admitStep(input(ok, l(o0, rcpt(ok, "s3", o0)), "s2")).toMap())
    }

    @Test
    fun thePinnedInputsAndTheWrapper() {
        val sw = signed(listOf(step("s1")))
        assertEquals(exp("allow", null, "s1"), Workflow.admitStep(input(sw, l(), "s1")).toMap())
        val bad = exp("deny", "bad_workflow", null)
        assertEquals(bad, Workflow.admitStep(input(sw, l(), "s1", principal = "x")).toMap())
        assertEquals(bad, Workflow.admitStep(input(sw, l(), "s1", rsSigner = "x")).toMap())
        assertEquals(bad, Workflow.admitStep(input(sw, l(), "s1", at = -1L)).toMap())
        assertEquals(bad, Workflow.admitStep(input(LinkedHashMap(sw).also { it["x"] = 1L }, l(), "s1")).toMap())
        assertEquals(bad, Workflow.admitStep(input(sw, l(), "s1", request = req("s1", "y" to 1L))).toMap())
        // receipts that are not a list are refused before the clock is read (an expired workflow would say "expired")
        assertEquals(bad, Workflow.admitStep(input(sw, "x", "s1", at = t0 + 3_600_000L)).toMap())
        assertEquals(exp("deny", "expired", "s1"), Workflow.admitStep(input(sw, l(), "s1", at = t0 + 3_600_000L)).toMap())
    }
}
