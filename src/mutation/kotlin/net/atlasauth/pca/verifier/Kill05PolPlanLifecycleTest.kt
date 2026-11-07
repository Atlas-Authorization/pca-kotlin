package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kill tests for PlanLifecycle (k05 Pol group): every structural refusal, the stored-record shape guard, the key layout, the
 * transition results (incl. a store that never / twice runs the update), approval expiry and the per-action check. Expected
 * strings are the reference's (packages/pca/src/server/plan-lifecycle.ts).
 */
@Suppress("UNCHECKED_CAST")
class Kill05PolPlanLifecycleTest {
    private fun node(id: String, verb: String = "read", resource: String = "/a"): LinkedHashMap<String, Any?> =
        linkedMapOf("id" to id, "verb" to verb, "resource" to resource)

    private fun reg(kv: AtomicKv = MemoryAtomicKv(), validator: ((Map<String, Any?>) -> PlanLifecycle.Validation)? = null) =
        PlanLifecycle.PlanRegistry(kv, "pca-plan:", { 1L }, validator)

    /** draft + validate + commit (+ authorize with `approval` when given); the root. */
    private fun lifecycle(r: PlanLifecycle.PlanRegistry, nodes: List<Map<String, Any?>>, approval: Map<String, Any?>? = linkedMapOf("by" to "p")): String {
        val root = r.draft("g", nodes).record!!["root"] as String
        assertTrue(r.validate("g", root).ok)
        assertTrue(r.commit("g", root).ok)
        if (approval != null) assertTrue(r.authorize("g", root, approval).ok)
        return root
    }

    @Test fun statesAndToString() {
        assertEquals(listOf("draft", "validated", "committed", "authorized", "revoked"), PlanLifecycle.STATES)
        val t = reg().draft(null, listOf(node("a")))
        assertEquals("a plan needs a grant", t.reason)
        assertEquals("PlanLifecycle.Transition({ok=false, state=unknown, reason=a plan needs a grant})", t.toString())
        assertEquals("PlanLifecycle.Status({state=unknown, executable=false, reason=plan r is unknown for this grant})", reg().status("g", "r", 0L).toString())
    }

    @Test fun structuralProblems() {
        assertEquals("a plan needs at least one node", PlanLifecycle.structuralProblem(emptyList<Any?>()))
        assertEquals("a plan needs at least one node", PlanLifecycle.structuralProblem("x"))
        assertNull(PlanLifecycle.structuralProblem(listOf(node("a"))))
        assertEquals("every node needs an id", PlanLifecycle.structuralProblem(listOf("x")))
        assertEquals("every node needs an id", PlanLifecycle.structuralProblem(listOf(null)))
        assertEquals("every node needs an id", PlanLifecycle.structuralProblem(listOf(node("a").also { it["id"] = "" })))
        assertEquals("duplicate node id 'a'", PlanLifecycle.structuralProblem(listOf(node("a"), node("a"))))
        assertEquals("node 'a' needs a verb and a resource", PlanLifecycle.structuralProblem(listOf(node("a").also { it.remove("resource") })))
        assertEquals("node 'a' needs a verb and a resource", PlanLifecycle.structuralProblem(listOf(node("a").also { it.remove("verb") })))
        assertNull(PlanLifecycle.structuralProblem(listOf(node("a").also { it["reversibility_class"] = "costly" })))
        assertEquals("node 'a' has an unknown reversibility class 'bogus'", PlanLifecycle.structuralProblem(listOf(node("a").also { it["reversibility_class"] = "bogus" })))
        assertEquals("node 'a' has an unknown reversibility class '5'", PlanLifecycle.structuralProblem(listOf(node("a").also { it["reversibility_class"] = Json.Num("5") })))
    }

    @Test fun rootBindsPreAndPost() {
        val plain = node("a")
        val pre = node("a").also { it["pre"] = listOf("x") }
        val post = node("a").also { it["post"] = listOf("y") }
        val rPlain = PlanLifecycle.planRoot(listOf(plain))
        assertNotEquals(rPlain, PlanLifecycle.planRoot(listOf(pre)))
        assertNotEquals(rPlain, PlanLifecycle.planRoot(listOf(post)))
        assertEquals(Pca.merkleRoot(listOf(Pca.planLeaf("a", pre, Pca.conditionsDigest(listOf("x"), null)))), PlanLifecycle.planRoot(listOf(pre)))
        assertEquals(Pca.merkleRoot(listOf(Pca.planLeaf("a", post, Pca.conditionsDigest(null, listOf("y"))))), PlanLifecycle.planRoot(listOf(post)))
    }

    @Test fun keyLayoutPrefixAndDefaultClock() {
        val kv = MemoryAtomicKv()
        val r = PlanLifecycle.PlanRegistry(kv, "myp:", { 7L })
        val grant = "a b/ç!'()~*"
        val root = r.draft(grant, listOf(node("a"))).record!!["root"] as String
        assertNotNull(kv.get("myp:a%20b%2F%C3%A7!'()~*:$root"))
        assertEquals(7L, (r.get(grant, root)!!["createdAt"] as Number).toLong())

        val before = System.currentTimeMillis()
        val t = PlanLifecycle.PlanRegistry().draft("g", listOf(node("a")))
        val at = (t.record!!["createdAt"] as Number).toLong()
        assertTrue("$at >= $before", at >= before && at <= System.currentTimeMillis())
    }

    @Test fun draftCopiesNodesAndExplainsAnEmptyPlan() {
        assertEquals("the plan cannot be committed: merkleRoot: empty leaf set", reg().draft("g", emptyList()).reason)
        val nodes = arrayListOf<Map<String, Any?>>(node("a"))
        val t = reg().draft("g", nodes)
        nodes.clear()
        assertEquals(1, (t.record!!["nodes"] as List<*>).size)
    }

    @Test fun storedRecordShapeGuard() {
        val kv = MemoryAtomicKv()
        val r = reg(kv)
        kv.set("pca-plan:g:r1", "junk")
        kv.set("pca-plan:g:r2", linkedMapOf("root" to Json.Num("5"), "nodes" to ArrayList<Any?>(), "state" to "draft"))
        kv.set("pca-plan:g:r3", linkedMapOf("root" to "r3", "nodes" to "x", "state" to "draft"))
        kv.set("pca-plan:g:r4", linkedMapOf("nodes" to ArrayList<Any?>(), "state" to "draft"))
        for (k in listOf("r1", "r2", "r3", "r4")) {
            assertNull(k, r.get("g", k))
            assertEquals(k, "unknown", r.status("g", k, 0L).state)
        }
    }

    @Test fun storeThatSkipsOrRepeatsTheUpdate() {
        // a store whose update never runs the function: the transition stays "unknown"
        val never = object : AtomicKv {
            override fun get(key: String): Any? = null
            override fun set(key: String, value: Any?) {}
            override fun update(key: String, fn: (Any?) -> Any?): Any? = null
        }
        val t = reg(never).commit("g", "r")
        assertFalse(t.ok)
        assertEquals("unknown", t.state)
        assertEquals("plan r is unknown for this grant", t.reason)
        // a store that retries the function (the record vanished between attempts): the LAST attempt decides
        val rec = linkedMapOf<String, Any?>("grantRef" to "g", "root" to "r", "nodes" to listOf(node("a")), "state" to "validated")
        val twice = object : AtomicKv {
            override fun get(key: String): Any? = null
            override fun set(key: String, value: Any?) {}
            override fun update(key: String, fn: (Any?) -> Any?): Any? { fn(MemoryAtomicKv.copyTree(rec)); return fn(null) }
        }
        val t2 = reg(twice).commit("g", "r")
        assertFalse(t2.ok)
        assertEquals("unknown", t2.state)
        assertEquals("plan r is unknown for this grant", t2.reason)
    }

    @Test fun validateHashAndValidatorReasons() {
        val kv = MemoryAtomicKv()
        kv.set("pca-plan:g:bogus", linkedMapOf("grantRef" to "g", "root" to "bogus", "nodes" to listOf(node("a")), "state" to "draft"))
        assertEquals("plan bogus is invalid: the stored nodes no longer hash to the root", reg(kv).validate("g", "bogus").reason)

        fun reasonWith(v: (Map<String, Any?>) -> PlanLifecycle.Validation): String? {
            val r = reg(validator = v)
            val root = r.draft("g", listOf(node("a"))).record!!["root"] as String
            val t = r.validate("g", root)
            assertFalse(t.ok)
            assertEquals("draft", t.state)
            return t.reason!!.removePrefix("plan $root is invalid: ")
        }
        assertEquals("validator error (fail closed): ", reasonWith { throw IllegalStateException() })
        assertEquals("validator error (fail closed): down", reasonWith { throw IllegalStateException("down") })
        assertEquals("", reasonWith { PlanLifecycle.Validation.refuse("") })
        assertEquals("x", reasonWith { PlanLifecycle.Validation.refuse("x") })
    }

    @Test fun authorizeApprovalShapeAndStateNow() {
        val kv = MemoryAtomicKv()
        val r = reg(kv)
        val root = lifecycle(r, listOf(node("a")), approval = null)
        val bad = "an approval names who approved (`by`)"
        assertEquals(bad, r.authorize("g", "nope", null).reason)
        assertEquals("unknown", r.authorize("g", "nope", null).state)
        assertEquals("committed", r.authorize("g", root, linkedMapOf("by" to "")).state)
        kv.set("pca-plan:g:odd", linkedMapOf("root" to "odd", "nodes" to ArrayList<Any?>(), "state" to Json.Num("5")))
        assertEquals("unknown", r.authorize("g", "odd", null).state)

        val exp = "approval.expiresAt must be a time (epoch ms)"
        for (e in listOf<Any?>("x", null, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            val t = r.authorize("g", root, linkedMapOf("by" to "p", "expiresAt" to e))
            assertEquals("$e", exp, t.reason)
            assertEquals("$e", "committed", t.state)
        }
        assertTrue(r.authorize("g", root, linkedMapOf("by" to "p", "expiresAt" to Json.Num("1e3"))).ok)
        val r2 = reg()
        assertTrue(r2.authorize("g", lifecycle(r2, listOf(node("a")), approval = null), linkedMapOf("by" to "p")).ok)
    }

    @Test fun approvalExpiryBoundaryAndText() {
        val r = reg()
        val root = lifecycle(r, listOf(node("a")), linkedMapOf("by" to "p", "expiresAt" to Json.Num("1e3")))
        assertTrue(r.status("g", root, 999L).executable)
        val s = r.status("g", root, 1000L)
        assertFalse(s.executable)
        assertEquals("authorized", s.state)
        assertEquals("plan $root: the principal's approval expired at 1000", s.reason)
        assertTrue(r.isPlanAuthorized("g", root)) // the registry clock (1) is before the expiry
        assertFalse(r.isPlanAuthorized("g", "nope"))
    }

    @Test fun storedAuthorizedRecordsWithOddApprovalsOrNodes() {
        val kv = MemoryAtomicKv()
        val r = reg(kv)
        val nodes = listOf(node("a"))
        val root = PlanLifecycle.planRoot(nodes)
        fun put(key: String, rootV: String, approval: Any?, withApproval: Boolean = true) {
            val m = linkedMapOf<String, Any?>("grantRef" to "g", "root" to rootV, "nodes" to nodes, "state" to "authorized")
            if (withApproval) m["approval"] = approval
            kv.set("pca-plan:$key:$rootV", m)
        }
        put("g", root, null, withApproval = false)
        assertTrue(r.status("g", root, 5L).executable)
        put("h", root, "x")
        assertTrue(r.status("h", root, 5L).executable)
        put("i", root, linkedMapOf("by" to "p", "expiresAt" to "x"))
        assertEquals("plan $root: the principal's approval expired at x", r.status("i", root, 5L).reason)
        put("g", "bogus", linkedMapOf("by" to "p"))
        val s = r.status("g", "bogus", 5L)
        assertFalse(s.executable)
        assertEquals("plan bogus: the stored nodes no longer hash to the root", s.reason)
        kv.set("pca-plan:g:num", linkedMapOf("root" to "num", "nodes" to ArrayList<Any?>(), "state" to Json.Num("5")))
        assertFalse(r.isPlanAuthorized("g", "num"))
    }

    @Test fun revokeFromEveryLiveStateAndTheReasonText() {
        val r = reg()
        val committed = lifecycle(r, listOf(node("c")), approval = null)
        assertTrue(r.revoke("g", committed, "why").ok)
        val authorized = lifecycle(r, listOf(node("a")))
        val t = r.revoke("g", authorized, null)
        assertTrue(t.ok)
        assertEquals("", t.record!!["revokedReason"])
        assertEquals("plan $authorized is revoked ()", r.status("g", authorized, 1L).reason)
        assertEquals("plan $authorized is revoked: cannot revoke", r.revoke("g", authorized, "again").reason)
        // a stored record without a state is never revoked (refused or fail-closed throw)
        val kv = MemoryAtomicKv()
        kv.set("pca-plan:g:s", linkedMapOf("root" to "s", "nodes" to listOf(node("a"))))
        val ok = try { reg(kv).revoke("g", "s", "x").ok } catch (e: RuntimeException) { false }
        assertFalse(ok)
    }

    @Test fun checkPerActionRules() {
        val r = reg()
        val n2 = node("n2", "write", "/b").also { it["params_digest"] = Pca.paramsDigest(linkedMapOf("k" to "v")) }
        val root = lifecycle(r, listOf(node("n1"), n2))
        val read = Authorize.Operation("read", "/a", emptyMap())
        val write = Authorize.Operation("write", "/b", linkedMapOf("k" to "v"))
        assertTrue(r.check("g", root, "n1", read, 1L).executable)
        assertTrue(r.check("g", root, null, write, 1L).executable)
        assertTrue(r.check("g", root, null, null, 1L).executable)
        assertEquals("plan $root has no node 'zz'", r.check("g", root, "zz", null, 1L).reason)
        val miss = r.check("g", root, "n1", write, 1L)
        assertFalse(miss.executable)
        assertEquals("authorized", miss.state)
        assertEquals("plan $root: the operation (write on /b with these params) is not what the principal approved", miss.reason)
        assertEquals(
            "plan $root: the operation (read on /a with these params) is not what the principal approved",
            r.check("g", root, null, Authorize.Operation("read", "/a", linkedMapOf("k" to "v")), 1L).reason,
        )
        val unhashable = r.check("g", root, null, Authorize.Operation("read", "/a", linkedMapOf("k" to "\uD800")), 1L)
        assertFalse(unhashable.executable)
        assertEquals("authorized", unhashable.state)
        assertEquals("plan $root: the operation's params cannot be hashed", unhashable.reason)
        // not executable: the status stands, whatever the node / operation
        val c = lifecycle(r, listOf(node("c1")), approval = null)
        assertEquals("plan $c is committed but not authorized by the principal", r.check("g", c, "zz", null, 1L).reason)
        assertEquals("unknown", r.check("g", "nope", "zz", read, 1L).state)
    }

    @Test fun contextOfKnownRoots() {
        val r = reg()
        val root = lifecycle(r, listOf(node("a")))
        val ctx = r.context("g", root, 1L)!!
        assertTrue(ctx.planAuthorized)
        assertEquals(listOf<Map<String, Any?>>(node("a")), ctx.plan)
        val c = lifecycle(r, listOf(node("b")), approval = null)
        val cc = r.context("g", c, 1L)!!
        assertFalse(cc.planAuthorized)
        assertEquals("committed", cc.status.state)
        assertNull(r.context("g", "nope", 1L))
    }
}
