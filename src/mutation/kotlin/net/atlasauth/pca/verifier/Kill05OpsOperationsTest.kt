package net.atlasauth.pca.verifier

import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Operation records (T3) outcome by outcome, against the reference (`packages/pca/src/server/operations.ts`): the stores, every
 * refusal reason, the exact outcome and record of each path, the races a store can lose, recovery and reconciliation with their
 * default clock, and the executor's re-check, catalog class, timeout and replay answer. Self-contained (no shared corpus).
 */
@Suppress("UNCHECKED_CAST")
class Kill05OpsOperationsTest {
    private val T0 = 1_800_000_000_000L
    private val TO = 1000.0
    private val PD = Pca.paramsDigest(null)
    private val NEVER: (Operations.ExecutionHandle) -> Any? = { throw AssertionError("the function must not run") }

    /** A store that can lose (or fail) chosen transitions and forget a record on chosen reads. */
    private class Scripted : Operations.Store {
        val m = Operations.MemoryStore()
        var onTransition: (String) -> Boolean? = { null }
        var nullGet: (Int) -> Boolean = { false }
        var gets = 0

        override fun create(record: Map<String, Any?>): Map<String, Any?>? = m.create(record)

        override fun get(id: String): Map<String, Any?>? {
            val i = gets++
            return if (nullGet(i)) null else m.get(id)
        }

        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean =
            onTransition("$from>${next["state"]}") ?: m.transition(id, from, next)

        override fun listOpen(): List<Map<String, Any?>>? = m.listOpen()
    }

    private fun pc(cls: String?, exp: Any? = null): Map<String, Any?> {
        val action = LinkedHashMap<String, Any?>()
        if (cls != null) action["reversibility_class"] = cls
        val p = LinkedHashMap<String, Any?>()
        if (exp != null) p["exp"] = exp
        p["action"] = action
        return p
    }

    private fun aop(id: String) = Authorize.AuthorizedOperation("v", "/r", PD, id)

    private fun az(id: String, p: Map<String, Any?>?, allow: Boolean = true, op: Authorize.AuthorizedOperation? = aop(id)) =
        Authorize.Result(allow, 200, emptyMap(), emptyList(), null, operation = op, pcactn = p)

    private fun exec(
        a: Authorize.Result?, s: Operations.Store?, now: Long = T0, recheck: ((Operations.ExecutionHandle) -> Operations.Recheck)? = null,
        recheckFor: String = "irreversible", cls: String? = null, operation: Authorize.Operation? = null, fn: (Operations.ExecutionHandle) -> Any?,
    ): Operations.ExecuteOutcome = Operations.executeAuthorized(a, s, operation, recheck, recheckFor, cls, TO, { now }, fn)

    private fun rec(id: String, state: String, vararg extra: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("id" to id, "state" to state, "verb" to "v", "resource" to "/r", "params_digest" to PD, "reversibility" to "reversible", "startedAt" to T0)
        for ((k, v) in extra) m[k] = v
        return m
    }

    private fun seed(s: Operations.Store, r: Map<String, Any?>) = assertNull(s.create(r))

    private fun assertOutcome(want: Map<String, Any?>, o: Operations.ExecuteOutcome) {
        assertEquals(want, o.toMap())
        assertEquals("Operations.ExecuteOutcome($want)", o.toString())
    }

    private fun assertRefused(reason: String, o: Operations.ExecuteOutcome) {
        assertOutcome(linkedMapOf("status" to "refused", "reason" to reason), o)
        assertNull(o.operationId)
        assertFalse(o.replayed)
        assertTrue(o.recorded)
        assertNull(o.error)
        assertNull(o.result)
        assertNull(o.authorization)
    }

    private fun canon(v: Any?) = Json.canonicalize(v)

    // ---- the stores ----------------------------------------------------------------------------------------------------

    @Test
    fun theStoresKeepTheContract() {
        assertEquals(listOf("pending", "executing", "committed", "failed", "aborted", "uncertain"), Operations.STATES)
        val m = Operations.MemoryStore()
        assertEquals("process", m.scope)
        for ((id, st) in listOf("p" to "pending", "x" to "executing", "c" to "committed", "f" to "failed", "a" to "aborted")) seed(m, rec(id, st))
        assertEquals(listOf("p", "x"), m.listOpen().map { it["id"] as String }.sorted())
        assertEquals("pending", m.create(rec("p", "committed"))!!["state"])
        // `next` without an id: the store keeps the record's id
        assertTrue(m.transition("p", "pending", linkedMapOf("state" to "executing")))
        assertEquals(linkedMapOf<String, Any?>("state" to "executing", "id" to "p"), m.get("p"))
        assertFalse(m.transition("p", "pending", linkedMapOf("state" to "aborted")))
        assertFalse(m.transition("none", "pending", linkedMapOf("state" to "aborted")))
        assertNull(m.get("none"))

        // the interface defaults: shared, and no listing
        val bare = object : Operations.Store {
            override fun create(record: Map<String, Any?>): Map<String, Any?>? = null
            override fun get(id: String): Map<String, Any?>? = null
            override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean = false
        }
        assertEquals("shared", bare.scope)
        assertNull(bare.listOpen())
    }

    @Test
    fun theKvStoreNamespacesItsKeysAndReadsOnlyRecords() {
        val kv = MemoryAtomicKv()
        val s = Operations.KvStore(kv)
        assertEquals("shared", s.scope)
        assertEquals("process", Operations.KvStore(kv, "x:", "process").scope)
        assertNull(s.listOpen())
        assertNull(s.create(rec("a", "pending")))
        assertEquals("pending", (kv.get("pca-op:a") as Map<*, *>)["state"])
        assertNull(Operations.KvStore(kv, "x:").create(rec("a", "committed")))
        assertEquals("committed", (kv.get("x:a") as Map<*, *>)["state"])
        assertEquals("pending", s.create(rec("a", "failed"))!!["state"])
        assertTrue(s.transition("a", "pending", linkedMapOf("state" to "executing")))
        assertEquals(linkedMapOf<String, Any?>("state" to "executing", "id" to "a"), s.get("a"))
        assertFalse(s.transition("a", "pending", linkedMapOf("state" to "aborted")))
        assertFalse(s.transition("none", "pending", linkedMapOf("state" to "aborted")))
        assertNull(s.get("none"))
        // a stored value that is not a record (no string id, no string state) reads as absent and is replaced by a create
        val junk = listOf<Pair<String, Any?>>(
            "n1" to "text", "n2" to linkedMapOf("state" to "pending"), "n3" to linkedMapOf("id" to 1L, "state" to "pending"),
            "n4" to linkedMapOf("id" to "n4"), "n5" to linkedMapOf("id" to "n5", "state" to 2L),
        )
        for ((k, v) in junk) {
            kv.set("pca-op:$k", v)
            assertNull(k, s.get(k))
            assertFalse(k, s.transition(k, "pending", linkedMapOf("state" to "aborted")))
            assertNull(k, s.create(rec(k, "pending")))
            assertEquals(k, "pending", s.get(k)!!["state"])
        }
    }

    @Test
    fun everyOutcomeHasTheReferenceShape() {
        val auth = Authorize.Result(false, 403, emptyMap(), emptyList(), "nope")
        val cases: List<Pair<Operations.ExecuteOutcome, Map<String, Any?>>> = listOf(
            Operations.ExecuteOutcome("committed", "i", result = "R", replayed = true, recorded = false) to
                linkedMapOf<String, Any?>("status" to "committed", "operationId" to "i", "result" to "R", "replayed" to true, "recorded" to false),
            Operations.ExecuteOutcome("failed", "i", error = "e", replayed = true) to
                linkedMapOf<String, Any?>("status" to "failed", "operationId" to "i", "error" to "e", "replayed" to true),
            Operations.ExecuteOutcome("aborted", "i", reason = "why") to linkedMapOf<String, Any?>("status" to "aborted", "operationId" to "i", "reason" to "why", "replayed" to false),
            Operations.ExecuteOutcome("uncertain", "i", reason = "u", replayed = true) to
                linkedMapOf<String, Any?>("status" to "uncertain", "operationId" to "i", "reason" to "u", "replayed" to true),
            Operations.ExecuteOutcome("pending", "i") to linkedMapOf<String, Any?>("status" to "pending", "operationId" to "i", "replayed" to true),
            Operations.ExecuteOutcome("refused", reason = "r") to linkedMapOf<String, Any?>("status" to "refused", "reason" to "r"),
            Operations.ExecuteOutcome("denied", reason = "nope", authorization = auth) to linkedMapOf<String, Any?>("status" to "denied", "reason" to "nope"),
        )
        for ((o, want) in cases) assertOutcome(want, o)
        assertFalse(cases[0].first.recorded)
        assertTrue(cases[1].first.recorded)
        assertEquals("e", cases[1].first.error)
        assertEquals("i", cases[1].first.operationId)
        assertSame(auth, cases[6].first.authorization)
    }

    // ---- refusals ------------------------------------------------------------------------------------------------------

    @Test
    fun refusalsNameTheMissingPartAndRecordNothing() {
        val st = Operations.MemoryStore()
        val p = pc("reversible")
        assertRefused("executeAuthorized: missing required component: store (fail closed)", exec(az("op", p), null, fn = NEVER))
        val notAllowed = "executeAuthorized: the authorization did not allow an operation"
        val bad = listOf<Authorize.Result?>(
            null, az("op", p, allow = false), az("op", null), az("op", p, op = null), az("op", p, op = Authorize.AuthorizedOperation("v", "/r", PD, "")),
        )
        for (b in bad) assertRefused(notAllowed, exec(b, st, fn = NEVER))
        // the same parts, complete, run (a one-character id is an id)
        assertEquals("committed", exec(az("o", p), st) { "r" }.status)

        val st2 = Operations.MemoryStore()
        assertRefused(
            "executeAuthorized: the authorization is not for this operation (verb, resource or params differ)",
            exec(az("op", p), st2, operation = Authorize.Operation("v", "/other", emptyMap()), fn = NEVER),
        )
        val needs = "executeAuthorized: a irreversible operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)"
        assertRefused(needs, exec(az("op", linkedMapOf("action" to "not an object")), st2, fn = NEVER))
        assertRefused(needs, exec(az("op", linkedMapOf<String, Any?>()), st2, fn = NEVER))
        assertRefused(needs, exec(az("op", p), st2, cls = "irreversible", fn = NEVER))
        assertRefused(
            "executeAuthorized: a rate_limited operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)",
            exec(az("op", pc("costly")), st2, recheckFor = "always", fn = NEVER),
        )
        assertNull("a refusal records nothing", st2.get("op"))
        // the operation it IS for runs; a costly one needs no recheck by default
        assertEquals("committed", exec(az("op", p), st2, operation = Authorize.Operation("v", "/r", emptyMap())) { "r" }.status)
        assertEquals("committed", exec(az("c", pc("costly")), st2) { "r" }.status)
    }

    // ---- the fresh paths -----------------------------------------------------------------------------------------------

    @Test
    fun aCommitSeesTheHandleAndRecordsTheResult() {
        val st = Operations.MemoryStore()
        val p = pc("reversible")
        val a = az("op", p)
        val o = exec(a, st) { h ->
            assertEquals("op", h.idempotencyKey)
            assertSame(a.operation, h.operation)
            assertSame(p, h.pcactn)
            val running = st.get("op")!!
            assertEquals("executing", running["state"])
            assertEquals(T0, running["executingAt"])
            "done"
        }
        assertOutcome(linkedMapOf("status" to "committed", "operationId" to "op", "result" to "done", "replayed" to false, "recorded" to true), o)
        assertTrue(o.recorded)
        assertEquals("done", o.result)
        assertNull(o.error)
        assertNull(o.reason)
        assertEquals(
            "{\"executingAt\":1800000000000,\"finishedAt\":1800000000000,\"id\":\"op\",\"params_digest\":\"$PD\",\"resource\":\"/r\",\"result\":\"done\"," +
                "\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"committed\",\"verb\":\"v\"}",
            canon(st.get("op")),
        )
        val nul = exec(az("n", p), st) { null }
        assertOutcome(linkedMapOf("status" to "committed", "operationId" to "n", "result" to null, "replayed" to false, "recorded" to true), nul)
        assertTrue(st.get("n")!!.containsKey("result"))
    }

    @Test
    fun aThrowIsRecordedAsFailed() {
        val st = Operations.MemoryStore()
        val boom = exec(az("b", pc("reversible")), st) { throw IllegalStateException("boom") }
        assertOutcome(linkedMapOf("status" to "failed", "operationId" to "b", "error" to "boom", "replayed" to false), boom)
        assertEquals("boom", boom.error)
        assertNull(boom.reason)
        assertEquals("failed", st.get("b")!!["state"])
        assertEquals("boom", st.get("b")!!["error"])
        val anon = exec(az("a", pc("reversible")), st) { throw IllegalStateException() }
        assertEquals("IllegalStateException", anon.error)
        assertEquals("IllegalStateException", st.get("a")!!["error"])
        // a store that cannot record the failure: the failure is still returned
        val sc = Scripted()
        sc.onTransition = { k -> if (k == "executing>failed") throw IllegalStateException("store down") else null }
        val f = exec(az("x", pc("reversible")), sc) { throw IllegalArgumentException("bad") }
        assertOutcome(linkedMapOf("status" to "failed", "operationId" to "x", "error" to "bad", "replayed" to false), f)
        assertEquals("executing", sc.m.get("x")!!["state"])
    }

    @Test
    fun aCommitThatCannotBeRecordedSaysSo() {
        // a recovery made it uncertain while fn ran: the commit is still recorded
        val st = Operations.MemoryStore()
        val out = exec(az("op", pc("reversible")), st) {
            assertEquals("uncertain", Operations.recoverOperation(st, "op", 0.0, { T0 + 1 })!!["state"])
            "done"
        }
        assertOutcome(linkedMapOf("status" to "committed", "operationId" to "op", "result" to "done", "replayed" to false, "recorded" to true), out)
        assertEquals("committed", st.get("op")!!["state"])
        assertEquals("done", st.get("op")!!["result"])

        // the uncertain record was reconciled as failed meanwhile: the commit is not recorded, the reconciliation stands
        val st2 = Operations.MemoryStore()
        val lost = exec(az("op", pc("reversible")), st2) {
            Operations.recoverOperation(st2, "op", 0.0, { T0 + 1 })
            assertTrue(Operations.resolveOperation(st2, "op", false, "gone", { T0 + 2 }))
            "done"
        }
        assertOutcome(linkedMapOf("status" to "committed", "operationId" to "op", "result" to "done", "replayed" to false, "recorded" to false), lost)
        assertFalse(lost.recorded)
        assertEquals("failed", st2.get("op")!!["state"])

        // a store error while recording the commit
        val sc = Scripted()
        sc.onTransition = { k -> if (k == "executing>committed") throw IllegalStateException("store down") else null }
        val err = exec(az("op", pc("reversible")), sc) { "done" }
        assertOutcome(linkedMapOf("status" to "committed", "operationId" to "op", "result" to "done", "replayed" to false, "recorded" to false), err)
        assertFalse(err.recorded)
    }

    @Test
    fun recheckRefusalsAbortWithTheirReason() {
        fun case(exp: Any?, r: (Operations.ExecutionHandle) -> Operations.Recheck, want: String) = Triple(exp, r, want)
        val cases = listOf(
            case(null, { _ -> Operations.Recheck.refuse("") }, "recheck: refused"),
            case(null, { _ -> Operations.Recheck.refuse("why") }, "recheck: why"),
            case(null, { _ -> Operations.Recheck.refuse("w") }, "recheck: w"),
            case(null, { _ -> throw IllegalStateException("down") }, "recheck: recheck error (fail closed): down"),
            case(null, { _ -> throw IllegalStateException() }, "recheck: recheck error (fail closed): IllegalStateException"),
            case(T0 - 1, { _ -> throw AssertionError("an expired PCActn is not re-checked") }, "recheck: the PCActn expired at 1799999999999"),
        )
        for ((i, cs) in cases.withIndex()) {
            val st = Operations.MemoryStore()
            val id = "r$i"
            val o = exec(az(id, pc("irreversible", cs.first)), st, recheck = cs.second, fn = NEVER)
            assertOutcome(linkedMapOf("status" to "aborted", "operationId" to id, "reason" to cs.third, "replayed" to false), o)
            assertFalse(o.replayed)
            val r = st.get(id)!!
            assertEquals("aborted", r["state"])
            assertEquals(cs.third, r["error"])
            assertEquals(T0, r["finishedAt"])
            assertFalse(r.containsKey("executingAt"))
        }
        // not expired: exactly at exp, a NaN exp, a boolean exp, no exp, a future exp
        for (exp in listOf<Any?>(T0, Double.NaN, true, null, T0 + 1)) {
            val checks = AtomicInteger()
            val o = exec(az("e", pc("irreversible", exp)), Operations.MemoryStore(), recheck = { _ -> checks.incrementAndGet(); Operations.Recheck.OK }) { "ran" }
            assertEquals(exp.toString(), "committed", o.status)
            assertEquals(1, checks.get())
        }
        // "always" re-checks a reversible operation too
        assertEquals("aborted", exec(az("al", pc("reversible")), Operations.MemoryStore(), recheck = { _ -> Operations.Recheck.refuse("no") }, recheckFor = "always", fn = NEVER).status)
        // no clock given: the wall clock (a far past and a far future expiry)
        val w1 = Operations.executeAuthorized(az("w1", pc("irreversible", 1L)), Operations.MemoryStore(), recheck = { _ -> Operations.Recheck.OK }, fn = NEVER)
        assertEquals("recheck: the PCActn expired at 1", w1.reason)
        val w2 = Operations.executeAuthorized(az("w2", pc("irreversible", 4_000_000_000_000L)), Operations.MemoryStore(), recheck = { _ -> Operations.Recheck.OK }) { "x" }
        assertEquals("committed", w2.status)
    }

    // ---- answers from the record ---------------------------------------------------------------------------------------

    @Test
    fun everyRecordStateHasItsAnswer() {
        val cases = listOf<Pair<Map<String, Any?>, Map<String, Any?>>>(
            rec("c", "committed") to linkedMapOf("status" to "committed", "operationId" to "c", "result" to null, "replayed" to true, "recorded" to true),
            rec("c2", "committed", "result" to "R") to linkedMapOf("status" to "committed", "operationId" to "c2", "result" to "R", "replayed" to true, "recorded" to true),
            rec("f", "failed") to linkedMapOf("status" to "failed", "operationId" to "f", "error" to "failed", "replayed" to true),
            rec("f1", "failed", "error" to "") to linkedMapOf("status" to "failed", "operationId" to "f1", "error" to "failed", "replayed" to true),
            rec("f2", "failed", "error" to "e") to linkedMapOf("status" to "failed", "operationId" to "f2", "error" to "e", "replayed" to true),
            rec("a", "aborted") to linkedMapOf("status" to "aborted", "operationId" to "a", "reason" to "aborted", "replayed" to true),
            rec("a1", "aborted", "error" to "") to linkedMapOf("status" to "aborted", "operationId" to "a1", "reason" to "aborted", "replayed" to true),
            rec("a2", "aborted", "error" to "x") to linkedMapOf("status" to "aborted", "operationId" to "a2", "reason" to "x", "replayed" to true),
            rec("u", "uncertain") to linkedMapOf("status" to "uncertain", "operationId" to "u", "reason" to "outcome unknown", "replayed" to true),
            rec("u1", "uncertain", "error" to "") to linkedMapOf("status" to "uncertain", "operationId" to "u1", "reason" to "outcome unknown", "replayed" to true),
            rec("u2", "uncertain", "error" to "y") to linkedMapOf("status" to "uncertain", "operationId" to "u2", "reason" to "y", "replayed" to true),
            rec("p", "pending") to linkedMapOf("status" to "pending", "operationId" to "p", "replayed" to true),
            rec("x", "executing", "executingAt" to T0) to linkedMapOf("status" to "pending", "operationId" to "x", "replayed" to true),
            rec("w", "weird") to linkedMapOf("status" to "uncertain", "operationId" to "w", "reason" to "unknown record state 'weird'", "replayed" to true),
            rec("w7", "weird", "state" to 7L) to linkedMapOf("status" to "uncertain", "operationId" to "w7", "reason" to "unknown record state '7'", "replayed" to true),
        )
        for ((r, want) in cases) {
            val st = Operations.MemoryStore()
            seed(st, r)
            val o = exec(az(r["id"] as String, pc("reversible")), st, fn = NEVER)
            assertOutcome(want, o)
            assertTrue(o.replayed)
            assertEquals("answering never changes a settled or fresh record", r, st.get(r["id"] as String))
        }
    }

    @Test
    fun openRecordsAreSettledByTheirOwnClock() {
        // executing: aged from executingAt; exactly the timeout is not stale
        val st = Operations.MemoryStore()
        seed(st, rec("x", "executing", "executingAt" to T0 + 500))
        assertEquals("pending", exec(az("x", pc("reversible")), st, now = T0 + 1500, fn = NEVER).status)
        val late = exec(az("x", pc("reversible")), st, now = T0 + 1501, fn = NEVER)
        val unc = "no outcome recorded within 1000 ms of the start: the side effect may or may not have happened"
        assertOutcome(linkedMapOf("status" to "uncertain", "operationId" to "x", "reason" to unc, "replayed" to true), late)
        assertEquals(unc, st.get("x")!!["error"])
        assertEquals(T0 + 1501, st.get("x")!!["finishedAt"])
        // executing without executingAt: aged from startedAt
        seed(st, rec("y", "executing"))
        assertEquals("uncertain", exec(az("y", pc("reversible")), st, now = T0 + 1001, fn = NEVER).status)
        // pending: aged from startedAt even when an executingAt is present
        seed(st, rec("p", "pending", "executingAt" to T0 + 900))
        assertEquals("pending", exec(az("p", pc("reversible")), st, now = T0 + 1000, fn = NEVER).status)
        val ab = exec(az("p", pc("reversible")), st, now = T0 + 1001, fn = NEVER)
        assertOutcome(linkedMapOf("status" to "aborted", "operationId" to "p", "reason" to "not started within 1000 ms of the claim: the side effect never ran", "replayed" to true), ab)
        // no usable start time: never settled
        seed(st, rec("q", "pending", "startedAt" to "soon"))
        assertEquals("pending", exec(az("q", pc("reversible")), st, now = T0 + 10_000_000, fn = NEVER).status)
    }

    @Test
    fun aSettleThatLosesAnswersWhatIsStored() {
        val s = Scripted()
        seed(s, rec("x", "executing", "executingAt" to T0))
        s.onTransition = { k -> if (k == "executing>uncertain") false else null }
        assertEquals("executing", Operations.recoverOperation(s, "x", TO, { T0 + 1001 })!!["state"])
        // ... and when the record is gone afterwards, the settled one is returned
        s.gets = 0
        s.nullGet = { i -> i == 1 }
        val gone = Operations.recoverOperation(s, "x", TO, { T0 + 1001 })!!
        assertEquals("uncertain", gone["state"])
        assertEquals("no outcome recorded within 1000 ms of the start: the side effect may or may not have happened", gone["error"])
        assertNull(Operations.recoverOperation(Operations.MemoryStore(), "none", TO, { T0 }))
    }

    @Test
    fun anAbortThatLosesNeverOverwritesAnotherState() {
        // the re-check itself sees the claim settled as uncertain: the abort is not forced over it
        val st = Operations.MemoryStore()
        val out = exec(az("op", pc("irreversible")), st, recheck = { _ ->
            assertTrue(st.transition("op", "pending", rec("op", "uncertain", "error" to "moved")))
            Operations.Recheck.refuse("no")
        }, fn = NEVER)
        assertOutcome(linkedMapOf("status" to "uncertain", "operationId" to "op", "reason" to "moved", "replayed" to true), out)
        assertEquals("uncertain", st.get("op")!!["state"])

        // the abort loses and the record is gone
        val gone = Scripted()
        gone.onTransition = { k -> if (k == "pending>aborted") false else null }
        gone.nullGet = { i -> i == 0 }
        val g = exec(az("op", pc("irreversible")), gone, recheck = { _ -> Operations.Recheck.refuse("no") }, fn = NEVER)
        assertOutcome(linkedMapOf("status" to "uncertain", "operationId" to "op", "reason" to "the operation record disappeared", "replayed" to true), g)
        assertTrue(g.replayed)

        // the abort loses once, then the answer is read at the current time (the claim is long stale by then)
        val late = Scripted()
        var n = 0
        late.onTransition = { k -> if (k == "pending>aborted" && n++ == 0) false else null }
        val clock = AtomicInteger()
        val ticking: () -> Long = { if (clock.getAndIncrement() == 0) T0 else T0 + 5000 }
        val l = Operations.executeAuthorized(az("op", pc("irreversible")), late, null, { _ -> Operations.Recheck.refuse("no") }, "irreversible", null, TO, ticking, NEVER)
        assertOutcome(linkedMapOf("status" to "aborted", "operationId" to "op", "reason" to "not started within 1000 ms of the claim: the side effect never ran", "replayed" to true), l)
    }

    @Test
    fun aClaimMovedBeforeTheStartIsAnsweredAtTheCurrentTime() {
        val s = Scripted()
        var n = 0
        s.onTransition = { k -> if (k == "pending>executing" && n++ == 0) false else null }
        val clock = AtomicInteger()
        val ticking: () -> Long = { if (clock.getAndIncrement() == 0) T0 else T0 + 5000 }
        val out = Operations.executeAuthorized(az("op", pc("reversible")), s, null, null, "irreversible", null, TO, ticking, NEVER)
        assertOutcome(linkedMapOf("status" to "aborted", "operationId" to "op", "reason" to "not started within 1000 ms of the claim: the side effect never ran", "replayed" to true), out)

        val g = Scripted()
        g.onTransition = { k -> if (k == "pending>executing") false else null }
        g.nullGet = { i -> i == 0 }
        assertOutcome(
            linkedMapOf("status" to "uncertain", "operationId" to "op", "reason" to "the operation record disappeared", "replayed" to true),
            exec(az("op", pc("reversible")), g, fn = NEVER),
        )
    }

    // ---- recovery and reconciliation -----------------------------------------------------------------------------------

    @Test
    fun recovery() {
        try {
            Operations.recoverOperations(Operations.KvStore(MemoryAtomicKv()), TO, { T0 })
            fail("a store without listOpen must be refused")
        } catch (e: UnsupportedOperationException) {
            assertEquals("recoverOperations: the store has no listOpen (recover by id with recoverOperation)", e.message)
        }
        val st = Operations.MemoryStore()
        seed(st, rec("a", "pending"))
        seed(st, rec("b", "pending", "startedAt" to T0 + 900))
        seed(st, rec("c", "executing", "executingAt" to T0))
        seed(st, rec("d", "committed"))
        val got = Operations.recoverOperations(st, TO, { T0 + 1001 }).sortedBy { it["id"] as String }
        assertEquals(listOf("a" to "aborted", "c" to "uncertain"), got.map { it["id"] to it["state"] })
        assertEquals("pending", st.get("b")!!["state"])

        // a record that disappears between the listing and its recovery is skipped
        val s = Scripted()
        seed(s, rec("z", "pending"))
        s.nullGet = { i -> i == 0 }
        assertEquals(emptyList<Map<String, Any?>>(), Operations.recoverOperations(s, TO, { T0 + 5000 }))

        // the defaults: 5 minutes, the wall clock
        val now = System.currentTimeMillis()
        val w = Operations.MemoryStore()
        seed(w, linkedMapOf("id" to "fresh", "state" to "pending", "startedAt" to now - 60_000))
        assertEquals(emptyList<Map<String, Any?>>(), Operations.recoverOperations(w))
        assertEquals("pending", Operations.recoverOperation(w, "fresh")!!["state"])
        seed(w, linkedMapOf("id" to "old", "state" to "pending", "startedAt" to now - 600_000))
        val old = Operations.recoverOperations(w)
        assertEquals(listOf("old" to "aborted"), old.map { it["id"] to it["state"] })
        seed(w, linkedMapOf("id" to "ancient", "state" to "pending", "startedAt" to 0L))
        assertEquals("aborted", Operations.recoverOperation(w, "ancient")!!["state"])
        assertNull(Operations.recoverOperation(w, "missing"))
    }

    @Test
    fun reconciliation() {
        val unc = rec("u", "uncertain", "executingAt" to T0, "finishedAt" to T0 + 5, "error" to "why")
        val base = "\"executingAt\":1800000000000,\"finishedAt\":1800000000009,\"id\":\"u\",\"params_digest\":\"$PD\",\"resource\":\"/r\""

        val st = Operations.MemoryStore()
        seed(st, unc)
        assertTrue(Operations.resolveOperation(st, "u", true, "R", { T0 + 9 }))
        assertEquals(
            "{\"error\":\"why\",$base,\"result\":\"R\",\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"committed\",\"verb\":\"v\"}",
            canon(st.get("u")),
        )
        assertFalse("only an uncertain record is settled", Operations.resolveOperation(st, "u", true, "R2", { T0 + 10 }))
        assertFalse(Operations.resolveOperation(st, "u", false, "x", { T0 + 10 }))
        assertEquals("R", st.get("u")!!["result"])
        assertFalse(Operations.resolveOperation(st, "missing", true, "R", { T0 }))

        // committed with no result: no result member (the reference's `result: undefined`)
        val st2 = Operations.MemoryStore()
        seed(st2, unc)
        assertTrue(Operations.resolveOperation(st2, "u", true, null, { T0 + 9 }))
        assertEquals(
            "{\"error\":\"why\",$base,\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"committed\",\"verb\":\"v\"}",
            canon(st2.get("u")),
        )

        val st3 = Operations.MemoryStore()
        seed(st3, unc)
        assertTrue(Operations.resolveOperation(st3, "u", false, "never applied", { T0 + 9 }))
        assertEquals(
            "{\"error\":\"never applied\",$base,\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"failed\",\"verb\":\"v\"}",
            canon(st3.get("u")),
        )

        // the default clock is the wall clock
        val st4 = Operations.MemoryStore()
        seed(st4, unc)
        val before = System.currentTimeMillis()
        assertTrue(Operations.resolveOperation(st4, "u", false, "e"))
        val at = st4.get("u")!!["finishedAt"] as Long
        assertTrue(at >= before && at <= System.currentTimeMillis())

        // the store loses the transition: not settled
        val s = Scripted()
        seed(s, unc)
        s.onTransition = { _ -> false }
        assertFalse(Operations.resolveOperation(s, "u", true, "R", { T0 }))
        assertFalse(Operations.resolveOperation(s, "u", false, "e", { T0 }))
    }

    // ---- the executor's re-check -----------------------------------------------------------------------------------------

    private val grantG = linkedMapOf<String, Any?>("g" to "rant")

    private fun executor(
        isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Any?)?, plans: PlanLifecycle.PlanRegistry? = null,
        extra: ((Operations.ExecutionHandle) -> Operations.Recheck)? = null, now: Long = T0,
        resolve: ((String) -> Map<String, Any?>?)? = { ref -> if (ref == "g1") grantG else null },
    ) = Operations.Executor(Operations.MemoryStore(), Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), isRevoked, plans = plans, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk), "aud", resolve, extra, now = { now })

    private fun handle(grantRef: Any?, plan: Any? = null): Operations.ExecutionHandle {
        val p = LinkedHashMap<String, Any?>()
        if (grantRef != null) p["grant_ref"] = grantRef
        if (plan != null) p["plan"] = plan
        return Operations.ExecutionHandle("id", aop("id"), p)
    }

    private fun assertRecheck(reason: String?, r: Operations.Recheck) {
        if (reason == null) {
            assertTrue(r.reason, r.ok)
            assertNull(r.reason)
        } else {
            assertFalse(r.ok)
            assertEquals(reason, r.reason)
        }
    }

    @Test
    fun theExecutorRecheck() {
        val asked = ArrayList<Any?>()
        val ok = executor({ _, _ -> false }, resolve = { ref -> asked.add(ref); if (ref == "g1") grantG else null })
        assertRecheck("the grant is no longer known", ok.recheckAll(handle(null)))
        assertRecheck("the grant is no longer known", ok.recheckAll(handle(1L)))
        assertEquals("a missing or non-string grant_ref is never resolved", emptyList<Any?>(), asked)
        assertRecheck("the grant is no longer known", ok.recheckAll(handle("g2")))
        assertRecheck(null, ok.recheckAll(handle("g1")))
        assertEquals(listOf<Any?>("g2", "g1"), asked)
        assertRecheck("the grant is no longer known", executor({ _, _ -> false }, resolve = null).recheckAll(handle("g1")))
        assertRecheck("the grant has been revoked", executor({ _, _ -> true }).recheckAll(handle("g1")))
        assertRecheck("revocation could not be checked", executor({ _, _ -> null }).recheckAll(handle("g1")))
        assertRecheck("revocation could not be checked", executor({ _, _ -> "yes" }).recheckAll(handle("g1")))
        assertRecheck("revocation could not be checked", executor({ _, _ -> throw IllegalStateException("down") }).recheckAll(handle("g1")))
        assertRecheck("revocation could not be checked", executor(null).recheckAll(handle("g1")))
        // the revocation check sees the presented PCActn and the resolved grant
        val seen = ArrayList<Any?>()
        val h = handle("g1")
        executor({ p, g -> seen.add(p); seen.add(g); false }).recheckAll(h)
        assertSame(h.pcactn, seen[0])
        assertSame(grantG, seen[1])
        // the extra re-check runs last
        assertRecheck("approval withdrawn", executor({ _, _ -> false }, extra = { _ -> Operations.Recheck.refuse("approval withdrawn") }).recheckAll(handle("g1")))
        assertRecheck(null, executor({ _, _ -> false }, extra = { _ -> Operations.Recheck.OK }).recheckAll(handle("g1")))
        assertRecheck("the grant has been revoked", executor({ _, _ -> true }, extra = { _ -> throw AssertionError("not reached") }).recheckAll(handle("g1")))
    }

    private val planNodes = listOf<Map<String, Any?>>(
        linkedMapOf("id" to "n1", "verb" to "v", "resource" to "/r"), linkedMapOf("id" to "n2", "verb" to "v", "resource" to "/s"),
    )

    @Test
    fun theExecutorRechecksARegisteredPlanAtItsOwnClock() {
        val reg = PlanLifecycle.PlanRegistry(now = { T0 })
        val root = reg.draft("g1", planNodes).record!!["root"] as String
        assertTrue(reg.validate("g1", root).ok)
        assertTrue(reg.commit("g1", root).ok)
        val ex = executor({ _, _ -> false }, reg)
        assertRecheck("plan $root is committed but not authorized by the principal", ex.recheckAll(handle("g1", linkedMapOf("root" to root))))
        // not a registered plan, or no usable root: nothing to check
        assertRecheck(null, ex.recheckAll(handle("g1", linkedMapOf("root" to "unknown-root"))))
        assertRecheck(null, ex.recheckAll(handle("g1", linkedMapOf("root" to 1L))))
        assertRecheck(null, ex.recheckAll(handle("g1", "not an object")))
        assertRecheck(null, executor({ _, _ -> false }).recheckAll(handle("g1", linkedMapOf("root" to root))))

        assertTrue(reg.authorize("g1", root, linkedMapOf("by" to "alice", "expiresAt" to T0 + 100)).ok)
        assertRecheck(null, ex.recheckAll(handle("g1", linkedMapOf("root" to root))))
        assertRecheck(null, ex.recheckAll(handle("g1", linkedMapOf("root" to root, "node_id" to "n1"))))
        assertRecheck(null, ex.recheckAll(handle("g1", linkedMapOf("root" to root, "node_id" to 1L))))
        assertRecheck("plan $root has no node 'nX'", ex.recheckAll(handle("g1", linkedMapOf("root" to root, "node_id" to "nX"))))
        // the approval is judged at the executor's clock
        assertRecheck(
            "plan $root: the principal's approval expired at ${T0 + 100}",
            executor({ _, _ -> false }, reg, now = T0 + 100).recheckAll(handle("g1", linkedMapOf("root" to root))),
        )
        // a revoked grant is refused before the plan is looked at
        assertRecheck("the grant has been revoked", executor({ _, _ -> true }, reg).recheckAll(handle("g1", linkedMapOf("root" to root))))
        assertTrue(reg.revoke("g1", root, "withdrawn").ok)
        assertRecheck("plan $root is revoked (withdrawn)", ex.recheckAll(handle("g1", linkedMapOf("root" to root))))

        // an executor without a clock uses the wall clock
        val reg2 = PlanLifecycle.PlanRegistry()
        val root2 = reg2.draft("g1", planNodes).record!!["root"] as String
        assertTrue(reg2.validate("g1", root2).ok && reg2.commit("g1", root2).ok)
        assertTrue(reg2.authorize("g1", root2, linkedMapOf("by" to "alice", "expiresAt" to 1L)).ok)
        val wall = Operations.Executor(Operations.MemoryStore(), Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, plans = reg2, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk), "aud", { _ -> grantG })
        assertRecheck("plan $root2: the principal's approval expired at 1", wall.recheckAll(handle("g1", linkedMapOf("root" to root2))))
    }

    // ---- the executor end to end (the shared authorize fixture) ----------------------------------------------------------

    private val c = AuthorizeTestKit.case("envelope-max-spend-within")
    private val fixP = AuthorizeTestKit.pcactn(c)
    private val fixOp = AuthorizeTestKit.op(c)

    private fun fixExecutor(store: Operations.Store?, pendingTimeoutMs: Double = Operations.PENDING_TIMEOUT_MS.toDouble()) = Operations.Executor(
        store, Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, provenance = ProvHarness.options, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk), AuthorizeTestKit.AUD,
        { AuthorizeTestKit.grant(c) }, pendingTimeoutMs = pendingTimeoutMs, now = { AuthorizeTestKit.NOW },
    )

    @Test
    fun theExecutorAnswersAReplayFromTheRecordAtItsOwnClock() {
        val st = Operations.MemoryStore()
        val ex = fixExecutor(st)
        val bundle = ProvHarness.bundle(fixOp)
        val first = ex.execute(fixP, fixOp, provenance = bundle) { "paid" }
        assertEquals(first.toString(), "committed", first.status)
        val id = Pca.hashCanonical(fixP)
        assertEquals(id, first.operationId)
        val retry = ex.execute(fixP, fixOp, provenance = bundle, fn = NEVER)
        assertOutcome(linkedMapOf("status" to "committed", "operationId" to id, "result" to "paid", "replayed" to true, "recorded" to true), retry)

        // the record reopened as a stale claim: the replay settles it at the executor's clock
        val reopened = LinkedHashMap(st.get(id)!!)
        reopened["state"] = "pending"
        reopened["startedAt"] = AuthorizeTestKit.NOW - 600_000L
        assertTrue(st.transition(id, "committed", reopened))
        val stale = ex.execute(fixP, fixOp, provenance = bundle, fn = NEVER)
        assertOutcome(linkedMapOf("status" to "aborted", "operationId" to id, "reason" to "not started within 300000 ms of the claim: the side effect never ran", "replayed" to true), stale)

        // a record for other params does not answer: the replay denial stands
        val other = LinkedHashMap(st.get(id)!!)
        other["params_digest"] = PD
        assertTrue(st.transition(id, "aborted", other))
        val d = ex.execute(fixP, fixOp, provenance = bundle, fn = NEVER)
        assertEquals("denied", d.status)
        assertNotNull(d.authorization)
        assertFalse(d.authorization!!.allow)
        assertNotNull(d.reason)
        assertEquals(d.authorization!!.reason, d.reason)
        assertNull(d.operationId)
    }

    @Test
    fun theExecutorAnswersAnOpenClaimWithItsOwnTimeout() {
        val st = Operations.MemoryStore()
        val id = Pca.hashCanonical(fixP)
        seed(st, linkedMapOf("id" to id, "state" to "pending", "startedAt" to AuthorizeTestKit.NOW - 1000L))
        val o = fixExecutor(st, pendingTimeoutMs = 2000.0).execute(fixP, fixOp, provenance = ProvHarness.bundle(fixOp), fn = NEVER)
        assertOutcome(linkedMapOf("status" to "pending", "operationId" to id, "replayed" to true), o)
        assertRefused("createExecutor: missing required component: operations (fail closed)", fixExecutor(null).execute(fixP, fixOp, provenance = ProvHarness.bundle(fixOp), fn = NEVER))
    }

    // ---- the executor's catalog class (a reversible PCActn minted here) -------------------------------------------------

    private val aud = "ins_ops_kill"
    private val email = Authorize.Operation("email.send", "mail", linkedMapOf("to" to "bob@acme.example", "subject" to "Q3 report", "body" to "Attached."))

    private fun minted(): Pair<Map<String, Any?>, Map<String, Any?>> {
        val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 9 }))
        val holder = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 10 }))
        val env = Issue.obj(
            "predicates" to listOf(Issue.obj("verb" to "email.send", "resource" to "mail")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy(),
        )
        val g = Issue.mintGrant(principal, holder.id()!!, null, env, "send the Q3 report")
        val p = Agent(holder, aud, g.grant, clock = { T0 }).act(email.verb, email.resource, email.params)
        return Pair(g.grant, p)
    }

    private fun mintedExecutor(
        g: Map<String, Any?>, store: Operations.Store, classOf: ((Authorize.Operation) -> String?)?, recheck: ((Operations.ExecutionHandle) -> Operations.Recheck)? = null,
    ) = Operations.Executor(
        store, Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, provenance = ProvHarness.options, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk), aud, { _ -> g }, recheck,
        reversibilityClassOf = classOf, now = { T0 },
    )

    @Test
    fun theCatalogClassIsTheStricterOne() {
        val (g, p) = minted()
        assertEquals("reversible", (p["action"] as Map<*, *>)["reversibility_class"])
        val bundle = ProvHarness.bundle(email)

        val s0 = Operations.MemoryStore()
        val o0 = mintedExecutor(g, s0, null, recheck = { _ -> throw AssertionError("a reversible operation is not re-checked") }).execute(p, email, provenance = bundle) { "sent" }
        assertEquals(o0.toString(), "committed", o0.status)
        assertEquals("reversible", s0.get(o0.operationId!!)!!["reversibility"])

        val seen = ArrayList<Authorize.Operation>()
        val s1 = Operations.MemoryStore()
        val o1 = mintedExecutor(g, s1, { op -> seen.add(op); "irreversible" }).execute(p, email, provenance = bundle) { "sent" }
        assertEquals(o1.toString(), "committed", o1.status)
        assertEquals("irreversible", s1.get(o1.operationId!!)!!["reversibility"])
        assertEquals(listOf(email), seen)

        for (cls in listOf<String?>("reversible", null)) {
            val s = Operations.MemoryStore()
            val o = mintedExecutor(g, s, { _ -> cls }).execute(p, email, provenance = bundle) { "sent" }
            assertEquals(o.toString(), "committed", o.status)
            assertEquals("reversible", s.get(o.operationId!!)!!["reversibility"])
        }

        // the catalog's irreversible class makes the executor re-check: a refusing extra re-check aborts
        val s4 = Operations.MemoryStore()
        val o4 = mintedExecutor(g, s4, { _ -> "irreversible" }, recheck = { _ -> Operations.Recheck.refuse("step-up gone") }).execute(p, email, provenance = bundle, fn = NEVER)
        assertEquals(o4.toString(), "aborted", o4.status)
        assertEquals("recheck: step-up gone", o4.reason)
    }
}
