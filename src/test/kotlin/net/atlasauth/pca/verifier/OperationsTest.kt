package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Operation records (T3): replays `operation-vectors.json` scenario by scenario (a fresh in-memory store, a fixed clock per
 * step), plus concurrency on the in-memory and the durable store, recovery and the executor. A missing vector file fails.
 */
@Suppress("UNCHECKED_CAST")
class OperationsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("operation-vectors.json") }
    private val emptyDigest = Pca.paramsDigest(null)

    /** An allowed result carrying exactly what the vectors' pre-authorized operation carries. */
    private fun authorization(id: String, signedClass: String?, exp: Any? = null, verb: String = "payments.refund", resource: String = "/orders/1", digest: String = emptyDigest): Authorize.Result {
        val action = LinkedHashMap<String, Any?>()
        if (signedClass != null) action["reversibility_class"] = signedClass
        val pc = LinkedHashMap<String, Any?>()
        if (exp != null) pc["exp"] = exp
        pc["action"] = action
        return Authorize.Result(true, 200, emptyMap(), emptyList(), null, operation = Authorize.AuthorizedOperation(verb, resource, digest, id), pcactn = pc)
    }

    private fun canon(v: Any?) = Json.canonicalize(v)

    private fun runScenario(steps: List<Map<String, Any?>>): List<Any?> {
        val store = Operations.MemoryStore()
        val out = ArrayList<Any?>()
        for (s in steps) {
            val at = if (s.containsKey("at")) Json.asLong(s["at"]) else 0L
            when (s["op"]) {
                "seed" -> { store.create(LinkedHashMap(s["record"] as Map<String, Any?>)); out.add(null) }
                "get" -> out.add(store.get(s["id"] as String))
                "recover" -> {
                    val older = if (s.containsKey("older_than_ms")) IntentJs.num(s["older_than_ms"])!! else Operations.PENDING_TIMEOUT_MS.toDouble()
                    out.add(
                        Operations.recoverOperations(store, older, { at }).map { linkedMapOf<String, Any?>("id" to it["id"], "state" to it["state"]) }
                            .sortedBy { it["id"] as String },
                    )
                }
                "recover_one" -> {
                    val older = if (s.containsKey("older_than_ms")) IntentJs.num(s["older_than_ms"])!! else Operations.PENDING_TIMEOUT_MS.toDouble()
                    out.add(Operations.recoverOperation(store, s["id"] as String, older, { at }))
                }
                "resolve" -> {
                    val o = s["outcome"] as Map<String, Any?>
                    val committed = o["state"] == "committed"
                    out.add(Operations.resolveOperation(store, s["id"] as String, committed, if (committed) o["result"] else o["error"], { at }))
                }
                else -> out.add(execute(store, s, at))
            }
        }
        return out
    }

    private fun recheckOf(spec: Any?): ((Operations.ExecutionHandle) -> Operations.Recheck)? {
        if (spec == null) return null
        if (spec == "ok") return { _ -> Operations.Recheck.OK }
        val m = spec as Map<String, Any?>
        if (m.containsKey("refuse")) return { _ -> Operations.Recheck.refuse(m["refuse"] as String) }
        return { _ -> throw IllegalStateException(m["throw"] as String) }
    }

    private fun execute(store: Operations.Store, s: Map<String, Any?>, at: Long): Map<String, Any?> {
        val calls = AtomicInteger()
        val notAllowed = s["not_allowed"] == true
        val noStore = s["no_store"] == true
        val az: Authorize.Result =
            if (notAllowed) Authorize.Result(false, 403, emptyMap(), emptyList(), null)
            else authorization(
                s["id"] as String, s["signed_class"] as String?, s["exp"], (s["verb"] as String?) ?: "payments.refund",
                (s["resource"] as String?) ?: "/orders/1", (s["params_digest"] as String?) ?: emptyDigest,
            )
        val recheck = recheckOf(s["recheck"])
        val recheckFor = (s["recheck_for"] as String?) ?: "irreversible"
        val serverClass = s["server_class"] as String?
        val timeout = if (s.containsKey("timeout_ms")) IntentJs.num(s["timeout_ms"])!! else Operations.PENDING_TIMEOUT_MS.toDouble()
        val spec = s["fn"] as Map<String, Any?>
        val outcome = Operations.executeAuthorized(az, if (noStore) null else store, null, recheck, recheckFor, serverClass, timeout, { at }) { h ->
            calls.incrementAndGet()
            when (spec["kind"]) {
                "throw" -> throw IllegalStateException(spec["message"] as String)
                "reenter" -> Operations.executeAuthorized(az, store, null, recheck, recheckFor, serverClass, timeout, { at }) { throw IllegalStateException("inner must not run") }.status
                else -> if (spec.containsKey("result")) spec["result"] else h.idempotencyKey
            }
        }
        return linkedMapOf(
            "outcome" to outcome.toMap(), "fn_calls" to calls.get().toLong(),
            "record" to (if (noStore || notAllowed) null else store.get(s["id"] as String)),
        )
    }

    @Test
    fun corpusIsComplete() {
        assertEquals(1, (doc["constants"] as Map<String, Any?>).size)
        assertEquals(Operations.PENDING_TIMEOUT_MS, Json.asLong((doc["constants"] as Map<String, Any?>)["pending_timeout_ms"]))
        assertEquals(19, (doc["scenarios"] as List<*>).size)
    }

    @Test
    fun everyScenarioDecidesLikeTheReference() {
        for (scn in doc["scenarios"] as List<Map<String, Any?>>) {
            val got = runScenario(scn["steps"] as List<Map<String, Any?>>)
            val want = scn["expect"] as List<Any?>
            assertEquals("${scn["name"]} step count", want.size, got.size)
            // the step's answer, canonical (numbers compare by value, key order is irrelevant)
            for (i in want.indices) assertEquals("${scn["name"]} step $i", canon(want[i]), canon(got[i]))
        }
    }

    // ---- concurrency ----

    private fun stores(): List<Operations.Store> {
        val path = AuthorizeTestKit.tempDb()
        return listOf(Operations.MemoryStore(), Operations.jdbcStore(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) }))
    }

    private fun inThreads(n: Int, body: (Int) -> Unit) {
        val gate = CyclicBarrier(n)
        val errors = java.util.Collections.synchronizedList(ArrayList<Throwable>())
        val ts = (0 until n).map { i ->
            Thread {
                try { gate.await(); body(i) } catch (e: Throwable) { errors.add(e) }
            }
        }
        ts.forEach { it.start() }
        ts.forEach { it.join() }
        if (errors.isNotEmpty()) throw AssertionError("worker failed: ${errors[0]}", errors[0])
    }

    @Test
    fun parallelExecutionsOfOneIdRunFnExactlyOnce() {
        for (store in stores()) {
            val az = authorization("op-par", "reversible")
            val calls = AtomicInteger()
            val outcomes = java.util.Collections.synchronizedList(ArrayList<Operations.ExecuteOutcome>())
            inThreads(8) { outcomes.add(Operations.executeAuthorized(az, store) { calls.incrementAndGet(); "done" }) }
            assertEquals(1, calls.get())
            assertEquals(1, outcomes.count { it.status == "committed" && !it.replayed })
            assertTrue(outcomes.all { it.status == "committed" || it.status == "pending" })
        }
    }

    @Test
    fun parallelExecutionsThroughSeparateStoreObjectsOnOneFileRunFnOnce() {
        val path = AuthorizeTestKit.tempDb()
        val az = authorization("op-shared", "reversible")
        val calls = AtomicInteger()
        inThreads(8) {
            // its own connections, like another worker
            val store = Operations.jdbcStore(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) })
            Operations.executeAuthorized(az, store) { calls.incrementAndGet(); "done" }
        }
        assertEquals(1, calls.get())
        val after = Operations.jdbcStore(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) }).get("op-shared")
        assertEquals("committed", after!!["state"])
    }

    @Test
    fun aDurableRecordSurvivesANewStoreObject() {
        val path = AuthorizeTestKit.tempDb()
        fun store() = Operations.jdbcStore(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) })
        val az = authorization("op-dur", "reversible")
        val first = Operations.executeAuthorized(az, store()) { linkedMapOf("n" to 1L) }
        val again = Operations.executeAuthorized(az, store()) { linkedMapOf("n" to 2L) }
        assertEquals(canon(linkedMapOf("n" to 1L)), canon(first.result))
        assertEquals(canon(linkedMapOf("n" to 1L)), canon(again.result))
        assertTrue(again.replayed)
        assertEquals("committed", again.status)
    }

    @Test
    fun anUnfinishedDurableRecordIsNeverRerun() {
        val path = AuthorizeTestKit.tempDb()
        fun store() = Operations.jdbcStore(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) })
        store().create(
            linkedMapOf(
                "id" to "op-x", "state" to "executing", "verb" to "v", "resource" to "/r", "params_digest" to emptyDigest,
                "reversibility" to "reversible", "startedAt" to 0L, "executingAt" to 0L,
            ),
        )
        val calls = AtomicInteger()
        val o = Operations.executeAuthorized(authorization("op-x", "reversible"), store(), now = { 10 * 60_000L }) { calls.incrementAndGet() }
        assertEquals("uncertain", o.status)
        assertEquals(0, calls.get())
    }

    @Test
    fun recoverOperationsNeedsAStoreThatLists() {
        try {
            Operations.recoverOperations(Operations.KvStore(MemoryAtomicKv()))
            fail("a store without listOpen must be refused")
        } catch (e: UnsupportedOperationException) {
            assertTrue(e.message!!.contains("listOpen"))
        }
    }

    @Test
    fun aMissingStoreOrADeniedAuthorizationRunsNothing() {
        val calls = AtomicInteger()
        val noStore = Operations.executeAuthorized(authorization("a", "reversible"), null) { calls.incrementAndGet() }
        assertEquals("refused", noStore.status)
        val denied = Operations.executeAuthorized(Authorize.Result(false, 403, emptyMap(), emptyList(), null), Operations.MemoryStore()) { calls.incrementAndGet() }
        assertEquals("refused", denied.status)
        assertEquals(0, calls.get())
    }

    // ---- the executor ----

    private val c = case("envelope-max-spend-within")
    private val step = AuthorizeTestKit.steps(c)[0]
    private val pcactn = step["pcactn"] as Map<String, Any?>
    private val operation = Authorize.Operation.fromJson(step["operation"])!!

    private fun executor(
        store: Operations.Store?, isRevoked: (Map<String, Any?>, Map<String, Any?>) -> Any? = { _, _ -> false },
        plan: String? = Authorize.SINGLE_STEP, plans: PlanLifecycle.PlanRegistry? = null,
    ) = Operations.Executor(
        store, Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), isRevoked, plan, plans = plans, provenance = ProvHarness.options), AuthorizeTestKit.AUD, { grant(c) },
        now = { AuthorizeTestKit.NOW },
    )

    @Test
    fun theExecutorCommitsAndAnswersARetryFromTheRecord() {
        val ex = executor(Operations.MemoryStore())
        val keys = ArrayList<String>()
        val first = ex.execute(pcactn, operation, provenance = ProvHarness.bundle(operation)) { h -> keys.add(h.idempotencyKey); "paid" }
        assertEquals(first.toString(), "committed", first.status)
        assertEquals("paid", first.result)
        assertFalse(first.replayed)
        assertEquals(listOf(Pca.hashCanonical(pcactn)), keys)
        val retry = ex.execute(pcactn, operation, provenance = ProvHarness.bundle(operation)) { keys.add("again"); "paid-twice" }
        assertEquals("committed", retry.status)
        assertEquals("paid", retry.result)
        assertTrue(retry.replayed)
        assertEquals(1, keys.size)
    }

    @Test
    fun aGrantRevokedBetweenAuthorizeAndRunAborts() {
        val n = AtomicInteger()
        val ex = executor(Operations.MemoryStore(), isRevoked = { _, _ -> n.incrementAndGet() > 1 }) // allows authorize, revoked at the recheck
        val ran = AtomicInteger()
        val o = ex.execute(pcactn, operation, provenance = ProvHarness.bundle(operation)) { ran.incrementAndGet() }
        assertEquals("aborted", o.status)
        assertEquals("recheck: the grant has been revoked", o.reason)
        assertEquals(0, ran.get())
    }

    @Test
    fun aDenialWithoutARecordStands() {
        val o = executor(Operations.MemoryStore(), isRevoked = { _, _ -> true }).execute(pcactn, operation, provenance = ProvHarness.bundle(operation)) { 1 }
        assertEquals("denied", o.status)
        assertFalse(o.authorization!!.allow)
    }

    @Test
    fun anExecutorWithoutAStoreRefuses() {
        assertEquals("refused", executor(null).execute(pcactn, operation, provenance = ProvHarness.bundle(operation)) { 1 }.status)
    }

    @Test
    fun theExecutorRechecksThatARegisteredPlanIsStillExecutable() {
        val p = pcactn
        val a = p["action"] as Map<String, Any?>
        val node = linkedMapOf<String, Any?>(
            "id" to (p["plan"] as Map<String, Any?>)["node_id"], "verb" to a["verb"], "resource" to a["resource"],
            "params_digest" to a["params_digest"], "reversibility_class" to a["reversibility_class"],
        )
        val gid = grant(c)["id"] as String
        val reg = PlanLifecycle.PlanRegistry(now = { AuthorizeTestKit.NOW })
        val root = reg.draft(gid, listOf(node)).record!!["root"] as String
        assertTrue(reg.validate(gid, root).ok && reg.commit(gid, root).ok && reg.authorize(gid, root, linkedMapOf("by" to "principal")).ok)
        val n = AtomicInteger()
        val isRevoked: (Map<String, Any?>, Map<String, Any?>) -> Any? = { _, _ ->
            if (n.incrementAndGet() == 2) reg.revoke(gid, root, "principal withdrew approval") // between authorize and the recheck
            false
        }
        val ran = AtomicInteger()
        val o = executor(Operations.MemoryStore(), isRevoked, plan = null, plans = reg).execute(p, operation, provenance = ProvHarness.bundle(operation)) { ran.incrementAndGet() }
        assertEquals(o.toString(), "aborted", o.status)
        assertEquals(0, ran.get())
        assertEquals("recheck: plan $root is revoked (principal withdrew approval)", o.reason)
    }

    @Test
    fun theOutcomeOfARecheckThatThrowsIsAFailClosedAbort() {
        val store = Operations.MemoryStore()
        val o = Operations.executeAuthorized(authorization("t", "irreversible"), store, recheck = { throw IllegalStateException("store down") }) { 1 }
        assertEquals("aborted", o.status)
        assertEquals("recheck: recheck error (fail closed): store down", o.reason)
        assertNotNull(store.get("t"))
        assertNull(store.get("nope"))
    }
}
