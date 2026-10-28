package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Plan lifecycle (T10): replays `plan-vectors.json` scenario by scenario (one fresh registry per scenario, the clock set per step) on
 * the in-memory and on a durable store, the Merkle root against the reference's, concurrent transitions, and the `Authorize.Input.plans`
 * wiring. A missing vector file fails.
 */
@Suppress("UNCHECKED_CAST")
class PlanLifecycleTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("plan-vectors.json") }
    private val scenarios: List<Map<String, Any?>> get() = doc["scenarios"] as List<Map<String, Any?>>

    private fun validatorOf(name: Any?): ((Map<String, Any?>) -> PlanLifecycle.Validation)? = when (name) {
        "accept" -> { _ -> PlanLifecycle.Validation.OK }
        "refuse" -> { _ -> PlanLifecycle.Validation.refuse("node outside the grant") }
        "throw" -> { _ -> throw IllegalStateException("policy down") }
        else -> null
    }

    private fun canon(v: Any?) = Json.canonicalize(v)

    private fun runSteps(reg: PlanLifecycle.PlanRegistry, clock: AtomicLong, steps: List<Map<String, Any?>>): List<Any?> {
        val out = ArrayList<Any?>()
        for (s in steps) {
            val at = Json.asLong(s["at"])
            clock.set(at)
            val grant = s["grant"] as String
            val root = s["root"] as String?
            when (s["op"]) {
                "draft" -> out.add(reg.draft(grant, s["nodes"] as List<Map<String, Any?>>).toMap())
                "validate" -> out.add(reg.validate(grant, root!!).toMap())
                "commit" -> out.add(reg.commit(grant, root!!).toMap())
                "authorize" -> out.add(reg.authorize(grant, root!!, s["approval"] as Map<String, Any?>?).toMap())
                "revoke" -> out.add(reg.revoke(grant, root!!, s["reason"] as String?).toMap())
                "status" -> out.add(reg.status(grant, root!!, at).toMap())
                "check" -> out.add(
                    reg.check(grant, root!!, s["node_id"] as String?, Authorize.Operation.fromJson(opOf(s["operation"])), at).toMap(),
                )
                "is_plan_authorized" -> out.add(reg.isPlanAuthorized(grant, root!!))
                "context" -> out.add(reg.context(grant, root!!, at)?.toMap())
                else -> throw AssertionError("unknown step ${s["op"]}")
            }
        }
        return out
    }

    /** The vector's operation may omit `params` (an empty object then). */
    private fun opOf(o: Any?): Any? {
        if (o !is Map<*, *>) return null
        val m = LinkedHashMap<String, Any?>(o as Map<String, Any?>)
        if (!m.containsKey("params")) m["params"] = LinkedHashMap<String, Any?>()
        return m
    }

    private fun registry(scn: Map<String, Any?>, kv: AtomicKv): Pair<PlanLifecycle.PlanRegistry, AtomicLong> {
        val clock = AtomicLong(0)
        return Pair(PlanLifecycle.PlanRegistry(kv, "pca-plan:", { clock.get() }, validatorOf(scn["validator"])), clock)
    }

    @Test
    fun corpusIsComplete() {
        assertEquals(12, scenarios.size)
        assertEquals(scenarios.sumOf { (it["steps"] as List<*>).size }, scenarios.sumOf { (it["expect"] as List<*>).size })
    }

    @Test
    fun everyScenarioMatchesTheReferenceInMemory() {
        for (scn in scenarios) {
            val (reg, clock) = registry(scn, MemoryAtomicKv())
            val got = runSteps(reg, clock, scn["steps"] as List<Map<String, Any?>>)
            val want = scn["expect"] as List<Any?>
            for (i in want.indices) assertEquals("${scn["name"]} step $i", canon(want[i]), canon(got[i]))
        }
    }

    @Test
    fun everyScenarioMatchesTheReferenceOnADurableStore() {
        val path = AuthorizeTestKit.tempDb()
        for ((n, scn) in scenarios.withIndex()) {
            // a fresh table per scenario (the registry keys are shared across scenarios otherwise)
            val kv = JdbcAtomicKv(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) }, "plans_$n")
            val (reg, clock) = registry(scn, kv)
            val got = runSteps(reg, clock, scn["steps"] as List<Map<String, Any?>>)
            val want = scn["expect"] as List<Any?>
            for (i in want.indices) assertEquals("${scn["name"]} step $i (durable)", canon(want[i]), canon(got[i]))
        }
    }

    @Test
    fun theRootIsTheReferencesRoot() {
        val first = scenarios[0]["steps"] as List<Map<String, Any?>>
        assertEquals(first[1]["root"], PlanLifecycle.planRoot(first[0]["nodes"] as List<Map<String, Any?>>))
    }

    @Test
    fun parallelClaimsOfOneTransitionHaveOneWinner() {
        val path = AuthorizeTestKit.tempDb()
        for (kv in listOf<AtomicKv>(MemoryAtomicKv(), JdbcAtomicKv(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) }))) {
            val reg = PlanLifecycle.PlanRegistry(kv, now = { 1L })
            val root = reg.draft("g1", listOf(linkedMapOf<String, Any?>("id" to "n1", "verb" to "v", "resource" to "/r"))).record!!["root"] as String
            assertTrue(reg.validate("g1", root).ok)
            val results = java.util.Collections.synchronizedList(ArrayList<PlanLifecycle.Transition>())
            val gate = CyclicBarrier(8)
            val errors = java.util.Collections.synchronizedList(ArrayList<Throwable>())
            val ts = (0 until 8).map {
                Thread { try { gate.await(); results.add(reg.commit("g1", root)) } catch (e: Throwable) { errors.add(e) } }
            }
            ts.forEach { it.start() }
            ts.forEach { it.join() }
            assertTrue(errors.toString(), errors.isEmpty())
            assertEquals(1, results.count { it.ok })
            assertTrue(results.filter { !it.ok }.all { it.state == "committed" })
        }
    }

    @Test
    fun parallelClaimsThroughSeparateRegistriesOnOneFileHaveOneWinner() {
        val path = AuthorizeTestKit.tempDb()
        val nodes = listOf(linkedMapOf<String, Any?>("id" to "n1", "verb" to "v", "resource" to "/r"))
        val first = PlanLifecycle.PlanRegistry(JdbcAtomicKv(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) }), now = { 1L })
        val root = first.draft("g1", nodes).record!!["root"] as String
        first.validate("g1", root)
        val results = java.util.Collections.synchronizedList(ArrayList<PlanLifecycle.Transition>())
        val gate = CyclicBarrier(8)
        val errors = java.util.Collections.synchronizedList(ArrayList<Throwable>())
        val ts = (0 until 8).map {
            Thread {
                try {
                    val reg = PlanLifecycle.PlanRegistry(JdbcAtomicKv(PcaJdbcStateStore.ConnectionSource { AuthorizeTestKit.sqlite(path) }), now = { 1L }) // its own connections
                    gate.await()
                    results.add(reg.commit("g1", root))
                } catch (e: Throwable) { errors.add(e) }
            }
        }
        ts.forEach { it.start() }
        ts.forEach { it.join() }
        assertTrue(errors.toString(), errors.isEmpty())
        assertEquals(1, results.count { it.ok })
    }

    // ---- Authorize.Input.plans ----

    private val c = case("envelope-max-spend-within")
    private val step = AuthorizeTestKit.steps(c)[0]
    private val pcactn = step["pcactn"] as Map<String, Any?>

    private fun authorizeWith(plans: PlanLifecycle.PlanRegistry?, plan: String? = null): Authorize.Result = Authorize.authorize(
        pcactn,
        Authorize.Input(
            operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) },
            stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW, plan = plan, plans = plans,
        ),
    )

    private fun fixtureNode(): Map<String, Any?> {
        val a = pcactn["action"] as Map<String, Any?>
        return linkedMapOf(
            "id" to (pcactn["plan"] as Map<String, Any?>)["node_id"], "verb" to a["verb"], "resource" to a["resource"],
            "params_digest" to a["params_digest"], "reversibility_class" to a["reversibility_class"],
        )
    }

    @Test
    fun anUnregisteredPlanIsRefusedByName() {
        val r = authorizeWith(PlanLifecycle.PlanRegistry())
        assertFalse(r.allow)
        assertEquals("fail", r.checks["plan_state"])
        assertEquals("fail", r.checks["plan_root_authorized"])
        val root = (pcactn["plan"] as Map<String, Any?>)["root"]
        assertTrue(r.reasons.toString(), r.reasons.contains("plan_state: plan $root is unknown to the plan registry"))
    }

    @Test
    fun aRegisteredPlanIsExecutableOnlyOnceAuthorized() {
        val node = fixtureNode()
        assertEquals("the fixture plan is a single-step plan", (pcactn["plan"] as Map<String, Any?>)["root"], PlanLifecycle.planRoot(listOf(node)))
        val gid = grant(c)["id"] as String
        val reg = PlanLifecycle.PlanRegistry(now = { AuthorizeTestKit.NOW })
        val root = reg.draft(gid, listOf(node)).record!!["root"] as String
        assertTrue(reg.validate(gid, root).ok)
        assertTrue(reg.commit(gid, root).ok)
        val committed = authorizeWith(reg)
        assertFalse(committed.allow)
        assertEquals("fail", committed.checks["plan_state"])
        assertTrue(committed.reasons.toString(), committed.reasons.joinToString(" ").contains("committed but not authorized by the principal"))
        assertTrue(reg.authorize(gid, root, linkedMapOf("by" to "principal")).ok)
        val ok = authorizeWith(reg)
        assertTrue(ok.reasons.toString(), ok.allow)
        assertEquals("pass", ok.checks["plan_state"])
        assertEquals("pass", ok.checks["plan_root_authorized"])
        assertTrue(reg.revoke(gid, root, "changed my mind").ok)
        val again = authorizeWith(reg)
        assertFalse(again.allow)
        assertEquals("fail", again.checks["plan_state"])
    }

    @Test
    fun anUnknownRootFallsBackToSingleStepWhenThatPlanIsConfigured() {
        val r = authorizeWith(PlanLifecycle.PlanRegistry(), plan = Authorize.SINGLE_STEP)
        assertTrue(r.reasons.toString(), r.allow)
        assertFalse(r.checks.containsKey("plan_state"))
    }
}
