package net.atlasauth.pca.verifier

import java.util.concurrent.atomic.AtomicInteger
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.op
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The undo admission hook in `authorize`: an unanswered escalation that is not a provenance escalation can run now under a veto
 * window (allow + `undo_window` obligation); a provenance escalation, a presented answer, a throwing hook and a deny never convert.
 * The escalate-class failure is injected through the module-internal [Authorize.coreHook].
 */
@Suppress("UNCHECKED_CAST")
class UndoAuthorizeTest {
    private val c = case("envelope-predicate-within")
    private val windowEnd = AuthorizeTestKit.NOW + 900_000L

    @After
    fun reset() { Authorize.coreHook = null }

    private fun inject(check: String, reason: String?) {
        Authorize.coreHook = { core ->
            core.checks[check] = false
            if (reason != null) core.reasons.add("$check: $reason")
            core.allow = false
        }
    }

    private class Counting(val answer: (Map<String, Any?>, Map<String, Any?>, Authorize.Operation) -> Undo.Admission?) : Authorize.UndoHook {
        val calls = AtomicInteger()
        var seen: Authorize.Operation? = null
        override fun admit(pcactn: Map<String, Any?>, grant: Map<String, Any?>, operation: Authorize.Operation): Undo.Admission? {
            calls.incrementAndGet()
            seen = operation
            return answer(pcactn, grant, operation)
        }
    }

    private fun admitting() = Counting { _, _, _ -> Undo.Admission("op_1", windowEnd, "drafts.delete", "drafts:box1") }

    private fun run(hook: Authorize.UndoHook?, bundle: Boolean = true, answer: Any? = null): Authorize.Result = Authorize.authorize(
        pcactn(c),
        Authorize.Input(
            operation = op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) }, stateStore = Authorize.MemoryStateStore(),
            isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP, escalationAnswer = answer,
            provenanceOptions = ProvHarness.options, provenance = if (bundle) ProvHarness.bundle(op(c)) else null, undo = hook,
        ),
    )

    @Test
    fun withoutAFailureTheHookIsNeverCalled() {
        val h = admitting()
        val r = run(h)
        assertTrue(r.reasons.toString(), r.allow)
        assertNull(r.undo)
        assertTrue(r.obligations.isEmpty())
        assertEquals(0, h.calls.get())
    }

    /** (a) an escalate-class failure with an admitting hook: allow under the window, with the admission and the obligation. */
    @Test
    fun anEscalationWithAnAdmittingHookRunsUnderTheWindow() {
        inject("tighten", "escalate: asked by tighten rule 'a'")
        val h = admitting()
        val r = run(h)
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals("allow", r.decision)
        assertEquals(200, r.status)
        assertNull(r.escalation)
        assertEquals(1, h.calls.get())
        assertEquals(op(c).verb, h.seen!!.verb)
        assertEquals("pass", r.checks["tighten"])
        assertEquals("pass", r.checks["undo_window"])
        assertEquals("pass", r.checks["provenance_flow"])
        assertFalse(r.checks.containsValue("fail"))
        assertTrue(r.reasons.toString(), r.reasons.contains("undo_window: runs now under a veto window until $windowEnd (compensation drafts.delete)"))
        assertEquals("op_1", r.undo!!.id)
        assertEquals(windowEnd, r.undo!!.windowEnd)
        assertEquals("drafts:box1", r.undo!!.compensationResource)
        val ob = linkedMapOf<String, Any?>("kind" to "undo_window", "params" to linkedMapOf<String, Any?>("id" to "op_1", "window_end" to windowEnd), "due" to windowEnd)
        assertEquals(Json.canonicalize(listOf(ob)), Json.canonicalize(r.obligations))
        assertNull(Obligations.obligationError(r.obligations[0]))
        // the replay claim still spends the counter: the same proof again is a replay, not a second window
        val store = Authorize.MemoryStateStore()
        val input = Authorize.Input(
            operation = op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) }, stateStore = store, isRevoked = { _, _ -> false },
            now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP, provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(op(c)), undo = h,
        )
        assertTrue(Authorize.authorize(pcactn(c), input).allow)
        val again = Authorize.authorize(pcactn(c), input)
        assertFalse(again.allow)
        assertEquals("fail", again.checks["replay"])
    }

    /** (b) a provenance_flow escalation (no bundle on a sensitive action): stays escalate, the hook is never called. */
    @Test
    fun aProvenanceFlowEscalationIsNeverConverted() {
        val h = admitting()
        val r = run(h, bundle = false)
        assertFalse(r.allow)
        assertEquals("escalate", r.decision)
        assertEquals("fail", r.checks["provenance_flow"])
        assertNull(r.undo)
        assertTrue(r.obligations.isEmpty())
        assertEquals(0, h.calls.get())
        // together with another escalate-class failure it is still a provenance escalation
        inject("tighten", "escalate: asked by tighten rule 'a'")
        val both = run(h, bundle = false)
        assertEquals("escalate", both.decision)
        assertEquals(0, h.calls.get())
    }

    /** (c) an Intent v2 rule-17 `provenance` failure (escalate-class): the hook is never called. */
    @Test
    fun aRule17ProvenanceEscalationIsNeverConverted() {
        inject("provenance", "intent_required: where did this value come from")
        val h = admitting()
        val r = run(h)
        assertFalse(r.allow)
        assertEquals("escalate", r.decision)
        assertEquals("fail", r.checks["provenance"])
        assertEquals("pass", r.checks["provenance_flow"])
        assertNull(r.undo)
        assertEquals(0, h.calls.get())
    }

    /** (d) an escalation answer was presented: the answer path decides, the hook is not called. */
    @Test
    fun aPresentedAnswerIsNeverConverted() {
        inject("tighten", "escalate: asked by tighten rule 'a'")
        val h = admitting()
        val r = run(h, answer = "not an answer")
        assertFalse(r.allow)
        assertEquals("escalate", r.decision)
        assertNull(r.undo)
        assertEquals(0, h.calls.get())
    }

    /** (e) the hook throws (or answers nothing, or a malformed admission): no admission, the escalation stands. */
    @Test
    fun aThrowingOrDecliningHookLeavesTheEscalation() {
        inject("tighten", "escalate: asked by tighten rule 'a'")
        val hooks = listOf(
            Counting { _, _, _ -> throw IllegalStateException("coordinator down") },
            Counting { _, _, _ -> null },
            Counting { _, _, _ -> Undo.Admission("x".repeat(129), windowEnd, "drafts.delete", "drafts:box1") }, // id over 128 characters
            Counting { _, _, _ -> Undo.Admission("op_1", -1L, "drafts.delete", "drafts:box1") }, // negative window_end
        )
        for (h in hooks) {
            val r = run(h)
            assertFalse(r.allow)
            assertEquals("escalate", r.decision)
            assertEquals("fail", r.checks["tighten"])
            assertNull(r.checks["undo_window"])
            assertNull(r.undo)
            assertTrue(r.obligations.isEmpty())
            assertEquals(1, h.calls.get())
        }
    }

    /** (f) a deny verdict: the hook is not called. */
    @Test
    fun aDenyIsNeverConverted() {
        val h = admitting()
        inject("tighten", "hard failure")
        val r = run(h)
        assertFalse(r.allow)
        assertEquals("deny", r.decision)
        assertNull(r.undo)
        assertEquals(0, h.calls.get())
        // one hard failure among escalate-class ones is a deny as well
        Authorize.coreHook = { core ->
            core.checks["tighten"] = false
            core.reasons.add("tighten: escalate: q")
            core.checks["classes"] = false
            core.reasons.add("classes: rejected")
            core.allow = false
        }
        assertEquals("deny", run(h).decision)
        assertEquals(0, h.calls.get())
    }

    @Test
    fun theOptionsCarryTheHook() {
        inject("tighten", "escalate: asked by tighten rule 'a'")
        val h = admitting()
        val o = Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, Authorize.SINGLE_STEP, provenance = ProvHarness.options, undo = h)
        val r = o.run(pcactn(c), op(c), AuthorizeTestKit.AUD, { grant(c) }, now = AuthorizeTestKit.NOW, provenance = ProvHarness.bundle(op(c)))
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals("op_1", r.undo!!.id)
        assertEquals(1, h.calls.get())
    }
}
