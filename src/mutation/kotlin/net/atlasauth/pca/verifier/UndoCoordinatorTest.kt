package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/** The undo-window coordinator over the TypeScript-signed `envelope-predicate-within` grant: open, veto with the one-click token, compensate, finalize. */
@Suppress("UNCHECKED_CAST")
class UndoCoordinatorTest {
    private val c = case("envelope-predicate-within")
    private val seed = ByteArray(32) { 5 }
    private val t0 = AuthorizeTestKit.NOW

    private class Rig(
        val clock: AtomicLong, val notices: CopyOnWriteArrayList<Map<String, Any?>>, val alerts: CopyOnWriteArrayList<Map<String, Any?>>,
        val calls: CopyOnWriteArrayList<Map<String, Any?>>, val co: UndoCoordinator, val store: UndoStore,
    )

    private fun rig(deliver: Boolean = true, fail: Boolean = false, relay: UndoRelay? = null): Rig {
        val clock = AtomicLong(t0)
        val notices = CopyOnWriteArrayList<Map<String, Any?>>()
        val alerts = CopyOnWriteArrayList<Map<String, Any?>>()
        val calls = CopyOnWriteArrayList<Map<String, Any?>>()
        val store = KvUndoStore(MemoryAtomicKv(), true)
        val co = createUndoCoordinator(
            UndoCoordinatorOptions(
                store = store, engine = UndoEngine { _, _ -> null }, signerSecret = seed, audience = AuthorizeTestKit.AUD,
                resolveGrant = UndoGrantResolver { _, _ -> grant(c) },
                compensate = UndoCompensator { call -> calls.add(call); if (fail) throw IllegalStateException("boom"); linkedMapOf<String, Any?>("undone" to true) },
                operations = Operations.MemoryStore(), notifier = UndoNotifier { n -> notices.add(n); linkedMapOf<String, Any?>("delivered" to deliver) },
                alert = UndoAlertSink { a -> alerts.add(a) }, now = { clock.get() }, relay = relay,
            ),
        )
        return Rig(clock, notices, alerts, calls, co, store)
    }

    /** An admission for the fixture's own call, undone by the same (authorized) verb; the engine step is bypassed. */
    private fun admission(id: String = "rec-1"): Map<String, Any?> {
        val pc = pcactn(c)
        val comp = linkedMapOf<String, Any?>(
            "verb" to "payments.send", "resource" to "payments/acme", "params" to linkedMapOf<String, Any?>("amount" to 50L), "undo_of" to id, "def_digest" to "dd",
        )
        return linkedMapOf(
            "id" to id, "opened_at" to t0, "window_end" to t0 + 900_000L, "converted" to false,
            "plan" to linkedMapOf<String, Any?>("def_digest" to "da", "compensation" to comp), "compensation" to comp, "pcactn" to pc, "grant" to grant(c),
            "operation" to linkedMapOf<String, Any?>("verb" to "payments.send", "resource" to "payments/acme", "params" to linkedMapOf<String, Any?>("amount" to 50L)),
        )
    }

    /** A ledger that records each release's evidence; every other call is a no-op settle. */
    private fun recordingLedger(seen: MutableList<Pair<String, Map<String, Any?>?>>): BudgetLedger =
        java.lang.reflect.Proxy.newProxyInstance(BudgetLedger::class.java.classLoader, arrayOf(BudgetLedger::class.java)) { _, m, a ->
            if (m.name == "release") { seen.add((a[1] as String) to (a[2] as Map<String, Any?>?)); BudgetLedger.SettleOutcome("settled", 1L, null) }
            else if (m.name == "durable") true
            else BudgetLedger.SettleOutcome("settled", 1L, null)
        } as BudgetLedger

    private fun rollbackWith(budget: UndoBudget): Rig {
        val clock = AtomicLong(t0)
        val co = createUndoCoordinator(
            UndoCoordinatorOptions(
                store = KvUndoStore(MemoryAtomicKv(), true), engine = UndoEngine { _, _ -> null }, signerSecret = seed, audience = AuthorizeTestKit.AUD,
                resolveGrant = UndoGrantResolver { _, _ -> grant(c) },
                compensate = UndoCompensator { _ -> linkedMapOf<String, Any?>("undone" to true) },
                operations = Operations.MemoryStore(), notifier = UndoNotifier { _ -> linkedMapOf<String, Any?>("delivered" to true) },
                alert = UndoAlertSink { }, now = { clock.get() }, budget = budget,
            ),
        )
        val info = co.open(admission())
        co.holdBudget("rec-1", listOf(linkedMapOf<String, Any?>("key" to "k", "id" to "r1")))
        co.recordEffect("rec-1", linkedMapOf<String, Any?>("id" to "pay_1"))
        assertTrue(co.veto("rec-1", info["token"] as String).ok)
        return Rig(clock, CopyOnWriteArrayList(), CopyOnWriteArrayList(), CopyOnWriteArrayList(), co, KvUndoStore(MemoryAtomicKv(), true))
    }

    @Test fun aBudgetReleaseCarriesNoEvidenceUnlessTheCallerSuppliesIt() {
        val seen = ArrayList<Pair<String, Map<String, Any?>?>>()
        rollbackWith(UndoBudget(recordingLedger(seen)))
        assertEquals(1, seen.size)
        assertNull(seen[0].second)
    }

    @Test fun aCallersReleaseEvidenceIsPassedThroughWithTheReason() {
        val seen = ArrayList<Pair<String, Map<String, Any?>?>>()
        val reasons = ArrayList<String>()
        rollbackWith(UndoBudget(recordingLedger(seen), UndoReleaseEvidence { r, how -> reasons.add(how); linkedMapOf<String, Any?>("for" to r["id"], "how" to how) }))
        assertEquals(listOf("rollback"), reasons)
        assertEquals(linkedMapOf<String, Any?>("for" to "r1", "how" to "rollback"), seen[0].second)
    }

    @Test fun componentsAreChecked() {
        assertEquals(listOf("store", "engine", "signerSecret", "audience", "resolveGrant", "compensate", "operations", "notifier", "alert"), missingUndoComponents(UndoCoordinatorOptions(null, null, null, null, null, null, null, null, null)))
        assertEquals(listOf("signerSecret"), missingUndoComponents(UndoCoordinatorOptions(KvUndoStore(MemoryAtomicKv(), true), UndoEngine { _, _ -> null }, ByteArray(31), "a", UndoGrantResolver { _, _ -> null }, UndoCompensator { null }, Operations.MemoryStore(), UndoNotifier { null }, UndoAlertSink { })))
        try {
            createUndoCoordinator(UndoCoordinatorOptions(null, null, null, null, null, null, null, null, null))
            fail("a coordinator without components must be refused")
        } catch (e: UndoError) {
            assertEquals("config", e.code)
        }
        try {
            createUndoCoordinator(UndoCoordinatorOptions(KvUndoStore(MemoryAtomicKv(), false), UndoEngine { _, _ -> null }, seed, "a", UndoGrantResolver { _, _ -> null }, UndoCompensator { null }, Operations.MemoryStore(), UndoNotifier { null }, UndoAlertSink { }))
            fail("a volatile store must be refused")
        } catch (e: UndoError) {
            assertEquals("not_durable", e.code)
        }
    }

    @Test fun admissionShape() {
        assertNull(undoAdmissionError(linkedMapOf("id" to "x", "window_end" to 5L, "compensation" to linkedMapOf("verb" to "v"))))
        assertEquals("an admission must be an object", undoAdmissionError("x"))
        assertTrue(undoAdmissionError(linkedMapOf("id" to "", "window_end" to 5L, "compensation" to linkedMapOf("verb" to "v")))!!.startsWith("admission id"))
        assertTrue(undoAdmissionError(linkedMapOf("id" to "x", "window_end" to -1L, "compensation" to linkedMapOf("verb" to "v")))!!.startsWith("admission window_end"))
        assertTrue(undoAdmissionError(linkedMapOf("id" to "x", "window_end" to 1L, "compensation" to linkedMapOf("verb" to "")))!!.startsWith("admission compensation.verb"))
    }

    @Test fun signerPublicIsTheKeyId() {
        assertEquals(Keys.edFromSeed(seed).id(), undoSignerPublic(seed))
        assertEquals(undoSignerPublic(seed), rig().co.signerPublic)
    }

    @Test fun openThenVetoWithTheTokenCompensatesOnce() {
        val r = rig()
        val info = r.co.open(admission())
        assertEquals("rec-1", info["id"])
        assertEquals("opened", r.notices[0]["kind"])
        val token = info["token"] as String
        // a token for another record, or garbage, is refused and nothing runs
        assertFalse(r.co.veto("rec-1", "not-a-token").ok)
        r.co.recordEffect("rec-1", linkedMapOf<String, Any?>("id" to "pay_1"))
        r.clock.set(t0 + 1000)
        val v = r.co.veto("rec-1", token)
        assertTrue(v.reason, v.ok)
        assertEquals("compensated", v.record!!["state"])
        assertEquals(1, r.calls.size)
        assertEquals("rec-1", r.calls[0]["undoOf"])
        // the same veto again replays: the compensation does not run twice
        val again = r.co.veto("rec-1", token)
        assertTrue(again.ok && again.replayed)
        assertEquals(1, r.calls.size)
        assertEquals(listOf("opened", "vetoed", "compensated"), r.notices.map { it["kind"] })
        assertTrue(r.alerts.isEmpty())
        assertTrue(Undo.receiptChainError(r.co.get("rec-1")!!, r.co.signerPublic) == null)
    }

    @Test fun aFailedCompensationIsAnAlertNotASilence() {
        val r = rig(fail = true)
        val info = r.co.open(admission())
        r.co.recordEffect("rec-1", linkedMapOf<String, Any?>("id" to "pay_1"))
        val v = r.co.veto("rec-1", info["token"])
        assertTrue(v.ok)
        assertEquals("compensation_failed", v.record!!["state"])
        assertEquals("compensation_failed", r.alerts.last()["code"])
        assertEquals("critical", r.alerts.last()["level"])
    }

    @Test fun anUnannouncedWindowIsNoWindow() {
        val r = rig(deliver = false)
        try {
            r.co.open(admission())
            fail("a window nobody was told about must not open")
        } catch (e: UndoError) {
            assertTrue(e.message!!.contains("notify_failed"))
        }
        assertEquals("notify_failed", r.alerts.last()["code"])
        assertEquals("aborted", ((r.co.get("rec-1")!!["outcome"]) as Map<String, Any?>)["status"])
    }

    @Test fun finalizeDueClosesAnExpiredWindowAndReportsAMissingEffect() {
        val r = rig()
        r.co.open(admission())
        assertTrue(r.co.finalizeDue().isEmpty()) // still open
        r.clock.set(t0 + 900_001L)
        assertEquals(listOf("rec-1"), r.co.finalizeDue())
        assertEquals("finalized", r.co.get("rec-1")!!["state"])
        assertEquals("effect_unknown", r.alerts.last()["code"])
        // a token is dead once the window closed
        val tok = r.co.open(admission("rec-2"))["token"]
        r.clock.set(t0 + 2_000_000L)
        assertFalse(r.co.veto("rec-2", tok).ok)
    }

    @Test fun anOperatorVetoAndAnUnknownRecord() {
        val r = rig()
        r.co.open(admission())
        r.co.recordEffect("rec-1", linkedMapOf<String, Any?>("id" to "pay_1"))
        assertEquals("unknown", r.co.vetoAsOperator("nope", "ops").code)
        assertEquals("malformed", r.co.vetoAsOperator("rec-1", "").code)
        val v = r.co.vetoAsOperator("rec-1", "ops@example.com")
        assertTrue(v.reason, v.ok)
        assertEquals("compensated", v.record!!["state"])
    }

    @Test fun aRelayThatCannotBeReadFinalizesNothing() {
        val r = rig(relay = UndoRelay { throw IllegalStateException("down") })
        r.co.open(admission())
        r.clock.set(t0 + 900_001L + UNDO_RELAY_GRACE_MS)
        assertTrue(r.co.finalizeDue().isEmpty())
        assertEquals("veto_relay_failed", r.alerts.last()["code"])
        assertEquals("open", r.co.get("rec-1")!!["state"])
    }

    @Test fun reportUndoEffectMapsTheOutcome() {
        val r = rig()
        r.co.open(admission())
        assertEquals("open", reportUndoEffect(r.co, "rec-1", linkedMapOf<String, Any?>("status" to "pending"))["state"])
        assertNotNull(reportUndoEffect(r.co, "rec-1", linkedMapOf<String, Any?>("status" to "committed", "result" to linkedMapOf<String, Any?>("id" to "p"))).get("effect"))
        r.co.open(admission("rec-3"))
        assertEquals("finalized", reportUndoEffect(r.co, "rec-3", linkedMapOf<String, Any?>("status" to "failed"))["state"])
    }

    @Test fun hostedRelayParsesTheListAndRefusesAMalformedBody() {
        val ok = hostedUndoVetoRelay("https://x/", "sk", { url, h ->
            assertEquals("https://x/v1/pca/undo/vetoes?limit=200", url)
            assertEquals("Bearer sk", h["authorization"])
            Pair(200, "{\"data\":[{\"record_id\":\"r\",\"veto\":{\"token\":\"t\",\"at\":5}}]}")
        })
        assertEquals("r", ok.pending()[0]["id"])
        for (bad in listOf(Pair(500, "{}"), Pair(200, "{}"), Pair(200, "{\"data\":[{\"record_id\":1}]}"))) {
            try {
                hostedUndoVetoRelay("https://x", "sk", { _, _ -> bad }).pending()
                fail("a bad relay answer must throw")
            } catch (e: UndoError) {
                assertEquals("invalid", e.code)
            }
        }
    }
}
