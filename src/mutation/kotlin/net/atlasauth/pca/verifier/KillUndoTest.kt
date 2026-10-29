package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for undo windows (Undo.kt, the `undo_window` obligation): the token check order (every failure code reachable,
 * the inclusive exp boundary), the receipt member count, the chain's prev / at / last-state rules, every transition row, the
 * window clamp edges and the obligation params.
 */
@Suppress("UNCHECKED_CAST")
class KillUndoTest {
    private val seed = ByteArray(32) { 11 }
    private val signer = Keys.edFromSeed(seed).id()
    private val other = Keys.edFromSeed(ByteArray(32) { 12 }).id()
    private val d43 = "D".repeat(43)
    private val end = 1_800_000_900_000L

    private val rec = linkedMapOf<String, Any?>(
        "id" to "op_1", "aud" to "drafts-rs", "principal" to "P".repeat(43), "compensation_digest" to d43, "render_digest" to "R".repeat(43), "window_end" to end,
    )
    private val token: Map<String, Any?> get() = Undo.signToken(rec, seed)

    @Test
    fun tokenCheckOrderAndTheInclusiveBoundary() {
        val t = token
        assertEquals("ok", Undo.tokenCheck(t, signer, rec, end - 1))
        assertEquals("ok", Undo.tokenCheck(t, signer, rec, end))
        assertEquals("expired", Undo.tokenCheck(t, signer, rec, end + 1))
        // malformed wins over everything else
        assertEquals("malformed", Undo.tokenCheck(LinkedHashMap(t).also { it["x"] = 1L }, other, rec, end + 1))
        assertEquals("malformed", Undo.tokenCheck(LinkedHashMap(t).also { it.remove("sig") }, signer, rec, 0L))
        assertEquals("malformed", Undo.tokenCheck(LinkedHashMap(t).also { it["kind"] = "pca-undo-receipt" }, signer, rec, 0L))
        assertEquals("malformed", Undo.tokenCheck("x", signer, rec, 0L))
        // signer before signature, record, binding, expiry
        assertEquals("signer", Undo.tokenCheck(t, other, LinkedHashMap(rec).also { it["id"] = "op_2" }, end + 1))
        val tampered = LinkedHashMap(t).also { it["exp"] = end + 1 }
        assertEquals("signature", Undo.tokenCheck(tampered, signer, LinkedHashMap(rec).also { it["id"] = "op_2" }, end + 2))
        // record before binding and expiry
        assertEquals("record", Undo.tokenCheck(t, signer, LinkedHashMap(rec).also { it["id"] = "op_2"; it["aud"] = "x" }, end + 1))
        // binding before expiry: each bound member
        for (k in listOf("aud", "principal", "compensation_digest", "render_digest", "window_end")) {
            val changed = LinkedHashMap(rec).also { it[k] = if (k == "window_end") end + 5 else "Z".repeat(43) }
            assertEquals(k, "binding", Undo.tokenCheck(t, signer, changed, end + 10))
        }
        // a record with no render digest binds the empty one
        val noRender = LinkedHashMap(rec).also { it.remove("render_digest") }
        assertEquals("ok", Undo.tokenCheck(Undo.signToken(noRender, seed), signer, noRender, end))
        assertEquals("binding", Undo.tokenCheck(Undo.signToken(noRender, seed), signer, rec, end))
        // a non-integer clock never passes
        assertTrue(Undo.tokenCheck(t, signer, rec, 1.5) != "ok")
        assertTrue(Undo.tokenCheck(t, signer, rec, null) != "ok")
    }

    @Test
    fun tokenEncodingRoundTripsAndRefusesNonCanonical() {
        val t = token
        val e = Undo.encodeToken(t)
        assertEquals(Json.canonicalize(t), Json.canonicalize(Undo.decodeToken(e)))
        assertNull(Undo.decodeToken("$e="))
        assertNull(Undo.decodeToken(Pca.b64("[1]".toByteArray(Charsets.UTF_8))))
        assertTrue(Undo.tokenDigest(t) != Undo.tokenDigest(LinkedHashMap(t).also { it["exp"] = 1L }))
    }

    private fun receipt(event: String, state: String, at: Long, prev: String, note: String = "") = Undo.signReceipt(
        linkedMapOf("record" to "op_1", "event" to event, "state" to state, "at" to at, "compensation_digest" to d43, "prev" to prev, "note" to note), seed,
    )

    private fun chain(): List<Map<String, Any?>> {
        val a = receipt("opened", "open", 10L, "")
        val b = receipt("effect", "open", 10L, Undo.receiptDigest(a)) // equal time is fine
        val c = receipt("vetoed", "vetoed", 20L, Undo.receiptDigest(b), "token")
        return listOf(a, b, c)
    }

    private fun check(rs: List<Any?>, state: String = "vetoed") =
        Undo.receiptChainError(linkedMapOf("id" to "op_1", "compensation_digest" to d43, "state" to state, "receipts" to rs), signer)

    @Test
    fun receiptMemberCountAndSignature() {
        val r = chain()[0]
        assertEquals(11, r.size)
        assertTrue(Undo.verifyReceipt(r, signer))
        assertFalse(Undo.verifyReceipt(LinkedHashMap(r).also { it["extra"] = "" }, signer))
        assertFalse(Undo.verifyReceipt(LinkedHashMap(r).also { it.remove("note") }, signer))
        assertFalse(Undo.verifyReceipt(r, other))
        assertFalse(Undo.verifyReceipt(LinkedHashMap(r).also { it["note"] = "x" }, signer))
        assertFalse(Undo.verifyReceipt(LinkedHashMap(r).also { it["event"] = "exploded" }, signer))
        assertFalse(Undo.verifyReceipt(LinkedHashMap(r).also { it["state"] = "pending" }, signer))
        assertFalse(Undo.verifyReceipt("x", signer))
    }

    @Test
    fun chainPrevAtAndLastState() {
        val (a, b, c) = chain()
        assertNull(check(listOf(a, b, c)))
        assertNull(check(listOf(a, b), "open"))
        assertEquals("no receipts", check(emptyList()))
        assertEquals("the last receipt does not state the record state", check(listOf(a, b, c), "open"))
        assertEquals("receipt 1 does not link to the previous one", check(listOf(a, c)))
        assertEquals("receipt 1 does not link to the previous one", check(listOf(a, receipt("effect", "open", 10L, ""))))
        assertEquals("receipt 0 does not link to the previous one", check(listOf(receipt("opened", "open", 10L, Undo.receiptDigest(a)))))
        assertEquals("the first receipt is not opened", check(listOf(receipt("effect", "open", 10L, "")), "open"))
        val back = receipt("effect", "open", 9L, Undo.receiptDigest(a))
        assertEquals("receipt 1 goes back in time", check(listOf(a, back), "open"))
        assertEquals("receipt 0 does not verify", check(listOf(LinkedHashMap(a).also { it["note"] = "x" })))
        val otherRecord = Undo.receiptChainError(linkedMapOf("id" to "op_2", "compensation_digest" to d43, "state" to "vetoed", "receipts" to listOf(a, b, c)), signer)
        assertEquals("receipt 0 is for another record", otherRecord)
        val otherComp = Undo.receiptChainError(linkedMapOf("id" to "op_1", "compensation_digest" to "E".repeat(43), "state" to "vetoed", "receipts" to listOf(a, b, c)), signer)
        assertEquals("receipt 0 is for another record", otherComp)
    }

    private val veto = mapOf("kind" to "veto", "veto" to mapOf("at" to 1L, "via" to "token", "by" to "p"))
    private fun r(state: String, vararg extra: Pair<String, Any?>) = linkedMapOf<String, Any?>("state" to state, "window_end" to end, "ver" to 3L, "attempt" to 0L).also { it.putAll(extra) }
    private fun out(t: Undo.Transition) = listOfNotNull(t.outcome, t.code, t.record?.get("state")?.takeIf { t.outcome == "applied" })

    @Test
    fun everyTransitionRow() {
        val eff = "effect" to mapOf("at" to 1L)
        // veto
        assertEquals(listOf("applied", "vetoed"), out(Undo.transition(r("open"), veto, end)))
        assertEquals(listOf("refused", "window_closed"), out(Undo.transition(r("open"), veto, end + 1)))
        for (s in listOf("vetoed", "compensated", "compensation_failed")) assertEquals(listOf("replayed"), out(Undo.transition(r(s), veto, 0L)))
        assertEquals(listOf("refused", "finalized"), out(Undo.transition(r("finalized"), veto, 0L)))
        for (via in listOf("token", "operator", "fraud_proof", "revocation")) {
            val v = mapOf("kind" to "veto", "veto" to mapOf("at" to 1L, "via" to via, "by" to "p"))
            assertEquals(via, "applied", Undo.transition(r("open"), v, 0L).outcome)
        }
        assertEquals("vetoed", Undo.transition(r("open"), veto, 0L).event)
        assertEquals("token", Undo.transition(r("open"), veto, 0L).note)
        // finalize
        assertEquals(listOf("refused", "window_open"), out(Undo.transition(r("open"), mapOf("kind" to "finalize"), end)))
        assertEquals(listOf("applied", "finalized"), out(Undo.transition(r("open"), mapOf("kind" to "finalize"), end + 1)))
        assertEquals(listOf("replayed"), out(Undo.transition(r("finalized"), mapOf("kind" to "finalize"), end + 1)))
        assertEquals(listOf("refused", "vetoed"), out(Undo.transition(r("vetoed"), mapOf("kind" to "finalize"), end + 1)))
        // abort
        val abort = mapOf("kind" to "abort", "reason" to "x")
        assertEquals(listOf("applied", "finalized"), out(Undo.transition(r("open"), abort, 0L)))
        assertEquals(listOf("applied", "finalized"), out(Undo.transition(r("vetoed"), abort, 0L)))
        assertEquals(listOf("refused", "effect_recorded"), out(Undo.transition(r("open", eff), abort, 0L)))
        assertEquals(listOf("replayed"), out(Undo.transition(r("finalized", "outcome" to mapOf("status" to "aborted")), abort, 0L)))
        assertEquals(listOf("refused", "finalized"), out(Undo.transition(r("finalized", "outcome" to mapOf("status" to "finalized")), abort, 0L)))
        assertEquals(listOf("refused", "finalized"), out(Undo.transition(r("compensated"), abort, 0L)))
        // effect
        val effect = mapOf("kind" to "effect", "result" to mapOf("id" to "d_1"))
        val applied = Undo.transition(r("open"), effect, 7L)
        assertEquals(listOf("applied", "open"), out(applied))
        assertEquals(Json.canonicalize(mapOf("at" to 7L, "result" to mapOf("id" to "d_1"))), Json.canonicalize(applied.record!!["effect"]))
        assertEquals(listOf("applied", "vetoed"), out(Undo.transition(r("vetoed"), effect, 0L)))
        assertEquals(listOf("replayed"), out(Undo.transition(r("open", eff), effect, 0L)))
        assertEquals(listOf("refused", "finalized"), out(Undo.transition(r("finalized"), effect, 0L)))
        // compensated
        val comp = mapOf("kind" to "compensated")
        assertEquals(listOf("applied", "compensated"), out(Undo.transition(r("vetoed", eff), comp, 0L)))
        assertEquals(listOf("applied", "compensated"), out(Undo.transition(r("compensation_failed", eff), comp, 0L)))
        assertEquals(listOf("refused", "not_vetoed"), out(Undo.transition(r("open", eff), comp, 0L)))
        assertEquals(listOf("replayed"), out(Undo.transition(r("compensated", eff), comp, 0L)))
        // compensation_failed
        val failed = mapOf("kind" to "compensation_failed", "reason" to "x")
        assertEquals(listOf("applied", "compensation_failed"), out(Undo.transition(r("vetoed", eff), failed, 0L)))
        assertEquals(listOf("refused", "not_vetoed"), out(Undo.transition(r("open", eff), failed, 0L)))
        assertEquals(listOf("replayed"), out(Undo.transition(r("compensation_failed", eff), failed, 0L)))
        // retry
        val retry = Undo.transition(r("compensation_failed", eff, "attempt" to 2L), mapOf("kind" to "retry"), 0L)
        assertEquals(listOf("applied", "vetoed"), out(retry))
        assertEquals(3L, IntentJs.lng(retry.record!!["attempt"]))
        assertEquals(4L, IntentJs.lng(retry.record!!["ver"]))
        assertEquals(listOf("refused", "not_failed"), out(Undo.transition(r("vetoed", eff), mapOf("kind" to "retry"), 0L)))
        // malformed input is refused, never thrown
        assertEquals(listOf("refused", "invalid"), out(Undo.transition(r("open"), mapOf("kind" to "explode"), 0L)))
        assertEquals(listOf("refused", "invalid"), out(Undo.transition(r("pending"), veto, 0L)))
        assertEquals(listOf("refused", "invalid"), out(Undo.transition(r("open"), veto, 1.5)))
        assertEquals(listOf("refused", "invalid"), out(Undo.transition("x", veto, 0L)))
        assertEquals(listOf("refused", "invalid"), out(Undo.transition(r("open"), mapOf("kind" to "veto", "veto" to mapOf("at" to 1L, "via" to "token", "by" to "")), 0L)))
        assertEquals(listOf("refused", "invalid"), out(Undo.transition(r("open"), mapOf("kind" to "veto", "veto" to mapOf("at" to 1L, "via" to "email", "by" to "p")), 0L)))
        // the input record is never modified
        val before = r("open")
        Undo.transition(before, veto, 0L)
        assertEquals("open", before["state"])
        assertEquals(3L, before["ver"])
    }

    @Test
    fun windowClampEdges() {
        assertEquals(Undo.DEFAULT_WINDOW_MS, Undo.resolveWindow(null))
        assertEquals(Undo.DEFAULT_WINDOW_MS, Undo.resolveWindow("120000"))
        assertEquals(Undo.MIN_WINDOW_MS, Undo.resolveWindow(Undo.MIN_WINDOW_MS - 1))
        assertEquals(Undo.MIN_WINDOW_MS, Undo.resolveWindow(Undo.MIN_WINDOW_MS))
        assertEquals(Undo.MIN_WINDOW_MS + 1, Undo.resolveWindow(Undo.MIN_WINDOW_MS + 1))
        assertEquals(Undo.MAX_WINDOW_MS, Undo.resolveWindow(Undo.MAX_WINDOW_MS))
        assertEquals(Undo.MAX_WINDOW_MS, Undo.resolveWindow(Undo.MAX_WINDOW_MS + 1))
        assertEquals(120_000L, Undo.resolveWindow(120_000.9))
        assertEquals(300_000L, Undo.resolveWindow(600_000L, maxMs = 300_000.0))
        assertEquals(Undo.MIN_WINDOW_MS, Undo.resolveWindow(5L, minMs = 1.0))
        assertEquals(60_000L, Undo.resolveWindow(null, defaultMs = 60_000.0))
        assertEquals(120_000L, Undo.resolveWindow(1L, minMs = 120_000.0, maxMs = 60_000.0))
        assertEquals(Undo.MAX_WINDOW_MS, Undo.resolveWindow(1e300))
        assertEquals(Undo.DEFAULT_WINDOW_MS, Undo.resolveWindow(Double.POSITIVE_INFINITY))
        assertEquals(Undo.DEFAULT_WINDOW_MS, Undo.resolveWindow(Double.NaN))
    }

    @Test
    fun obligationParams() {
        fun ob(params: Any?) = linkedMapOf<String, Any?>("kind" to "undo_window", "params" to params, "due" to end)
        assertNull(Obligations.obligationError(ob(mapOf("id" to "op_1", "window_end" to end))))
        assertNull(Obligations.obligationError(ob(mapOf("id" to "x".repeat(128), "window_end" to 0L))))
        assertNotNull(Obligations.obligationError(ob(mapOf("id" to "x".repeat(129), "window_end" to end))))
        assertNotNull(Obligations.obligationError(ob(mapOf("id" to "", "window_end" to end))))
        assertNotNull(Obligations.obligationError(ob(mapOf("id" to "op_1", "window_end" to -1L))))
        assertNotNull(Obligations.obligationError(ob(mapOf("id" to "op_1", "window_end" to 1.5))))
        assertNotNull(Obligations.obligationError(ob(mapOf("id" to "op_1", "window_end" to end, "by" to "x"))))
        assertNotNull(Obligations.obligationError(ob(mapOf("id" to "op_1"))))
        assertNotNull(Obligations.obligationError(ob(mapOf("window_end" to end))))
        assertNotNull(Obligations.obligationError(linkedMapOf<String, Any?>("kind" to "undo_window")))
        assertEquals(Json.canonicalize(ob(mapOf("id" to "op_1", "window_end" to end))), Json.canonicalize(Undo.Admission("op_1", end, "v", "r").obligation()))
    }
}
