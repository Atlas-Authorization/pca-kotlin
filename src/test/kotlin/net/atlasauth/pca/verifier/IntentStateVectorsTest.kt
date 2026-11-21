package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays `intent-state-vectors.json` (Track 3: accumulators, history windows, sequencer receipts, monitors) against the
 * TypeScript reference, EXACT outcomes (canonical JSON of the output, reason text included). Every function of the corpus has a
 * runner here: a function without one fails [everyFunctionOfTheCorpusIsRun].
 */
@Suppress("UNCHECKED_CAST")
class IntentStateVectorsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("intent-state-vectors.json") }
    private val cases: List<Map<String, Any?>> get() = doc["cases"] as List<Map<String, Any?>>

    private fun m(o: Any?): Map<String, Any?> = IntentJs.obj(o)
    private fun s(o: Any?): String = o as String
    private fun d(o: Any?): Double = IntentJs.num(o)!!
    private fun args(c: Map<String, Any?>): List<Any?> = c["args"] as List<Any?>

    private fun toJson(o: Any?): Any? = when (o) {
        is Long, is Int -> Json.Num(o.toString())
        is IntentAcc.AccValue -> {
            val r = LinkedHashMap<String, Any?>()
            if (o.reason != null) {
                r["ok"] = false
                r["reason"] = o.reason
                if (o.value != 0L || o.key != null) r["leaked"] = "${o.value}/${o.key}"
            } else {
                r["ok"] = true
                r["val"] = Json.Num(o.value.toString())
                r["key"] = o.key
            }
            r
        }
        else -> o
    }

    private val ran = HashSet<String>()

    private fun run(fn: String, f: (List<Any?>) -> Any?) {
        ran.add(fn)
        val bad = ArrayList<String>()
        var n = 0
        for (c in cases) {
            if (fn != c["fn"]) continue
            n++
            val got: Any? = try { f(args(c)) } catch (e: RuntimeException) { "THREW $e" }
            val want = Json.canonicalize(c["out"])
            val g = Json.canonicalize(toJson(got))
            if (want != g) bad.add("${c["name"]}\n    want $want\n    got  $g")
        }
        assertTrue("no cases for $fn", n > 0)
        assertTrue("${bad.size}/$n $fn cases differ from the TS reference:\n  " + bad.take(30).joinToString("\n  "), bad.isEmpty())
    }

    private fun throwsOf(f: () -> Any?): Any? = try { f() } catch (e: RuntimeException) { linkedMapOf("throws" to true) }

    @Test
    fun formatAndSize() {
        assertEquals("pca-intent-state-vectors", doc["format"])
        assertEquals(1.0, IntentJs.num(doc["ver"])!!, 0.0)
        assertTrue(cases.size >= 3000)
    }

    @Test
    fun declarationsAndStates() {
        run("accumulatorDeclError") { IntentAcc.accumulatorDeclError(it[0]) }
        run("monitorDeclError") { IntentAcc.monitorDeclError(it[0]) }
        run("monitorStates") { IntentAcc.monitorStates(m(it[0])) }
        run("trackedKeySetError") { IntentAcc.trackedKeySetError(it[0]) }
        run("preStateError") { IntentAcc.preStateError(it[0], it[1]) }
        run("preValue") { IntentAcc.preValue(it[0], m(it[1])) }
        run("combineAcc") { a ->
            IntentAcc.combineAcc(a[0], m(a[1]), IntentAcc.AccValue(null, IntentJs.lng(IntentJs.get(a[2], "val")), IntentJs.get(a[2], "key") as String?))
        }
    }

    @Test
    fun selectionValuesAndReceipts() {
        run("accSelects") { IntentAcc.accSelects(m(it[0]), s(it[1]), it[2]) }
        run("accValueOf") { IntentAcc.accValueOf(m(it[0]), s(it[1]), m(it[2]), it[3]) }
        run("receiptArithmeticOk") { IntentAcc.receiptArithmeticOk(it[0], m(it[1]), IntentJs.lng(it[2])) }
        run("pcactnReservationDigest") { IntentAcc.pcactnReservationDigest(m(it[0])) }
        run("receiptShapeError") { IntentAcc.receiptShapeError(it[0]) }
        run("keySetShapeError") { IntentAcc.keySetShapeError(it[0]) }
        run("verifyKeySet") { IntentAcc.verifyKeySet(it[0], s(it[1]), it[2], it[3] as Boolean) }
        run("verifyReceiptSignature") { a ->
            if (a[0] is Map<*, *>) IntentAcc.verifyReceiptSignature(m(a[0]), s(a[1]), if (a[2] == null) null else m(a[2])) else false
        }
        run("verifyReceiptAgainstHolder") { IntentAcc.verifyReceiptAgainstHolder(m(it[0]), m(it[1]), it[2], d(it[3]), d(it[4]), d(it[5]), it[6]) }
    }

    @Test
    fun sessionHistories() {
        run("inWindow") { IntentHistory.inWindow(m(it[0]), it[1], it[2]) }
        run("accKeyOf") { IntentHistory.accKeyOf(m(it[0]), m(it[1])) }
        run("accPreState") { a ->
            val cand = m(a[2])
            throwsOf { IntentHistory.accPreState(m(a[0]), (a[1] as? List<Any?>) ?: emptyList(), m(cand["params"]), cand["t"], a[3]) }
        }
        run("accPost") { a ->
            val cand = m(a[2])
            throwsOf { Json.Num(IntentHistory.accPost(m(a[0]), (a[1] as? List<Any?>) ?: emptyList(), cand["verb"] as String, m(cand["params"]), cand["t"], a[3]).toString()) }
        }
        run("monitorStep") { IntentHistory.monitorStep(m(it[0]), s(it[1]), m(it[2])) }
        run("monitorState") { IntentHistory.monitorState(m(it[0]), (it[1] as? List<Any?>) ?: emptyList()) }
    }

    @Test
    fun everyFunctionOfTheCorpusIsRun() {
        val known = setOf(
            "accumulatorDeclError", "monitorDeclError", "monitorStates", "trackedKeySetError", "preStateError", "preValue", "combineAcc", "accSelects",
            "accValueOf", "receiptArithmeticOk", "pcactnReservationDigest", "receiptShapeError", "keySetShapeError", "verifyKeySet", "verifyReceiptSignature",
            "verifyReceiptAgainstHolder", "inWindow", "accKeyOf", "accPreState", "accPost", "monitorStep", "monitorState",
        )
        val seen = HashMap<String, Int>()
        for (c in cases) {
            val fn = c["fn"] as String
            assertTrue("no runner for corpus function $fn", fn in known)
            seen.merge(fn, 1) { a, b -> a + b }
        }
        for (f in known) assertTrue("corpus has no case for $f", (seen[f] ?: 0) > 0)
    }
}
