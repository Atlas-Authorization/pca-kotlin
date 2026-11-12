package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for undo windows (packages/pca/src/undo.ts): test-data/k05-undo.json.gz from
 * tools/pca-audit/k05-oracles/undo-oracle.mts. Results compare as lenient canonical JSON; a reference throw ({$throws}) requires a
 * throw (Undo's signers raise plain IllegalArgumentException, so a reference `code` is not compared). Secrets are base64url seeds.
 */
@Suppress("UNCHECKED_CAST")
class K05UndoDiffTest {
    companion object {
        const val FILE = "k05-undo.json.gz"
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(bad: List<String>) = assertTrue("${bad.size} divergent case(s):\n" + bad.joinToString("\n"), bad.isEmpty())
        fun isThrow(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
        fun show(o: Any?): String = if (isThrow(o)) "THROWS" else Json.canonicalize(o)
        fun seedOf(s: Any?): ByteArray = Pca.decodeB64uStrict(s, -1) ?: throw IllegalArgumentException("bad seed")
        fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")

    }

    /** One case per reference call; [f] returns the native result (or throws), [skip] names cases with no native counterpart. */
    private fun diff(fn: String, skip: (Map<String, Any?>) -> Boolean = { false }, f: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        var ran = 0
        for (c in of(fn)) {
            if (skip(c)) continue
            ran++
            val want = show(c["out"])
            val got = try { Json.canonicalize(f(args(c))) } catch (t: Throwable) { "THROWS" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        assertTrue("$fn: every case skipped", ran > 0)
        report(bad)
    }

    @Test fun compensationDigest() = diff("compensationDigest") { Undo.compensationDigest(map(it[0])) }

    @Test fun signUndoToken() = diff("signUndoToken") { Undo.signToken(map(it[0]), seedOf(it[1])) }

    // a non-object record reads every member as undefined in the reference: the empty map; a null record throws there (malformed)
    // and the native record parameter is non-null
    @Test fun undoTokenCheck() = diff("undoTokenCheck", { args(it)[2] == null || args(it)[1] !is String }) {
        Undo.tokenCheck(it[0], it[1] as String, it[2] as? Map<String, Any?> ?: emptyMap(), it[3])
    }

    @Test fun encodeUndoToken() = diff("encodeUndoToken") { Undo.encodeToken(map(it[0])) }
    @Test fun undoTokenDigest() = diff("undoTokenDigest") { Undo.tokenDigest(map(it[0])) }

    @Test fun decodeUndoToken() = diff("decodeUndoToken") { Undo.decodeToken(it[0]) }

    @Test fun signUndoReceipt() = diff("signUndoReceipt") { Undo.signReceipt(map(it[0]), seedOf(it[1])) }
    @Test fun undoReceiptDigest() = diff("undoReceiptDigest") { Undo.receiptDigest(map(it[0])) }

    // the native pin is a non-null String (a null pin never verifies in the reference either)
    @Test fun verifyUndoReceipt() = diff("verifyUndoReceipt", { args(it)[1] !is String }) { Undo.verifyReceipt(it[0], it[1] as String) }

    @Test fun undoReceiptChainError() = diff("undoReceiptChainError") { Undo.receiptChainError(map(it[0]), it[1] as String) }

    @Test fun undoTransition() = diff("undoTransition") {
        val t = Undo.transition(it[0], it[1], it[2])
        val o = linkedMapOf<String, Any?>("outcome" to t.outcome)
        if (t.code != null) o["code"] = t.code
        if (t.reason != null) o["reason"] = t.reason
        if (t.record != null) o["record"] = t.record
        if (t.outcome == "applied") o["receipt"] = linkedMapOf<String, Any?>("event" to t.event, "note" to t.note)
        o
    }

    @Test fun resolveUndoWindow() = diff("resolveUndoWindow") {
        val p = map(it[1])
        Undo.resolveWindow(it[0], IntentJs.num(p["minMs"]), IntentJs.num(p["maxMs"]), IntentJs.num(p["defaultMs"]))
    }
}
