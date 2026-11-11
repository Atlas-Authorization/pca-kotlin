package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for the canonical approval render (packages/pca approval-render.ts + pca-actions
 * approval-render.ts / approval-profiles.ts): test-data/k05-approval.json.gz from tools/pca-audit/k05-oracles/approval-oracle.mts.
 * Values compare as canonical JSON; a reference throw requires a native throw (an ActionKitError with the same code when the
 * case carries one). renderApproval runs unreviewed (confirmed = false: no def here carries a signed confirmation).
 * Skipped: spcExpectation / cibaApprovalDetails (not in the Kotlin port); minorToDecimal cases whose args are not JSON
 * integers (the typed (Long, Long) API cannot take them; the reference refuses every one). A -0 is compared like any other case:
 * the reference refuses it per the strict JSON profile, as the native does.
 */
@Suppress("UNCHECKED_CAST")
class K05ApprovalDiffTest {
    private class Threw(val t: Throwable)
    private object Typed

    companion object {
        const val FILE = "k05-approval.json.gz"
        val SKIPPED = setOf("spcExpectation", "cibaApprovalDetails")
    }

    private fun of(fn: String) = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
    private fun isThrow(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
    private fun show(v: Any?): String = (if (v is Threw) "THROWS ${v.t}" else try { Json.canonicalize(v) } catch (e: Exception) { v.toString() }).let { if (it.length > 300) it.take(300) + "..." else it }
    private fun long(x: Any?): Long? = (x as? Json.Num)?.raw?.toLongOrNull()

    private fun check(fn: String, wantOf: (Any?) -> Any? = { it }, call: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val args = c["args"] as List<Any?>
            val want = wantOf(c["out"])
            val got: Any? = try { call(args) } catch (t: Throwable) { Threw(t) }
            val ok = when {
                got === Typed -> isThrow(want) // the typed API cannot take it; the reference must refuse it too
                isThrow(want) -> got is Threw && ((want as Map<*, *>)["code"] == null || (got.t as? ActionKitError)?.code == (want as Map<*, *>)["code"])
                got is Threw -> false
                else -> Json.canonicalize(want) == Json.canonicalize(got)
            }
            if (ok) continue
            bad.add("${c["name"]}\n  want: ${show(want)}\n  got:  ${show(got)}")
        }
        assertTrue("$fn: ${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    @Test fun everyFnIsPortedOrSkipped() {
        val ported = setOf(
            "approvalRenderShapeError", "approvalRenderDigest", "approvalChallengeB64u", "bindingWords", "renderApproval", "validateDef",
            "psd2Linking", "minorToDecimal", "approvalBatch",
        )
        val unknown = K05Oracle.fns(FILE) - ported - SKIPPED
        assertTrue("oracle fns without a native mapping: $unknown", unknown.isEmpty())
    }

    @Test fun renderShapeError() = check("approvalRenderShapeError") { Approval.renderShapeError(it[0]) }
    @Test fun renderDigest() = check("approvalRenderDigest") { Approval.renderDigest(it[0]) }
    @Test fun challenge() = check("approvalChallengeB64u") { Approval.challenge(it[0], it[1]) }
    @Test fun bindingWords() = check("bindingWords") { Approval.bindingWords(it[0]) }
    @Test fun render() = check("renderApproval") { Approval.render(it[0] as Map<String, Any?>, it[1], false) }
    @Test fun validateDef() = check("validateDef") { Actions.validateDef(it[0]) }
    @Test fun psd2Linking() = check("psd2Linking") { Approval.psd2Linking(it[0] as Map<String, Any?>) }
    @Test fun minorToDecimal() = check("minorToDecimal") {
        val m = long(it[0]); val e = long(it[1])
        if (m == null || e == null) Typed else Approval.minorToDecimal(m, e)
    }
    // the reference returns the challenge as bytes ({$bytes: b64url}); the native returns the b64url string
    @Test fun batch() = check("approvalBatch", { o ->
        if (o is Map<*, *> && IntentJs.get(o, "challenge") is Map<*, *>) LinkedHashMap(o as Map<String, Any?>).also { m -> m["challenge"] = IntentJs.get(m["challenge"], "\$bytes") } else o
    }) { Approval.batch(it[0] as List<Any?>) }
}
