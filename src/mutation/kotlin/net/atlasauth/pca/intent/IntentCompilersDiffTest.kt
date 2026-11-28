package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentCompilers.IntentCompiler
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the k-compiler pipeline: prompts, strict slot parsing, panel runs and structural disagreement. */
@Suppress("UNCHECKED_CAST")
class IntentCompilersDiffTest {
    private val m = "ref-intent-compilers"

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    private fun compiler(so: Any?): IntentCompiler {
        val s = mp(so)
        val id = s["id"] as String?
        val family = s["family"] as String?
        return when (s["kind"] as String) {
            "captured" -> IntentCompilers.capturedSlotsCompiler(id) // no id: the default name
            "fixed" -> IntentCompilers.fixedCompiler(id!!, family!!) { s["policy"] }
            "throws" -> IntentCompilers.fixedCompiler(id!!, family!!) { throw IllegalStateException("boom") }
            "slots" -> IntentCompilers.slotsCompiler(id!!, family!!) { s["raw"] as String }
            else -> IntentCompilers.slotsCompiler(id!!, family!!) { throw IllegalStateException("llm down") }
        }
    }

    private fun compilers(specs: Any?): List<IntentCompiler> = ls(specs).map { compiler(it) }

    @Test fun slotsPrompt() = OracleCases.each(m, "slotsPrompt") { a -> IntentCompilers.slotsPrompt(a[0] as String, null) }

    @Test fun parseSlotsJSON() = OracleCases.each(m, "parseSlotsJSON") { a -> IntentCompilers.parseSlotsJSON(a[0] as String, null) }

    @Test fun runScenario() = OracleCases.each(m, "runScenario") { a -> IntentCompilers.runCompilers(mp(a[0]), compilers(a[1])) }

    @Test fun analyze() = OracleCases.each(m, "analyze") { a -> IntentCompilers.analyzeDisagreement(ls(a[0]), mp(a[1])) }

    @Test fun flags() = OracleCases.each(m, "flags") { a -> IntentCompilers.panelFlags(IntentCompilers.analyzeDisagreement(ls(a[0]), mp(a[1]))) }

    @Test fun anchors() = OracleCases.each(m, "anchors") { a -> IntentCompilers.committeeAnchors(ls(a[0]), IntentOmega.dbl(a[1])) }

    @Test fun compareScenario() = OracleCases.each(m, "compareScenario") { a ->
        IntentCompilers.compileAndCompare(mp(a[0]), compilers(a[1]), mp(a[2]))
    }
}
