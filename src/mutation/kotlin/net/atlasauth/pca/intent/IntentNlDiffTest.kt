package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentCompilers.IntentCompiler
import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the vectors of the natural-language facade compiler: grounding prompt, strict policy parse, compile and panel run. */
@Suppress("UNCHECKED_CAST")
class IntentNlDiffTest {
    private val m = "ref-intent-nl-java"

    private fun catalog(extras: Any?): Catalog {
        if (extras == null) return Catalog.DEFAULT
        val specs = ArrayList(Catalog.BUILTIN)
        for (eo in extras as List<Any?>) {
            val e = eo as Map<String, Any?>
            val connector = e["connector"] as String
            val action = e["action"] as String
            val aliases = if (e["aliases"] != null) (e["aliases"] as List<Any?>).map { it as String } else emptyList()
            specs.add(
                Catalog.Spec(
                    connector, action, "$connector.$action", e["reversibility"] as String, IntentOmega.dbl(e["blastRadius"]), e["amountField"] as String?,
                    e["description"] as String, aliases,
                ),
            )
        }
        return Catalog(specs)
    }

    private fun compiler(raw: String, prompt: StringBuilder): IntentCompiler = IntentCompilers.nlFacadeCompiler("nl", "fam") { p ->
        prompt.setLength(0)
        prompt.append(p)
        if ("THROWS" == raw) throw IllegalStateException("llm down")
        raw
    }

    private fun input(text: Any?, cat: Catalog): Map<String, Any?> = linkedMapOf("text" to text, "catalog" to cat)

    @Test fun nlPrompt() = OracleCases.each(m, "nlPrompt") { a -> IntentCompilers.nlPrompt(a[0] as String, catalog(a[1])) }

    @Test fun parseNLPolicy() = OracleCases.each(m, "parseNLPolicy") { a -> IntentCompilers.parseNLPolicy(a[0] as String, catalog(a[1])) }

    @Test fun nlCompile() = OracleCases.each(m, "nlCompile") { a ->
        val prompt = StringBuilder()
        val output = compiler(a[1] as String, prompt).compile(input(a[0], catalog(a[2])))
        linkedMapOf("prompt" to prompt.toString(), "output" to output)
    }

    @Test fun nlRun() = OracleCases.each(m, "nlRun") { a ->
        IntentCompilers.runCompilers(input(a[0], catalog(a[2])), listOf(compiler(a[1] as String, StringBuilder())))
    }
}
