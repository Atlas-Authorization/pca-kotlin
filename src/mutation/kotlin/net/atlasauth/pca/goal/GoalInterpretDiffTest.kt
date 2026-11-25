package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the interpreters: candidate extraction, slot fill, rule/form/model interpreters, prompt, grounding, vendor completions, typed form. */
@Suppress("UNCHECKED_CAST")
class GoalInterpretDiffTest {
    private val M = "ref-goal-interpret"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null

    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun ont(o: Any?): Map<String, Any?> = if (o is String) GoalOntologies.ontology(o)!! else m(o)!!

    private fun byKey(listO: Any?, key: String, v: Any?): Map<String, Any?> {
        for (x in l(listO)) if (v == m(x)!![key]) return m(x)!!
        throw IllegalStateException("not found $v")
    }

    private fun req(ont: Map<String, Any?>, text: Any?, sources: Any?, form: Any?): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["principal"] = "p1"
        r["text"] = text
        r["ontology"] = ont
        if (sources != null) r["sources"] = sources
        if (form != null) r["form"] = form
        return r
    }

    private fun prompt(p: GoalInterpret.Prompt): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["system"] = p.system
        r["user"] = p.user
        return r
    }

    @Test fun sourceDigest() = OracleCases.each(M, "sourceDigest") { a -> GoalInterpret.sourceDigest(a[0] as String) }

    @Test fun slotStemsOf() = OracleCases.each(M, "slotStemsOf") { a -> GoalInterpret.slotStems(m(a[0])!!) }

    @Test fun extractCandidates() = OracleCases.each(M, "extractCandidates") { a -> GoalInterpret.extractCandidates(a[1] as String, ont(a[0]), a[2] as String?).toJson() }

    @Test fun fillTemplateById() = OracleCases.each(M, "fillTemplateById") { a ->
        val o = ont(a[0])
        GoalInterpret.fillTemplate(byKey(o["templates"], "id", a[1]), o, a[2] as String, a[3] as String?)
    }

    @Test fun buildPromptOf() = OracleCases.each(M, "buildPromptOf") { a -> prompt(GoalInterpret.buildPrompt(req(ont(a[0]), a[1], a[2], null), a[3] == true)) }

    @Test fun promptKeyOf() = OracleCases.each(M, "promptKeyOf") { a -> GoalInterpret.promptKey(a[1] as String, GoalInterpret.Prompt(a[2] as String, a[3] as String)) }

    @Test fun replayLookup() = OracleCases.each(M, "replayLookup") { a ->
        val rec = LinkedHashMap<String, String>()
        for ((k, v) in m(a[2])!!) rec[k] = v as String
        GoalInterpret.replayCompletion(a[1] as String, rec).complete(GoalInterpret.Prompt(a[3] as String, a[4] as String))
    }

    @Test fun parseTemplateJSON() = OracleCases.each(M, "parseTemplateJSON") { a -> GoalInterpret.parseTemplateJSON(a[0] as String) }

    @Test fun groundedOf() = OracleCases.each(M, "groundedOf") { a ->
        val o = ont(a[0])
        val t = byKey(o["templates"], "id", a[1])
        GoalInterpret.grounded(byKey(t["slots"], "name", a[2]), a[3], GoalInterpret.extractCandidates(a[4] as String, o, null))
    }

    @Test fun interpretRule() = OracleCases.each(M, "interpretRule") { a ->
        GoalInterpret.ruleInterpreter("rule", a[3] as String?).interpret(req(ont(a[0]), a[1], a[2], null))
    }

    @Test fun interpretForm() = OracleCases.each(M, "interpretForm") { a ->
        // the generator passes sources ["s"] on its "form text" requests and none on the others
        GoalInterpret.formInterpreter("form").interpret(req(ont(a[0]), a[2], if (a[2] == "form text") arrayListOf<Any?>("s") else null, a[1]))
    }

    @Test fun interpretLlm() = OracleCases.each(M, "interpretLlm") { a ->
        val mode = m(a[3])!!
        val c = GoalInterpret.Completion {
            if (mode.containsKey("throw")) throw RuntimeException("boom")
            mode["raw"] as String
        }
        GoalInterpret.llmInterpreter("m", "f", c, a[4] == true, a[5] as String?).interpret(req(ont(a[0]), a[1], a[2], null))
    }

    @Test fun vendor() = OracleCases.each(M, "vendor") { a ->
        val kind = a[1] as String
        val cfg = m(a[2])!!
        val fk = m(a[3])!!
        val rq = LinkedHashMap<String, Any?>()
        val fetch = GoalInterpret.Fetch { url, method, headers, body ->
            rq["url"] = url
            rq["method"] = method
            rq["headers"] = LinkedHashMap<String, Any?>(headers)
            rq["body"] = body
            if (fk["throwMsg"] != null) throw RuntimeException(fk["throwMsg"] as String)
            if (fk.isEmpty()) { // the generator's last two cases answer with a fixed 200 reply whatever the spec says
                val ok = if (kind == "anthropic") """{"content":[{"type":"text","text":"x"}]}""" else """{"choices":[{"message":{"content":"x"}}]}"""
                return@Fetch GoalInterpret.Fetched(true, 200, ok)
            }
            val st = (fk["status"] as Json.Num).raw
            GoalInterpret.Fetched(fk["ok"] == true, if (st == "200") 200 else st.toInt(), if (fk["body"] == null) "null" else Json.canonicalize(fk["body"]))
        }
        val mt = if (cfg["maxTokens"] == null) null else (cfg["maxTokens"] as Json.Num).raw.toInt()
        val c = if (kind == "anthropic") GoalInterpret.anthropicCompletion(cfg["apiKey"] as String, cfg["model"] as String?, fetch, mt)
        else GoalInterpret.openaiCompletion(cfg["apiKey"] as String, cfg["model"] as String?, cfg["baseUrl"] as String?, fetch)
        val out = LinkedHashMap<String, Any?>()
        try {
            out["text"] = c.complete(GoalInterpret.Prompt(a[4] as String, a[5] as String))
        } catch (e: Exception) {
            out["error"] = e.message
        }
        out["req"] = rq
        out
    }

    @Test fun interpretRefundForm() = OracleCases.each(M, "interpretRefundForm") { a -> GoalInterpret.interpretForm(a[0], m(a[1]), a[2] as String?) }

    @Test fun lexicalCompare() = OracleCases.each(M, "lexicalCompare") { a -> GoalInterpret.lexicalComparator(ont(a[0]))(a[1] as String, a[2] as String) }
}
