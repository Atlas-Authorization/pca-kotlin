package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the reference oracle over the authoring-file text loader (YAML 1.2 core and JSON, with source positions). A syntax error is compared by class
 * (the parser's wording is its own). Where this loader is deliberately STRICTER than the reference the result must be a single "not YAML" refusal on a
 * text that uses one of the documented constructs, never a different successful value.
 */
@Suppress("UNCHECKED_CAST")
class ActionsYamlLoadDiffTest {
    private val M = "ref-actions-yaml-load-py"
    private val stricter = Regex("(^|\\s)!(?!!(str|map|seq)\\b)\\S|\\? \\[|\r(?!\n)|!!binary")

    private fun norm(r: Any?): Any? {
        val m = r as Map<String, Any?>
        val o = LinkedHashMap<String, Any?>()
        for (k in listOf("defs", "notes", "errors", "locs", "rules", "ns")) if (m.containsKey(k)) o[k] = m[k]
        return o
    }

    @Test fun loadActionsText() {
        val bad = ArrayList<String>()
        for (c in OracleCases.of(M, "loadActionsText")) {
            val args = c["args"] as List<Any?>
            val text = args[0] as String
            val fmt = args[1] as String
            val got = OracleCases.toJson(ActionsText.loadActionsText(text, fmt)) as Map<String, Any?>
            val exp = c["out"] as Map<String, Any?>
            val gotErrors = got["errors"] as List<Any?>
            val e0 = ((exp["errors"] as? List<Any?>)?.firstOrNull() as? Map<String, Any?>)?.get("message") as? String ?: ""
            val gm = if (gotErrors.size == 1) (gotErrors[0] as Map<String, Any?>)["message"] as String else ""
            val ok = if (e0.startsWith("not YAML") || e0.startsWith("YAML warning") || e0.startsWith("not JSON")) {
                val prefixOk = if (fmt == "yaml") gm.startsWith("not YAML") || gm.startsWith("YAML warning") else gm.startsWith("not JSON")
                gotErrors.size == 1 && (got["defs"] as List<Any?>).isEmpty() && prefixOk
            } else if (IntentJs.jsonEquals(norm(exp), IntentJs.normalize(norm(got)))) true
            else stricter.containsMatchIn(text) && gotErrors.size == 1 && gm.startsWith("not YAML") && (got["defs"] as List<Any?>).isEmpty()
            if (!ok) bad.add(c["name"].toString())
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }
}
