package net.atlasauth.pca.actions

import net.atlasauth.pca.actions.importers.ImportModel
import net.atlasauth.pca.actions.importers.ImportProviders
import net.atlasauth.pca.actions.importers.ImportRules
import net.atlasauth.pca.actions.importers.ImportSuggest
import net.atlasauth.pca.actions.importers.ModelAdapter
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Test

/** Replays the reference oracle over the suggestion rules (digest, signature, facts, apply) and the model assist and provider adapters. */
@Suppress("UNCHECKED_CAST")
class ActionsImportSuggestDiffTest {
    private val M = "ref-actions-import-suggest"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun rules(x: Any?): Map<String, Any?> = if ("default" == x) ImportRules.DEFAULT_RULES else m(x)
    private fun reg(x: Any?): Map<String, Map<String, Any?>>? = if ("core" == x) Actions.CORE_REGISTRY else null

    @Test fun stem() = OracleCases.each(M, "stem") { a -> ImportSuggest.stem(a[0] as String) }
    @Test fun factsOf() = OracleCases.each(M, "factsOf") { a -> ImportSuggest.factsOf(m(a[0])).toJson() }
    @Test fun defaultRules() = OracleCases.each(M, "DEFAULT_RULES") { _ -> ImportRules.DEFAULT_RULES }
    @Test fun defaultRulesSealedDigest() {
        OracleCases.each(M, "DEFAULT_RULES_SEALED_DIGEST") { _ -> ImportRules.DEFAULT_RULES_SEALED["digest"] }
        assertEquals(ImportRules.publishedDigest(), ImportRules.DEFAULT_RULES_SEALED["digest"])
    }
    @Test fun suggestRulesError() = OracleCases.each(M, "suggestRulesError") { a ->
        var known: Set<String>? = null
        if (a.size > 1 && a[1] is List<*>) known = l(a[1]).map { it as String }.toCollection(LinkedHashSet())
        ImportSuggest.suggestRulesError(if (a[0] is Map<*, *> || "default" == a[0]) rules(a[0]) else a[0], known) // a non-object is refused by the function itself
    }
    @Test fun rulesDigest() = OracleCases.each(M, "rulesDigest") { a -> ImportSuggest.rulesDigest(rules(a[0])) }
    @Test fun sealRules() = OracleCases.each(M, "sealRules") { a -> ImportSuggest.sealRules(m(a[0])) }
    @Test fun signRules() = OracleCases.each(M, "signRules") { a -> ImportSuggest.signRules(m(a[0]), a[1] as String, OracleCases.seed(a[2] as String)) }
    @Test fun verifyRules() = OracleCases.each(M, "verifyRules") { a -> ImportSuggest.verifyRules(a[0], l(a[1]).map { m(it) }) }
    @Test fun suggestWithRules() = OracleCases.each(M, "suggestWithRules") { a -> ImportSuggest.suggestWithRules(m(a[0]), rules(a[1]), if (a.size > 2) reg(a[2]) else null) }
    @Test fun unionSuggestions() = OracleCases.each(M, "unionSuggestions") { a -> ImportSuggest.unionSuggestions(m(a[0]), m(a[1])) }
    @Test fun applySuggestion() = OracleCases.each(M, "applySuggestion") { a -> ImportSuggest.applySuggestion(m(a[0]), m(a[1]), m(a[2])) }

    @Test fun vocabulary() = OracleCases.each(M, "vocabulary") { _ -> ImportModel.vocabulary(Actions.CORE_REGISTRY) }
    @Test fun promptDigest() = OracleCases.each(M, "promptDigest") { _ -> ImportModel.promptDigest(Actions.CORE_REGISTRY) }
    @Test fun buildRequest() = OracleCases.each(M, "buildRequest") { a -> ImportModel.buildRequest(m(a[0]), Actions.CORE_REGISTRY) }
    @Test fun parseTraitList() = OracleCases.each(M, "parseTraitList") { a -> ImportModel.parseTraitList(a[0] as String, Actions.CORE_REGISTRY) }

    private fun adapter(spec: Map<String, Any?>): ModelAdapter = object : ModelAdapter {
        override fun id(): String = spec["id"] as String
        override fun version(): String? = spec["version"] as String?
        override fun complete(req: Map<String, Any?>): String? {
            if (spec.containsKey("throws")) throw Exception(spec["throws"] as String)
            return spec["answer"] as String?
        }
    }

    @Test fun suggestWithModels() = OracleCases.each(M, "suggestWithModels") { a ->
        ImportModel.suggestWithModels(m(a[0]), l(a[1]).map { adapter(m(it)) }, Actions.CORE_REGISTRY)
    }

    @Test fun modelConfigFromEnv() = OracleCases.each(M, "modelConfigFromEnv") { a -> ImportProviders.modelConfigFromEnv(m(a[0]), m(a[1])).toMap() }

    @Test fun providerAdapterComplete() = OracleCases.each(M, "providerAdapterComplete") { a ->
        val cfg = m(a[0])
        val spec = m(a[1])
        val req = m(a[2])
        val env = LinkedHashMap<String, Any?>()
        env[if (cfg["provider"] == "anthropic") "ANTHROPIC_API_KEY" else "OPENAI_API_KEY"] = cfg["apiKey"]
        val c = ImportProviders.modelConfigFromEnv(env, flags(cfg))
        val call = arrayOfNulls<Any>(1)
        val fake = ImportProviders.FetchLike { url, headers, body, _ ->
            val cm = LinkedHashMap<String, Any?>()
            cm["url"] = url
            cm["headers"] = LinkedHashMap<String, Any?>(headers)
            cm["body"] = body
            call[0] = cm
            if (spec.containsKey("throws")) throw Exception(spec["throws"] as String)
            val ok = !spec.containsKey("ok") || spec["ok"] == true
            val status = if (spec.containsKey("status")) (spec["status"] as Json.Num).raw.toDouble().toInt() else 200
            object : ImportProviders.FetchResponse {
                override fun ok(): Boolean = ok
                override fun status(): Int = status
                override fun json(): Any? { if (spec["badjson"] == true) throw Exception("bad json"); return spec["json"] }
            }
        }
        val out = LinkedHashMap<String, Any?>()
        var text: String? = null
        var error: String? = null
        try { text = ImportProviders.providerAdapter(c, fake).complete(req) } catch (e: Exception) { error = e.message }
        // the reference reads its call record before the awaited completion returns, so a success reports no call; a refusal reports it
        out["call"] = if (error != null) call[0] else null
        if (error != null) out["error"] = error else out["text"] = text
        out
    }

    private fun flags(cfg: Map<String, Any?>): Map<String, Any?> {
        val f = LinkedHashMap<String, Any?>()
        f["provider"] = cfg["provider"]
        f["model"] = cfg["model"]
        return f
    }
}
