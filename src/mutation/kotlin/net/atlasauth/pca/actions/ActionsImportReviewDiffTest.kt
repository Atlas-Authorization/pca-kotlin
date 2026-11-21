package net.atlasauth.pca.actions

import net.atlasauth.pca.actions.importers.ImportEval
import net.atlasauth.pca.actions.importers.ImportPipeline
import net.atlasauth.pca.actions.importers.ImportReview
import net.atlasauth.pca.actions.importers.ImportRules
import net.atlasauth.pca.actions.importers.ModelAdapter
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the importer pipeline, the eval harness and the review / confirmation flow. */
@Suppress("UNCHECKED_CAST")
class ActionsImportReviewDiffTest {
    private val M = "ref-actions-import-review"
    private val CORE = Actions.CORE_REGISTRY

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun defs(xs: Any?): List<Map<String, Any?>> = l(xs).map { m(it) }
    private fun dbl(o: Any?): Double? = if (o == null) null else (o as Json.Num).raw.toDouble()

    private fun adapter(spec: Map<String, Any?>): ModelAdapter = object : ModelAdapter {
        override fun id(): String = spec["id"] as String
        override fun version(): String? = spec["version"] as String?
        override fun complete(req: Map<String, Any?>): String? {
            if (spec.containsKey("throws")) throw Exception(spec["throws"] as String)
            return spec["answer"] as String?
        }
    }

    private fun suggestOpts(so: Map<String, Any?>): ImportPipeline.SuggestOpts {
        val o = ImportPipeline.SuggestOpts()
        o.mode = so["mode"] as String?
        o.registry = CORE
        if ("default" == so["rules"]) {
            val r = LinkedHashMap<String, Any?>(ImportRules.DEFAULT_RULES)
            r["rules"] = ArrayList<Any?>(l(ImportRules.DEFAULT_RULES["rules"]).subList(0, 20))
            o.rules = r
        }
        if (so["models"] is List<*>) o.models = l(so["models"]).map { adapter(m(it)) }
        return o
    }

    // ---- eval ----
    @Test fun parseHandTsv() = OracleCases.each(M, "parseHandTsv") { a -> ImportEval.parseHandTsv(a[0] as String) }
    @Test fun parseCorpusJsonl() = OracleCases.each(M, "parseCorpusJsonl") { a -> ImportEval.parseCorpusJsonl(a[0] as String) }
    @Test fun realSplit() = OracleCases.each(M, "realSplit") { a -> ImportEval.realSplit(if (a.isEmpty()) null else a[0]) }
    @Test fun importCorpus() = OracleCases.each(M, "importCorpus") { a -> ImportEval.importCorpus(l(a[0])) }
    @Test fun evalSuggest() = OracleCases.each(M, "evalSuggest") { a ->
        ImportEval.evalSuggest(l(a[0]), if (a.size > 1 && "default" != a[1]) m(a[1]) else null, CORE, if (a.size > 2) dbl(a[2]) else null)
    }
    @Test fun renderEvalMarkdown() = OracleCases.each(M, "renderEvalMarkdown") { a -> ImportEval.renderEvalMarkdown(m(a[0])) }
    @Test fun floorFailures() = OracleCases.each(M, "floorFailures") { a -> ImportEval.floorFailures(m(a[0]), m(a[1])) }

    // ---- pipeline ----
    @Test fun importActions() = OracleCases.each(M, "importActions") { a -> ImportPipeline.importActions(a[0] as String?, a[1], m(a[2])) }
    @Test fun importers() = OracleCases.each(M, "IMPORTERS") { a -> ImportPipeline.runImporter(a[0] as String, a[1], m(a[2])) }
    @Test fun suggestDefs() = OracleCases.each(M, "suggestDefs") { a -> ImportPipeline.suggestDefs(defs(a[0]), if (a.size > 1) suggestOpts(m(a[1])) else null) }
    @Test fun importAndSuggest() = OracleCases.each(M, "importAndSuggest") { a -> ImportPipeline.importAndSuggest(a[0] as String?, a[1], m(a[2]), suggestOpts(m(a[3]))) }
    @Test fun defsToJsonl() = OracleCases.each(M, "defsToJsonl") { a -> ImportPipeline.defsToJsonl(defs(a[0])) }
    @Test fun jsonlToDefs() = OracleCases.each(M, "jsonlToDefs") { a -> ImportPipeline.jsonlToDefs(a[0] as String) }

    // ---- review ----
    @Test fun verifyAttestation() = OracleCases.each(M, "verifyAttestation") { a -> ImportReview.verifyAttestation(m(a[0]), m(a[1]), CORE) }
    @Test fun reviewStatus() = OracleCases.each(M, "reviewStatus") { a -> ImportReview.reviewStatus(m(a[0]), m(a[1]), CORE) }
    @Test fun revertStale() = OracleCases.each(M, "revertStale") { a -> ImportReview.revertStale(m(a[0]), m(a[1]), CORE) }
    @Test fun reviewPriority() = OracleCases.each(M, "reviewPriority") { a -> ImportReview.reviewPriority(m(a[0]), CORE) }
    @Test fun reviewQueueOrder() = OracleCases.each(M, "reviewQueueOrder") { a -> ImportReview.reviewQueueOrder(defs(a[0]), CORE) }
    @Test fun prepareReview() = OracleCases.each(M, "prepareReview") { a -> ImportReview.prepareReview(m(a[0]), CORE, if (a.size > 1) m(a[1]) else null) }
    @Test fun confirmDef() = OracleCases.each(M, "confirmDef") { a ->
        val c = m(a[1])
        ImportReview.confirmDef(
            m(a[0]), CORE, c["kid"] as String, OracleCases.seed(c["seed"] as String), if (c.containsKey("pins")) m(c["pins"]) else null,
            l(c["finalTraits"]), if (c.containsKey("dismissed")) l(c["dismissed"]) else null, c["ts"],
        )
    }
}
