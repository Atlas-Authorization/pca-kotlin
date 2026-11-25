package net.atlasauth.pca.actions

import net.atlasauth.pca.actions.importers.AsyncApiImporter
import net.atlasauth.pca.actions.importers.ImportCommon
import net.atlasauth.pca.actions.importers.ImportLimits
import net.atlasauth.pca.actions.importers.JsonSchemaImporter
import net.atlasauth.pca.actions.importers.McpImporter
import net.atlasauth.pca.actions.importers.OpenApiImporter
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the importer helpers (naming, text hygiene, references, limits) and the four core importers. */
@Suppress("UNCHECKED_CAST")
class ActionsImportCoreDiffTest {
    private val MOD = "ref-actions-import-core"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun i(o: Any?): Int = (o as Json.Num).raw.toDouble().toInt()

    private fun limits(l: ImportLimits): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["max_bytes"] = l.maxBytes
        out["max_ops"] = l.maxOps
        out["max_json_depth"] = l.maxJsonDepth
        out["max_nodes"] = l.maxNodes
        out["max_ref_nodes"] = l.maxRefNodes
        out["max_ref_depth"] = l.maxRefDepth
        return out
    }

    @Test fun tokensOf() = OracleCases.each(MOD, "tokensOf") { a -> ImportCommon.tokensOf(a[0]) }

    @Test fun humanize() = OracleCases.each(MOD, "humanize") { a -> ImportCommon.humanize(a[0]) }

    @Test fun verbOf() = OracleCases.each(MOD, "verbOf") { a -> ImportCommon.verbOf(a[0] as String, a[1]) }

    @Test fun aliasOf() = OracleCases.each(MOD, "aliasOf") { a -> ImportCommon.aliasOf(a[0], a[1] as String?) }

    @Test fun paramSeg() = OracleCases.each(MOD, "paramSeg") { a -> ImportCommon.paramSeg(a[0] as String) }

    @Test fun clip() = OracleCases.each(MOD, "clip") { a -> ImportCommon.clip(a[0], i(a[1])) }

    @Test fun pointer() = OracleCases.each(MOD, "pointer") { a -> ImportCommon.pointer(a[0], a[1]) }

    @Test fun resolveLimits() = OracleCases.each(MOD, "resolveLimits") { a -> limits(ImportLimits.resolve(if (a.isEmpty()) null else a[0])) }

    @Test fun checkParsed() = OracleCases.each(MOD, "checkParsed") { a -> ImportLimits.resolve(a[1]).checkParsed(a[0]) }

    @Test fun textSizeCheck() = OracleCases.each(MOD, "textSizeCheck") { a -> ImportLimits.resolve(a[1]).textSizeCheck(a[0] as String); null }

    @Test fun importOpenApi() = OracleCases.each(MOD, "importOpenApi") { a -> OpenApiImporter.importOpenApi(a[0], m(a[1])) }

    @Test fun importMcp() = OracleCases.each(MOD, "importMcp") { a -> McpImporter.importMcp(a[0], m(a[1])) }

    @Test fun importJsonSchema() = OracleCases.each(MOD, "importJsonSchema") { a -> JsonSchemaImporter.importJsonSchema(a[0], m(a[1])) }

    @Test fun importAsyncApi() = OracleCases.each(MOD, "importAsyncApi") { a -> AsyncApiImporter.importAsyncApi(a[0], m(a[1])) }
}
