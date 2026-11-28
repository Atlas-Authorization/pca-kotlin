package net.atlasauth.pca.actions.importers

import java.util.TreeSet
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json

/**
 * `import` then `suggest` as one call, the importer registry of the command line, and the text forms the CLI prints and reads
 * (JSON Lines of defs). Pure: no file system, no network (the caller fetches and writes). YAML is not handled here: a YAML source is parsed by
 * the caller and passed in as the already-parsed JSON tree.
 */
@Suppress("UNCHECKED_CAST")
object ImportPipeline {
    /** Kept for callers of the first importer: the default operation bound. */
    const val MAX_IMPORT_OPS: Int = 20_000

    /** Import one source of the given kind. Every def is `unreviewed`. `opts`: the common options (plus `verb` etc. for jsonschema). */
    fun importActions(kind: String?, source: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        if (kind == null) throw ActionKitError("bad_kind", "unknown import kind 'null' (one of " + ImportCommon.IMPORT_KINDS.joinToString(", ") + ")")
        return when (kind) {
            "openapi" -> OpenApiImporter.importOpenApi(source, opts)
            "mcp" -> McpImporter.importMcp(source, opts)
            "graphql" -> GraphqlImporter.importGraphql(source, opts)
            "grpc" -> GrpcImporter.importGrpc(source, opts)
            "asyncapi" -> AsyncApiImporter.importAsyncApi(source, opts)
            "jsonschema" -> JsonSchemaImporter.importJsonSchema(source, opts)
            else -> throw ActionKitError("bad_kind", "unknown import kind '$kind' (one of " + ImportCommon.IMPORT_KINDS.joinToString(", ") + ")")
        }
    }

    /**
     * The command-line importer shape: `{defs, todo: ["<where>: <message>"]}`. A JSON Schema import needs `verb` in the options.
     * Kinds are exactly [ImportCommon.IMPORT_KINDS].
     */
    fun runImporter(kind: String, doc: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        if (!ImportCommon.IMPORT_KINDS.contains(kind)) throw IllegalArgumentException("no importer '$kind'")
        if (kind == "jsonschema" && !Jx.truthy(opts["verb"])) throw IllegalArgumentException("a JSON Schema import needs --verb <ns.noun.action>")
        val r = importActions(kind, doc, opts)
        val todo = ArrayList<Any?>()
        for (t in Jx.a(r["todo"])) todo.add(Jx.jsStr(Jx.get(t, "where")) + ": " + Jx.jsStr(Jx.get(t, "message")))
        return Jx.obj("defs", r["defs"], "todo", todo)
    }

    /** What [suggestDefs] reads: `mode` (`rules` default, `model`, `none`), rule set, registry, model adapters. */
    class SuggestOpts {
        @JvmField var mode: String? = null
        @JvmField var rules: Map<String, Any?>? = null
        @JvmField var registry: Map<String, Map<String, Any?>>? = null
        @JvmField var models: List<ModelAdapter>? = null
    }

    /** Suggest for already imported defs. Returns `{defs (state suggested), errors: [{verb, model, error}]}`. */
    fun suggestDefs(defs: List<Map<String, Any?>>, o: SuggestOpts?): Map<String, Any?> {
        val so = o ?: SuggestOpts()
        val mode = so.mode ?: "rules"
        if (mode == "none") return Jx.obj("defs", ArrayList<Any?>(defs), "errors", ArrayList<Any?>())
        val registry = so.registry ?: Actions.CORE_REGISTRY
        val rules = so.rules ?: ImportRules.DEFAULT_RULES
        val digest = if (rules === ImportRules.DEFAULT_RULES) ImportRules.DEFAULT_RULES_SEALED["digest"] as String else ImportSuggest.rulesDigest(rules)
        val out = ArrayList<Any?>()
        val errors = ArrayList<Any?>()
        for (d in defs) {
            var s = ImportSuggest.suggestWithRules(d, rules, registry)
            var models: List<Any?>? = null
            if (mode == "model") {
                val run = ImportModel.suggestWithModels(d, so.models ?: emptyList(), registry)
                for (e in Jx.a(run["errors"])) { val m = LinkedHashMap<String, Any?>(); m["verb"] = d["verb"]; m.putAll(Jx.m(e)); errors.add(m) }
                val tr = TreeSet<String>()
                for (t in Jx.a(s["traits"])) tr.add(t as String)
                for (t in Jx.a(Jx.m(run["suggestion"])["traits"])) tr.add(t as String)
                s = Jx.obj("traits", ArrayList<Any?>(tr), "roles", s["roles"], "tags", s["tags"], "fired", s["fired"])
                models = Jx.a(run["models"])
            }
            val by = Jx.obj("rules", Jx.obj("version", rules["version"], "digest", digest, "fired", s["fired"]))
            if (models != null && models.isNotEmpty()) by["models"] = models
            out.add(ImportSuggest.applySuggestion(d, s, by))
        }
        return Jx.obj("defs", out, "errors", errors)
    }

    /** Import then suggest: the import report with `defs` replaced by the suggested defs, plus `suggestErrors`. */
    fun importAndSuggest(kind: String?, source: Any?, opts: Map<String, Any?>?, suggest: SuggestOpts?): Map<String, Any?> {
        val r = importActions(kind, source, opts)
        val defs = ArrayList<Map<String, Any?>>()
        for (d in Jx.a(r["defs"])) defs.add(Jx.m(d))
        val s = suggestDefs(defs, suggest)
        val out = LinkedHashMap(r)
        out["defs"] = s["defs"]
        out["suggestErrors"] = s["errors"]
        return out
    }

    // ---- JSON Lines ----

    /** One def per line, strict canonical JSON, sorted by verb: byte-reproducible. */
    fun defsToJsonl(defs: List<Map<String, Any?>>): String {
        val sorted = ArrayList(defs)
        sorted.sortWith { a, b -> (a["verb"] as String).compareTo(b["verb"] as String) }
        val sb = StringBuilder()
        for (i in sorted.indices) { if (i > 0) sb.append('\n'); sb.append(Json.canonicalizeStrict(sorted[i])) }
        if (defs.isNotEmpty()) sb.append('\n')
        return sb.toString()
    }

    /** Parse and validate a JSONL file of defs. Throws ActionKitError `bad_defs` naming the first bad line. */
    fun jsonlToDefs(text: String): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        val lines = text.split("\n")
        for (i in lines.indices) {
            val l = Jx.jsTrim(lines[i])
            if (l.isEmpty()) continue
            val v: Any? = try { Json.parseLenient(l) } catch (e: RuntimeException) { throw ActionKitError("bad_defs", "line ${i + 1}: not JSON") }
            val bad = Actions.validateDef(v)
            if (bad != null) throw ActionKitError("bad_defs", "line ${i + 1}: $bad")
            out.add(Jx.m(v))
        }
        return out
    }
}
