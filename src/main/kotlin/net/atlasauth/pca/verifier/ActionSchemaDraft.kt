package net.atlasauth.pca.verifier

import net.atlasauth.pca.compliance.ComplianceJs as J

/**
 * The v1 drafting importers of the action schema: an MCP `tools/list` or an OpenAPI document becomes a DRAFT unsigned schema plus the list of
 * decisions the developer must still make. Pure over JSON trees (Map / List / String / Boolean / Json.Num / null); every verb drafts irreversible
 * unless the source says otherwise. The action kit's importers supersede these for new code.
 */
@Suppress("UNCHECKED_CAST")
object ActionSchemaDraft {
    private const val MAX_REF_DEPTH = 8
    private const val MAX_REF_NODES = 20_000
    private val NAME_RE = Regex("[A-Za-z0-9_]{1,64}")
    private val JSON_MEDIA_RE = Regex("^application/[^;]*\\+json(;|$)", RegexOption.IGNORE_CASE)

    /** Where `#/...` references resolve and where unrepresentable parts are reported; `left` is the per-operation expansion budget. */
    private class Ctx(val root: Any?, val todo: MutableList<String>) {
        var left: Int? = null
    }

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = LinkedHashMap<String, Any?>().also { for ((k, v) in kv) it[k] = v }

    private fun n(d: Double): Json.Num = Json.Num(J.numStr(d))

    private fun isSafe(o: Any?): Boolean = IntentJs.isSafeInteger(o)

    private fun m(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: emptyMap()

    private fun isStrList(o: Any?): Boolean = o is List<*> && o.all { it is String }

    /** `x.slice(0, 1024)` of a truthy description: strings and arrays slice, anything else is not a function. */
    private fun slice1024(v: Any?): Any? = when (v) {
        is String -> if (v.length > 1024) v.substring(0, 1024) else v
        is List<*> -> v.take(1024)
        else -> throw IllegalStateException("x.slice is not a function")
    }

    /** `String(x)` for the type tags in messages. */
    private fun str(v: Any?): String = J.tpl(v)

    /** `new Set(x)` as a list: arrays by element, strings by character, nothing for null or undefined; anything else is not iterable. */
    private fun members(x: Any?): List<Any?> = when {
        J.nullish(x) -> emptyList()
        x is List<*> -> x
        x is String -> x.codePoints().toArray().map { String(Character.toChars(it)) }
        else -> throw IllegalStateException("${J.tpl(x)} is not iterable")
    }

    /** Follow a local `#/a/b` pointer; null when absent, not local, or not an object (the reference's undefined). */
    private fun pointer(root: Any?, ref: String): Any? {
        if (!ref.startsWith("#/")) return null
        var cur: Any? = root
        for (raw in ref.substring(2).split("/")) {
            val seg = raw.replace("~1", "/").replace("~0", "~")
            cur = when (cur) {
                is Map<*, *> -> if (cur.containsKey(seg)) cur[seg] else return null
                is List<*> -> {
                    val i = seg.toIntOrNull()
                    if (i != null && i.toString() == seg && i >= 0 && i < cur.size) cur[i] else return null
                }
                else -> return null
            }
        }
        return if (cur is Map<*, *> || cur is List<*>) cur else null
    }

    /** `{...into, ...from}`: a non-object spreads nothing. */
    private fun spread(into: MutableMap<String, Any?>, from: Any?) {
        if (from is Map<*, *>) for ((k, v) in from) into[k as String] = v
    }

    private fun isNullType(t: Any?): Boolean = t == "null" || (t is List<*> && t.all { it == "null" })

    /** Follow `$ref`s, merge `allOf`, collapse `anyOf` / `oneOf` to its single non-null variant or to a union of string constants. */
    private fun flatten(s: Any?, c: Ctx, where: String, depth: Int = 0): Map<String, Any?> {
        if (s == null || (s !is Map<*, *> && s !is List<*>)) return LinkedHashMap()
        val left = (c.left ?: MAX_REF_NODES) - 1
        c.left = left
        if (left < 0) {
            if (left == -1) c.todo.add("$where: schema expansion stopped after $MAX_REF_NODES nodes (declared string; refine or drop)")
            return LinkedHashMap()
        }
        if (depth > MAX_REF_DEPTH) {
            c.todo.add("$where: schema nesting or reference chain deeper than $MAX_REF_DEPTH (declared string; refine or drop)")
            return LinkedHashMap()
        }
        var cur = LinkedHashMap<String, Any?>()
        spread(cur, s)
        val ref = cur["\$ref"]
        if (ref is String) {
            val target = pointer(c.root, ref)
            if (target == null) {
                c.todo.add("$where: reference '${ref.take(120)}' is not a local reference that resolves (declared string; refine or drop)")
                return LinkedHashMap()
            }
            val siblings = LinkedHashMap(cur).also { it.remove("\$ref") }
            cur = LinkedHashMap(flatten(target, c, where, depth + 1))
            spread(cur, siblings)
        }
        val allOf = cur["allOf"]
        if (allOf is List<*>) {
            val rest = LinkedHashMap(cur).also { it.remove("allOf") }
            var acc = LinkedHashMap<String, Any?>()
            for (member in allOf) {
                val mm = flatten(member, c, where, depth + 1)
                val next = LinkedHashMap<String, Any?>()
                spread(next, acc)
                spread(next, mm)
                val props = LinkedHashMap<String, Any?>()
                spread(props, acc["properties"])
                spread(props, mm["properties"])
                next["properties"] = props
                next["required"] = ArrayList<Any?>().also { it.addAll(members(acc["required"])); it.addAll(members(mm["required"])) }
                acc = next
            }
            cur = acc
            spread(cur, rest)
        }
        val alts = if (cur["anyOf"] != null) cur["anyOf"] else cur["oneOf"]
        if (alts is List<*>) {
            val rest = LinkedHashMap(cur).also { it.remove("anyOf"); it.remove("oneOf") }
            val live = alts.map { flatten(it, c, where, depth + 1) }.filter { !isNullType(it["type"]) }
            if (live.size == 1) {
                val out = LinkedHashMap(live[0])
                spread(out, rest)
                return out
            }
            val consts = live.map { mm ->
                val k = mm["const"]
                val e = mm["enum"]
                if (k is String) listOf(k) else if (isStrList(e)) (e as List<String>) else null
            }
            if (live.size > 1 && consts.all { it != null }) {
                val out = LinkedHashMap(rest)
                out["type"] = "string"
                out["enum"] = ArrayList<Any?>(LinkedHashSet(consts.flatMap { it!! }))
                return out
            }
            c.todo.add("$where: a union of ${live.size} schemas has no schema representation (declared string; refine or drop)")
            return rest
        }
        if (cur["const"] is String && !cur.containsKey("enum")) cur["enum"] = listOf(cur["const"])
        return cur
    }

    /** JSON Schema property -> parameter declaration; sensitivity defaults to material, unrepresentable shapes become flagged string placeholders. */
    private fun decl(name: String, schema: Any?, required: Boolean, c: Ctx): Map<String, Any?> {
        val todo = c.todo
        val s = flatten(schema, c, "action.params.$name")
        val tRaw: Any? = if (s.containsKey("type")) s["type"] else J.UNDEF
        val t: Any? = if (tRaw is List<*>) tRaw.indexOfFirst { it != "null" }.let { if (it < 0) J.UNDEF else tRaw[it] } else tRaw
        val base = LinkedHashMap<String, Any?>()
        base["semantic"] = if (s["x-pca-semantic"] != null) s["x-pca-semantic"] else "unknown"
        base["sensitivity"] = if (s["x-pca-sensitivity"] != null) s["x-pca-sensitivity"] else "material"
        if (!required) base["required"] = false
        if (J.truthy(s["description"])) base["description"] = slice1024(s["description"])
        if (!J.truthy(s["x-pca-semantic"])) todo.add("action.params.$name: semantic type")
        val enumStrings: List<String>? = if (isStrList(s["enum"])) s["enum"] as List<String> else null
        val out = LinkedHashMap<String, Any?>()
        if (t == "integer") {
            out["type"] = "integer"
            out.putAll(base)
            if (isSafe(s["minimum"])) out["min"] = s["minimum"] else if (isSafe(s["exclusiveMinimum"])) out["min"] = n(IntentJs.num(s["exclusiveMinimum"])!! + 1)
            if (isSafe(s["maximum"])) out["max"] = s["maximum"] else if (isSafe(s["exclusiveMaximum"])) out["max"] = n(IntentJs.num(s["exclusiveMaximum"])!! - 1)
            if (J.truthy(s["x-pca-unit"])) out["unit"] = s["x-pca-unit"]
            if (J.truthy(s["x-pca-accumulates-into"])) out["accumulates_into"] = s["x-pca-accumulates-into"]
            return out
        }
        if (t == "boolean") { out["type"] = "boolean"; out.putAll(base); return out }
        if (t == "string" && s["format"] == "date") { out["type"] = "date"; out.putAll(base); return out }
        if (t == "string") {
            out["type"] = "string"
            out.putAll(base)
            if (enumStrings != null) out["values"] = enumStrings
            if (isSafe(s["maxLength"]) && IntentJs.num(s["maxLength"])!! > 0) out["max_len"] = s["maxLength"]
            return out
        }
        if (t == "array") {
            val items = flatten(s["items"], c, "action.params.$name[]")
            val itEnum: List<String>? = if (isStrList(items["enum"])) items["enum"] as List<String> else null
            if (J.truthy(s["uniqueItems"]) && itEnum != null) {
                out["type"] = "set"
                out.putAll(base)
                out["values"] = itEnum
                if (isSafe(s["minItems"])) out["min_items"] = s["minItems"]
                if (isSafe(s["maxItems"])) out["max_items"] = s["maxItems"]
                return out
            }
            val itRaw = items["type"]
            val itT = if (itRaw is List<*>) itRaw.firstOrNull() else itRaw
            out["type"] = "array"
            out.putAll(base)
            if (itT == "integer") out["items"] = "integer"
            if (isSafe(s["maxItems"])) out["max_items"] = s["maxItems"]
            if (isSafe(s["minItems"])) out["min_items"] = s["minItems"]
            return out
        }
        todo.add("action.params.$name: type '${str(t)}' has no schema representation (declared string; refine or drop)")
        out["type"] = "string"
        out.putAll(base)
        return out
    }

    /** MCP annotations give a LOWER bound on reversibility (hints never lower a classification). */
    fun reversibilityFromMcpHints(a: Any?): Map<String, Any?> {
        if (J.qprop(a, "readOnlyHint") == true) return obj("kind" to "read", "atLeast" to "reversible")
        if (J.qprop(a, "destructiveHint") == true) return obj("kind" to "write", "atLeast" to "rate_limited")
        return obj("kind" to "write", "atLeast" to "reversible")
    }

    private fun schemaOf(site: Any?, verbs: List<Any?>): LinkedHashMap<String, Any?> {
        val out = obj("v" to Json.Num("1"), "kind" to ActionSchema.ACTION_SCHEMA_KIND)
        for (k in listOf("site", "aud", "version")) {
            val v = J.prop(site, k)
            if (v !== J.UNDEF) out[k] = v
        }
        out["verbs"] = verbs
        return out
    }

    private fun sortVerbs(verbs: MutableList<LinkedHashMap<String, Any?>>) = verbs.sortWith { a, b -> Json.compareUtf8(str(a["verb"]), str(b["verb"])) }

    /** Draft schema from an MCP `tools/list`: verb = prefix + tool name; every write verb is drafted irreversible. */
    fun draftSchemaFromMcpTools(tools: List<Any?>, site: Any?): Map<String, Any?> {
        val todo = ArrayList<String>()
        val verbs = ArrayList<LinkedHashMap<String, Any?>>()
        for (t in tools) {
            val inputSchema = J.prop(t, "inputSchema")
            val name = J.own(t, "name")
            val c = Ctx(inputSchema, todo)
            val input = flatten(inputSchema, c, "${str(name)}: inputSchema")
            val props = m(input["properties"])
            val req = members(input["required"])
            val params = LinkedHashMap<String, Any?>()
            for (p in IntentJs.sortedUtf8(props.keys)) {
                if (!NAME_RE.matches(p)) {
                    todo.add("${str(name)}: parameter '$p' is not a schema name ([A-Za-z0-9_]{1,64}); rename it")
                    continue
                }
                params["action.params.$p"] = decl(p, props[p], req.contains(p), c)
            }
            val h = reversibilityFromMcpHints(J.own(t, "annotations"))
            val verbPrefix = J.prop(site, "verbPrefix")
            val verb = (if (J.nullish(verbPrefix)) "" else str(verbPrefix)) + str(name)
            if (h["kind"] == "write") todo.add("$verb: reversibility (drafted irreversible)")
            val v = obj("verb" to verb, "kind" to h["kind"], "params" to params, "reversibility" to (if (h["kind"] == "read") "reversible" else "irreversible"))
            v["mcp"] = if (name === J.UNDEF) LinkedHashMap<String, Any?>() else obj("tool" to name)
            if (J.truthy(J.own(t, "description"))) v["description"] = slice1024(J.own(t, "description"))
            verbs.add(v)
        }
        sortVerbs(verbs)
        return obj("schema" to schemaOf(site, verbs), "todo" to todo)
    }

    /** The JSON media type of a request body: `application/json` first, else any `application/` type with a `+json` suffix. */
    private fun jsonBodySchema(b: Any?): Any? {
        val content = J.qprop(b, "content")
        if (content !is Map<*, *>) return null
        val keys = IntentJs.sortedUtf8(content.keys.map { it as String })
        val key = keys.firstOrNull { it.lowercase() == "application/json" } ?: keys.firstOrNull { JSON_MEDIA_RE.containsMatchIn(it) } ?: return null
        return J.qprop(content[key], "schema").let { if (it === J.UNDEF) null else it }
    }

    /** Draft schema from OpenAPI: one verb per operation that has an `operationId`. */
    fun draftSchemaFromOpenApi(doc: Any?, site: Any?): Map<String, Any?> {
        val todo = ArrayList<String>()
        val verbs = ArrayList<LinkedHashMap<String, Any?>>()
        val c = Ctx(doc, todo)
        fun deref(x: Any?): Any? {
            if (x !is Map<*, *> && x !is List<*>) return null
            val ref = if (x is Map<*, *>) x["\$ref"] else null
            if (ref !is String) return x
            val t = pointer(doc, ref)
            if (t == null) todo.add("reference '${ref.take(120)}' is not a local reference that resolves")
            return t
        }
        val seen = ArrayList<Any?>()
        val paths = J.qprop(doc, "paths").let { if (it is Map<*, *>) it as Map<String, Any?> else emptyMap() }
        for (path in IntentJs.sortedUtf8(paths.keys)) {
            val ops = paths[path] ?: throw IllegalStateException("Cannot read properties of null (reading 'parameters')")
            if (ops !is Map<*, *>) continue
            val sharedRaw = ops["parameters"]
            val shared: List<Any?> = if (sharedRaw is List<*>) sharedRaw else emptyList()
            for (method in IntentJs.sortedUtf8(ops.keys.map { it as String })) {
                val op = ops[method]
                if (op !is Map<*, *> || !J.truthy(op["operationId"])) continue
                val opId = op["operationId"]
                val opIdS = str(opId)
                c.left = MAX_REF_NODES
                val kindHint = op["x-pca-kind"]
                val read = if (J.truthy(kindHint)) kindHint == "read" else method.lowercase() == "get" || method.lowercase() == "head"
                val verb: Any? = if (op["x-pca-verb"] != null) op["x-pca-verb"] else opId
                if (seen.any { it == verb }) todo.add("${str(verb)}: declared by more than one operation; give each a distinct x-pca-verb")
                seen.add(verb)
                val params = LinkedHashMap<String, Any?>()
                fun addName(name: String, sch: Any?, required: Boolean, source: String) {
                    if (!NAME_RE.matches(name)) {
                        todo.add("$opIdS: parameter '$name' is not a schema name; rename it")
                        return
                    }
                    val key = "action.params.$name"
                    if (params.containsKey(key)) {
                        todo.add("$opIdS: '$name' is declared by both the $source and another source; kept the first")
                        return
                    }
                    params[key] = decl(name, sch, required, c)
                }
                // request body first (it wins a name clash), then the operation's own parameters over the path item's
                val body = flatten(jsonBodySchema(deref(op["requestBody"])), c, "$opIdS: request body")
                val bprops = m(body["properties"])
                val breq = members(body["required"])
                for (name in IntentJs.sortedUtf8(bprops.keys)) addName(name, bprops[name], breq.contains(name), "request body")
                val merged = LinkedHashMap<String, Map<String, Any?>>()
                val own = op["parameters"]
                for (raw in shared + (if (own is List<*>) own else emptyList())) {
                    val q = deref(raw)
                    if (q !is Map<*, *> || q["name"] !is String || q["in"] !is String) continue
                    merged["${q["in"]}:${q["name"]}"] = q as Map<String, Any?>
                }
                for (key in IntentJs.sortedUtf8(merged.keys)) {
                    val q = merged[key]!!
                    if (q["in"] != "path" && q["in"] != "query") {
                        todo.add("$opIdS: ${q["in"]} parameter '${q["name"]}' is not an action parameter (the schema sees path, query and body parameters only)")
                        continue
                    }
                    val schema = q["schema"]
                    val sch = LinkedHashMap<String, Any?>()
                    spread(sch, schema)
                    val schemaDesc = if (schema is Map<*, *>) schema["description"] else null
                    if (J.truthy(q["description"]) && !J.truthy(schemaDesc)) sch["description"] = q["description"]
                    addName(q["name"] as String, sch, q["in"] == "path" || q["required"] == true, "${q["in"]} parameters")
                }
                val revHint = op["x-pca-reversibility"]
                val rev: Any? = if (revHint != null) revHint else if (read) "reversible" else "irreversible"
                if (!read && !J.truthy(revHint)) todo.add("${str(verb)}: reversibility (drafted irreversible)")
                val v = obj("verb" to verb, "kind" to (if (read) "read" else "write"), "params" to params, "reversibility" to rev, "openapi" to obj("operationId" to opId))
                if (J.truthy(op["description"])) v["description"] = slice1024(op["description"])
                verbs.add(v)
            }
        }
        sortVerbs(verbs)
        return obj("schema" to schemaOf(site, verbs), "todo" to todo)
    }
}
