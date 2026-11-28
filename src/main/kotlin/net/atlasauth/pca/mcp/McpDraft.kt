package net.atlasauth.pca.mcp

import net.atlasauth.pca.a2a.A2aPca
import net.atlasauth.pca.agentcard.AgentCards
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.ActionSchema
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/**
 * The v1 draft of a site action schema from an MCP tool list: JSON Schema flattening (local `$ref`, `allOf`, `anyOf` /
 * `oneOf`), the parameter declaration of each property and the verb of each tool. Pure over parsed JSON (Map, List, String, Boolean,
 * [Json.Num], null). Whatever cannot be represented is flagged in `todo` and drafted as a `string`, which rejects every
 * non-string value, so the draft fails closed until the developer refines it.
 */
@Suppress("UNCHECKED_CAST")
internal object McpDraft {
    private const val MAX_REF_DEPTH = 8
    private const val MAX_REF_NODES = 20_000
    private val NAME = Regex("^[A-Za-z0-9_]{1,64}$")
    private val INDEX = Regex("0|[1-9][0-9]{0,8}")

    /** Where references resolve and what could not be represented is reported; [left] is the reference-bomb budget. */
    private class Ctx(val root: Any?, val todo: MutableList<Any?>) {
        var left: Int? = null
    }

    /** Marks an absent member (JavaScript undefined) as opposed to JSON null. */
    private val UNDEF = Any()

    private fun isObj(o: Any?) = o is Map<*, *>

    /** `o.k` on a schema node: the member of a Map, else absent (null). */
    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    private fun jsStr(v: Any?): String = AgentCards.jsStr(v)

    /** `Number.isSafeInteger`. */
    fun safeInt(o: Any?): Boolean {
        val d = Js.num(o)
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.floor(d) && Math.abs(d) <= 9007199254740991.0
    }

    fun num(d: Double): Json.Num = Json.Num(AttestUtil.jsNumString(d))

    private fun truthy(o: Any?) = Js.truthy(o)

    /** `[...x]` of a schema member: absent or null is empty, a list copies, a string spreads by code point, other values are not iterable (throw). */
    private fun iter(x: Any?): ArrayList<Any?> {
        if (x == null) return ArrayList()
        if (x is List<*>) return ArrayList<Any?>(x)
        if (x is String) {
            val out = ArrayList<Any?>()
            var i = 0
            while (i < x.length) {
                val cp = x.codePointAt(i)
                out.add(String(Character.toChars(cp)))
                i += Character.charCount(cp)
            }
            return out
        }
        throw IllegalStateException("TypeError: not iterable")
    }

    /** Follow a local `#/a/b` JSON pointer in [root]; null when absent, not local, or not an object. */
    fun pointer(root: Any?, ref: String): Any? {
        if (!ref.startsWith("#/")) return null
        var cur: Any? = root
        for (raw in ref.substring(2).split("/")) {
            val seg = raw.replace("~1", "/").replace("~0", "~")
            if (cur is Map<*, *>) {
                if (!cur.containsKey(seg)) return null
                cur = cur[seg]
            } else if (cur is List<*>) {
                if (!INDEX.matches(seg) || seg.toInt() >= cur.size) return null
                cur = cur[seg.toInt()]
            } else return null
        }
        return if (cur is Map<*, *> || cur is List<*>) cur else null
    }

    private fun typeIsNull(m: Any?): Boolean {
        val t = get(m, "type")
        if (t == "null") return true
        if (t is List<*>) {
            for (x in t) if (x != "null") return false
            return true
        }
        return false
    }

    private fun stringEnum(m: Any?): List<Any?>? {
        val e = get(m, "enum")
        if (e is List<*>) {
            for (x in e) if (x !is String) return null
            return e as List<Any?>
        }
        return null
    }

    /**
     * Flatten what a parameter declaration cannot carry: follow local `$ref`s, merge `allOf`, collapse `anyOf` / `oneOf`
     * to its single non-null variant (or to the union of string constants). Unrepresentable parts are flagged in `todo`.
     */
    private fun flatten(s: Any?, c: Ctx, where: String, depth: Int = 0): Map<String, Any?> {
        if (s !is Map<*, *> && s !is List<*>) return LinkedHashMap()
        c.left = (c.left ?: MAX_REF_NODES) - 1
        if (c.left!! < 0) {
            if (c.left == -1) c.todo.add("$where: schema expansion stopped after $MAX_REF_NODES nodes (declared string; refine or drop)")
            return LinkedHashMap()
        }
        if (depth > MAX_REF_DEPTH) {
            c.todo.add("$where: schema nesting or reference chain deeper than $MAX_REF_DEPTH (declared string; refine or drop)")
            return LinkedHashMap()
        }
        var cur: Map<String, Any?> = A2aPca.spread(s)
        if (get(s, "\$ref") is String) {
            val ref = get(s, "\$ref") as String
            val target = pointer(c.root, ref)
            if (target == null) {
                c.todo.add("$where: reference '${if (ref.length > 120) ref.substring(0, 120) else ref}' is not a local reference that resolves (declared string; refine or drop)")
                return LinkedHashMap()
            }
            val siblings = A2aPca.spread(s)
            siblings.remove("\$ref")
            val merged = LinkedHashMap<String, Any?>(flatten(target, c, where, depth + 1))
            merged.putAll(siblings)
            cur = merged
        }
        if (cur["allOf"] is List<*>) {
            val allOf = cur["allOf"] as List<Any?>
            val rest = LinkedHashMap<String, Any?>(cur)
            rest.remove("allOf")
            val parts = ArrayList<Map<String, Any?>>()
            for (m in allOf) parts.add(flatten(m, c, where, depth + 1))
            var acc: Map<String, Any?> = LinkedHashMap()
            for (m in parts) {
                val next = LinkedHashMap<String, Any?>(acc)
                next.putAll(m)
                val props = A2aPca.spread(acc["properties"])
                props.putAll(A2aPca.spread(m["properties"]))
                next["properties"] = props
                val req = iter(acc["required"])
                req.addAll(iter(m["required"]))
                next["required"] = req
                acc = next
            }
            val merged = LinkedHashMap<String, Any?>(acc)
            merged.putAll(rest)
            cur = merged
        }
        val alts = if (cur["anyOf"] != null) cur["anyOf"] else cur["oneOf"]
        if (alts is List<*>) {
            val rest = LinkedHashMap<String, Any?>(cur)
            rest.remove("anyOf")
            rest.remove("oneOf")
            val live = ArrayList<Map<String, Any?>>()
            for (m in alts) {
                val f = flatten(m, c, where, depth + 1)
                if (!typeIsNull(f)) live.add(f)
            }
            if (live.size == 1) {
                val out = LinkedHashMap<String, Any?>(live[0])
                out.putAll(rest)
                return out
            }
            val consts = ArrayList<List<Any?>?>()
            var allConst = true
            for (m in live) {
                if (m["const"] is String) consts.add(arrayListOf<Any?>(m["const"]))
                else {
                    val e = stringEnum(m)
                    if (e == null) allConst = false
                    consts.add(e)
                }
            }
            if (live.size > 1 && allConst) {
                val uniq = LinkedHashSet<Any?>()
                for (l in consts) uniq.addAll(l!!)
                val out = LinkedHashMap<String, Any?>(rest)
                out["type"] = "string"
                out["enum"] = ArrayList<Any?>(uniq)
                return out
            }
            c.todo.add("$where: a union of ${live.size} schemas has no schema representation (declared string; refine or drop)")
            return rest
        }
        if (cur.containsKey("const") && !cur.containsKey("enum") && cur["const"] is String) {
            val out = LinkedHashMap<String, Any?>(cur)
            out["enum"] = arrayListOf<Any?>(cur["const"])
            cur = out
        }
        return cur
    }

    /** JSON Schema property to parameter declaration; sensitivity defaults to `material`, an unrepresentable shape becomes a `string` placeholder flagged in `todo`. */
    private fun declOf(name: String, schema: Any?, required: Boolean, c: Ctx): Map<String, Any?> {
        val s = flatten(schema, c, "action.params.$name")
        val t = typeOf(s)
        val base = LinkedHashMap<String, Any?>()
        base["semantic"] = if (s["x-pca-semantic"] != null) s["x-pca-semantic"] else "unknown"
        base["sensitivity"] = if (s["x-pca-sensitivity"] != null) s["x-pca-sensitivity"] else "material"
        if (!required) base["required"] = false
        if (truthy(s["description"])) base["description"] = slice1024(s["description"])
        if (!truthy(s["x-pca-semantic"])) c.todo.add("action.params.$name: semantic type")
        val enumStrings = stringEnum(s)
        val out = LinkedHashMap<String, Any?>()
        if (t == "integer") {
            out["type"] = "integer"
            out.putAll(base)
            if (safeInt(s["minimum"])) out["min"] = s["minimum"]
            else if (safeInt(s["exclusiveMinimum"])) out["min"] = num(Js.num(s["exclusiveMinimum"])!! + 1)
            if (safeInt(s["maximum"])) out["max"] = s["maximum"]
            else if (safeInt(s["exclusiveMaximum"])) out["max"] = num(Js.num(s["exclusiveMaximum"])!! - 1)
            if (truthy(s["x-pca-unit"])) out["unit"] = s["x-pca-unit"]
            if (truthy(s["x-pca-accumulates-into"])) out["accumulates_into"] = s["x-pca-accumulates-into"]
            return out
        }
        if (t == "boolean") { out["type"] = "boolean"; out.putAll(base); return out }
        if (t == "string" && s["format"] == "date") { out["type"] = "date"; out.putAll(base); return out }
        if (t == "string") {
            out["type"] = "string"
            out.putAll(base)
            if (enumStrings != null) out["values"] = enumStrings
            if (safeInt(s["maxLength"]) && Js.num(s["maxLength"])!! > 0) out["max_len"] = s["maxLength"]
            return out
        }
        if (t == "array") {
            val it = flatten(s["items"], c, "action.params.$name[]")
            val itEnum = stringEnum(it)
            if (truthy(s["uniqueItems"]) && itEnum != null) {
                out["type"] = "set"
                out.putAll(base)
                out["values"] = itEnum
                if (safeInt(s["minItems"])) out["min_items"] = s["minItems"]
                if (safeInt(s["maxItems"])) out["max_items"] = s["maxItems"]
                return out
            }
            val itTy = it["type"]
            val itT: Any? = if (itTy is List<*>) (if (itTy.isEmpty()) UNDEF else itTy[0]) else itTy
            out["type"] = "array"
            out.putAll(base)
            if (itT == "integer") out["items"] = "integer"
            if (safeInt(s["maxItems"])) out["max_items"] = s["maxItems"]
            if (safeInt(s["minItems"])) out["min_items"] = s["minItems"]
            return out
        }
        c.todo.add("action.params.$name: type '${if (t === UNDEF) "undefined" else jsStr(t)}' has no schema representation (declared string; refine or drop)")
        out["type"] = "string"
        out.putAll(base)
        return out
    }

    /** `Array.isArray(t) ? t.find(x => x !== 'null') : t` for the `type` member: the first element other than the string "null" (a JSON null element counts), else undefined. */
    private fun typeOf(s: Map<String, Any?>): Any? {
        if (!s.containsKey("type")) return UNDEF
        val t = s["type"]
        if (t is List<*>) {
            for (x in t) if (x != "null") return x
            return UNDEF
        }
        return t
    }

    /** `description.slice(0, 1024)`: a string or an array slices; any other truthy value has no slice (TypeError). */
    private fun slice1024(d: Any?): Any? {
        if (d is String) return if (d.length > 1024) d.substring(0, 1024) else d
        if (d is List<*>) return ArrayList<Any?>(d.subList(0, Math.min(1024, d.size)))
        throw IllegalStateException("TypeError: slice is not a function")
    }

    private fun isRead(annotations: Any?): Boolean = annotations is Map<*, *> && annotations["readOnlyHint"] == true

    /** Draft the schema and the decisions the developer must still make. [site]: `site`, `aud`, `version`, optional `verbPrefix`. */
    fun draft(tools: List<Any?>, site: Map<String, Any?>): Map<String, Any?> {
        val todo = ArrayList<Any?>()
        val verbs = ArrayList<Map<String, Any?>>()
        for (t in tools) {
            if (t == null) throw IllegalStateException("TypeError: cannot read properties of null (reading 'inputSchema')")
            val c = Ctx(get(t, "inputSchema"), todo)
            val tname = jsStr(if (has(t, "name")) get(t, "name") else "undefined")
            val input = flatten(get(t, "inputSchema"), c, "$tname: inputSchema")
            val props: Any? = if (input["properties"] != null) input["properties"] else LinkedHashMap<String, Any?>()
            val req = LinkedHashSet<Any?>(iter(input["required"]))
            val params = LinkedHashMap<String, Any?>()
            val names = ArrayList<String>(keysOf(props))
            names.sortWith(Comparator { a, b -> Json.compareUtf8(a, b) })
            for (name in names) {
                if (!NAME.matches(name)) {
                    todo.add("$tname: parameter '$name' is not a schema name ([A-Za-z0-9_]{1,64}); rename it")
                    continue
                }
                params["action.params.$name"] = declOf(name, valueOf(props, name), req.contains(name), c)
            }
            val read = isRead(get(t, "annotations"))
            val prefix: Any? = if (site["verbPrefix"] != null) site["verbPrefix"] else ""
            val verb = jsStr(prefix) + tname
            if (!read) todo.add("$verb: reversibility (drafted irreversible)")
            val v = LinkedHashMap<String, Any?>()
            v["verb"] = verb
            v["kind"] = if (read) "read" else "write"
            v["params"] = params
            v["reversibility"] = if (read) "reversible" else "irreversible"
            val mcp = LinkedHashMap<String, Any?>()
            if (has(t, "name")) mcp["tool"] = get(t, "name")
            v["mcp"] = mcp
            if (truthy(get(t, "description"))) v["description"] = slice1024(get(t, "description"))
            verbs.add(v)
        }
        verbs.sortWith(Comparator { a, b -> Json.compareUtf8(a["verb"] as String, b["verb"] as String) })
        val schema = LinkedHashMap<String, Any?>()
        schema["v"] = Json.Num("1")
        schema["kind"] = ActionSchema.ACTION_SCHEMA_KIND
        for (k in listOf("site", "aud", "version")) if (site.containsKey(k)) schema[k] = site[k]
        schema["verbs"] = ArrayList<Any?>(verbs)
        val out = LinkedHashMap<String, Any?>()
        out["schema"] = schema
        out["todo"] = todo
        return out
    }

    /** `Object.keys(o)` of a parsed value (Map keys, list indices, string indices; other values have none). */
    fun keysOf(o: Any?): List<String> {
        val out = ArrayList<String>()
        when (o) {
            is Map<*, *> -> for (k in o.keys) out.add(k as String)
            is List<*> -> for (i in o.indices) out.add(i.toString())
            is String -> for (i in o.indices) out.add(i.toString())
        }
        return out
    }

    fun valueOf(o: Any?, k: String): Any? = when (o) {
        is Map<*, *> -> o[k]
        is List<*> -> o[k.toInt()]
        is String -> o[k.toInt()].toString()
        else -> null
    }
}
