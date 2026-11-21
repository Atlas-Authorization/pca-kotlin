package net.atlasauth.pca.actions.importers

import net.atlasauth.pca.actions.importers.ImportCommon.Budget
import net.atlasauth.pca.actions.importers.ImportCommon.Ctx
import net.atlasauth.pca.actions.importers.ImportCommon.Draft
import net.atlasauth.pca.actions.importers.ImportCommon.addTodo
import net.atlasauth.pca.actions.importers.ImportCommon.clip
import net.atlasauth.pca.actions.importers.ImportCommon.emitDef
import net.atlasauth.pca.actions.importers.ImportCommon.finish
import net.atlasauth.pca.actions.importers.ImportCommon.flattenObject
import net.atlasauth.pca.actions.importers.ImportCommon.newBudget
import net.atlasauth.pca.actions.importers.ImportCommon.newCtx
import net.atlasauth.pca.actions.importers.ImportCommon.putProp
import net.atlasauth.pca.actions.importers.ImportCommon.withTrait
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Json

/**
 * GraphQL SDL or introspection JSON to drafts. Query fields are reads, Mutation fields are writes, Subscription fields are streaming
 * reads; arguments and input objects are flattened to dotted params. There is no method signal; everything stays `unreviewed`.
 */
@Suppress("UNCHECKED_CAST")
object GraphqlImporter {
    // ---- model ----

    /** `named` (name), `list` (of) or `nonnull` (of). */
    class GqlType internal constructor(@JvmField val k: String, @JvmField val name: String?, @JvmField val of: GqlType?) {
        internal fun toJson(): MutableMap<String, Any?> = if ("named" == k) Jx.obj("k", k, "name", name) else Jx.obj("k", k, "of", of!!.toJson())
        companion object { internal fun named(n: String): GqlType = GqlType("named", n, null) }
    }

    class GqlArg internal constructor(@JvmField val name: String, @JvmField val type: GqlType, @JvmField val desc: String?) {
        internal fun toJson(): MutableMap<String, Any?> {
            val m = Jx.obj("name", name, "type", type.toJson())
            if (desc != null) m["desc"] = desc
            return m
        }
    }

    class GqlField internal constructor(@JvmField val name: String, @JvmField val args: List<GqlArg>, @JvmField val type: GqlType, @JvmField val deprecated: Boolean, @JvmField val desc: String?) {
        internal fun toJson(): MutableMap<String, Any?> {
            val das = ArrayList<Any?>()
            for (a in args) das.add(a.toJson())
            val m = Jx.obj("name", name, "args", das, "type", type.toJson(), "deprecated", deprecated)
            if (desc != null) m["desc"] = desc
            return m
        }
    }

    class GqlTypeDef internal constructor(@JvmField val kind: String, @JvmField val name: String, @JvmField val fields: MutableList<GqlField>, @JvmField val values: MutableList<String>)

    class GqlSchema {
        @JvmField val types: MutableMap<String, GqlTypeDef> = LinkedHashMap()
        @JvmField var query: String? = null
        @JvmField var mutation: String? = null
        @JvmField var subscription: String? = null

        /** `{types: [[name, {kind, name, fields, values}]...], query?, mutation?, subscription?}`. */
        fun toJson(): MutableMap<String, Any?> {
            val ts = ArrayList<Any?>()
            for ((k, v) in types) {
                val fs = ArrayList<Any?>()
                for (f in v.fields) fs.add(f.toJson())
                ts.add(Jx.list(k, Jx.obj("kind", v.kind, "name", v.name, "fields", fs, "values", ArrayList<Any?>(v.values))))
            }
            val m = Jx.obj("types", ts)
            if (query != null) m["query"] = query
            if (mutation != null) m["mutation"] = mutation
            if (subscription != null) m["subscription"] = subscription
            return m
        }
    }

    // ---- SDL lexer ----

    private class Tok(@JvmField val t: String, @JvmField val v: String)

    private fun nameStart(c: Char): Boolean = c == '_' || (c in 'A'..'Z') || (c in 'a'..'z')
    private fun nameChar(c: Char): Boolean = nameStart(c) || (c in '0'..'9')

    private fun lex(src: String, maxTokens: Int): List<Tok> {
        val out = ArrayList<Tok>()
        var i = 0
        val n = src.length
        while (i < n) {
            val ch = src[i]
            val push: Tok
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ',' || ch == '﻿') { i++; continue }
            if (ch == '#') { while (i < n && src[i] != '\n') i++; continue }
            if (ch == '"') {
                if (src.startsWith("\"\"\"", i)) {
                    var j = i + 3
                    val s = StringBuilder()
                    while (j < n && !src.startsWith("\"\"\"", j)) {
                        if (src.startsWith("\\\"\"\"", j)) { s.append("\"\"\""); j += 4 } else s.append(src[j++])
                    }
                    if (j >= n) throw ActionKitError("bad_source", "unterminated GraphQL block string")
                    push = Tok("str", s.toString())
                    i = j + 3
                } else {
                    var j = i + 1
                    val s = StringBuilder()
                    while (j < n && src[j] != '"') {
                        if (src[j] == '\n') throw ActionKitError("bad_source", "unterminated GraphQL string")
                        if (src[j] == '\\') { if (j + 1 < n) s.append(src[j + 1]); j += 2 } else s.append(src[j++])
                    }
                    if (j >= n) throw ActionKitError("bad_source", "unterminated GraphQL string")
                    push = Tok("str", s.toString())
                    i = j + 1
                }
            } else if (nameStart(ch)) {
                var j = i + 1
                while (j < n && nameChar(src[j])) j++
                push = Tok("name", src.substring(i, j))
                i = j
            } else if (ch == '-' || (ch in '0'..'9')) {
                var j = i + 1
                while (j < n && (src[j] == '-' || src[j] == '+' || src[j] == '.' || (src[j] in '0'..'9') || src[j] == 'e' || src[j] == 'E')) j++
                push = Tok("int", src.substring(i, j))
                i = j
            } else if (src.startsWith("...", i)) { push = Tok("punct", "..."); i += 3 }
            else if ("!$&():=@[]{|}".indexOf(ch) >= 0) { push = Tok("punct", ch.toString()); i++ }
            else throw ActionKitError("bad_source", "unexpected character in GraphQL source at offset $i")
            if (out.size >= maxTokens) throw ActionKitError("import_limit", "the GraphQL source has too many tokens")
            out.add(push)
        }
        if (out.size >= maxTokens) throw ActionKitError("import_limit", "the GraphQL source has too many tokens")
        out.add(Tok("eof", ""))
        return out
    }

    // ---- SDL parser (type system definitions only; executable documents are rejected) ----

    private class P(val toks: List<Tok>, val schema: GqlSchema, val maxDepth: Int) {
        var i = 0

        fun cur(): Tok = toks[i]
        fun next(): Tok { val t = toks[i]; if ("eof" != t.t) i++; return t }
        fun isV(v: String): Boolean = "str" != cur().t && cur().v == v
        fun eat(v: String): Boolean { if (isV(v)) { i++; return true }; return false }
        fun expect(v: String) { if (!eat(v)) throw ActionKitError("bad_source", "GraphQL parse error: expected '$v' near '${clip(cur().v, 30)}'") }
        fun name(): String { val t = next(); if ("name" != t.t) throw ActionKitError("bad_source", "GraphQL parse error: expected a name near '${clip(t.v, 30)}'"); return t.v }
        fun desc(): String? = if ("str" == cur().t) next().v else null
        fun eof(): Boolean = "eof" == cur().t

        fun type(depth: Int): GqlType {
            if (depth > maxDepth) throw ActionKitError("import_limit", "GraphQL type nesting is too deep")
            val t: GqlType
            if (eat("[")) { t = GqlType("list", null, type(depth + 1)); expect("]") } else t = GqlType.named(name())
            return if (eat("!")) GqlType("nonnull", null, t) else t
        }

        /** Skip a constant value (default values, directive arguments). */
        fun value(depth: Int) {
            if (depth > maxDepth) throw ActionKitError("import_limit", "GraphQL value nesting is too deep")
            val t = cur()
            if ("str" == t.t) { i++; return }
            if ("int" == t.t || "name" == t.t) { i++; return }
            if (eat("[")) { while (!isV("]") && !eof()) value(depth + 1); expect("]"); return }
            if (eat("{")) { while (!isV("}") && !eof()) { name(); expect(":"); value(depth + 1) }; expect("}"); return }
            if (eat("$")) { name(); return }
            throw ActionKitError("bad_source", "GraphQL parse error: unexpected '${clip(t.v, 30)}'")
        }

        fun directives(): Boolean {
            var deprecated = false
            while (eat("@")) {
                val n = name()
                if (n == "deprecated") deprecated = true
                if (eat("(")) { while (!isV(")") && !eof()) { name(); expect(":"); value(0) }; expect(")") }
            }
            return deprecated
        }

        fun args(): List<GqlArg> {
            val out = ArrayList<GqlArg>()
            if (!eat("(")) return out
            while (!isV(")")) {
                if (eof()) throw ActionKitError("bad_source", "GraphQL parse error: unterminated argument list")
                var desc = desc()
                if (desc != null && desc.isEmpty()) desc = null
                val name = name()
                expect(":")
                val type = type(0)
                if (eat("=")) value(0)
                directives()
                out.add(GqlArg(name, type, desc))
            }
            expect(")")
            return out
        }

        fun fields(input: Boolean): MutableList<GqlField> {
            val out = ArrayList<GqlField>()
            if (!eat("{")) return out
            while (!isV("}")) {
                if (eof()) throw ActionKitError("bad_source", "GraphQL parse error: unterminated field list")
                var desc = desc()
                if (desc != null && desc.isEmpty()) desc = null
                val name = name()
                val args: List<GqlArg> = if (input) ArrayList() else args()
                expect(":")
                val type = type(0)
                if (input && eat("=")) value(0)
                val dep = directives()
                out.add(GqlField(name, args, type, dep, desc))
            }
            expect("}")
            return out
        }

        fun def() {
            desc()
            val kw = name()
            if (kw == "extend") { def(); return }
            if (kw == "schema") {
                directives()
                expect("{")
                while (!isV("}")) {
                    if (eof()) throw ActionKitError("bad_source", "GraphQL parse error: unterminated schema block")
                    val op = name(); expect(":"); val ty = name()
                    if (op == "query") schema.query = ty else if (op == "mutation") schema.mutation = ty else if (op == "subscription") schema.subscription = ty
                }
                expect("}")
                return
            }
            if (kw == "scalar") { val n = name(); directives(); merge(GqlTypeDef("scalar", n, ArrayList(), ArrayList())); return }
            if (kw == "directive") {
                expect("@"); name(); args()
                if (cur().v == "repeatable") i++
                if (cur().v == "on") i++
                eat("|")
                name()
                while (eat("|")) name()
                return
            }
            if (kw == "type" || kw == "interface" || kw == "input") {
                val n = name()
                if (cur().v == "implements") { i++; eat("&"); name(); while (eat("&")) name() }
                directives()
                merge(GqlTypeDef(if (kw == "type") "object" else if (kw == "input") "input" else "interface", n, fields(kw == "input"), ArrayList()))
                return
            }
            if (kw == "union") {
                val n = name(); directives()
                if (eat("=")) { eat("|"); name(); while (eat("|")) name() }
                merge(GqlTypeDef("union", n, ArrayList(), ArrayList()))
                return
            }
            if (kw == "enum") {
                val n = name(); directives()
                val values = ArrayList<String>()
                if (eat("{")) {
                    while (!isV("}")) {
                        if (eof()) throw ActionKitError("bad_source", "GraphQL parse error: unterminated enum")
                        desc(); values.add(name()); directives()
                    }
                    expect("}")
                }
                merge(GqlTypeDef("enum", n, ArrayList(), values))
                return
            }
            throw ActionKitError("bad_source", "GraphQL parse error: unsupported definition '${clip(kw, 30)}' (only type-system definitions are imported)")
        }

        fun merge(d: GqlTypeDef) {
            val old = schema.types[d.name]
            if (old == null) { schema.types[d.name] = d; return }
            old.fields.addAll(d.fields)
            old.values.addAll(d.values)
        }
    }

    @JvmStatic
    fun parseGraphqlSdl(src: String): GqlSchema = parseGraphqlSdl(src, 2_000_000)

    @JvmStatic
    fun parseGraphqlSdl(src: String, maxTokens: Int): GqlSchema {
        val toks = lex(src, maxTokens)
        val schema = GqlSchema()
        val p = P(toks, schema, 32)
        while (!p.eof()) p.def()
        return schema
    }

    // ---- introspection to model ----

    private fun introspectType(t: Any?, depth: Int): GqlType {
        if (depth > 16 || t !is Map<*, *>) throw ActionKitError("bad_source", "malformed introspection type reference")
        val m = Jx.m(t)
        if ("NON_NULL" == m["kind"]) return GqlType("nonnull", null, introspectType(m["ofType"], depth + 1))
        if ("LIST" == m["kind"]) return GqlType("list", null, introspectType(m["ofType"], depth + 1))
        val nm = m["name"]
        if (nm !is String) throw ActionKitError("bad_source", "malformed introspection type reference")
        return GqlType.named(nm)
    }

    private fun rootName(s: Map<String, Any?>, k: String): String? {
        val o = s[k]
        return if (o is Map<*, *> && Jx.m(o)["name"] is String) Jx.m(o)["name"] as String else null
    }

    private fun fieldOf(f: Any?): GqlField? {
        if (f !is Map<*, *> || Jx.m(f)["name"] !is String) return null
        val m = Jx.m(f)
        val args = ArrayList<GqlArg>()
        if (m["args"] is List<*>) {
            for (a in Jx.a(m["args"])) {
                if (a !is Map<*, *> || Jx.m(a)["name"] !is String) continue
                args.add(GqlArg(Jx.m(a)["name"] as String, introspectType(Jx.m(a)["type"], 0), if (Jx.m(a)["description"] is String) Jx.m(a)["description"] as String else null))
            }
        }
        val type = if (!m.containsKey("type")) GqlType.named("String") else introspectType(m["type"], 0)
        return GqlField(m["name"] as String, args, type, m["isDeprecated"] == true, if (m["description"] is String) m["description"] as String else null)
    }

    private val KINDS = mapOf("OBJECT" to "object", "INPUT_OBJECT" to "input", "ENUM" to "enum", "SCALAR" to "scalar", "INTERFACE" to "interface", "UNION" to "union")

    @JvmStatic
    fun fromIntrospection(doc: Any?): GqlSchema {
        val root: Any? = if (doc is Map<*, *> && Jx.m(doc)["data"] is Map<*, *>) Jx.m(doc)["data"] else doc
        val s: Any? = if (root is Map<*, *> && Jx.m(root)["__schema"] is Map<*, *>) Jx.m(root)["__schema"] else null
        if (s == null || Jx.m(s)["types"] !is List<*>) throw ActionKitError("bad_source", "not a GraphQL introspection result (no __schema.types)")
        val sm = Jx.m(s)
        val schema = GqlSchema()
        val q = rootName(sm, "queryType")
        val m = rootName(sm, "mutationType")
        val sub = rootName(sm, "subscriptionType")
        if (q != null && q.isNotEmpty()) schema.query = q
        if (m != null && m.isNotEmpty()) schema.mutation = m
        if (sub != null && sub.isNotEmpty()) schema.subscription = sub
        for (to in Jx.a(sm["types"])) {
            if (to !is Map<*, *>) continue
            val t = Jx.m(to)
            val name = t["name"]
            val rk = t["kind"]
            if (name !is String || rk !is String) continue
            if (name.startsWith("__")) continue
            val kind = KINDS[rk] ?: continue
            val fieldsRaw = if (kind == "input") t["inputFields"] else t["fields"]
            val fields = ArrayList<GqlField>()
            if (fieldsRaw is List<*>) for (f in Jx.a(fieldsRaw)) { val g = fieldOf(f); if (g != null) fields.add(g) }
            val values = ArrayList<String>()
            if (t["enumValues"] is List<*>) for (e in Jx.a(t["enumValues"])) if (e is Map<*, *> && Jx.m(e)["name"] is String) values.add(Jx.m(e)["name"] as String)
            schema.types[name] = GqlTypeDef(kind, name, fields, values)
        }
        return schema
    }

    // ---- model to JSON-schema-like to params ----

    private fun scalar(name: String): MutableMap<String, Any?>? = when (name) {
        "Int" -> Jx.obj("type", "integer", "format", "int32")
        "String", "ID" -> Jx.obj("type", "string")
        "Boolean" -> Jx.obj("type", "boolean")
        "Float" -> Jx.obj("type", "number")
        "Date" -> Jx.obj("type", "string", "format", "date")
        "DateTime" -> Jx.obj("type", "string", "format", "date-time")
        "Email" -> Jx.obj("type", "string", "format", "email")
        "UUID" -> Jx.obj("type", "string", "format", "uuid")
        "URL", "URI" -> Jx.obj("type", "string", "format", "url")
        else -> null
    }

    private class R(val s: MutableMap<String, Any?>, val nonnull: Boolean)

    /** A GraphQL type as a JSON-schema-like node; input objects expand with a cycle guard and a node budget. */
    private fun schemaOf(t: GqlType, gs: GqlSchema, c: Ctx, bud: Budget, stack: List<String>, where: String): R {
        var nonnull = false
        var cur = t
        while ("nonnull" == cur.k) { nonnull = true; cur = cur.of!! }
        if ("list" == cur.k) return R(Jx.obj("type", "array", "items", schemaOf(cur.of!!, gs, c, bud, stack, where).s), nonnull)
        val name = cur.name!!
        if (bud.left-- <= 0) {
            if (!bud.exhausted) { bud.exhausted = true; addTodo(c, where, "ref_budget", "type expansion stopped at the node budget (declared string; refine or drop)") }
            return R(LinkedHashMap(), nonnull)
        }
        val sc = scalar(name)
        if (sc != null) return R(sc, nonnull)
        val def = gs.types[name]
        if (def == null) { addTodo(c, where, "unknown_type", "type '${clip(name, 60)}' is not defined in the schema (declared string)"); return R(LinkedHashMap(), nonnull) }
        if (def.kind == "enum") return R(Jx.obj("type", "string", "enum", ArrayList<Any?>(LinkedHashSet(def.values))), nonnull)
        if (def.kind == "scalar") return R(Jx.obj("type", "string"), nonnull)
        if (def.kind == "input") {
            if (stack.contains(name)) { addTodo(c, where, "cyclic_ref", "input type '${clip(name, 60)}' is recursive (declared string; refine or drop)"); return R(LinkedHashMap(), nonnull) }
            val properties = LinkedHashMap<String, Any?>()
            val required = ArrayList<Any?>()
            val ns = ArrayList(stack)
            ns.add(name)
            for (f in def.fields) {
                val r = schemaOf(f.type, gs, c, bud, ns, where)
                val p = LinkedHashMap(r.s)
                if (Jx.truthy(f.desc)) p["description"] = f.desc
                putProp(properties, f.name, p)
                if (r.nonnull) required.add(f.name)
            }
            return R(Jx.obj("type", "object", "properties", properties, "required", required), nonnull)
        }
        addTodo(c, where, "output_type", "type '${clip(name, 60)}' is an output type and cannot be an argument (declared string)")
        return R(LinkedHashMap(), nonnull)
    }

    @JvmStatic
    fun importGraphql(source: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val c = newCtx("graphql", source, opts)
        val gs = if (source is String) parseGraphqlSdl(source) else fromIntrospection(source)
        val roots = listOf(
            listOf(gs.query ?: "Query", "query"),
            listOf(gs.mutation ?: "Mutation", "mutation"),
            listOf(gs.subscription ?: "Subscription", "subscription"),
        )
        for (ro in roots) {
            val rt = gs.types[ro[0]] ?: continue
            val op = ro[1]
            val fs = ArrayList(rt.fields)
            fs.sortWith { a, b -> Json.compareUtf8(a.name, b.name) }
            for (f in fs) {
                val where = op + " " + clip(f.name, 80)
                c.root = null
                val bud = newBudget(c)
                val properties = LinkedHashMap<String, Any?>()
                val required = ArrayList<Any?>()
                for (a in f.args) {
                    val r = schemaOf(a.type, gs, c, bud, ArrayList(), where + "(" + a.name + ")")
                    val p = LinkedHashMap(r.s)
                    if (Jx.truthy(a.desc)) p["description"] = a.desc
                    putProp(properties, a.name, p)
                    if (r.nonnull) required.add(a.name)
                }
                val params = LinkedHashMap<String, Any?>()
                flattenObject(Jx.obj("type", "object", "properties", properties, "required", required), c, bud, where, params)
                if (f.deprecated) addTodo(c, where, "deprecated", "the field is marked @deprecated")
                val d = Draft()
                d.name = f.name
                d.title = if (Jx.truthy(f.desc)) f.desc!!.split("\n")[0] else f.name
                d.description = f.desc
                d.effects = listOf(if (op == "mutation") "update" else "read")
                d.scope = "one"
                d.params = params
                if (op == "subscription") d.traits = withTrait(null, "pca.bulk")
                if (op != "mutation") d.idempotency = Jx.obj("mode", "natural")
                d.bindings = Jx.obj("graphql", Jx.obj("op", op, "field", clip(f.name, 200)))
                emitDef(c, d)
            }
        }
        return finish(c)
    }
}
