package net.atlasauth.pca.actions.importers

import net.atlasauth.pca.actions.importers.ImportCommon.Budget
import net.atlasauth.pca.actions.importers.ImportCommon.Ctx
import net.atlasauth.pca.actions.importers.ImportCommon.Draft
import net.atlasauth.pca.actions.importers.ImportCommon.addTodo
import net.atlasauth.pca.actions.importers.ImportCommon.clip
import net.atlasauth.pca.actions.importers.ImportCommon.emitDef
import net.atlasauth.pca.actions.importers.ImportCommon.finish
import net.atlasauth.pca.actions.importers.ImportCommon.flattenObject
import net.atlasauth.pca.actions.importers.ImportCommon.leafParam
import net.atlasauth.pca.actions.importers.ImportCommon.newBudget
import net.atlasauth.pca.actions.importers.ImportCommon.newCtx
import net.atlasauth.pca.actions.importers.ImportCommon.paramSeg
import net.atlasauth.pca.actions.importers.ImportCommon.pointer
import net.atlasauth.pca.actions.importers.ImportCommon.resolveSchema
import net.atlasauth.pca.actions.importers.ImportCommon.tokensOf
import net.atlasauth.pca.actions.importers.ImportCommon.verbOf
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Json

/** OpenAPI 3.x and Swagger 2 to drafts: one def per operation; the method gives the initial effects. */
@Suppress("UNCHECKED_CAST")
object OpenApiImporter {
    private val METHODS = listOf("get", "put", "post", "delete", "options", "head", "patch", "trace")
    private val EFFECT_OF = mapOf("get" to "read", "head" to "read", "options" to "read", "trace" to "read", "post" to "create", "put" to "update", "patch" to "update", "delete" to "delete")
    private val NATURAL = setOf("get", "head", "options", "trace", "put", "delete")
    private val BODY_TYPES = listOf("application/json", "application/x-www-form-urlencoded", "multipart/form-data")
    private val VERSIONISH = Regex("(?:v[0-9]+(?:\\.[0-9]+)?|api|rest|public|latest)", RegexOption.IGNORE_CASE)
    private val JSON_SUFFIX = Regex("^application/[^;]*\\+json(?:;|\\z)", RegexOption.IGNORE_CASE)
    private val X_VERB = Regex("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}")
    private val V3 = Regex("3\\.(?s:.*)")

    /** Follow a `$ref` chain (local only, bounded); returns the target (object or array), or null after noting why. */
    private fun deref(c: Ctx, x: Any?, where: String): Any? {
        if (x !is Map<*, *>) return null
        if (Jx.m(x)["\$ref"] !is String) return x
        val seen = LinkedHashSet<String>()
        var cur: Any? = x
        while (cur is Map<*, *> && Jx.m(cur)["\$ref"] is String) {
            val ref = Jx.m(cur)["\$ref"] as String
            if (seen.contains(ref) || seen.size > c.lim.maxRefDepth) { addTodo(c, where, "cyclic_ref", "a reference chain is cyclic or too deep"); return null }
            seen.add(ref)
            val t = pointer(c.root, ref)
            if (t == null) { addTodo(c, where, "unresolved_ref", "reference '${clip(ref, 120)}' does not resolve locally"); return null }
            cur = t
        }
        return cur
    }

    private fun endsWithParam(seg: String): Boolean {
        if (seg.length < 3 || seg[0] != '{' || seg[seg.length - 1] != '}') return false
        for (i in 1 until seg.length - 1) { val ch = seg[i]; if (ch == '\n' || ch == '\r' || ch == ' ' || ch == ' ') return false }
        return true
    }

    /** Path to the noun tokens and whether it ends in a path parameter. */
    private fun pathFacts(path: String): Pair<List<String>, Boolean> {
        val segs = ArrayList<String>()
        for (s in path.split("/")) if (s.isNotEmpty()) segs.add(s)
        val ewp = segs.isNotEmpty() && endsWithParam(segs[segs.size - 1])
        val nouns = ArrayList<String>()
        for (s in segs) if (s.indexOf('{') < 0 && s.indexOf('}') < 0 && !VERSIONISH.matches(s)) nouns.addAll(tokensOf(s))
        return Pair(nouns, ewp)
    }

    /** A Swagger 2 parameter in the OpenAPI 3 shape the rest of the importer reads. */
    private fun swagger2Param(p: Map<String, Any?>): Map<String, Any?> {
        if (p.containsKey("schema") || "body" == p["in"]) return p
        val sch = LinkedHashMap(p)
        val out = LinkedHashMap<String, Any?>()
        for (k in listOf("name", "in", "required", "description")) { if (p.containsKey(k)) out[k] = p[k]; sch.remove(k) }
        out["schema"] = sch
        return out
    }

    private fun lowerTrimType(k: String): String {
        val l = k.lowercase()
        val i = l.indexOf(';')
        return Jx.jsTrim(if (i < 0) l else l.substring(0, i))
    }

    /** The request body schema: Jx.UNDEF when there is none to declare. */
    private fun bodySchemaOf(c: Ctx, op: Map<String, Any?>, params: List<Map<String, Any?>>, swagger: Boolean, where: String): Any? {
        if (swagger) {
            for (q in params) if ("body" == q["in"]) return Jx.getU(q, "schema")
            return Jx.UNDEF
        }
        val rb = deref(c, if (Jx.getU(op, "requestBody") === Jx.UNDEF) null else op["requestBody"], where)
        val content = Jx.get(rb, "content")
        if (content !is Map<*, *>) return Jx.UNDEF
        val keys = ArrayList(Jx.m(content).keys)
        keys.sortWith { a, b -> Json.compareUtf8(a, b) }
        var pick: String? = null
        for (t in BODY_TYPES) {
            for (k in keys) if (lowerTrimType(k) == t) { pick = k; break }
            if (pick != null) break
        }
        if (pick == null) for (k in keys) if (JSON_SUFFIX.containsMatchIn(k)) { pick = k; break }
        if (pick == null) {
            if (keys.isNotEmpty()) {
                val f = ArrayList<String>()
                for (k in keys.subList(0, Math.min(3, keys.size))) f.add(clip(k, 40))
                addTodo(c, where, "body_type", "request body media types (" + f.joinToString(", ") + ") are not form or JSON; the body is not declared")
            }
            return Jx.UNDEF
        }
        return Jx.getU(Jx.m(content)[pick], "schema")
    }

    private fun isIdemKey(name: String): Boolean = name.length == 15 && name.lowercase() == "idempotency-key" && asciiOnly(name)

    private fun asciiOnly(s: String): Boolean { for (ch in s) if (ch.code > 0x7f) return false; return true }

    fun importOpenApi(source: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val c = newCtx("openapi", source, opts)
        if (source !is Map<*, *>) throw ActionKitError("bad_source", "an OpenAPI document must be an object")
        val src = Jx.m(source)
        val swagger = src["swagger"] is String && (src["swagger"] as String).startsWith("2")
        val v3 = src["openapi"] is String && V3.matches(src["openapi"] as String)
        if (!swagger && !v3) throw ActionKitError("bad_source", "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')")
        val paths: Map<String, Any?> = if (src["paths"] is Map<*, *>) Jx.m(src["paths"]) else LinkedHashMap()
        val globalSecurity: List<Any?>? = if (src["security"] is List<*>) Jx.a(src["security"]) else null
        val ns = opts!!["ns"] as String
        val pathKeys = ArrayList(paths.keys)
        pathKeys.sortWith { a, b -> Json.compareUtf8(a, b) }
        for (path in pathKeys) {
            val item0 = deref(c, paths[path], path) ?: continue
            val shared: List<Any?> = if (Jx.get(item0, "parameters") is List<*>) Jx.a(Jx.get(item0, "parameters")) else ArrayList()
            for (method in METHODS) {
                val opO = Jx.get(item0, method)
                if (opO !is Map<*, *>) continue
                val op = Jx.m(opO)
                val where = method.uppercase() + " " + clip(path, 120)
                val oid = op["operationId"]
                val operationId: String? = if (oid is String && oid.isNotEmpty() && oid.length <= 200) oid else null
                val pf = pathFacts(path)
                val nouns = pf.first
                val ewp = pf.second
                val nameRaw: String? = if (op["x-pca-verb"] is String && c.ext.contains("x-pca-verb")) op["x-pca-verb"] as String else null
                val verb: String
                if (nameRaw != null && X_VERB.matches(nameRaw) && nameRaw.startsWith("$ns.")) verb = nameRaw
                else if (operationId != null) verb = verbOf(ns, operationId)
                else {
                    val w = ArrayList(nouns.subList(Math.max(0, nouns.size - 2), nouns.size))
                    w.add(if (method == "get" && !ewp) "list" else method)
                    verb = verbOf(ns, w.joinToString(" "))
                }
                c.root = source
                val bud = newBudget(c)
                // parameters: the operation's own win over the path item's (by in+name)
                val merged = LinkedHashMap<String, Map<String, Any?>>()
                val raws = ArrayList(shared)
                if (op["parameters"] is List<*>) raws.addAll(Jx.a(op["parameters"]))
                for (raw in raws) {
                    val q0o = deref(c, raw, where)
                    if (q0o !is Map<*, *>) continue
                    val q0 = Jx.m(q0o)
                    if (q0["name"] !is String || q0["in"] !is String) continue
                    val q = if (swagger) swagger2Param(q0) else q0
                    merged["${q["in"]}:${q["name"]}"] = q
                }
                val all = ArrayList(merged.values)
                val params = LinkedHashMap<String, Any?>()
                var idemParam: String? = null
                val body = bodySchemaOf(c, op, all, swagger, where)
                if (body !== Jx.UNDEF) {
                    val b = resolveSchema(body, c, bud, "$where: request body")
                    if ("object" == b["type"] || b["properties"] is Map<*, *>) flattenObject(b, c, bud, where, params)
                    else addTodo(c, where, "body_shape", "the request body is not an object schema; it is not declared")
                }
                val sorted = ArrayList(all)
                sorted.sortWith { a, b -> Json.compareUtf8("${a["in"]}:${a["name"]}", "${b["in"]}:${b["name"]}") }
                for (q in sorted) {
                    val name = q["name"] as String
                    val inn = q["in"]
                    if ("header" == inn && isIdemKey(name)) { idemParam = "idempotency_key"; continue }
                    if ("body" == inn) continue
                    if ("path" != inn && "query" != inn && "formData" != inn) {
                        addTodo(c, where, "param_location", clip(inn, 12) + " parameter '" + clip(name, 60) + "' is not an action parameter (path, query and body only)")
                        continue
                    }
                    val sname = paramSeg(name)
                    if (sname != name) addTodo(c, "$where: $name", "renamed_param", "parameter '" + clip(name, 80) + "' is declared as '" + sname + "'")
                    var taken = params.containsKey(sname)
                    if (!taken) for (k in params.keys) if (k.startsWith("$sname.")) { taken = true; break }
                    if (taken) {
                        addTodo(c, "$where: $name", "skipped_param", "'$sname' is declared by the body and by a $inn parameter; kept the body's")
                        continue
                    }
                    if (params.size >= 64) { addTodo(c, where, "too_many_params", "more than 64 parameters; the rest are dropped"); break }
                    val merge = LinkedHashMap<String, Any?>()
                    val qs = q["schema"]
                    Jx.spread(merge, qs ?: LinkedHashMap<String, Any?>())
                    val qsDesc = if (qs == null) null else Jx.get(qs, "description")
                    if (Jx.truthy(q["description"]) && !Jx.truthy(qsDesc)) merge["description"] = q["description"]
                    val sch = resolveSchema(merge, c, bud, "$where: $name")
                    params[sname] = leafParam(sch, "path" == inn || q["required"] == true, c, bud, "$where: $name")
                }
                if (idemParam != null && !params.containsKey(idemParam)) params[idemParam] = Jx.obj("type", "string", "required", false, "max_len", Jx.n(255))
                else idemParam = null
                val scope = if (ewp || method == "post") "one" else "set"
                val natural = NATURAL.contains(method)
                // security scopes are a note, not a field
                val sec: List<Any?>? = if (op["security"] is List<*>) Jx.a(op["security"]) else globalSecurity
                val scopes = ArrayList<String>()
                if (sec != null) {
                    val u = LinkedHashSet<String>()
                    for (r in sec) if (r is Map<*, *>) for (v in Jx.m(r).values) if (v is List<*>) for (x in v) if (x is String) u.add(x)
                    scopes.addAll(u)
                    scopes.sortWith { a, b -> Json.compareUtf8(a, b) }
                }
                if (scopes.isNotEmpty()) {
                    val f = ArrayList<String>()
                    for (s in scopes.subList(0, Math.min(12, scopes.size))) f.add(clip(s, 60))
                    addTodo(c, where, "required_scope", "requires scope: " + f.joinToString(", "))
                }
                if (op["deprecated"] == true) addTodo(c, where, "deprecated", "the operation is marked deprecated")
                for (k in Jx.keys(op)) if (k.startsWith("x-") && !c.ext.contains(k)) { addTodo(c, where, "extension_ignored", "extension '" + clip(k, 60) + "' is ignored (not allow-listed)"); break }
                val d = Draft()
                d.name = if (operationId != null) operationId else where
                d.noAlias = operationId == null
                d.verb = verb
                d.title = if (op["summary"] is String && (op["summary"] as String).isNotEmpty()) op["summary"] else operationId
                d.description = if (op["description"] is String) op["description"] else if (op["summary"] is String) op["summary"] else null
                d.effects = arrayListOf(EFFECT_OF[method]!!)
                d.scope = scope
                d.params = params
                if (idemParam != null) d.idempotency = Jx.obj("mode", "key_param", "param", idemParam)
                else if (natural) d.idempotency = Jx.obj("mode", "natural")
                d.bindings = Jx.obj("openapi", Jx.obj("operationId", operationId ?: clip(method + "_" + path, 200), "method", method.uppercase(), "path", clip(path, 240)))
                emitDef(c, d)
            }
        }
        return finish(c)
    }
}
