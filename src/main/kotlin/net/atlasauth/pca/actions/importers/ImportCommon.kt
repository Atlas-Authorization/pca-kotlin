package net.atlasauth.pca.actions.importers

import java.text.Normalizer
import java.util.TreeSet
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * What every importer shares: result shapes, text hygiene, verb naming, the bounded `$ref` resolver, the JSON Schema to
 * parameter flattening, and the single place a draft def is assembled (always `unreviewed`). Sources, reports and defs are
 * JSON trees (Map / List / String / Boolean / Json.Num / null).
 */
@Suppress("UNCHECKED_CAST")
object ImportCommon {
    @JvmField val IMPORT_KINDS: List<String> = listOf("openapi", "mcp", "graphql", "grpc", "asyncapi", "jsonschema")
    @JvmField val DEFAULT_EXTENSIONS: List<String> = listOf("x-pca-verb", "x-pca-role", "x-pca-internal")

    internal val NS_RE = Regex("[a-z][a-z0-9_]{0,31}")
    internal val VERB_RE = Regex("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}")
    internal val ALIAS_RE = Regex("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,5}")
    private val ID_ROLE_RE = Regex("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}")
    private val X_ROLE_RE = Regex("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}")
    private val RTYPE_RE = Regex("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,4}")
    private const val MAX_TITLE_BYTES = 120
    private const val MAX_DESCRIPTION_BYTES = 1024
    private const val MAX_DEF_PARAMS = 64
    private const val MAX_PARAM_PATH_DEPTH = 3

    private val CORE_ROLES = listOf(
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    )

    // ---- context ----

    /** Per-import state: the namespace, limits, notes, source reference and what is already emitted. */
    class Ctx internal constructor(
        @JvmField val ns: String,
        @JvmField val kind: String,
        @JvmField val lim: ImportLimits,
        @JvmField val source: MutableMap<String, Any?>,
        @JvmField val ext: Set<Any?>,
        /** Parsed-source root that `#/...` references resolve in. */
        @JvmField var root: Any?,
    ) {
        @JvmField val todo: MutableList<Any?> = ArrayList()
        internal val verbs = LinkedHashSet<String>()
        internal val aliases = LinkedHashMap<String, String>()
        internal val defs: MutableList<Any?> = ArrayList()
    }

    /** The expansion budget of one operation: every schema node visited costs one. */
    class Budget internal constructor(@JvmField var left: Int) {
        @JvmField var exhausted: Boolean = false
    }

    fun newBudget(c: Ctx): Budget = Budget(c.lim.maxRefNodes.toInt())

    fun newCtx(kind: String, source: Any?, opts: Map<String, Any?>?): Ctx {
        val nso = opts?.get("ns")
        if (nso !is String || !NS_RE.matches(nso)) throw ActionKitError("bad_ns", "ns must match [a-z][a-z0-9_]{0,31}")
        val lim = ImportLimits.resolve(opts["limits"])
        val digest: String
        if (source is String) {
            lim.textSizeCheck(source)
            digest = Keys.b64u(Jx.sha256(Jx.utf8(source)))
        } else if (source is ByteArray) {
            if (source.size > lim.maxBytes) throw ActionKitError("import_limit", "the source is larger than ${lim.maxBytes} bytes")
            digest = Keys.b64u(Jx.sha256(source))
        } else {
            lim.checkParsed(source)
            digest = Keys.b64u(Jx.sha256(Jx.utf8(Json.canonicalize(source))))
        }
        val now: Any? = if (opts["now"] == null) Jx.n(0) else opts["now"]
        if (!Jx.isSafe(now) || Jx.num(now)!! < 0) throw ActionKitError("bad_opts", "now must be a non-negative integer")
        val uri: Any? = if (opts["uri"] == null) "source:$kind" else opts["uri"]
        val lic: Any? = if (opts["licence"] == null) "unknown" else opts["licence"]
        val src = Jx.obj("kind", kind, "uri", clip(uri, 2048), "spec_digest", digest, "licence", clip(lic, 128), "imported_at", now)
        val ext = LinkedHashSet<Any?>()
        val ae = opts["allowExtensions"]
        if (ae == null) ext.addAll(DEFAULT_EXTENSIONS) else ext.addAll(Jx.spreadList(ae))
        return Ctx(nso, kind, lim, src, ext, source)
    }

    fun addTodo(c: Ctx, where: String, code: String, message: String) {
        // a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
        if (c.todo.size < 5000) c.todo.add(Jx.obj("where", clip(where, 200), "code", code, "message", clip(message, 400)))
        else if (c.todo.size == 5000) c.todo.add(Jx.obj("where", "*", "code", "todo_truncated", "message", "further notes omitted"))
    }

    fun finish(c: Ctx): Map<String, Any?> = Jx.obj("defs", c.defs, "todo", c.todo, "source", c.source)

    // ---- text hygiene ----

    private fun ctrl(c: Char): Boolean {
        val x = c.code
        return (x <= 8) || x == 0x0B || x == 0x0C || (x in 0x0E..0x1F) || (x in 0x7F..0x9F) || x == 0x2028 || x == 0x2029 || (x in 0x202A..0x202E) || (x in 0x2066..0x2069)
    }

    private fun u8cp(cp: Int): Int = if (cp < 0x80) 1 else if (cp < 0x800) 2 else if (cp < 0x10000) 3 else 4

    /** NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to `maxBytes` at a code point. */
    fun clip(o: Any?, maxBytes: Int): String {
        if (o !is String) return ""
        val s: String = o
        val b = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { b.append(c).append(s[i + 1]); i++ }
                i++
                continue
            }
            if (Character.isLowSurrogate(c)) { i++; continue }
            b.append(if (ctrl(c)) ' ' else c)
            i++
        }
        val n = Normalizer.normalize(b.toString(), Normalizer.Form.NFC)
        val w = StringBuilder(n.length)
        var inSp = false
        for (c in n) {
            if (Jx.jsSpace(c)) { if (!inSp) w.append(' '); inSp = true } else { w.append(c); inSp = false }
        }
        val t = Jx.jsTrim(w.toString())
        if (Jx.u8(t) <= maxBytes) return t
        val out = StringBuilder()
        var used = 0
        var k = 0
        while (k < t.length) {
            val cp = t.codePointAt(k)
            if (used + u8cp(cp) > maxBytes) break
            used += u8cp(cp)
            out.appendCodePoint(cp)
            k += Character.charCount(cp)
        }
        return Jx.jsTrim(out.toString())
    }

    /** First non-empty of the arguments, clipped. */
    fun firstText(max: Int, vararg xs: Any?): String {
        for (x in xs) { val t = clip(x, max); if (t.isNotEmpty()) return t }
        return ""
    }

    // ---- tokens and verbs ----

    private val CAMEL1 = Regex("([a-z0-9])([A-Z])")
    private val CAMEL2 = Regex("([A-Z]+)([A-Z][a-z])")

    /** Lowercase word tokens of a name: camelCase, snake, kebab, dotted and slashed names alike. */
    fun tokensOf(name: Any?): List<String> {
        val s0 = Normalizer.normalize(Jx.jsStr(name), Normalizer.Form.NFKD)
        val b = StringBuilder(s0.length)
        for (c in s0) if (c.code < 0x300 || c.code > 0x36F) b.append(c)
        val s = CAMEL2.replace(CAMEL1.replace(b.toString(), "$1 $2"), "$1 $2").lowercase()
        val out = ArrayList<String>()
        var start = -1
        for (i in 0..s.length) {
            val ok = i < s.length && ((s[i] in 'a'..'z') || (s[i] in '0'..'9'))
            if (ok && start < 0) start = i
            if (!ok && start >= 0) { out.add(s.substring(start, i)); start = -1 }
        }
        return out
    }

    /** Words that name an action; they lead or trail a name and become the last verb segment. */
    @JvmField val ACTION_WORDS: Set<String> = setOf(
        "get", "list", "read", "fetch", "find", "search", "query", "show", "describe", "create", "add", "new", "make", "insert", "post", "put", "set", "update", "patch", "edit", "modify",
        "delete", "remove", "destroy", "drop", "send", "notify", "publish", "invite", "cancel", "refund", "charge", "pay", "run", "exec", "execute", "invoke", "start", "stop",
        "enable", "disable", "approve", "reject", "close", "open", "merge", "export", "import", "upload", "download", "subscribe", "unsubscribe", "revoke", "grant", "transfer",
    )

    private fun seg(toks: List<String>): String {
        val s = toks.joinToString("_")
        if (s.length <= 32) return s
        var h = Keys.b64u(Jx.sha256(Jx.utf8(s))).replace(Regex("[^A-Za-z0-9]"), "").lowercase()
        h = if (h.length > 4) h.substring(0, 4) else h
        val pad = StringBuilder(h)
        while (pad.length < 4) pad.append('0')
        return s.substring(0, 27) + "_" + pad
    }

    /**
     * A verb `<ns>.<noun...>.<action>` from a raw operation name. Explicit separators (`. / :` and white space) each become a
     * segment; a camelCase or snake name with a leading or trailing action word becomes `<noun>.<action>`; any other name is one segment.
     */
    fun verbOf(ns: String, raw: Any?): String {
        val r = Jx.jsStr(raw)
        val parts = ArrayList<List<String>>()
        val cur = StringBuilder()
        for (i in 0..r.length) {
            if (i == r.length || r[i] == '.' || r[i] == '/' || r[i] == ':' || Jx.jsSpace(r[i])) {
                val t = tokensOf(cur.toString())
                if (t.isNotEmpty()) parts.add(t)
                cur.setLength(0)
            } else cur.append(r[i])
        }
        var segs = ArrayList<String>()
        if (parts.size >= 2) { for (p in parts) segs.add(seg(p)) }
        else {
            val t = if (parts.isEmpty()) listOf("op") else parts[0]
            if (t.size >= 2 && ACTION_WORDS.contains(t[0])) { segs.add(seg(t.subList(1, t.size))); segs.add(seg(listOf(t[0]))) }
            else if (t.size >= 2 && ACTION_WORDS.contains(t[t.size - 1])) { segs.add(seg(t.subList(0, t.size - 1))); segs.add(seg(listOf(t[t.size - 1]))) }
            else segs.add(seg(t))
        }
        if (segs.size > 5) { val k = ArrayList(segs.subList(0, 2)); k.addAll(segs.subList(segs.size - 3, segs.size)); segs = k }
        val v = ns + "." + segs.joinToString(".")
        if (!VERB_RE.matches(v) || Jx.u8(v) > 128) return "$ns.op"
        return v
    }

    /** The short NL-layer alias of a raw name (snake tokens), or null when it is not a valid alias or equals the verb. */
    fun aliasOf(raw: Any?, verb: String?): String? {
        val a = tokensOf(raw).joinToString("_")
        return if (a.isNotEmpty() && a.length <= 64 && ALIAS_RE.matches(a) && a != verb) a else null
    }

    /** "createCustomer" to "Create customer": the title when the source gave none. */
    fun humanize(name: Any?): String {
        val t = tokensOf(name)
        if (t.isEmpty()) return ""
        val b = StringBuilder(t[0].substring(0, 1).uppercase()).append(t[0].substring(1))
        for (i in 1 until t.size) b.append(' ').append(t[i])
        return b.toString()
    }

    /** Make `verb` unique inside the import (`_2`, `_3` on the last segment), noting the collision. */
    fun uniqueVerb(c: Ctx, verb: String, where: String): String {
        if (!c.verbs.contains(verb)) return verb
        for (n in 2 until 100_000) {
            val sfx = "_$n"
            val dot = verb.lastIndexOf('.')
            val last = verb.substring(dot + 1)
            val cand = verb.substring(0, dot + 1) + last.substring(0, Math.min(last.length, 32 - sfx.length)) + sfx
            if (!c.verbs.contains(cand) && VERB_RE.matches(cand)) {
                addTodo(c, where, "duplicate_verb", "verb '$verb' is taken by an earlier operation; this one is '$cand'")
                return cand
            }
        }
        throw ActionKitError("import_limit", "too many operations map to one verb")
    }

    // ---- JSON Schema: bounded resolution ----

    internal fun isObj(v: Any?): Boolean = v is Map<*, *>
    internal fun own(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    private val INDEX_RE = Regex("0|[1-9][0-9]{0,9}")

    /** Follow a local `#/a/b` JSON pointer in `root`; null when absent, not local, or not an object. */
    fun pointer(root: Any?, refO: Any?): Any? {
        if (refO !is String || !refO.startsWith("#/")) return null
        var cur: Any? = root
        val rest = refO.substring(2)
        var from = 0
        while (true) {
            val j = rest.indexOf('/', from)
            val raw = if (j < 0) rest.substring(from) else rest.substring(from, j)
            val s = raw.replace("~1", "/").replace("~0", "~")
            val seg = Jx.decodeUriComponent(s) ?: s
            if (cur is Map<*, *>) {
                if (!cur.containsKey(seg)) return null
                cur = cur[seg]
            } else if (cur is List<*>) {
                // an array's own "length" is a number: no object results either way
                if (!INDEX_RE.matches(seg) || seg.toLong() >= cur.size) return null
                cur = cur[seg.toInt()]
            } else return null
            if (j < 0) break
            from = j + 1
        }
        return if (cur is Map<*, *> || cur is List<*>) cur else null
    }

    private fun mergeAll(a: Map<String, Any?>, m: Map<String, Any?>): MutableMap<String, Any?> {
        val out = LinkedHashMap(a)
        out.putAll(m)
        val props = LinkedHashMap<String, Any?>()
        Jx.spread(props, a["properties"])
        Jx.spread(props, m["properties"])
        val req = ArrayList<Any?>()
        if (a["required"] != null) req.addAll(Jx.spreadList(a["required"]))
        if (m["required"] != null) req.addAll(Jx.spreadList(m["required"]))
        out["properties"] = props
        out["required"] = req
        return out
    }

    private fun without(m: Map<String, Any?>, vararg ks: String): MutableMap<String, Any?> {
        val out = LinkedHashMap(m)
        for (k in ks) out.remove(k)
        return out
    }

    private fun isNullType(t: Any?): Boolean {
        if ("null" == t) return true
        if (t is List<*> && t.isNotEmpty()) { for (x in t) if ("null" != x) return false; return true }
        return false
    }

    fun resolveSchema(s: Any?, c: Ctx, bud: Budget, where: String): MutableMap<String, Any?> = resolveSchema(s, c, bud, where, emptyList(), 0)

    /**
     * Resolve what a parameter declaration cannot carry: follow local `$ref`s, merge `allOf`, collapse `anyOf`/`oneOf` to
     * the single non-null variant or to a union of string constants. What stays unrepresentable is noted in the todo list and left as `{}`.
     */
    fun resolveSchema(s: Any?, c: Ctx, bud: Budget, where: String, chain: List<String>, depth: Int): MutableMap<String, Any?> {
        if (s !is Map<*, *>) return LinkedHashMap()
        if (bud.left <= 0) {
            if (!bud.exhausted) {
                bud.exhausted = true
                addTodo(c, where, "ref_budget", "schema expansion stopped after ${c.lim.maxRefNodes} nodes (declared string; refine or drop)")
            }
            return LinkedHashMap()
        }
        bud.left--
        if (depth > c.lim.maxRefDepth) {
            addTodo(c, where, "ref_depth", "schema nesting or reference chain deeper than ${c.lim.maxRefDepth} (declared string; refine or drop)")
            return LinkedHashMap()
        }
        var cur: MutableMap<String, Any?> = Jx.m(s)
        val refv = cur["\$ref"]
        if (refv is String) {
            val ref: String = refv
            if (chain.contains(ref)) {
                addTodo(c, where, "cyclic_ref", "reference '${clip(ref, 120)}' is cyclic (declared string; refine or drop)")
                return LinkedHashMap()
            }
            val target = pointer(c.root, ref)
            if (target == null) {
                addTodo(c, where, "unresolved_ref", "reference '${clip(ref, 120)}' is not a local reference that resolves (declared string; refine or drop)")
                return LinkedHashMap()
            }
            val nc = ArrayList(chain)
            nc.add(ref)
            val merged = LinkedHashMap(resolveSchema(target, c, bud, where, nc, depth + 1))
            merged.putAll(without(cur, "\$ref"))
            cur = merged
        }
        if (cur["allOf"] is List<*>) {
            val rest = without(cur, "allOf")
            val rs = ArrayList<Map<String, Any?>>()
            for (m in Jx.a(cur["allOf"])) rs.add(resolveSchema(m, c, bud, where, chain, depth + 1))
            var acc: Map<String, Any?> = LinkedHashMap()
            for (m in rs) acc = mergeAll(acc, m)
            val n = LinkedHashMap(acc)
            n.putAll(rest)
            cur = n
        }
        val alts: List<Any?>? = if (cur["anyOf"] is List<*>) Jx.a(cur["anyOf"]) else if (cur["oneOf"] is List<*>) Jx.a(cur["oneOf"]) else null
        if (alts != null) {
            val rest = without(cur, "anyOf", "oneOf")
            val live = ArrayList<Map<String, Any?>>()
            val all = ArrayList<Map<String, Any?>>()
            for (m in alts) all.add(resolveSchema(m, c, bud, where, chain, depth + 1))
            for (m in all) if (!isNullType(m["type"])) live.add(m)
            if (live.size == 1) { val out = LinkedHashMap(live[0]); out.putAll(rest); return out }
            val consts = ArrayList<List<Any?>?>()
            var allConst = true
            for (m in live) {
                var k: List<Any?>? = null
                val cv = m["const"]
                val ev = m["enum"]
                if (cv is String) k = listOf(cv)
                else if (ev is List<*> && Jx.a(ev).all { it is String }) k = Jx.a(ev)
                if (k == null) allConst = false
                consts.add(k)
            }
            if (live.size > 1 && allConst) {
                val out = LinkedHashMap(rest)
                out["type"] = "string"
                val u = LinkedHashSet<Any?>()
                for (k in consts) u.addAll(k!!)
                out["enum"] = ArrayList(u)
                return out
            }
            addTodo(c, where, "union", "a union of ${live.size} schemas has no representation (declared string; refine or drop)")
            return rest
        }
        if (cur["const"] is String && !cur.containsKey("enum")) {
            val n = LinkedHashMap(cur)
            n["enum"] = Jx.list(cur["const"])
            cur = n
        }
        return cur
    }

    // ---- JSON Schema to params ----

    /** Param name segment hygiene: `[A-Za-z0-9_]{1,64}`; anything else is replaced by `_`. */
    fun paramSeg(raw: String): String {
        val b = StringBuilder(raw.length)
        var allUs = true
        for (c in raw) {
            val ok = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '_'
            b.append(if (ok) c else '_')
            if (c != '_' && ok) allUs = false
        }
        var s = if (allUs) "" else b.toString()
        if (s.length > 64) s = s.substring(0, 64)
        return if (s.isEmpty()) "p" else s
    }

    private val FORMATS = mapOf("email" to "email", "uuid" to "uuid", "uri" to "url", "url" to "url", "idn-email" to "email", "semver" to "semver")
    private val RESERVED = setOf("__proto__", "constructor", "prototype")
    private val INT_ROLES = setOf("money.amount", "money.fee", "count.limit", "bytes.size")

    private fun isRoleOk(r: String): Boolean = CORE_ROLES.contains(r) || ID_ROLE_RE.matches(r) || X_ROLE_RE.matches(r)

    private fun plainStr(x: Any?): Boolean {
        if (x !is String) return false
        if (x.isEmpty() || Jx.u8(x) > 256 || !Normalizer.isNormalized(x, Normalizer.Form.NFC)) return false
        var i = 0
        while (i < x.length) {
            val c = x[i]
            if (Character.isHighSurrogate(c) && i + 1 < x.length && Character.isLowSurrogate(x[i + 1])) { i += 2; continue }
            if (Character.isSurrogate(c)) return false
            i++
        }
        return true
    }

    private fun enumStrOf(en: Any?): List<Any?>? {
        if (en !is List<*>) return null
        val l = Jx.a(en)
        if (l.isEmpty() || l.size > 256) return null
        for (x in l) if (!plainStr(x)) return null
        return ArrayList(LinkedHashSet(l))
    }

    private fun firstNonNull(t: Any?): Any? {
        if (t is List<*>) { for (x in t) if ("null" != x) return x; return null }
        return t
    }

    private fun numOf(v: Double): Any = Json.Num(AttestUtil.jsNumString(v))

    /** A leaf schema to a param def. Unrepresentable shapes become `string` placeholders, noted. */
    fun leafParam(s: Map<String, Any?>, required: Boolean, c: Ctx, bud: Budget, where: String): MutableMap<String, Any?> {
        val t0 = firstNonNull(s["type"])
        val enumStr = enumStrOf(s["enum"])
        val t: Any? = if (t0 != null) t0 else if (enumStr != null) "string" else if (s["items"] is List<*> || s["items"] is Map<*, *>) "array" else null
        val base = LinkedHashMap<String, Any?>()
        base["type"] = "string"
        if (!required) base["required"] = false
        val desc = clip(s["description"], 280)
        if (desc.isNotEmpty()) base["description"] = desc
        val roleExt: String? = if (c.ext.contains("x-pca-role") && s["x-pca-role"] is String) s["x-pca-role"] as String else null
        val withRole = { p: MutableMap<String, Any?> ->
            if (roleExt == null) p
            else if (!isRoleOk(roleExt) || (INT_ROLES.contains(roleExt) && "integer" != p["type"])) {
                addTodo(c, where, "role_ignored", "x-pca-role '${clip(roleExt, 64)}' is not valid for a ${Jx.jsStr(p["type"])} parameter")
                p
            } else {
                val q = LinkedHashMap(p)
                q["role"] = roleExt
                q
            }
        }
        if ("integer" == t || ("number" == t && ("int32" == s["format"] || "int64" == s["format"]))) {
            val p = LinkedHashMap(base)
            p["type"] = "integer"
            val mn = s["minimum"]
            val mx = s["maximum"]
            val exMin = s["exclusiveMinimum"]
            val exMax = s["exclusiveMaximum"]
            if (Jx.isInt(mn) && exMin != true) p["min"] = mn
            else if (Jx.isInt(exMin)) p["min"] = numOf(Jx.num(exMin)!! + 1)
            else if (Jx.isInt(mn) && exMin == true) p["min"] = numOf(Jx.num(mn)!! + 1)
            if (Jx.isInt(mx) && exMax != true) p["max"] = mx
            else if (Jx.isInt(exMax)) p["max"] = numOf(Jx.num(exMax)!! - 1)
            else if (Jx.isInt(mx) && exMax == true) p["max"] = numOf(Jx.num(mx)!! - 1)
            if (p.containsKey("min") && p.containsKey("max") && Jx.num(p["min"])!! > Jx.num(p["max"])!!) { p.remove("min"); p.remove("max") }
            return withRole(p)
        }
        if ("boolean" == t) { val p = LinkedHashMap(base); p["type"] = "boolean"; return withRole(p) }
        if ("string" == t) {
            val f = if (s["format"] is String) s["format"] as String else ""
            val p = LinkedHashMap(base)
            if (f == "date") { p["type"] = "date"; return withRole(p) }
            if (f == "date-time") { p["type"] = "datetime"; return withRole(p) }
            if (enumStr != null) p["values"] = enumStr
            else if (s["enum"] is List<*> && Jx.a(s["enum"]).isNotEmpty()) addTodo(c, where, "enum_dropped", "enum values are not 1..256 plain strings (declared as a free string; refine)")
            if (FORMATS.containsKey(f)) p["format"] = FORMATS[f]
            val ml = s["maxLength"]
            if (Jx.isInt(ml) && Jx.num(ml)!! > 0 && Jx.num(ml)!! <= 16_777_216) p["max_len"] = ml
            return withRole(p)
        }
        if ("array" == t) {
            val it = resolveSchema(s["items"], c, bud, "$where[]")
            val itEnum = enumStrOf(it["enum"])
            val lim = LinkedHashMap<String, Any?>()
            val mi = s["maxItems"]
            val ni = s["minItems"]
            if (Jx.isInt(mi) && Jx.num(mi)!! >= 0) lim["max_items"] = mi
            if (Jx.isInt(ni) && Jx.num(ni)!! >= 0) lim["min_items"] = ni
            if (lim.containsKey("min_items") && lim.containsKey("max_items") && Jx.num(lim["min_items"])!! > Jx.num(lim["max_items"])!!) { lim.remove("min_items"); lim.remove("max_items") }
            if (s["uniqueItems"] == true && itEnum != null) {
                val p = LinkedHashMap(base)
                p["type"] = "set"
                p["values"] = itEnum
                p.putAll(lim)
                return withRole(p)
            }
            val itT = firstNonNull(it["type"])
            val items: String? = if ("integer" == itT) "integer" else if ("string" == itT) "string" else if ("boolean" == itT) "boolean" else null
            if (items == null && itT != null) addTodo(c, where, "array_items", "array items of type '${clip(Jx.jsStr(itT), 40)}' are not declared (items left open)")
            val p = LinkedHashMap(base)
            p["type"] = "array"
            if (items != null) p["items"] = items
            p.putAll(lim)
            return withRole(p)
        }
        if ("number" == t) addTodo(c, where, "unsupported_type", "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)")
        else addTodo(c, where, "unsupported_type", "type '${clip(if (t == null) "none" else Jx.jsStr(t), 40)}' has no representation (declared string; refine or drop)")
        val p = LinkedHashMap(base)
        p["type"] = "string"
        return withRole(p)
    }

    /** Assign a schema property the way `obj[name] = v` does: the engine's `__proto__` setter keeps no member. */
    internal fun putProp(m: MutableMap<String, Any?>, name: String, v: Any?) { if ("__proto__" != name) m[name] = v }

    /**
     * Flatten an object schema into params: nested objects become dotted names up to three segments; an object below that (or without
     * properties) is a `string` placeholder; a child of an optional parent is optional. At most 64 params; the rest are dropped, noted.
     */
    fun flattenObject(schema: Map<String, Any?>, c: Ctx, bud: Budget, where: String, out: MutableMap<String, Any?>) = flattenObject(schema, c, bud, where, out, emptyList(), true)

    internal fun flattenObject(schema: Map<String, Any?>, c: Ctx, bud: Budget, where: String, out: MutableMap<String, Any?>, prefix: List<String>, parentRequired: Boolean) {
        val props: Map<String, Any?> = if (isObj(schema["properties"])) schema["properties"] as Map<String, Any?> else LinkedHashMap()
        val req = LinkedHashSet<String>()
        if (schema["required"] is List<*>) for (x in Jx.a(schema["required"])) if (x is String) req.add(x)
        val names = ArrayList(props.keys)
        names.sortWith { a, b -> Json.compareUtf8(a, b) }
        for (name in names) {
            if (RESERVED.contains(name)) { addTodo(c, "$where: $name", "skipped_param", "parameter name '$name' is reserved; dropped"); continue }
            val child = resolveSchema(props[name], c, bud, "$where: $name")
            if (child["readOnly"] == true) continue
            val sname = paramSeg(name)
            if (sname != name) addTodo(c, "$where: $name", "renamed_param", "parameter '${clip(name, 80)}' is declared as '$sname'")
            val path = ArrayList(prefix)
            path.add(sname)
            val full = path.joinToString(".")
            val required = parentRequired && req.contains(name)
            val isObject = "object" == child["type"] || (!child.containsKey("type") && isObj(child["properties"]))
            if (isObject && isObj(child["properties"]) && Jx.m(child["properties"]).isNotEmpty() && path.size < MAX_PARAM_PATH_DEPTH) {
                flattenObject(child, c, bud, "$where: $full", out, path, required)
                continue
            }
            if (out.size >= MAX_DEF_PARAMS) { addTodo(c, where, "too_many_params", "more than $MAX_DEF_PARAMS parameters; '$full' and the rest are dropped"); return }
            var clash = out.containsKey(full)
            if (!clash) for (k in out.keys) if (k.startsWith("$full.") || full.startsWith("$k.")) { clash = true; break }
            if (clash) { addTodo(c, "$where: $full", "skipped_param", "parameter '$full' collides with another; kept the first"); continue }
            out[full] = if (isObject) placeholderObject(child, required, c, "$where: $full") else leafParam(child, required, c, bud, "$where: $full")
        }
    }

    private fun placeholderObject(s: Map<String, Any?>, required: Boolean, c: Ctx, where: String): Map<String, Any?> {
        addTodo(c, where, "object_leaf", "an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)")
        val p = LinkedHashMap<String, Any?>()
        p["type"] = "string"
        if (!required) p["required"] = false
        val d = clip(s["description"], 280)
        if (d.isNotEmpty()) p["description"] = d
        return p
    }

    // ---- assembling a draft def ----

    /** A draft operation: what the importer knows before the def is assembled. */
    class Draft {
        /** Raw operation name (operationId, tool name, field, rpc, ...). */
        @JvmField var name: Any? = null
        @JvmField var verb: String? = null
        @JvmField var title: Any? = null
        @JvmField var description: Any? = null
        @JvmField var effects: List<String>? = null
        @JvmField var scope: String? = null
        @JvmField var params: Map<String, Any?>? = null
        @JvmField var idempotency: Map<String, Any?>? = null
        @JvmField var traits: List<String>? = null
        @JvmField var noAlias: Boolean = false
        @JvmField var bindings: Map<String, Any?>? = null
    }

    /** Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted). Returns the def or null. */
    fun emitDef(c: Ctx, d: Draft): Map<String, Any?>? {
        if (c.defs.size >= c.lim.maxOps) throw ActionKitError("import_limit", "more than ${c.lim.maxOps} operations")
        val rawVerb = d.verb ?: verbOf(c.ns, d.name)
        val verb = uniqueVerb(c, if (VERB_RE.matches(rawVerb)) rawVerb else verbOf(c.ns, d.name), Jx.jsStr(d.name))
        val segs = verb.split(".")
        val rtype = if (segs.size > 2) segs.subList(0, segs.size - 1).joinToString(".") else segs[0]
        val title = firstText(MAX_TITLE_BYTES, d.title, humanize(d.name), verb)
        val description = clip(d.description, Math.min(MAX_DESCRIPTION_BYTES, 600))
        val alias = if (d.noAlias) null else aliasOf(d.name, verb)
        val def = LinkedHashMap<String, Any?>()
        def["v"] = Jx.n(1)
        def["kind"] = "pca-action-def"
        def["verb"] = verb
        if (alias != null && !c.aliases.containsKey(alias) && !c.verbs.contains(alias)) def["aliases"] = Jx.list(alias)
        def["title"] = if (title.isEmpty()) verb else title
        if (description.isNotEmpty()) def["description"] = description
        def["effects"] = ArrayList<Any?>(TreeSet(d.effects!!))
        def["resource"] = Jx.obj("type", if (RTYPE_RE.matches(rtype)) rtype else segs[0], "id", Jx.obj("prefix", "", "class", "any_safe", "len", Jx.list(Jx.n(1), Jx.n(128))), "scope", d.scope)
        def["params"] = d.params
        if (d.idempotency != null) def["idempotency"] = d.idempotency
        if (d.traits != null && d.traits!!.isNotEmpty()) def["traits"] = ArrayList<Any?>(TreeSet(d.traits!!))
        def["bindings"] = d.bindings
        def["review"] = Jx.obj("state", "unreviewed")
        def["source"] = Jx.obj("kind", c.source["kind"], "uri", c.source["uri"], "spec_digest", c.source["spec_digest"], "licence", c.source["licence"], "imported_at", c.source["imported_at"])
        val bad = Actions.validateDef(def)
        if (bad != null) {
            addTodo(c, Jx.jsStr(d.name), "invalid_def", "not emitted: $bad")
            return null
        }
        c.verbs.add(verb)
        if (def["aliases"] != null) c.aliases[Jx.a(def["aliases"])[0] as String] = verb
        c.defs.add(def)
        return def
    }

    /** Add a declared trait to a draft (used for hint-derived traits such as network egress). */
    fun withTrait(traits: List<String>?, t: String): List<String> {
        val s = LinkedHashSet<String>(traits ?: emptyList())
        s.add(t)
        return ArrayList(s)
    }
}
