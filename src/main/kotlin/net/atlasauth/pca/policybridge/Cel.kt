package net.atlasauth.pca.policybridge

import java.util.TreeSet
import java.util.regex.Pattern
import net.atlasauth.pca.verifier.Json

/**
 * Strict CEL import (Google IAM Conditions, Kubernetes ValidatingAdmissionPolicy, SpiceDB caveat expressions): one boolean CEL
 * expression becomes a PCA condition or is REJECTED, naming the construct. There is no best-effort mode: a condition that was dropped or
 * approximated would widen what a policy admits. No CEL runs anywhere; the predicate DSL is the only evaluator.
 *
 * Results are JSON maps: `{ok:true, condition, fields}` / `{ok:false, code, message, at}`.
 */
object Cel {
    private const val MAX_EXPR = 4096
    private const val MAX_DEPTH = 32
    private const val MAX_NODES = 256
    private const val MAX_LIST = 64
    private const val MAX_STR = 256
    private val FORBIDDEN = setOf("__proto__", "constructor", "prototype")
    private val TYPES = setOf("string", "int", "bool", "timestamp_ms")

    /** A refusal: a stable error code, the message and the offset in the expression. */
    private class Reject(val code: String, message: String, val at: Int) : RuntimeException(message, null, false, false)

    private fun rej(code: String, message: String, at: Int) = Reject(code, message, at)

    private fun n(v: Long): Any = Json.Num(v.toString())

    // ---- tokens ----

    private class Tok(val k: Char, val v: String, val at: Int) // k: 'i' id, 'n' int, 's' str, 'p' punct

    private val PUNCT = listOf("&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "(", ")", "[", "]", ",", ".", "-")

    private fun unsupportedChar(c: Char): String? = when (c) {
        '+' -> "arithmetic (+)"
        '*' -> "arithmetic (*)"
        '/' -> "arithmetic (/)"
        '%' -> "arithmetic (%)"
        '?' -> "the conditional operator"
        ':' -> "the conditional operator / map literal"
        '{', '}' -> "map or message literal"
        '@' -> "@"
        '&' -> "bitwise &"
        '|' -> "bitwise |"
        '^' -> "^"
        '~' -> "~"
        '=' -> "assignment"
        '`' -> "quoted identifier"
        else -> null
    }

    private fun lex(src: String): List<Tok> {
        val out = ArrayList<Tok>()
        var i = 0
        while (i < src.length) {
            val c = src[i]
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { i++; continue }
            if (c == '/' && i + 1 < src.length && src[i + 1] == '/') throw rej("unsupported", "comments", i)
            if (PbJs.isIdentStart(c)) {
                var j = i + 1
                while (j < src.length && PbJs.isIdentPart(src[j])) j++
                val w = src.substring(i, j)
                val nx = if (j < src.length) src[j] else '\u0000'
                if ((w == "r" || w == "b" || w == "R" || w == "B") && (nx == '"' || nx == '\'')) {
                    throw rej("unsupported", (if (w.lowercase(java.util.Locale.ROOT) == "r") "raw string" else "bytes") + " literal", i)
                }
                out.add(Tok('i', w, i))
                i = j
                continue
            }
            if (PbJs.isDigit(c)) {
                var j = i
                while (j < src.length && PbJs.isDigit(src[j])) j++
                val has = j < src.length
                val nxt = if (has) src[j] else '\u0000'
                if (has && nxt == '.' && j + 1 < src.length && PbJs.isDigit(src[j + 1])) throw rej("unsupported", "double literal", i)
                if (has && (nxt == 'e' || nxt == 'E')) throw rej("unsupported", "double literal", i)
                if (has && (nxt == 'u' || nxt == 'U')) throw rej("unsupported", "unsigned integer literal", i)
                if (has && (nxt == 'x' || nxt == 'X')) throw rej("unsupported", "hexadecimal literal", i)
                val w = src.substring(i, j)
                if (w.length > 1 && w[0] == '0') throw rej("unsupported", "integer literal with a leading zero", i)
                out.add(Tok('n', w, i))
                i = j
                continue
            }
            if (c == '"' || c == '\'') {
                val triple = "" + c + c + c
                if (src.startsWith(triple, i)) throw rej("unsupported", "triple-quoted string", i)
                var j = i + 1
                val s = StringBuilder()
                while (true) {
                    if (j >= src.length) throw rej("syntax", "unterminated string", i)
                    val d = src[j]
                    if (d == '\n' || d == '\r') throw rej("syntax", "unterminated string", i)
                    if (d == c) break
                    if (d == '\\') {
                        val has = j + 1 < src.length
                        val e = if (has) src[j + 1] else '\u0000'
                        val mapped: String? = if (!has) null else when (e) {
                            '\\' -> "\\"
                            '"' -> "\""
                            '\'' -> "'"
                            'n' -> "\n"
                            't' -> "\t"
                            'r' -> "\r"
                            else -> null
                        }
                        if (mapped == null) throw rej("unsupported", "string escape \\" + (if (has) e.toString() else ""), j)
                        s.append(mapped)
                        j += 2
                        continue
                    }
                    s.append(d)
                    j++
                }
                if (s.length > MAX_STR) throw rej("too_complex", "string literal longer than $MAX_STR", i)
                out.add(Tok('s', s.toString(), i))
                i = j + 1
                continue
            }
            var p: String? = null
            for (x in PUNCT) if (src.startsWith(x, i)) { p = x; break }
            if (p == null) {
                val u = unsupportedChar(c)
                throw rej(if (u != null) "unsupported" else "syntax", u ?: "unexpected character '$c'", i)
            }
            out.add(Tok('p', p, i))
            i += p.length
        }
        return out
    }

    // ---- parser ----

    /** An AST node of the parsed subset (see [toJson]). */
    private class Node(val t: String, var at: Int) { // t: or and not rel int str bool ts list var has method
        var op: String? = null
        var name: String? = null
        var fn: String? = null
        var l: Node? = null
        var r: Node? = null
        var e: Node? = null
        var target: Node? = null
        var arg: Node? = null
        var iv: Long = 0
        var sv: String? = null
        var bv: Boolean = false
        var items: List<Node>? = null
        fun copyWithName(name: String): Node { val c = Node("var", at); c.name = name; return c }
    }

    private val RELOPS = setOf("==", "!=", "<", "<=", ">", ">=")
    private val REJECTED_FUNCS = setOf(
        "size", "matches", "exists", "all", "exists_one", "map", "filter", "int", "uint", "double", "string", "bytes", "bool",
        "duration", "type", "dyn", "min", "max", "getHours", "getDayOfWeek", "getMinutes", "getSeconds", "getFullYear", "getMonth", "getDate", "getDayOfMonth", "getDayOfYear",
        "getMilliseconds", "extract", "format", "lowerAscii", "upperAscii", "trim", "split", "join", "replace", "substring", "indexOf", "lastIndexOf", "charAt", "isIpv4",
        "inIpRange", "cidr", "ip", "isCIDR", "containsIp", "url", "quantity", "semver", "optional",
    )

    private class Parser(val src: String, val toks: List<Tok>) {
        var pos = 0
        var nodes = 0

        fun peek(): Tok? = if (pos < toks.size) toks[pos] else null
        fun isP(v: String): Boolean { val t = peek(); return t != null && t.k == 'p' && t.v == v }
        fun eat(v: String): Boolean { if (isP(v)) { pos++; return true }; return false }
        fun peekAt(dflt: Int): Int = peek()?.at ?: dflt
        fun need(v: String) { if (!eat(v)) throw rej("syntax", "expected '$v'", peekAt(src.length)) }
        fun tick(at: Int) { if (++nodes > MAX_NODES) throw rej("too_complex", "more than $MAX_NODES nodes", at) }

        fun expr(d: Int): Node {
            if (d > MAX_DEPTH) throw rej("too_complex", "nesting deeper than $MAX_DEPTH", peekAt(0))
            return or(d)
        }

        fun or(d: Int): Node {
            var l = and(d)
            while (isP("||")) {
                val at = peek()!!.at
                pos++
                tick(at)
                val n = Node("or", at)
                n.l = l
                n.r = and(d)
                l = n
            }
            return l
        }

        fun and(d: Int): Node {
            var l = rel(d)
            while (isP("&&")) {
                val at = peek()!!.at
                pos++
                tick(at)
                val n = Node("and", at)
                n.l = l
                n.r = rel(d)
                l = n
            }
            return l
        }

        private fun isRelTok(u: Tok?): Boolean = u != null && ((u.k == 'p' && RELOPS.contains(u.v)) || (u.k == 'i' && u.v == "in"))

        fun rel(d: Int): Node {
            val l = unary(d)
            val t = peek() ?: return l
            val isIn = t.k == 'i' && t.v == "in"
            if (!isIn && !(t.k == 'p' && RELOPS.contains(t.v))) return l
            pos++
            tick(t.at)
            val n = Node("rel", t.at)
            n.op = if (isIn) "in" else t.v
            n.l = l
            n.r = unary(d)
            val u = peek()
            if (isRelTok(u)) throw rej("unsupported", "chained comparison", u!!.at)
            return n
        }

        fun unary(d: Int): Node {
            val t = peek()
            if (t != null && t.k == 'p' && t.v == "!") {
                pos++
                tick(t.at)
                if (d + 1 > MAX_DEPTH) throw rej("too_complex", "nesting deeper than $MAX_DEPTH", t.at)
                val n = Node("not", t.at)
                n.e = unary(d + 1)
                return n
            }
            if (t != null && t.k == 'p' && t.v == "-") {
                val nx = if (pos + 1 < toks.size) toks[pos + 1] else null
                if (nx == null || nx.k != 'n') throw rej("unsupported", "unary minus on a non-literal", t.at)
                pos += 2
                return intNode("-" + nx.v, t.at)
            }
            return member(d)
        }

        fun intNode(text: String, at: Int): Node {
            tick(at)
            val v = text.toDouble()
            if (!(v == Math.rint(v) && Math.abs(v) <= 9007199254740991.0)) throw rej("unsupported", "integer literal outside the safe-integer range", at)
            val n = Node("int", at)
            n.iv = v.toLong()
            return n
        }

        fun args(d: Int): List<Node> {
            val a = ArrayList<Node>()
            if (!isP(")")) { do { a.add(expr(d + 1)) } while (eat(",")) }
            need(")")
            return a
        }

        fun member(d: Int): Node {
            var n = primary(d)
            while (isP(".")) {
                val dot = peek()!!
                pos++
                val id = peek()
                if (id == null || id.k != 'i') throw rej("syntax", "expected a name after '.'", dot.at)
                pos++
                if (isP("(")) {
                    pos++
                    val a = args(d)
                    if (id.v != "startsWith" && id.v != "endsWith" && id.v != "contains") throw rej("unsupported", "method '${id.v}'", id.at)
                    if (a.size != 1) throw rej("syntax", "'${id.v}' takes one argument", id.at)
                    tick(id.at)
                    val m = Node("method", id.at)
                    m.target = n
                    m.fn = id.v
                    m.arg = a[0]
                    n = m
                } else {
                    if (n.t != "var") throw rej("unsupported", "field selection on something that is not a declared variable", dot.at)
                    n = n.copyWithName(n.name + "." + id.v)
                }
            }
            if (isP("[")) throw rej("unsupported", "index operator", peek()!!.at)
            return n
        }

        fun primary(d: Int): Node {
            val t = peek() ?: throw rej("syntax", "unexpected end of expression", src.length)
            if (t.k == 'n') { pos++; return intNode(t.v, t.at) }
            if (t.k == 's') { pos++; tick(t.at); val s = Node("str", t.at); s.sv = t.v; return s }
            if (t.k == 'p' && t.v == "(") { pos++; val e = expr(d + 1); need(")"); return e }
            if (t.k == 'p' && t.v == "[") {
                pos++
                val items = ArrayList<Node>()
                if (!isP("]")) {
                    do {
                        if (items.size >= MAX_LIST) throw rej("too_complex", "list longer than $MAX_LIST", t.at)
                        items.add(expr(d + 1))
                    } while (eat(","))
                }
                need("]")
                tick(t.at)
                val l = Node("list", t.at)
                l.items = items
                return l
            }
            if (t.k == 'i') {
                pos++
                if (t.v == "true" || t.v == "false") { tick(t.at); val b = Node("bool", t.at); b.bv = t.v == "true"; return b }
                if (t.v == "null") throw rej("unsupported", "null", t.at)
                if (isP("(")) {
                    pos++
                    val a = args(d)
                    if (t.v == "has") {
                        if (a.size != 1 || a[0].t != "var") throw rej("syntax", "has() takes one declared variable", t.at)
                        tick(t.at)
                        val h = Node("has", t.at)
                        h.e = a[0]
                        return h
                    }
                    if (t.v == "timestamp") {
                        val s = if (a.isEmpty()) null else a[0]
                        if (a.size != 1 || s == null || s.t != "str") throw rej("unsupported", "timestamp() of a non-literal", t.at)
                        val ts = Node("ts", t.at)
                        ts.iv = parseTimestamp(s.sv!!, t.at)
                        return ts
                    }
                    throw rej("unsupported", if (REJECTED_FUNCS.contains(t.v)) "function '${t.v}'" else "unknown function '${t.v}'", t.at)
                }
                if (t.v == "in") throw rej("syntax", "unexpected 'in'", t.at)
                tick(t.at)
                val v = Node("var", t.at)
                v.name = t.v
                return v
            }
            throw rej("syntax", "unexpected '${t.v}'", t.at)
        }

        fun root(): Node {
            val r = expr(0)
            if (pos < toks.size) throw rej("syntax", "unexpected '${toks[pos].v}'", toks[pos].at)
            return r
        }
    }

    private val TIMESTAMP = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,3}))?Z")

    private fun isLeap(y: Int): Boolean = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0

    /** Days since 1970-01-01 of a proleptic Gregorian date (no java.time: API 24). */
    private fun daysFromCivil(y0: Int, m: Int, d: Int): Long {
        val y = (if (m <= 2) y0 - 1 else y0).toLong()
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400
        val doy = (153 * (m + (if (m > 2) -3 else 9)) + 2) / 5 + d - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    private fun parseTimestamp(s: String, at: Int): Long {
        val m = TIMESTAMP.matcher(s)
        if (!m.matches()) throw rej("unsupported", "timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision", at)
        var frac = m.group(7) ?: ""
        while (frac.length < 3) frac += "0"
        val year = m.group(1).toInt()
        val month = m.group(2).toInt()
        val day = m.group(3).toInt()
        val hour = m.group(4).toInt()
        val minute = m.group(5).toInt()
        val second = m.group(6).toInt()
        val dim = when (month) {
            2 -> if (isLeap(year)) 29 else 28
            4, 6, 9, 11 -> 30
            else -> 31
        }
        if (month < 1 || month > 12 || day < 1 || day > dim || hour > 23 || minute > 59 || second > 59) throw rej("unsupported", "timestamp() is not a real instant", at)
        return ((daysFromCivil(year, month, day) * 24 + hour) * 60 + minute) * 60_000L + second * 1000L + frac.toInt()
    }

    private fun parse(src: String?): Node {
        if (src == null || src.isEmpty()) throw rej("syntax", "empty expression", 0)
        if (src.length > MAX_EXPR) throw rej("too_complex", "expression longer than $MAX_EXPR characters", 0)
        return Parser(src, lex(src)).root()
    }

    /** The AST as the reference prints it (a node is `{t, ..., at}`). */
    private fun toJson(x: Node): Any {
        val m = LinkedHashMap<String, Any?>()
        m["t"] = x.t
        when (x.t) {
            "or", "and" -> { m["l"] = toJson(x.l!!); m["r"] = toJson(x.r!!) }
            "not" -> m["e"] = toJson(x.e!!)
            "rel" -> { m["op"] = x.op; m["l"] = toJson(x.l!!); m["r"] = toJson(x.r!!) }
            "int", "ts" -> m["v"] = n(x.iv)
            "str" -> m["v"] = x.sv
            "bool" -> m["v"] = x.bv
            "list" -> m["items"] = x.items!!.mapTo(ArrayList<Any?>()) { toJson(it) }
            "var" -> m["name"] = x.name
            "has" -> m["e"] = toJson(x.e!!)
            else -> { m["target"] = toJson(x.target!!); m["fn"] = x.fn; m["arg"] = toJson(x.arg!!) }
        }
        m["at"] = n(x.at.toLong())
        return m
    }

    /** Parse a CEL expression of the supported subset into its tree `{ok:true, ast}`, or the refusal. */
    fun parseCel(expression: String?): Map<String, Any?> = try {
        PbJs.obj("ok", true, "ast", toJson(parse(expression)))
    } catch (e: Reject) {
        fail(e)
    } catch (e: RuntimeException) {
        PbJs.obj("ok", false, "code", "syntax", "message", "internal error", "at", n(0))
    } catch (e: StackOverflowError) {
        PbJs.obj("ok", false, "code", "syntax", "message", "internal error", "at", n(0))
    }

    private fun fail(e: Reject): Map<String, Any?> = PbJs.obj("ok", false, "code", e.code, "message", e.message, "at", n(e.at.toLong()))

    // ---- translation ----

    private fun isIdent(s: String): Boolean {
        if (s.isEmpty() || !PbJs.isIdentStart(s[0])) return false
        for (i in 1 until s.length) if (!PbJs.isIdentPart(s[i])) return false
        return true
    }

    private fun isDottedIdent(s: String, minParts: Int, roots: Set<String>?): Boolean {
        val parts = s.split(".")
        if (parts.size < minParts) return false
        for (i in parts.indices) {
            if (i == 0 && roots != null) { if (!roots.contains(parts[0])) return false; continue }
            if (!isIdent(parts[i])) return false
        }
        return true
    }

    private fun forbiddenPart(s: String): Boolean {
        for (p in s.split(".")) if (FORBIDDEN.contains(p)) return true
        return false
    }

    private val PCA_ROOTS = setOf("action", "subject", "env")

    @Suppress("UNCHECKED_CAST")
    private fun schemaError(s: Any?): String? {
        if (s !is Map<*, *>) return "the schema must be an object"
        val vars = s["vars"]
        if (vars !is Map<*, *>) return "the schema needs a vars object"
        val vm = vars as Map<String, Any?>
        for (name in PbJs.entryKeys(vm)) {
            val v = vm[name]
            if (!isDottedIdent(name, 1, null) || forbiddenPart(name)) return "bad variable name '$name'"
            val path = if (v is Map<*, *>) v["path"] else null
            if (v !is Map<*, *> || path !is String || !isDottedIdent(path, 2, PCA_ROOTS) || forbiddenPart(path)) {
                return "variable '$name' needs a path rooted at action, subject or env"
            }
            val type = v["type"]
            if (type !is String || !TYPES.contains(type)) return "variable '$name' has an unsupported type"
            if (v.containsKey("optional") && v["optional"] !is Boolean) return "variable '$name': optional must be a boolean"
        }
        return null
    }

    /** A comparison operand: a declared variable or a typed literal. */
    private class Operand(val isVar: Boolean, val type: String, val path: String?, val name: String?, val optional: Boolean, val value: Any?)

    private class Translator(val vars: Map<*, *>) {
        val fields = TreeSet<String>()

        fun operand(n: Node): Operand = when (n.t) {
            "var" -> {
                val v = if (vars.containsKey(n.name)) vars[n.name] else null
                if (v == null) throw rej("unknown_identifier", "'${n.name}' is not declared in the schema", n.at)
                val vm = v as Map<*, *>
                Operand(true, vm["type"] as String, vm["path"] as String, n.name, vm["optional"] == true, null)
            }
            "int" -> Operand(false, "int", null, null, false, n(n.iv))
            "str" -> Operand(false, "string", null, null, false, n.sv)
            "bool" -> Operand(false, "bool", null, null, false, n.bv)
            "ts" -> Operand(false, "timestamp_ms", null, null, false, n(n.iv))
            else -> throw rej("unsupported", "a computed value as a comparison operand", n.at)
        }

        fun read(o: Operand): String { fields.add(o.path!!); return o.path }

        fun flat(n: Node, t: String, out: MutableList<Node>) {
            if (n.t == t) { flat(n.l!!, t, out); flat(n.r!!, t, out) } else out.add(n)
        }

        fun tr(n: Node): Map<String, Any?> {
            when (n.t) {
                "or", "and" -> {
                    val parts = ArrayList<Node>()
                    flat(n, n.t, parts)
                    val out = ArrayList<Any?>()
                    for (p in parts) out.add(tr(p))
                    return PbJs.obj(if (n.t == "or") "any_of" else "all_of", out)
                }
                "not" -> return PbJs.obj("not", tr(n.e!!))
                "has" -> {
                    val o = operand(n.e!!)
                    if (!o.optional) throw rej("has_requires_optional", "has(${o.name}): mark the variable optional in the schema (its container must always be present)", n.at)
                    return PbJs.obj("field", read(o), "op", "exists", "value", true)
                }
                "var" -> {
                    val o = operand(n)
                    throw rej("unsupported", "a bare variable '${n.name}' as a condition" + (if (o.isVar && o.type == "bool") " (write ${n.name} == true)" else ""), n.at)
                }
                "method" -> {
                    val t = operand(n.target!!)
                    if (!t.isVar || t.type != "string") throw rej("type_mismatch", "${n.fn} needs a string variable", n.at)
                    val arg = n.arg!!
                    if (arg.t != "str" || arg.sv!!.isEmpty()) throw rej("unsupported", "${n.fn} of anything but a non-empty string literal", n.at)
                    val lit = arg.sv!!
                    if (n.fn == "startsWith") return PbJs.obj("field", read(t), "op", "prefix", "value", lit)
                    val esc = StringBuilder()
                    for (c in lit) {
                        if (c == '\\' || c == '*' || c == '?') esc.append('\\')
                        esc.append(c)
                    }
                    val glob = if (n.fn == "endsWith") "*$esc" else "*$esc*"
                    if (glob.length > 512) throw rej("too_complex", "literal too long for a glob", n.at)
                    return PbJs.obj("field", read(t), "op", "like", "value", glob)
                }
                "rel" -> return rel(n)
                else -> throw rej("constant_expression", "a bare constant is not a condition", n.at)
            }
        }

        fun rel(n: Node): Map<String, Any?> {
            if (n.op == "in") {
                val l = operand(n.l!!)
                if (!l.isVar) throw rej("constant_expression", "the left side of \"in\" must be a declared variable", n.at)
                val rn = n.r!!
                if (rn.t != "list" || rn.items!!.isEmpty()) throw rej("unsupported", "\"in\" against anything but a non-empty list literal", n.at)
                val items = ArrayList<Operand>()
                for (i in rn.items!!) items.add(operand(i))
                for (i in items) if (i.isVar || i.type != l.type) throw rej("type_mismatch", "list items must be ${l.type} literals", n.at)
                val field = read(l)
                val values = ArrayList<Any?>()
                for (i in items) values.add(i.value)
                return PbJs.obj("field", field, "op", "in", "value", values)
            }
            val l = operand(n.l!!)
            val r = operand(n.r!!)
            if (!l.isVar && !r.isVar) throw rej("constant_expression", "a comparison of two literals", n.at)
            if (l.type != r.type) throw rej("type_mismatch", "${l.type} against ${r.type}", n.at)
            val ty = l.type
            val eqOp = n.op == "==" || n.op == "!="
            if (!eqOp && ty == "bool") throw rej("type_mismatch", "ordering of booleans", n.at)
            val pcaOp = when (n.op) { "==" -> "eq"; "!=" -> "ne"; "<" -> "lt"; "<=" -> "lte"; ">" -> "gt"; else -> "gte" }
            if (l.isVar && r.isVar) return PbJs.obj("field", read(l), "op", pcaOp, "ref", read(r))
            if (l.isVar) return PbJs.obj("field", read(l), "op", pcaOp, "value", r.value)
            val flip = when (pcaOp) { "lt" -> "gt"; "lte" -> "gte"; "gt" -> "lt"; "gte" -> "lte"; else -> pcaOp }
            return PbJs.obj("field", read(r), "op", flip, "value", l.value)
        }
    }

    /** Translate one boolean CEL expression over [schema] (`{vars: {name: {path, type, optional?}}}`) into a PCA condition. */
    fun celToCondition(expression: String?, schema: Any?): Map<String, Any?> {
        val se = schemaError(schema)
        if (se != null) return PbJs.obj("ok", false, "code", "bad_schema", "message", se, "at", n(0))
        try {
            val ast = parse(expression)
            val t = Translator((schema as Map<*, *>)["vars"] as Map<*, *>)
            val condition = t.tr(ast)
            if (t.fields.isEmpty()) throw rej("constant_expression", "the expression reads no variable", 0)
            return PbJs.obj("ok", true, "condition", condition, "fields", ArrayList<Any?>(t.fields))
        } catch (e: Reject) {
            return fail(e)
        } catch (e: RuntimeException) {
            return PbJs.obj("ok", false, "code", "syntax", "message", "internal error", "at", n(0))
        } catch (e: StackOverflowError) {
            return PbJs.obj("ok", false, "code", "syntax", "message", "internal error", "at", n(0))
        }
    }

    /** One expression as a permit predicate for [verb] (a string or a list of strings) and optionally [resource]. */
    fun celToPredicate(expression: String?, schema: Any?, verb: Any?, resource: String?): Map<String, Any?> {
        val r = celToCondition(expression, schema)
        if (r["ok"] != true) return r
        val predicate = LinkedHashMap<String, Any?>()
        predicate["verb"] = verb
        if (resource != null) predicate["resource"] = resource
        val where = ArrayList<Any?>()
        where.add(r["condition"])
        predicate["where"] = where
        return PbJs.obj("ok", true, "predicate", predicate, "fields", r["fields"])
    }

    /**
     * A batch (an IAM policy's bindings, a VAP's validations): every item (`{name, expression, verb, resource?}`) is translated or
     * reported. One rejection makes the report's errors non-empty, and [PolicyBridge.decide] then denies everything (an incomplete
     * import never grants).
     */
    fun celConditionsToPca(items: List<Map<String, Any?>>, schema: Any?): Map<String, Any?> {
        val predicates = ArrayList<Any?>()
        val translated = ArrayList<Any?>()
        val errors = ArrayList<Any?>()
        for (it in items) {
            val res = it["resource"]
            val r = celToPredicate(it["expression"] as String?, schema, it["verb"], res as String?)
            val name = it["name"].toString()
            if (r["ok"] == true) {
                predicates.add(r["predicate"])
                val fs = r["fields"] as List<*>
                translated.add("$name: translated exactly (reads " + fs.joinToString(", ") + ")")
            } else {
                errors.add("$name: rejected (${r["code"]}) at ${r["at"]}: ${r["message"]}")
            }
        }
        val report = LinkedHashMap<String, Any?>()
        report["source"] = "cel"
        report["translated"] = translated
        report["skipped"] = ArrayList<Any?>()
        report["errors"] = errors
        return PolicyBridge.result(predicates, ArrayList(), report)
    }
}
