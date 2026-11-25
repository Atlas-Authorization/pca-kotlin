package net.atlasauth.pca.analyzer

/**
 * DATA FILTERING: a residual compiled to a parameterized SQL WHERE clause (and a UCAST tree) so a list endpoint can push authorization into
 * its query. Soundness rule: the filter may only ever return a SUBSET of what the evaluator admits. Anything it cannot express exactly (a
 * regex resource, a `ref`, `like` / `matches` / `member_of`, string ordering, a field with no column) makes the whole
 * compile fail with a reason (`ok: false`); it never emits a looser filter. SQL's three-valued logic is Kleene's, the same as the
 * evaluator's: an unresolvable permit condition is NULL and the row is dropped; a veto is wrapped in `COALESCE(.., TRUE)`.
 *
 * Expressions are JSON objects: {t: "true" | "false" | "cmp" | "in" | "prefix" | "null" | "and" | "or" | "not" | "coalesce", ...}.
 */
object Filter {
    private class Unsupported(m: String) : RuntimeException(m)

    private val COL_RE = Regex("[A-Za-z_][A-Za-z0-9_]{0,62}(\\.[A-Za-z_][A-Za-z0-9_]{0,62})?")

    private fun scalar(v: Any?): Boolean = v is Boolean || v is String || AJs.isFin(v)

    private fun colOf(path: Any?, cols: Map<String, Any?>?): String {
        if (path is String && cols == null) throw IllegalStateException("columns is not an object")
        val c: Any? = if (path is String && cols!!.containsKey(path)) cols[path] else null
        if (c !is String || !COL_RE.matches(c)) {
            throw Unsupported("field '" + CaveatAnalysis.jsString(path, true) + "' has no usable column")
        }
        return c
    }

    private fun tOf(t: String): Map<String, Any?> = AJs.obj("t", t)

    private fun and(xs: List<Map<String, Any?>>): Map<String, Any?> {
        if (xs.isEmpty()) return tOf("true")
        if (xs.size == 1) return xs[0]
        return AJs.obj("t", "and", "xs", ArrayList<Any?>(xs))
    }

    private fun or(xs: List<Map<String, Any?>>): Map<String, Any?> {
        if (xs.isEmpty()) return tOf("false")
        if (xs.size == 1) return xs[0]
        return AJs.obj("t", "or", "xs", ArrayList<Any?>(xs))
    }

    private fun not(x: Map<String, Any?>): Map<String, Any?> = AJs.obj("t", "not", "x", x)
    private fun coalesce(x: Map<String, Any?>, def: Boolean): Map<String, Any?> = AJs.obj("t", "coalesce", "x", x, "def", def)
    private fun cmp(col: String, op: String, v: Any?): Map<String, Any?> = AJs.obj("t", "cmp", "col", col, "op", op, "v", v)
    private fun isNull(col: String, isNull: Boolean): Map<String, Any?> = AJs.obj("t", "null", "col", col, "isNull", isNull)

    private fun cond(c: Any?, cols: Map<String, Any?>?): Map<String, Any?> {
        if (!(c is Map<*, *> || c is List<*>)) throw Unsupported("malformed condition")
        if (Field.isGroup(c)) {
            val all = AJs.get(c, "all_of")
            val any = AJs.get(c, "any_of")
            if (AJs.has(c, "all_of") && all is List<*> && all.isNotEmpty()) {
                val xs = ArrayList<Map<String, Any?>>()
                for (x in all) xs.add(cond(x, cols))
                return and(xs)
            }
            if (AJs.has(c, "any_of") && any is List<*> && any.isNotEmpty()) {
                val xs = ArrayList<Map<String, Any?>>()
                for (x in any) xs.add(cond(x, cols))
                return or(xs)
            }
            if (AJs.has(c, "not")) return not(cond(AJs.get(c, "not"), cols))
            throw Unsupported("empty condition group")
        }
        if (!Field.isLeaf(c)) throw Unsupported("malformed condition")
        if (AJs.has(c, "ref")) throw Unsupported("cross-field ref")
        val col = colOf(AJs.get(c, "field"), cols)
        val v = AJs.get(c, "value")
        val opO = AJs.get(c, "op")
        val op = if (opO is String) opO else ""
        when (op) {
            "eq", "ne" -> {
                if (!scalar(v)) throw Unsupported("$op against a non-scalar")
                return cmp(col, op, v)
            }
            "lt", "lte", "gt", "gte" -> {
                if (!AJs.isFin(v)) throw Unsupported("string ordering follows UTF-8 byte order, which SQL collations do not guarantee")
                return cmp(col, op, v)
            }
            "in", "nin" -> {
                var ok = v is List<*> && v.isNotEmpty()
                if (ok) for (x in v as List<*>) if (!scalar(x)) { ok = false; break }
                if (!ok) throw Unsupported("$op needs a non-empty list of scalars")
                return AJs.obj("t", "in", "col", col, "vs", v, "neg", op == "nin")
            }
            "prefix" -> {
                if (v !is String) throw Unsupported("prefix needs a string")
                return AJs.obj("t", "prefix", "col", col, "prefix", v)
            }
            "exists" -> return isNull(col, v == false)
            else -> throw Unsupported("operator '" + CaveatAnalysis.jsString(opO, AJs.has(c, "op")) + "' has no exact SQL form")
        }
    }

    private fun resourceExpr(p: Any?, cols: Map<String, Any?>?): Map<String, Any?> {
        val has = AJs.has(p, "resource")
        val r = AJs.get(p, "resource")
        if (!has || "*" == r) return tOf("true")
        val col = colOf("action.resource", cols)
        val s = r as String // a non-string matcher is a compilation error, as in the reference
        if (s.startsWith("re:")) throw Unsupported("regex resource matcher")
        if (s.endsWith("*")) return AJs.obj("t", "prefix", "col", col, "prefix", s.substring(0, s.length - 1))
        return cmp(col, "eq", s)
    }

    private fun vetoExpr(v: Any?, cols: Map<String, Any?>?): Map<String, Any?> {
        val `when` = AJs.req(AJs.get(v, "when"))
        val ws = ArrayList<Map<String, Any?>>()
        if (AJs.has(`when`, "resource")) ws.add(coalesce(resourceExpr(`when`, cols), true))
        val where = AJs.get(`when`, "where")
        if (where is List<*>) for (c in where) ws.add(coalesce(cond(c, cols), true))
        val parts = ArrayList<Map<String, Any?>>()
        parts.add(and(ws))
        val over = AJs.get(v, "over")
        if (AJs.truthy(over)) {
            val col = colOf(AJs.get(over, "path"), cols)
            val os = ArrayList<Map<String, Any?>>()
            os.add(isNull(col, true))
            os.add(cmp(col, "lt", AJs.n(0)))
            os.add(cmp(col, "gt", AJs.get(over, "threshold")))
            parts.add(or(os))
        }
        val unless = AJs.get(v, "unless")
        if ("approval" != AJs.get(v, "kind") && AJs.truthy(unless) && unless is List<*> && unless.isNotEmpty()) {
            val us = ArrayList<Map<String, Any?>>()
            for (c in unless) us.add(coalesce(cond(c, cols), false))
            parts.add(not(and(us)))
        }
        return and(parts)
    }

    private fun partExpr(p: Any?, cols: Map<String, Any?>?, include: String): Map<String, Any?> {
        val permits = ArrayList<Map<String, Any?>>()
        for (x in AJs.list(AJs.get(p, "predicates"))) {
            val parts = ArrayList<Map<String, Any?>>()
            parts.add(resourceExpr(x, cols))
            val where = AJs.get(x, "where")
            if (where is List<*>) for (c in where) parts.add(cond(c, cols))
            permits.add(and(parts))
        }
        val gates = ArrayList<Map<String, Any?>>()
        gates.add(or(permits))
        for (v in AJs.list(AJs.get(p, "vetoes"))) {
            val e = vetoExpr(v, cols)
            // an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
            if ("deny" == AJs.get(v, "kind") || include == "autonomous") gates.add(not(e))
        }
        for (t in AJs.list(AJs.get(p, "tighten"))) {
            if (include == "autonomous") gates.add(not(coalesce(cond(AJs.get(t, "when"), cols), true)))
            else if ("deny" == AJs.get(t, "signal")) gates.add(not(coalesce(cond(AJs.get(t, "when"), cols), true)))
        }
        return and(gates)
    }

    private val SYMS: Map<Any?, String> = mapOf("eq" to "=", "ne" to "<>", "lt" to "<", "lte" to "<=", "gt" to ">", "gte" to ">=")

    private fun render(e: Map<String, Any?>, postgres: Boolean, params: MutableList<Any?>): String {
        val t = e["t"] as String
        when (t) {
            "true" -> return "TRUE"
            "false" -> return "FALSE"
            "cmp" -> {
                val sym = SYMS[e["op"]]
                return "" + e["col"] + " " + sym + " " + ph(e["v"], postgres, params)
            }
            "in" -> {
                val hs = ArrayList<String>()
                for (v in AJs.list(e["vs"])) hs.add(ph(v, postgres, params))
                return "" + e["col"] + " " + (if (e["neg"] == true) "NOT IN" else "IN") + " (" + hs.joinToString(", ") + ")"
            }
            "prefix" -> {
                val sb = StringBuilder()
                for (ch in e["prefix"] as String) { if (ch == '!' || ch == '%' || ch == '_') sb.append('!'); sb.append(ch) }
                sb.append('%')
                return "" + e["col"] + " LIKE " + ph(sb.toString(), postgres, params) + " ESCAPE '!'"
            }
            "null" -> return "" + e["col"] + " IS " + (if (e["isNull"] == true) "" else "NOT ") + "NULL"
            "and", "or" -> {
                val rs = ArrayList<String>()
                for (x in AJs.list(e["xs"])) rs.add(render(AJs.map(x), postgres, params))
                return "(" + rs.joinToString(if (t == "and") " AND " else " OR ") + ")"
            }
            "not" -> return "NOT (" + render(AJs.map(e["x"]), postgres, params) + ")"
            else -> return "COALESCE(" + render(AJs.map(e["x"]), postgres, params) + ", " + (if (e["def"] == true) "TRUE" else "FALSE") + ")"
        }
    }

    private fun ph(v: Any?, postgres: Boolean, params: MutableList<Any?>): String {
        params.add(v)
        return if (postgres) "$" + params.size else "?"
    }

    /** Compile a residual to a parameterized SQL filter ({ok, expr, sql, params, ucast}), or say why it cannot be done exactly ({ok: false, reason}). Options: columns, dialect, include. */
    fun toFilter(res: Map<String, Any?>, o: Map<String, Any?>? = null): Map<String, Any?> {
        try {
            if ("never" == AJs.get(res, "decision")) return AJs.obj("ok", true, "expr", tOf("false"), "sql", "FALSE", "params", ArrayList<Any?>(), "ucast", toUcast(tOf("false")))
            val inc = AJs.get(o, "include")
            val include = if (inc == null) "autonomous" else if (inc is String) inc else ""
            val own = AJs.copy(AJs.get(res, "policy"))
            val meet = own.remove("meet")
            val all = ArrayList<Any?>()
            all.add(own)
            if (meet != null) all.addAll(AJs.list(meet))
            val colsO = AJs.get(o, "columns")
            val parts = ArrayList<Map<String, Any?>>()
            for (p in all) parts.add(partExpr(p, if (colsO is Map<*, *>) AJs.map(colsO) else null, include))
            val expr = and(parts)
            val params = ArrayList<Any?>()
            val d = AJs.get(o, "dialect")
            val sql = render(expr, d == null || "postgres" == d, params)
            return AJs.obj("ok", true, "expr", expr, "sql", sql, "params", params, "ucast", toUcast(expr))
        } catch (e: Unsupported) {
            return AJs.obj("ok", false, "reason", e.message)
        } catch (e: RuntimeException) {
            return AJs.obj("ok", false, "reason", "filter compilation error")
        } catch (e: StackOverflowError) {
            return AJs.obj("ok", false, "reason", "filter compilation error")
        }
    }

    // ---- evaluation of an expression over a row (Kleene) ----

    private fun get(row: Map<String, Any?>, c: String?): Any? = if (c != null && row.containsKey(c)) row[c] else null

    private fun typeOf(x: Any?): String = when {
        x is String -> "string"
        x is Boolean -> "boolean"
        AJs.isNum(x) -> "number"
        else -> "object"
    }

    private fun cmpVals(a: Any?, b: Any?): Int {
        if (a is String && b is String) return a.compareTo(b)
        val x = AJs.toNum(a)
        val y = AJs.toNum(b)
        return if (x < y) -1 else if (x > y) 1 else if (x == y) 0 else 2 // 2: unordered (NaN)
    }

    /** Evaluate a filter expression over one row with Kleene semantics: TRUE, FALSE, or null (unknown). */
    fun evalFilter(e: Map<String, Any?>, row: Map<String, Any?>): Boolean? {
        when (e["t"] as String) {
            "true" -> return true
            "false" -> return false
            "cmp" -> {
                val a = get(row, e["col"] as String?)
                val b = e["v"]
                if (a == null || typeOf(a) != typeOf(b)) return null
                val op = e["op"] as String
                if (op == "eq") return AJs.strictEq(a, b)
                if (op == "ne") return !AJs.strictEq(a, b)
                val c = cmpVals(a, b)
                if (c == 2) return false
                return if (op == "lt") c < 0 else if (op == "lte") c <= 0 else if (op == "gt") c > 0 else c >= 0
            }
            "in" -> {
                val a = get(row, e["col"] as String?) ?: return null
                val hit = AJs.includes(AJs.list(e["vs"]), a)
                return if (e["neg"] == true) !hit else hit
            }
            "prefix" -> {
                val a = get(row, e["col"] as String?)
                return if (a is String) a.startsWith(e["prefix"] as String) else null
            }
            "null" -> return (get(row, e["col"] as String?) == null) == (e["isNull"] == true)
            "and" -> {
                var unk = false
                for (y in AJs.list(e["xs"])) {
                    val v = evalFilter(AJs.map(y), row)
                    if (v == false) return false
                    if (v == null) unk = true
                }
                return if (unk) null else true
            }
            "or" -> {
                var unk = false
                for (y in AJs.list(e["xs"])) {
                    val v = evalFilter(AJs.map(y), row)
                    if (v == true) return true
                    if (v == null) unk = true
                }
                return if (unk) null else false
            }
            "not" -> {
                val v = evalFilter(AJs.map(e["x"]), row)
                return if (v == null) null else !v
            }
            else -> {
                val v = evalFilter(AJs.map(e["x"]), row)
                return v ?: (e["def"] == true)
            }
        }
    }

    // ---- UCAST ----

    private fun isEmpty(u: Map<String, Any?>, op: String): Boolean =
        "compound" == u["type"] && op == u["operator"] && AJs.list(u["value"]).isEmpty()

    private fun compound(op: String, v: List<Any?>): Map<String, Any?> = AJs.obj("type", "compound", "operator", op, "value", v)

    private fun join(op: String, xs: List<Map<String, Any?>>): Map<String, Any?> {
        val other = if (op == "and") "or" else "and"
        val flat = ArrayList<Map<String, Any?>>()
        for (x in xs) {
            if ("compound" == x["type"] && op == x["operator"]) for (y in AJs.list(x["value"])) flat.add(AJs.map(y))
            else flat.add(x)
        }
        for (x in flat) if (isEmpty(x, other)) return compound(other, ArrayList())
        val kept = ArrayList<Any?>()
        for (x in flat) if (!isEmpty(x, op)) kept.add(x)
        if (kept.size == 1) return AJs.map(kept[0])
        return compound(op, kept)
    }

    private fun and2(xs: List<Map<String, Any?>>): Map<String, Any?> = join("and", xs)
    private fun or2(xs: List<Map<String, Any?>>): Map<String, Any?> = join("or", xs)
    private fun not2(x: Map<String, Any?>): Map<String, Any?> { val v = ArrayList<Any?>(); v.add(x); return compound("not", v) }
    private fun f(field: String, op: String, value: Any?): Map<String, Any?> = AJs.obj("type", "field", "field", field, "operator", op, "value", value)
    private fun notNull(c: String): Map<String, Any?> = f(c, "ne", null)
    private fun l(vararg xs: Map<String, Any?>): List<Map<String, Any?>> = ArrayList(xs.asList())

    private fun mapAll(xs: Any?, positive: Boolean): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        for (x in AJs.list(xs)) out.add(if (positive) tU(AJs.map(x)) else fU(AJs.map(x)))
        return out
    }

    private val INV: Map<String, String> = mapOf("eq" to "ne", "ne" to "eq", "lt" to "gte", "lte" to "gt", "gt" to "lte", "gte" to "lt")

    private fun tU(x: Map<String, Any?>): Map<String, Any?> {
        val col = x["col"] as String?
        when (x["t"] as String) {
            "true" -> return and2(ArrayList())
            "false" -> return or2(ArrayList())
            "cmp" -> return if ("ne" == x["op"]) and2(l(notNull(col!!), f(col, "ne", x["v"]))) else f(col!!, x["op"] as String, x["v"])
            "in" -> return if (x["neg"] == true) and2(l(notNull(col!!), f(col, "nin", x["vs"]))) else f(col!!, "in", x["vs"])
            "prefix" -> return f(col!!, "startswith", x["prefix"])
            "null" -> return if (x["isNull"] == true) f(col!!, "eq", null) else notNull(col!!)
            "and" -> return and2(mapAll(x["xs"], true))
            "or" -> return or2(mapAll(x["xs"], true))
            "not" -> return fU(AJs.map(x["x"]))
            else -> return if (x["def"] == true) not2(fU(AJs.map(x["x"]))) else tU(AJs.map(x["x"]))
        }
    }

    private fun fU(x: Map<String, Any?>): Map<String, Any?> {
        val col = x["col"] as String?
        when (x["t"] as String) {
            "true" -> return or2(ArrayList())
            "false" -> return and2(ArrayList())
            "cmp" -> {
                val inv = INV[x["op"] as String]
                return and2(l(notNull(col!!), f(col, inv!!, x["v"])))
            }
            "in" -> return if (x["neg"] == true) f(col!!, "in", x["vs"]) else and2(l(notNull(col!!), f(col, "nin", x["vs"])))
            "prefix" -> return and2(l(notNull(col!!), not2(f(col, "startswith", x["prefix"]))))
            "null" -> return if (x["isNull"] == true) notNull(col!!) else f(col!!, "eq", null)
            "and" -> return or2(mapAll(x["xs"], false))
            "or" -> return and2(mapAll(x["xs"], false))
            "not" -> return tU(AJs.map(x["x"]))
            else -> return if (x["def"] == true) fU(AJs.map(x["x"])) else not2(tU(AJs.map(x["x"]))) // coalesce(x, FALSE) is false exactly when x is not definitely true
        }
    }

    /** The filter as a UCAST tree whose rows are exactly those the SQL form selects (every node compiled to "definitely true" / "definitely false"). */
    fun toUcast(e: Map<String, Any?>): Map<String, Any?> = tU(e)

    /** Evaluate a UCAST tree over one row (two-valued; a comparison with NULL is false, `eq null` / `ne null` test for NULL). */
    fun evalUcast(u: Map<String, Any?>, row: Map<String, Any?>): Boolean {
        if ("compound" == u["type"]) {
            val vs = AJs.list(u["value"])
            val op = u["operator"] as String
            if (op == "and") { for (c in vs) if (!evalUcast(AJs.map(c), row)) return false; return true }
            if (op == "or") { for (c in vs) if (evalUcast(AJs.map(c), row)) return true; return false }
            return !evalUcast(AJs.map(vs[0]), row)
        }
        val a = get(row, u["field"] as String?)
        val v = u["value"]
        val op = u["operator"] as String
        if (op == "eq" && v == null) return a == null
        if (op == "ne" && v == null) return a != null
        if (a == null) return false
        when (op) {
            "eq" -> return AJs.strictEq(a, v)
            "ne" -> return typeOf(a) == typeOf(v) && !AJs.strictEq(a, v)
            "lt" -> { val c = cmpVals(a, v); return typeOf(a) == typeOf(v) && c != 2 && c < 0 }
            "lte" -> { val c = cmpVals(a, v); return typeOf(a) == typeOf(v) && c != 2 && c <= 0 }
            "gt" -> { val c = cmpVals(a, v); return typeOf(a) == typeOf(v) && c != 2 && c > 0 }
            "gte" -> { val c = cmpVals(a, v); return typeOf(a) == typeOf(v) && c != 2 && c >= 0 }
            "in" -> return AJs.includes(AJs.list(v), a)
            "nin" -> return !AJs.includes(AJs.list(v), a)
            else -> return a is String && a.startsWith(v as String) // startswith
        }
    }
}
