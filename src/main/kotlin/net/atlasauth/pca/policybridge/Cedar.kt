package net.atlasauth.pca.policybridge

import java.util.regex.Pattern

/**
 * Cedar to PCA predicate translator: `permit`/`forbid (principal, action, resource) [when {..}] [unless {..}];` units become permit
 * predicates and deny predicates over the predicate DSL. Everything outside the documented subset is reported and fails closed (a
 * dropped `forbid` is an error).
 */
object Cedar {
    /** The reflexive adjacency map (child uid to parent uids) that `in` / member_of resolves against. */
    internal const val ENTITY_PARENTS = "env.entity_parents"

    /** An error of the translation (the reference's thrown `Error`); its message lands in the report. */
    internal class CedarError(m: String) : RuntimeException(m, null, false, false)

    fun cedarToPca(policyText: String): Map<String, Any?> = translateCedar(policyText, true)

    /** `errorGuards = false` omits the trailing "no attribute was missing" guard (structure only; not exact). */
    fun translateCedar(policyText: String, errorGuards: Boolean): Map<String, Any?> {
        val report = PolicyBridge.newReport("cedar")
        val predicates = ArrayList<Any?>()
        val denies = ArrayList<Any?>()
        val cleaned = stripComments(policyText)
        for (stmt in PbJs.trimmedNonEmpty(PbJs.splitTopLevel(cleaned, ";"))) {
            try {
                translateStatement(stmt, predicates, denies, report, errorGuards)
            } catch (e: CedarError) {
                PolicyBridge.list(report, "errors").add("policy \"" + PbJs.truncate(stmt) + "\": " + e.message)
            } catch (e: StackOverflowError) {
                PolicyBridge.list(report, "errors").add("policy \"" + PbJs.truncate(stmt) + "\": Maximum call stack size exceeded")
            }
        }
        return PolicyBridge.result(predicates, denies, report)
    }

    private val COMMENT = Pattern.compile("//[^\\n]*")
    private fun stripComments(text: String): String = COMMENT.matcher(text).replaceAll("")

    // ---- statement ----

    private val ANNOT = Pattern.compile(PbJs.S + "*(?:@[A-Za-z_][A-Za-z0-9_]*" + PbJs.S + "*\\([^)]*\\)" + PbJs.S + "*)+")
    private val HEAD = Pattern.compile(PbJs.S + "*(permit|forbid)" + PbJs.S + "*\\(", Pattern.CASE_INSENSITIVE)

    private fun translateStatement(stmt: String, permits: MutableList<Any?>, denies: MutableList<Any?>, report: Map<String, Any?>, errorGuards: Boolean) {
        var body = stmt
        val annot = ANNOT.matcher(body)
        if (annot.lookingAt()) body = PbJs.slice(body, annot.end())

        val head = HEAD.matcher(body)
        if (!head.lookingAt()) {
            PolicyBridge.list(report, "skipped").add("unrecognized statement: \"" + PbJs.truncate(stmt) + "\"")
            return
        }
        val effect = if (head.group(1).lowercase(java.util.Locale.ROOT) == "forbid") "forbid" else "permit"

        val openIdx = body.indexOf('(', head.start())
        val closeIdx = PbJs.matchDelim(body, openIdx, '(', ')')
        if (closeIdx < 0) throw CedarError("unterminated scope parentheses")
        val scopeText = body.substring(openIdx + 1, closeIdx)
        val rest = body.substring(closeIdx + 1)

        val scope = parseScope(scopeText)

        val where = ArrayList<Any?>(scope.scopeConditions)
        val guards = ArrayList<Any?>()

        for (block in parseConditionBlocks(rest)) {
            val parsed = parseExpr(block.text)
            if (parsed == null) {
                PolicyBridge.list(report, "skipped").add("unmodeled ${block.kind}-condition \"" + PbJs.truncate(block.text) + "\" — policy dropped (fail closed)")
                dropPolicy(effect, stmt, report)
                return
            }
            where.add(if (block.kind == "when") parsed else PbJs.obj("not", parsed))
            val g = noError(parsed)
            if (g != null) guards.add(g)
        }

        val conditionCount = where.size
        if (errorGuards && guards.isNotEmpty()) where.add(if (guards.size == 1) guards[0] else PbJs.obj("all_of", guards))

        val predicate = LinkedHashMap<String, Any?>()
        predicate["verb"] = scope.verb
        if (scope.resource != null) predicate["resource"] = scope.resource
        if (where.isNotEmpty()) predicate["where"] = where

        val on = if (scope.resource != null && scope.resource!!.isNotEmpty()) " on " + scope.resource else ""
        if (effect == "permit") {
            permits.add(predicate)
            PolicyBridge.list(report, "translated").add("permit → verb " + PbJs.jsonVerb(scope.verb) + on + " (" + conditionCount + " condition(s))")
        } else {
            denies.add(predicate)
            PolicyBridge.list(report, "translated").add("forbid → deny verb " + PbJs.jsonVerb(scope.verb) + on + " (" + conditionCount + " condition(s))")
        }
    }

    /** A dropped permit grants nothing; a dropped forbid is unsafe, so it is an error. */
    private fun dropPolicy(effect: String, stmt: String, report: Map<String, Any?>) {
        if (effect == "forbid") {
            PolicyBridge.list(report, "errors").add("forbid could not be fully modeled and was dropped — treat result as fail-closed: \"" + PbJs.truncate(stmt) + "\"")
        }
    }

    // ---- scope ----

    private class Scope {
        var verb: Any? = "*"
        var resource: String? = null
        val scopeConditions = ArrayList<Any?>()
    }

    private val SCOPE_CLAUSE = Pattern.compile("(principal|action|resource)" + PbJs.WB_R + PbJs.S + "*(?:(==|in|is)" + PbJs.S + "*)?([\\s\\S]*)")

    private fun parseScope(scopeText: String): Scope {
        val result = Scope()
        for (clause in PbJs.trimmedNonEmpty(PbJs.splitTopLevel(scopeText, ","))) {
            val m = SCOPE_CLAUSE.matcher(clause)
            if (!m.matches()) throw CedarError("unparseable scope clause \"" + PbJs.truncate(clause) + "\"")
            val variable = m.group(1)
            val op: String? = m.group(2)
            val operand = PbJs.trim(m.group(3) ?: "")

            if (op == null) continue

            if (variable == "action") {
                if (op == "==") {
                    val id = entityId(operand) ?: throw CedarError("action == expects an Action entity, got \"" + PbJs.truncate(operand) + "\"")
                    result.verb = id
                } else if (op == "in" && operand.startsWith("[")) {
                    val verbs = ArrayList<Any?>()
                    for (it in PbJs.trimmedNonEmpty(PbJs.splitTopLevel(PbJs.slice(operand, 1, -1), ","))) {
                        val id = entityId(it) ?: throw CedarError("action in [...] expects Action entities, got \"" + PbJs.truncate(it) + "\"")
                        verbs.add(id)
                    }
                    result.verb = verbs
                } else {
                    throw CedarError("unsupported action scope operator \"$op\"")
                }
            } else {
                val field = if (variable == "resource") "action.resource" else "subject.id"
                if (op == "==") {
                    val eid = entityUid(operand)
                    if (variable == "resource") {
                        if (eid == null) throw CedarError("resource == expects an entity, got \"" + PbJs.truncate(operand) + "\"")
                        result.resource = eid
                    } else {
                        if (eid == null) throw CedarError("principal == expects an entity, got \"" + PbJs.truncate(operand) + "\"")
                        result.scopeConditions.add(PbJs.obj("field", field, "op", "eq", "value", eid))
                    }
                } else if (op == "is") {
                    val type = typeName(operand) ?: throw CedarError("$variable is expects a type, got \"" + PbJs.truncate(operand) + "\"")
                    result.scopeConditions.add(PbJs.obj("field", field, "op", "is_a", "value", type))
                } else {
                    val mem = memberOfCondition(field, operand) ?: throw CedarError("$variable in expects an entity (hierarchy), got \"" + PbJs.truncate(operand) + "\"")
                    result.scopeConditions.add(mem)
                }
            }
        }
        return result
    }

    // ---- conditions ----

    private class Block(val kind: String, val text: String)

    private val BLOCK = Pattern.compile(PbJs.WB_L + "(when|unless)" + PbJs.WB_R + PbJs.S + "*\\{")

    private fun parseConditionBlocks(rest: String): List<Block> {
        val blocks = ArrayList<Block>()
        val m = BLOCK.matcher(rest)
        var pos = 0
        while (pos <= rest.length && m.find(pos)) {
            val kind = if (m.group(1) == "unless") "unless" else "when"
            val open = rest.indexOf('{', m.start())
            val close = PbJs.matchDelim(rest, open, '{', '}')
            if (close < 0) throw CedarError("unterminated $kind block")
            blocks.add(Block(kind, rest.substring(open + 1, close)))
            pos = close + 1
        }
        return blocks
    }

    /** A boolean expression: `||` (any_of) over `&&` (all_of) over parentheses over comparison atoms; null if outside the subset. */
    private fun parseExpr(text: String): Map<String, Any?>? {
        val t = PbJs.trim(text)
        if (t.isEmpty()) return null

        val ors = PbJs.trimmedNonEmpty(PbJs.splitTopLevel(t, "||"))
        if (ors.size > 1) {
            val subs = ArrayList<Any?>()
            for (s in ors) { val c = parseExpr(s) ?: return null; subs.add(c) }
            return PbJs.obj("any_of", subs)
        }
        val ands = PbJs.trimmedNonEmpty(PbJs.splitTopLevel(t, "&&"))
        if (ands.size > 1) {
            val subs = ArrayList<Any?>()
            for (s in ands) { val c = parseExpr(s) ?: return null; subs.add(c) }
            return PbJs.obj("all_of", subs)
        }
        if (t.startsWith("(") && PbJs.matchDelim(t, 0, '(', ')') == t.length - 1) return parseExpr(PbJs.slice(t, 1, -1))
        return parseAtom(t)
    }

    private val CMP = listOf("==" to "eq", "!=" to "ne", "<=" to "lte", ">=" to "gte", "<" to "lt", ">" to "gt")
    private val WORD_OP = Pattern.compile("([\\s\\S]*?" + PbJs.NS + ")" + PbJs.S + "+(in|is|like|has)" + PbJs.S + "+([\\s\\S]+)")

    private fun parseAtom(text: String): Map<String, Any?>? {
        val t = PbJs.trim(text)
        for (c in CMP) {
            val idx = PbJs.indexOfTopLevel(t, c.first)
            if (idx >= 0) {
                val lhs = PbJs.trim(t.substring(0, idx))
                val rhs = PbJs.trim(t.substring(idx + c.first.length))
                return buildComparison(lhs, c.second, rhs)
            }
        }
        val wm = WORD_OP.matcher(t)
        if (wm.matches()) return buildWordOp(PbJs.trim(wm.group(1)), wm.group(2), PbJs.trim(wm.group(3)))
        return null
    }

    private fun buildComparison(lhsRaw: String, op: String, rhsRaw: String): Map<String, Any?>? {
        val field = toFieldPath(lhsRaw) ?: return null
        if (field == "action.verb") {
            if (op != "eq" && op != "ne") return null
            val id = entityId(rhsRaw)
            return if (id == null) null else PbJs.obj("field", field, "op", op, "value", id)
        }
        if (isPathExpr(rhsRaw)) {
            val refPath = toFieldPath(rhsRaw)
            if (refPath != null) return PbJs.obj("field", field, "op", op, "ref", refPath)
        }
        val lit = toLiteral(rhsRaw)
        if (lit === NO_LITERAL) return null
        return PbJs.obj("field", field, "op", op, "value", lit)
    }

    private val HAS_ATTR = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*")

    private fun buildWordOp(lhsRaw: String, kind: String, rhsRaw: String): Map<String, Any?>? {
        if (kind == "has") {
            if (!HAS_ATTR.matcher(rhsRaw).matches()) return null
            val f = toFieldPath("$lhsRaw.$rhsRaw")
            return if (f == null) null else PbJs.obj("field", f, "op", "exists")
        }

        val field = toFieldPath(lhsRaw) ?: return null

        if (field == "action.verb") {
            if (kind != "in") return null
            val inner = if (rhsRaw.startsWith("[") && rhsRaw.endsWith("]")) PbJs.slice(rhsRaw, 1, -1) else rhsRaw
            val ids = ArrayList<Any?>()
            for (x in PbJs.trimmedNonEmpty(PbJs.splitTopLevel(inner, ","))) {
                val id = entityId(x) ?: return null
                ids.add(id)
            }
            return if (ids.isNotEmpty()) PbJs.obj("field", field, "op", "in", "value", ids) else null
        }

        if (kind == "is") {
            val type = typeName(rhsRaw)
            return if (type == null) null else PbJs.obj("field", field, "op", "is_a", "value", type)
        }

        if (kind == "like") {
            if (rhsRaw.length < 2 || !rhsRaw.startsWith("\"") || !rhsRaw.endsWith("\"")) return null
            return PbJs.obj("field", field, "op", "like", "value", cedarLikeToGlob(rhsRaw.substring(1, rhsRaw.length - 1)))
        }

        // kind == "in"
        if (rhsRaw.startsWith("[")) {
            val inner = if (rhsRaw.endsWith("]")) PbJs.slice(rhsRaw, 1, -1) else PbJs.slice(rhsRaw, 1)
            val items = PbJs.trimmedNonEmpty(PbJs.splitTopLevel(inner, ","))
            var allEntities = true
            for (it in items) if (entityUid(it) == null) { allEntities = false; break }
            if (allEntities && items.isNotEmpty()) {
                val uids = ArrayList<Any?>()
                for (it in items) uids.add(entityUid(it))
                return PbJs.obj("field", field, "op", "member_of", "value", uids, "collection", ENTITY_PARENTS)
            }
            val values = ArrayList<Any?>()
            for (it in items) {
                val lit = toLiteral(it)
                if (lit === NO_LITERAL) return null
                values.add(lit)
            }
            return PbJs.obj("field", field, "op", "in", "value", values)
        }
        return memberOfCondition(field, rhsRaw)
    }

    /** A member_of condition for `<field> in <entity|path>` (entity literal gives a value, a path gives a ref). */
    private fun memberOfCondition(field: String, operand: String): Map<String, Any?>? {
        val eid = entityUid(operand)
        if (eid != null) return PbJs.obj("field", field, "op", "member_of", "value", eid, "collection", ENTITY_PARENTS)
        if (isPathExpr(operand)) {
            val ref = toFieldPath(operand)
            if (ref != null) return PbJs.obj("field", field, "op", "member_of", "ref", ref, "collection", ENTITY_PARENTS)
        }
        return null
    }

    private val PATH_START = Pattern.compile("(principal|resource|action|context)" + PbJs.WB_R)
    private fun isPathExpr(expr: String): Boolean = PATH_START.matcher(expr).lookingAt()

    private val P_ATTR = Pattern.compile("principal\\.([A-Za-z_][A-Za-z0-9_.]*)")
    private val R_ATTR = Pattern.compile("resource\\.([A-Za-z_][A-Za-z0-9_.]*)")
    private val C_ATTR = Pattern.compile("context\\.([A-Za-z_][A-Za-z0-9_.]*)")

    /** Map a Cedar scope-variable expression to a PCA dotted field path; null if not a path. */
    private fun toFieldPath(expr: String): String? {
        if (expr == "principal") return "subject.id"
        if (expr == "resource") return "action.resource"
        if (expr == "action") return "action.verb"
        if (expr == "context") return "env"
        val mp = P_ATTR.matcher(expr)
        if (mp.matches()) return "subject." + mp.group(1)
        val mr = R_ATTR.matcher(expr)
        if (mr.matches()) return "env.resource." + mr.group(1)
        val mc = C_ATTR.matcher(expr)
        if (mc.matches()) return "env." + mc.group(1)
        return null
    }

    // ---- literals / entities ----

    /** A Cedar type name (`User`, `Ns::User`), or null. */
    internal fun typeName(expr: String): String? {
        val s = PbJs.trim(expr)
        var i = 0
        val n = s.length
        while (true) {
            if (i >= n || !PbJs.isIdentStart(s[i])) return null
            i++
            while (i < n && PbJs.isIdentPart(s[i])) i++
            if (i == n) return s
            if (i + 1 < n && s[i] == ':' && s[i + 1] == ':') { i += 2; continue }
            return null
        }
    }

    /** Split `Prefix::"id"` into {prefix, id}, or null (prefix at least one character, no line terminator or space; id without a quote). */
    private fun entityParts(expr: String): Array<String>? {
        val s = PbJs.trim(expr)
        val n = s.length
        if (n < 4 || s[n - 1] != '"') return null
        val j = s.lastIndexOf('"', n - 2)
        if (j < 3 || s[j - 1] != ':' || s[j - 2] != ':') return null
        val prefix = s.substring(0, j - 2)
        for (c in prefix) {
            if (c == '\n' || c == '\r' || c == ' ' || c == ' ') return null
        }
        return arrayOf(prefix, s.substring(j + 1, n - 1))
    }

    /** The quoted id of an entity reference `Ns::Type::"id"`, or null. */
    internal fun entityId(expr: String): String? = entityParts(expr)?.get(1)

    /** An entity reference rendered as its UID with quotes dropped: `Type::"id"` becomes `Type::id`. */
    internal fun entityUid(expr: String): String? = entityParts(expr)?.let { it[0] + "::" + it[1] }

    internal val NO_LITERAL = Any()
    private val NUMBER = Pattern.compile("-?[0-9]+(?:\\.[0-9]+)?")

    private fun toLiteral(expr: String): Any? {
        val s = PbJs.trim(expr)
        if (s.length >= 2 && s[0] == '"' && s[s.length - 1] == '"' && s.indexOf('"', 1) == s.length - 1) return s.substring(1, s.length - 1)
        if (s == "true") return true
        if (s == "false") return false
        if (NUMBER.matcher(s).matches()) return PbJs.number(s)
        val eid = entityUid(s)
        if (eid != null) return eid
        return NO_LITERAL
    }

    /** A Cedar `like` pattern (only `*` is a wildcard; `\*` is a literal star) as the PCA glob. */
    internal fun cedarLikeToGlob(inner: String): String {
        val out = StringBuilder()
        var i = 0
        while (i < inner.length) {
            val ch = inner[i]
            if (ch == '\\') {
                if (i + 1 < inner.length) {
                    val n = inner[i + 1]
                    if (n == '*') { out.append("\\*"); i += 2; continue }
                    out.append(escapeGlobLiteral(n))
                    i += 2
                    continue
                }
                out.append("\\\\")
                i++
                continue
            }
            if (ch == '*') { out.append('*'); i++; continue }
            out.append(escapeGlobLiteral(ch))
            i++
        }
        return out.toString()
    }

    private fun escapeGlobLiteral(ch: Char): String = if (ch == '*' || ch == '?' || ch == '\\') "\\" + ch else ch.toString()

    // ---- Cedar evaluation-error semantics ----

    private val TOTAL_FIELDS = setOf("subject.id", "action.verb", "action.resource", "env")

    /** Attribute reads that can raise a Cedar "attribute missing" error: principal.x, resource.x, context.x. */
    private fun guardedPaths(field: String?): List<String> {
        if (field == null || TOTAL_FIELDS.contains(field) || field.startsWith("env.entity_parents")) return emptyList()
        return if (field.startsWith("subject.") || field.startsWith("env.")) listOf(field) else emptyList()
    }

    private fun exists(field: String): Map<String, Any?> = PbJs.obj("field", field, "op", "exists")

    private fun allOf(xs: List<Map<String, Any?>>): Map<String, Any?> = if (xs.size == 1) xs[0] else PbJs.obj("all_of", ArrayList<Any?>(xs))
    private fun anyOf(xs: List<Map<String, Any?>>): Map<String, Any?> = if (xs.size == 1) xs[0] else PbJs.obj("any_of", ArrayList<Any?>(xs))

    /**
     * "Evaluating this expression raises no Cedar error", as a condition (null = it cannot). Cedar evaluates && and || left to right
     * and does not look at the right side once the left has decided, so it only needs its attributes present when the left was true
     * (&&) or false (||).
     */
    @Suppress("UNCHECKED_CAST")
    internal fun noError(c: Map<String, Any?>): Map<String, Any?>? {
        if (c.containsKey("not")) return noError(c["not"] as Map<String, Any?>)
        if (c.containsKey("all_of") || c.containsKey("any_of")) {
            val isAnd = c.containsKey("all_of")
            val kids = (if (isAnd) c["all_of"] else c["any_of"]) as List<Any?>
            var acc: Map<String, Any?>? = null
            for (i in kids.size - 1 downTo 0) {
                val kid = kids[i] as Map<String, Any?>
                val n = noError(kid)
                val cont = if (acc == null) null else anyOf(listOf(if (isAnd) PbJs.obj("not", kid) else kid, acc))
                acc = if (n == null) cont else if (cont == null) n else allOf(listOf(n, cont))
            }
            return acc
        }
        val field = c["field"] as String?
        val ref = c["ref"] as String?
        if ("exists" == c["op"] && field != null) {
            val k = field.lastIndexOf('.')
            val base = if (k >= 0 && k < field.length - 1) field.substring(0, k) else field
            var parts = 1
            for (ch in base) if (ch == '.') parts++
            val deep = parts >= (if (base.startsWith("env.resource")) 3 else 2)
            val baseNeeds = ArrayList<Map<String, Any?>>()
            if (deep) for (p in guardedPaths(base)) baseNeeds.add(exists(p))
            return if (baseNeeds.isEmpty()) null else allOf(baseNeeds)
        }
        val needs = ArrayList<Map<String, Any?>>()
        for (p in guardedPaths(field)) needs.add(exists(p))
        for (p in guardedPaths(ref)) needs.add(exists(p))
        return if (needs.isEmpty()) null else allOf(needs)
    }
}
