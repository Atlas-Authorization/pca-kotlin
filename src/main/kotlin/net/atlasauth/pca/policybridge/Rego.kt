package net.atlasauth.pca.policybridge

import java.util.regex.Pattern
import net.atlasauth.pca.verifier.Json

/**
 * OPA/Rego to PCA predicate translator. Models only the "allow rule as a conjunction of input comparisons" idiom and fails closed on
 * everything else: a rule with a conjunct outside the subset is dropped whole (never widened). Each allow rule is an independent predicate.
 */
object Rego {
    private val COMMENT = Pattern.compile("#[^\\n]*")
    private val PACKAGE = Pattern.compile(PbJs.WB_L + "package" + PbJs.S + "+([A-Za-z_][A-Za-z0-9_.]*)")
    private val DEFAULT = Pattern.compile(PbJs.WB_L + "default" + PbJs.S + "+allow" + PbJs.S + "*(?::?=)" + PbJs.S + "*(true|false)" + PbJs.WB_R)

    fun regoToPca(moduleText: String): Map<String, Any?> {
        val report = PolicyBridge.newReport("rego")
        val predicates = ArrayList<Any?>()

        val src = COMMENT.matcher(moduleText).replaceAll("")

        val pkg = PACKAGE.matcher(src)
        if (pkg.find()) PolicyBridge.list(report, "translated").add("package " + pkg.group(1))

        val def = DEFAULT.matcher(src)
        val hasDef = def.find()
        if (hasDef && def.group(1) == "true") {
            PolicyBridge.list(report, "skipped").add("`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny")
        } else if (!hasDef) {
            PolicyBridge.list(report, "skipped").add("no `default allow = false` found; assuming default-deny")
        }

        for (body in extractAllowBodies(src, report)) translateRule(body, predicates, report)

        return PolicyBridge.result(predicates, ArrayList(), report)
    }

    private val SPLIT = Regex("[\\n;]")

    private fun translateRule(body: String, predicates: MutableList<Any?>, report: Map<String, Any?>) {
        var verb: Any? = "*"
        var resource: String? = null
        val where = ArrayList<Any?>()

        for (stmt in PbJs.trimmedNonEmpty(SPLIT.split(body))) {
            val parsed = parseStatement(stmt)
            if (parsed.kind == Kind.UNMODELED) {
                PolicyBridge.list(report, "skipped").add("unmodeled statement \"" + PbJs.truncate(stmt) + "\" — rule dropped (fail closed)")
                return
            }
            if (parsed.kind == Kind.VERB) {
                if (verb == "*") {
                    verb = parsed.verb
                } else {
                    val have = asList(verb)
                    val next = asList(parsed.verb)
                    val both = ArrayList<Any?>()
                    for (v in have) if (next.contains(v)) both.add(v)
                    if (both.isEmpty()) {
                        PolicyBridge.list(report, "translated").add("rule can never match (contradictory action selectors), nothing emitted")
                        return
                    }
                    verb = if (both.size == 1) both[0] else both
                }
            } else if (parsed.kind == Kind.RESOURCE) {
                if (resource != null && resource != parsed.resource) {
                    PolicyBridge.list(report, "translated").add("rule can never match (contradictory resource selectors), nothing emitted")
                    return
                }
                resource = parsed.resource
            } else {
                where.add(parsed.condition)
            }
        }

        val predicate = LinkedHashMap<String, Any?>()
        predicate["verb"] = verb
        if (resource != null) predicate["resource"] = resource
        if (where.isNotEmpty()) predicate["where"] = where
        predicates.add(predicate)
        PolicyBridge.list(report, "translated").add("allow → verb " + PbJs.jsonVerb(verb) + (if (resource != null && resource.isNotEmpty()) " on $resource" else "") + " (" + where.size + " condition(s))")
    }

    @Suppress("UNCHECKED_CAST")
    private fun asList(verb: Any?): List<Any?> = if (verb is List<*>) verb as List<Any?> else listOf(verb)

    private enum class Kind { VERB, RESOURCE, CONDITION, UNMODELED }

    private class Parsed(val kind: Kind) {
        var verb: Any? = null
        var resource: String? = null
        var condition: Map<String, Any?>? = null

        companion object {
            val UNMODELED = Parsed(Kind.UNMODELED)
            fun verb(v: Any?): Parsed { val p = Parsed(Kind.VERB); p.verb = v; return p }
            fun resource(r: String): Parsed { val p = Parsed(Kind.RESOURCE); p.resource = r; return p }
            fun cond(c: Map<String, Any?>): Parsed { val p = Parsed(Kind.CONDITION); p.condition = c; return p }
        }
    }

    private val NOT = Pattern.compile("not" + PbJs.S + "+([\\s\\S]+)")
    private val UNMODELED_SYNTAX = Pattern.compile(
        ":=|" + PbJs.WB_L + "some" + PbJs.WB_R + "|" + PbJs.WB_L + "every" + PbJs.WB_R + "|\\[" + PbJs.DOT + "*\\|" + PbJs.DOT + "*\\]",
    )
    private val INDEXED = Pattern.compile(PbJs.WB_L + "input\\.[A-Za-z0-9_.]*\\[")
    private val COMPARISON = Pattern.compile(
        "(?s)(input\\.[A-Za-z0-9_.]+)" + PbJs.S + "*(==|!=|<=|>=|<|>|" + PbJs.WB_L + "in" + PbJs.WB_R + ")" + PbJs.S + "*(.+)",
    )
    private val INPUT_PATH = Pattern.compile("input\\.[A-Za-z0-9_.]+")

    private fun parseStatement(stmt: String): Parsed {
        val s = PbJs.trim(stmt)

        val nm = NOT.matcher(s)
        if (nm.matches()) {
            val inner = parseStatement(PbJs.trim(nm.group(1)))
            if (inner.kind != Kind.CONDITION) return Parsed.UNMODELED
            // `not input.p == lit` is unification and stays inside the negation (an absent path makes it undefined, so the not
            // holds); every other comparison resolves its arguments first, so an absent path leaves the statement undefined.
            val c = inner.condition!!
            if ("eq" == c["op"] && c["field"] is String) {
                val all = ArrayList<Any?>()
                all.add(PbJs.obj("field", c["field"], "op", "exists"))
                if (c["ref"] is String) all.add(PbJs.obj("field", c["ref"], "op", "exists"))
                all.add(c)
                return Parsed.cond(PbJs.obj("not", PbJs.obj("all_of", all)))
            }
            return Parsed.cond(PbJs.obj("not", c))
        }

        val builtin = parseBuiltin(s)
        if (builtin != null) return builtin

        if (UNMODELED_SYNTAX.matcher(s).find()) return Parsed.UNMODELED
        if (s.indexOf('(') >= 0) return Parsed.UNMODELED
        if (INDEXED.matcher(s).find()) return Parsed.UNMODELED

        val m = COMPARISON.matcher(s)
        if (!m.matches()) return Parsed.UNMODELED
        val path = m.group(1)
        val opTok = m.group(2)
        val rhsRaw = PbJs.trim(m.group(3))
        val sub = path.substring("input.".length)

        if (opTok == "in") {
            val set = parseSetLiteral(rhsRaw) ?: return Parsed.UNMODELED
            if (sub == "action") {
                for (v in set) if (v !is String) return Parsed.UNMODELED
                return Parsed.verb(ArrayList(set))
            }
            return Parsed.cond(PbJs.obj("field", "env.$sub", "op", "in", "value", set))
        }

        if ((opTok == "==" || opTok == "!=") && INPUT_PATH.matcher(rhsRaw).matches()) {
            return Parsed.cond(PbJs.obj("field", "env.$sub", "op", if (opTok == "!=") "ne" else "eq", "ref", "env." + rhsRaw.substring("input.".length)))
        }

        val lit = toLiteral(rhsRaw)
        if (lit === NO_LITERAL) return Parsed.UNMODELED

        if (opTok == "==") {
            if (sub == "action" && lit is String) return Parsed.verb(lit)
            if (sub == "resource" && lit is String) return Parsed.resource(lit)
            return Parsed.cond(PbJs.obj("field", "env.$sub", "op", "eq", "value", lit))
        }
        if (opTok == "!=") return Parsed.cond(PbJs.obj("field", "env.$sub", "op", "ne", "value", lit))

        if (!(lit is Number || lit is Json.Num)) return Parsed.UNMODELED
        val cmp = if (opTok == "<") "lt" else if (opTok == "<=") "lte" else if (opTok == ">") "gt" else "gte"
        return Parsed.cond(PbJs.obj("field", "env.$sub", "op", cmp, "value", lit))
    }

    private val STARTSWITH = Pattern.compile(
        "startswith\\(" + PbJs.S + "*(input\\.[A-Za-z0-9_.]+)" + PbJs.S + "*," + PbJs.S + "*\"([^\"]*)\"" + PbJs.S + "*\\)",
    )
    private val GLOB = Pattern.compile(
        "glob\\.match\\(" + PbJs.S + "*\"([^\"]*)\"" + PbJs.S + "*," + PbJs.S + "*(\\[" + PbJs.S + "*\\]|null)" + PbJs.S + "*," + PbJs.S + "*(input\\.[A-Za-z0-9_.]+)" + PbJs.S + "*\\)",
    )
    private val GLOB_META = Pattern.compile("[\\[\\]{}]")
    private val WILDCARD = Pattern.compile("[*?\\\\]")

    /** A pure, anchored matcher builtin as a condition; null = not a builtin we model (fall through), UNMODELED = recognised but outside the subset. */
    private fun parseBuiltin(s: String): Parsed? {
        val sw = STARTSWITH.matcher(s)
        if (sw.matches()) {
            val sub = sw.group(1).substring("input.".length)
            return Parsed.cond(PbJs.obj("field", "env.$sub", "op", "prefix", "value", sw.group(2)))
        }
        val gm = GLOB.matcher(s)
        if (gm.matches()) {
            val pattern = gm.group(1)
            if (GLOB_META.matcher(pattern).find()) return Parsed.UNMODELED
            // An EMPTY delimiter list means OPA splits on ".", so a wildcard would be cut by a dot: only `null` makes `*` span all.
            if (gm.group(2).startsWith("[") && WILDCARD.matcher(pattern).find()) return Parsed.UNMODELED
            val sub = gm.group(3).substring("input.".length)
            return Parsed.cond(PbJs.obj("field", "env.$sub", "op", "like", "value", pattern))
        }
        return null
    }

    /** Find each `allow` rule body `{ ... }`, brace-aware (set literals inside the body use braces). */
    private val ALLOW = Pattern.compile(
        PbJs.WB_L + "allow" + PbJs.WB_R + PbJs.S + "*(?:(?::?=" + PbJs.S + "*true" + PbJs.WB_R + "|=" + PbJs.S + "*true" + PbJs.WB_R + "|" + PbJs.WB_L + "if" + PbJs.WB_R + ")" + PbJs.S + "*)?\\{",
    )

    private fun extractAllowBodies(src: String, report: Map<String, Any?>): List<String> {
        val bodies = ArrayList<String>()
        val m = ALLOW.matcher(src)
        var pos = 0
        while (pos <= src.length && m.find(pos)) {
            val open = src.indexOf('{', m.start())
            val close = PbJs.matchDelim(src, open, '{', '}')
            if (close < 0) {
                PolicyBridge.list(report, "errors").add("unterminated `allow { ... }` block")
                break
            }
            bodies.add(src.substring(open + 1, close))
            pos = close + 1
        }
        return bodies
    }

    // ---- literals ----

    private val NO_LITERAL = Any()
    private val NUMBER = Pattern.compile("-?[0-9]+(?:\\.[0-9]+)?")

    private fun toLiteral(expr: String): Any? {
        val s = PbJs.trim(expr)
        if (s.length >= 2 && s[0] == '"' && s[s.length - 1] == '"' && s.indexOf('"', 1) == s.length - 1) return s.substring(1, s.length - 1)
        if (s == "true") return true
        if (s == "false") return false
        if (NUMBER.matcher(s).matches()) return PbJs.number(s)
        return NO_LITERAL
    }

    /** A Rego set `{"a","b"}` or array `["a","b"]` of scalar literals; null when it is neither or an item is not a scalar. */
    private fun parseSetLiteral(expr: String): List<Any?>? {
        val s = PbJs.trim(expr)
        val isSet = s.startsWith("{") && s.endsWith("}")
        val isArr = s.startsWith("[") && s.endsWith("]")
        if (!isSet && !isArr) return null
        val values = ArrayList<Any?>()
        for (it in PbJs.trimmedNonEmpty(PbJs.splitTopLevel(PbJs.slice(s, 1, -1), ","))) {
            val lit = toLiteral(it)
            if (lit === NO_LITERAL) return null
            values.add(lit)
        }
        return values
    }
}
