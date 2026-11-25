package net.atlasauth.pca.analyzer

/**
 * VALIDATING A POLICY AGAINST THE ACTION SCHEMA / ACTIONDEFS: a lint that compares the two descriptions of the same actions before the
 * policy is signed (an undeclared parameter, a number compared with a string, an enum value that does not exist, a bound the schema makes
 * impossible or redundant, a predicate that can never match, a money verb with no ceiling, a unit-bearing parameter read without the matching
 * unit tag). Verb shapes are {verb, params: {name: {type?, values?, min?, max?, unit?, semantic?, sensitivity?, required?}}}.
 */
object Validate {
    private val DEF_TYPES = listOf("string", "integer", "boolean", "date", "set", "array")
    private val NUMERIC_OPS = listOf("lt", "lte", "gt", "gte")
    private val EQ_OPS = listOf("eq", "ne", "in", "nin")
    private val UNDEF = Any()

    /**
     * Verb shapes from real ActionDefs ({verb, params: {name: {type, role?, required?, values?, min?, max?, sensitivity?}}}). Types the
     * policy language cannot compare directly (`datetime`, `duration`, `object_ref`) are left untyped; a money role keeps its semantic so
     * the unbounded-money lint applies.
     */
    fun verbShapesFromActionDefs(defs: List<*>): List<Any?> {
        val out = ArrayList<Any?>()
        for (d in defs) {
            val params = LinkedHashMap<String, Any?>()
            val dp = AJs.copy(AJs.get(d, "params"))
            for (k in AJs.keys(dp)) params[k] = shapeOfDef(dp[k])
            val s = AJs.obj()
            AJs.putIf(s, "verb", d, "verb")
            s["params"] = params
            out.add(s)
        }
        return out
    }

    private fun shapeOfDef(p: Any?): MutableMap<String, Any?> {
        val m = AJs.obj()
        val t = AJs.get(AJs.req(p), "type")
        if (t is String && DEF_TYPES.contains(t)) m["type"] = t
        if (AJs.truthy(AJs.get(p, "role"))) m["semantic"] = AJs.get(p, "role")
        if (AJs.truthy(AJs.get(p, "values"))) m["values"] = AJs.get(p, "values")
        if (AJs.has(p, "min")) m["min"] = AJs.get(p, "min")
        if (AJs.has(p, "max")) m["max"] = AJs.get(p, "max")
        if (AJs.truthy(AJs.get(p, "sensitivity"))) m["sensitivity"] = AJs.get(p, "sensitivity")
        if (AJs.has(p, "required")) m["required"] = AJs.get(p, "required")
        return m
    }

    /** The verbs and parameters of a signed action schema ({verbs: [...]}), a list of shapes, or a list of ActionDefs. */
    fun verbShapes(src: Any?): List<Any?> {
        val out = ArrayList<Any?>()
        if (src !is List<*> && AJs.has(src, "verbs")) {
            for (v in AJs.list(AJs.get(src, "verbs"))) {
                val params = LinkedHashMap<String, Any?>()
                val vp = AJs.copy(AJs.get(v, "params"))
                for (k in AJs.keys(vp)) {
                    val d = vp[k]
                    val m = AJs.obj()
                    AJs.putIf(m, "type", d, "type")
                    if (AJs.truthy(AJs.get(d, "values"))) m["values"] = AJs.get(d, "values")
                    if (AJs.has(d, "min")) m["min"] = AJs.get(d, "min")
                    if (AJs.has(d, "max")) m["max"] = AJs.get(d, "max")
                    if (AJs.truthy(AJs.get(d, "unit"))) m["unit"] = AJs.get(d, "unit")
                    AJs.putIf(m, "semantic", d, "semantic")
                    AJs.putIf(m, "sensitivity", d, "sensitivity")
                    if (AJs.has(d, "required")) m["required"] = AJs.get(d, "required")
                    params[k] = m
                }
                val s = AJs.obj()
                AJs.putIf(s, "verb", v, "verb")
                s["params"] = params
                out.add(s)
            }
            return out
        }
        for (d in AJs.list(src)) {
            val verb: Any? = if (AJs.truthy(AJs.get(d, "verb"))) AJs.get(d, "verb") else if (AJs.truthy(AJs.get(d, "id"))) AJs.get(d, "id") else ""
            val orig = AJs.copy(AJs.get(d, "params"))
            val params = LinkedHashMap<String, Any?>()
            for (k in AJs.keys(orig)) {
                val m = shapeOfDef(orig[k])
                // shape-style params carry `semantic` and `unit` directly; keep them
                val o = orig[k]
                if (AJs.has(o, "semantic")) m["semantic"] = AJs.get(o, "semantic")
                if (AJs.has(o, "unit")) m["unit"] = AJs.get(o, "unit")
                params[k] = m
            }
            out.add(AJs.obj("verb", verb, "params", params))
        }
        return out
    }

    private fun leaves(c: Any?, into: MutableList<Any?>) {
        if (!(c is Map<*, *> || c is List<*>)) return
        if (Field.isGroup(c)) {
            val all = AJs.get(c, "all_of")
            val any = AJs.get(c, "any_of")
            if (AJs.has(c, "all_of") && all is List<*>) for (x in all) leaves(x, into)
            else if (AJs.has(c, "any_of") && any is List<*>) for (x in any) leaves(x, into)
            else if (AJs.has(c, "not")) leaves(AJs.get(c, "not"), into)
        } else into.add(c)
    }

    private fun typeOk(t: Any?, v: Any?): Boolean = when (t) {
        null -> true
        "integer" -> AJs.isFin(v)
        "boolean" -> v is Boolean
        "string", "date" -> v is String
        else -> true
    }

    private fun typeofJs(x: Any?): String = when {
        x == null -> "object"
        x is String -> "string"
        x is Boolean -> "boolean"
        AJs.isNum(x) -> "number"
        else -> "object"
    }

    private fun s(o: Any?): String = CaveatAnalysis.jsString(o, o !== UNDEF)

    private fun verbMatches(pv: Any?, verb: Any?): Boolean =
        "*" == pv || AJs.strictEq(pv, verb) || (pv is List<*> && (AJs.includes(pv, "*") || AJs.includes(pv, verb)))

    private fun bound(x: Any?, dflt: String): String = if (x == null) dflt else CaveatAnalysis.jsString(x, true)

    /**
     * Lint a policy against the schema it is written for: {ok (false when any finding is an error), findings: [{code, severity, message, where}]}.
     * Options: units (the grant's unit map), schemaUnits, listUngranted.
     */
    fun validatePolicyAgainstSchema(policy: Any?, src: Any?, o: Map<String, Any?>?): Map<String, Any?> {
        val shapes = verbShapes(src)
        val byVerb = LinkedHashMap<String, MutableMap<String, Any?>>()
        for (sh in shapes) { val v = AJs.get(sh, "verb"); if (v is String) byVerb[v] = AJs.map(sh) }
        var schemaUnits = AJs.get(o, "schemaUnits")
        if (schemaUnits == null && src !is List<*> && AJs.has(src, "units")) schemaUnits = AJs.get(src, "units")
        val model = Enumerate.toModel(policy)
        val findings = ArrayList<Any?>()
        val hasUnits = AJs.has(o, "units")

        for (i in model.predicates.indices) {
            val p = model.predicates[i]
            if (!(p is Map<*, *> || p is List<*>)) continue
            check(p, "predicates[$i]", false, shapes, byVerb, o, hasUnits, schemaUnits, findings)
            val r = Analyzer.alwaysDenies(AJs.obj("predicates", AJs.arr(p)))
            if (r["alwaysDenies"] == true && !AJs.truthy(r["approximate"])) add(findings, "unreachable-predicate", "warn", "predicates[$i]", "no action can ever match this predicate")
        }
        for (i in model.vetoes.indices) check(AJs.req(AJs.get(model.vetoes[i], "when")), "vetoes[$i]", true, shapes, byVerb, o, hasUnits, schemaUnits, findings)

        // a money verb with no ceiling in any predicate that grants it
        for (sh in shapes) {
            val verb = AJs.get(sh, "verb")
            val sp = AJs.copy(AJs.get(sh, "params"))
            val money = ArrayList<String>()
            for (k in AJs.keys(sp)) if (isMoney(sp[k])) money.add(k)
            if (money.isEmpty()) continue
            val granting = ArrayList<Any?>()
            for (p in model.predicates) if (verbMatches(AJs.get(p, "verb"), verb)) granting.add(p)
            if (granting.isEmpty()) {
                if (AJs.truthy(AJs.get(o, "listUngranted"))) add(findings, "verb-not-granted", "info", s(verb), "the schema declares '" + s(verb) + "' but no predicate grants it")
                continue
            }
            for (name in money) {
                val path = "action.params.$name"
                if (!granting.all { bounded(it, path) }) add(findings, "unbounded-money", "warn", s(verb), "'" + s(verb) + "' can move '" + name + "' with no per-action ceiling in at least one granting predicate")
            }
        }
        if (AJs.truthy(AJs.get(o, "listUngranted"))) {
            for (sh in shapes) {
                val sp = AJs.copy(AJs.get(sh, "params"))
                if (sp.values.any { isMoney(it) }) continue
                val granted = model.predicates.any { verbMatches(AJs.get(it, "verb"), AJs.get(sh, "verb")) }
                if (!granted) add(findings, "verb-not-granted", "info", s(AJs.get(sh, "verb")), "the schema declares '" + s(AJs.get(sh, "verb")) + "' but no predicate grants it")
            }
        }
        val ok = findings.none { "error" == AJs.get(it, "severity") }
        return AJs.obj("ok", ok, "findings", findings)
    }

    private fun isMoney(d: Any?): Boolean {
        val sem = AJs.get(d, "semantic") ?: return false
        return (sem as String).startsWith("money.")
    }

    private fun bounded(p: Any?, path: String): Boolean {
        val w = AJs.get(p, "where") as? List<*> ?: return false
        for (c in w) {
            val target: Any? = if (Field.isGroup(c)) AJs.obj("all_of", if (AJs.has(c, "all_of")) AJs.get(c, "all_of") else ArrayList<Any?>()) else c
            val ls = ArrayList<Any?>()
            leaves(target, ls)
            for (l in ls) {
                val op = AJs.get(l, "op")
                if (Field.isLeaf(l) && path == AJs.get(l, "field") && (op == "lt" || op == "lte" || op == "eq" || op == "in")) return true
            }
        }
        return false
    }

    private fun add(findings: MutableList<Any?>, code: String, severity: String, where: String, message: String) {
        findings.add(AJs.obj("code", code, "severity", severity, "where", where, "message", message))
    }

    private fun check(
        p: Any?, where: String, isVeto: Boolean, shapes: List<Any?>, byVerb: Map<String, MutableMap<String, Any?>>, o: Map<String, Any?>?,
        hasUnits: Boolean, schemaUnits: Any?, findings: MutableList<Any?>,
    ) {
        val pv = AJs.get(p, "verb")
        val verbs = ArrayList<Any?>()
        if ("*" == pv || (pv is List<*> && AJs.includes(pv, "*"))) for (sh in shapes) verbs.add(AJs.get(sh, "verb"))
        else if (pv is List<*>) verbs.addAll(pv)
        else verbs.add(if (AJs.has(p, "verb")) pv else UNDEF)
        for (v in verbs) {
            if (v !is String || !byVerb.containsKey(v)) add(findings, "undeclared-verb", if (isVeto) "warn" else "error", where, "verb '" + s(v) + "' is not declared by the schema")
        }
        val declared = ArrayList<MutableMap<String, Any?>>()
        for (v in verbs) if (v is String && byVerb.containsKey(v)) declared.add(byVerb[v]!!)
        if (declared.isEmpty()) return
        val pw = AJs.get(p, "where") as? List<*> ?: return
        for (wi in pw.indices) {
            val cs = ArrayList<Any?>()
            leaves(pw[wi], cs)
            for (c in cs) {
                if (!Field.isLeaf(c) || !(AJs.get(c, "field") as String).startsWith("action.params.")) continue
                val name = (AJs.get(c, "field") as String).substring("action.params.".length).split(".")[0]
                val at = "$where.where[$wi]"
                val having = declared.filter { val ps = AJs.get(it, "params"); ps is Map<*, *> && ps.containsKey(name) }
                if (having.isEmpty()) {
                    add(findings, "undeclared-param", "error", at, "parameter '" + name + "' is declared by none of " + joinVerbs(declared))
                    continue
                }
                if (having.size < declared.size) {
                    // identity, as the reference compares objects
                    val rest = declared.filter { sh -> having.none { it === sh } }
                    add(findings, "undeclared-param", "warn", at, "parameter '" + name + "' is not declared by " + joinVerbs(rest))
                }
                val d = AJs.map(AJs.get(having[0], "params"))[name]
                val op = AJs.get(c, "op")
                val value = AJs.get(c, "value")
                val vals: List<Any?> = if (value is List<*> && (op == "in" || op == "nin")) AJs.list(value) else AJs.arr(value)
                val dtype = AJs.get(d, "type")
                val noRef = !AJs.has(c, "ref")
                if (noRef && op is String && (EQ_OPS.contains(op) || NUMERIC_OPS.contains(op))) {
                    for (x in vals) if (!typeOk(dtype, x)) add(findings, "type-mismatch", "error", at, "'" + name + "' is " + s(dtype) + " but is compared (" + op + ") with " + typeofJs(x))
                }
                if (op is String && NUMERIC_OPS.contains(op) && dtype != null && "integer" != dtype) {
                    if ("string" == dtype || "date" == dtype) add(findings, "ordering-on-string", "warn", at, "'" + name + "' is " + s(dtype) + ": ordering follows UTF-8 byte order")
                    else add(findings, "type-mismatch", "error", at, "ordering operator " + op + " on " + s(dtype) + " parameter '" + name + "'")
                }
                val dvals = AJs.get(d, "values")
                if (AJs.truthy(dvals) && (op == "eq" || op == "in") && vals.isNotEmpty() && vals[0] is String) {
                    val missing = ArrayList<Any?>()
                    for (x in vals) if (x is String && !AJs.includes(AJs.list(dvals), x)) missing.add(x)
                    if (missing.size == vals.size) add(findings, "value-not-in-enum", "error", at, "no value of " + op + " " + AJs.stringify(vals) + " is in the schema's set for '" + name + "'")
                    else if (missing.isNotEmpty()) add(findings, "value-not-in-enum", "warn", at, AJs.stringify(missing) + " are not in the schema's set for '" + name + "'")
                }
                if ("integer" == dtype && AJs.isNum(value) && noRef) {
                    val v = AJs.num(value)!!
                    val hasMax = AJs.has(d, "max")
                    val hasMin = AJs.has(d, "min")
                    val dmax = if (hasMax) AJs.toNum(AJs.get(d, "max")) else Double.NaN
                    val dmin = if (hasMin) AJs.toNum(AJs.get(d, "min")) else Double.NaN
                    val opS = op as? String ?: ""
                    val dead = (opS == "eq" && ((hasMax && v > dmax) || (hasMin && v < dmin))) ||
                        (opS == "gt" && hasMax && v >= dmax) ||
                        (opS == "gte" && hasMax && v > dmax) ||
                        (opS == "lt" && hasMin && v <= dmin) ||
                        (opS == "lte" && hasMin && v < dmin)
                    val range = "[" + bound(AJs.get(d, "min"), "-inf") + ", " + bound(AJs.get(d, "max"), "inf") + "]"
                    if (dead) add(findings, "out-of-range", "error", at, "'" + name + "' " + opS + " " + AJs.fmt(v) + " can never hold: the schema bounds it to " + range)
                    else if ((opS == "lte" && hasMax && v >= dmax) || (opS == "gte" && hasMin && v <= dmin)) add(findings, "redundant-bound", "info", at, "'" + name + "' " + opS + " " + AJs.fmt(v) + " never binds: the schema already bounds it to " + range)
                }
                val unit = AJs.get(d, "unit")
                if (AJs.truthy(unit) && hasUnits && op is String && (NUMERIC_OPS.contains(op) || op == "eq") && !isVeto) {
                    val units = AJs.get(o, "units")
                    var tag = AJs.get(units, AJs.get(c, "field") as String)
                    if (tag == null) tag = AJs.get(units, "action.params.$name")
                    val sch = if (schemaUnits == null) null else AJs.get(schemaUnits, s(unit))
                    if (tag == null) add(findings, "unit-missing", "error", at, "'" + name + "' carries unit '" + s(unit) + "' but the policy has no unit tag for it (rule 20)")
                    else if (AJs.truthy(sch) && (!AJs.strictEq(AJs.get(tag, "kind"), AJs.get(sch, "kind")) || !AJs.strictEq(AJs.get(tag, "currency"), AJs.get(sch, "currency")) || !AJs.strictEq(AJs.get(tag, "exponent"), AJs.get(sch, "exponent")))) {
                        add(findings, "unit-mismatch", "error", at, "'" + name + "': policy unit " + AJs.stringify(tag) + " differs from the schema's " + AJs.stringify(sch) + " (rule 20)")
                    }
                }
            }
        }
    }

    private fun joinVerbs(shapes: List<Map<String, Any?>>): String =
        shapes.joinToString(", ") { CaveatAnalysis.jsString(AJs.get(it, "verb"), AJs.has(it, "verb")) }
}
