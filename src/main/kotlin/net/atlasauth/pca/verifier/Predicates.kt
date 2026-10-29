package net.atlasauth.pca.verifier

/**
 * The deterministic predicate DSL (packages/pca/src/predicates.ts `evaluatePredicates`): the ONE evaluator the Intent
 * Layer v2 `layers` check runs each ceiling through. Pure data, total, fail closed.
 *
 * A predicate is `{verb, resource?, where?}`: `verb` a string (`"*"` = any) or a list of them; `resource` exact, `"*"`,
 * a trailing-`*` prefix or `re:<pattern>` (full match, linear-time [SafeRegex]); `where` a list of conditions that must
 * all hold. A condition is a leaf `{field, op, value | ref, collection?}` over a dotted path rooted at `action`,
 * `subject` or `env`, or a grouping `all_of` / `any_of` / `not` evaluated three-valued (an undecidable child never
 * satisfies a `not`). Operators: eq, ne, in, nin, lt, lte, gt, gte, prefix, exists, like, matches, is_a, member_of.
 * Numbers compare by binary64 value; strings by UTF-8 bytes; equality by the canonical JSON text.
 *
 * The context is a JSON-tree map `{action: {verb, resource, params?}, subject?, env?}`.
 */
object Predicates {
    const val MAX_PATTERN_SUBJECT_LEN = 512
    const val MAX_LIKE_PATTERN_LEN = 512
    const val MAX_MATCHES_PATTERN_LEN = 200
    const val MAX_MEMBER_CLOSURE_NODES = 10_000
    const val MAX_RE_RESOURCE_LEN = 512

    /** Three-valued condition truth. */
    enum class Tri { TRUE, FALSE, UNKNOWN }

    private val ROOTS = setOf("action", "subject", "env")
    private val FORBIDDEN = setOf("__proto__", "constructor", "prototype")
    private val INDEX = Regex("0|[1-9][0-9]*")

    private fun isObjRec(x: Any?): Boolean = x is Map<*, *>

    /** JavaScript `typeof x === 'object' && x !== null` (maps and lists). */
    private fun isJsObject(x: Any?): Boolean = x is Map<*, *> || x is List<*>

    /** The resolved value of a dotted path: `found` plus the value (own members only). */
    class Resolved internal constructor(val found: Boolean, val value: Any?)

    private val NOT_FOUND = Resolved(false, null)

    /** Resolve a dotted path into the context. Own members only; an unknown root is not found. */
    fun resolvePath(ctx: Map<String, Any?>?, path: Any?): Resolved {
        if (path !is String || path.isEmpty()) return NOT_FOUND
        val segs = path.split(".")
        if (segs[0] !in ROOTS) return NOT_FOUND
        if (ctx == null || !ctx.containsKey(segs[0])) return NOT_FOUND
        var cur: Any? = ctx[segs[0]]
        for (i in 1 until segs.size) {
            val s = segs[i]
            if (s in FORBIDDEN || !isJsObject(cur)) return NOT_FOUND
            if (cur is List<*>) {
                if (!INDEX.matches(s)) return NOT_FOUND
                val idx = s.toDouble()
                if (idx >= cur.size) return NOT_FOUND
                cur = cur[idx.toInt()]
            } else {
                val m = cur as Map<*, *>
                if (!m.containsKey(s)) return NOT_FOUND
                cur = m[s]
            }
        }
        return Resolved(true, cur)
    }

    /** Equal lenient canonical texts (see [IntentJs.jsonEquals]). */
    private fun deepEq(a: Any?, b: Any?): Boolean = IntentJs.jsonEquals(a, b)

    /** -1 / 0 / 1, or null when the values have no order (mixed types, non-finite numbers, lone surrogates). */
    private fun ordered(a: Any?, b: Any?): Int? {
        val x = IntentJs.num(a)
        val y = IntentJs.num(b)
        if (x != null && y != null) {
            if (!IntentJs.isFinite(a) || !IntentJs.isFinite(b)) return null
            return if (x < y) -1 else if (x > y) 1 else 0
        }
        if (a is String && b is String) {
            if (Json.hasLoneSurrogate(a) || Json.hasLoneSurrogate(b)) return null
            return Integer.signum(Json.compareUtf8(a, b))
        }
        return null
    }

    // ---- like (anchored glob over UTF-16 code units) ----
    private const val LIT = 0
    private const val ONE = 1
    private const val STAR = 2

    /** Tokens as {kind, char}; null on a dangling trailing backslash. Consecutive stars collapse. */
    private fun parseGlob(glob: String): List<IntArray>? {
        val out = ArrayList<IntArray>()
        var i = 0
        while (i < glob.length) {
            val ch = glob[i]
            if (ch == '\\') {
                if (i + 1 >= glob.length) return null
                out.add(intArrayOf(LIT, glob[i + 1].code))
                i++
            } else if (ch == '*') {
                if (out.isEmpty() || out[out.size - 1][0] != STAR) out.add(intArrayOf(STAR, 0))
            } else if (ch == '?') out.add(intArrayOf(ONE, 0))
            else out.add(intArrayOf(LIT, ch.code))
            i++
        }
        return out
    }

    internal fun globMatch(glob: String, s: String): Boolean? {
        val toks = parseGlob(glob) ?: return null
        var ti = 0
        var si = 0
        var starTi = -1
        var starSi = 0
        while (si < s.length) {
            val t = if (ti < toks.size) toks[ti] else null
            if (t != null && t[0] == STAR) {
                starTi = ++ti
                starSi = si
            } else if (t != null && (t[0] == ONE || s[si].code == t[1])) {
                ti++
                si++
            } else if (starTi >= 0) {
                ti = starTi
                si = ++starSi
            } else return false
        }
        while (ti < toks.size && toks[ti][0] == STAR) ti++
        return ti == toks.size
    }

    private fun typeTagMatch(v: Any?, t: String): Boolean? {
        if (v is String) return v == t || v.startsWith("$t::")
        if (v is Map<*, *>) {
            var decidable = false
            var matched = false
            val ty = v["type"]
            if (v.containsKey("type") && ty is String) {
                decidable = true
                if (ty == t || ty.startsWith("$t::")) matched = true
            }
            val tags = v["tags"]
            if (v.containsKey("tags") && tags is List<*>) {
                decidable = true
                for (x in tags) if (t == x) matched = true
            }
            return if (decidable) matched else null
        }
        return null
    }

    private fun neighboursOf(adj: Map<*, *>, node: String): List<String> {
        val out = ArrayList<String>()
        if (node in FORBIDDEN || !adj.containsKey(node)) return out
        val raw = adj[node]
        if (raw is String) out.add(raw)
        else if (raw is List<*>) for (x in raw) if (x is String) out.add(x)
        return out
    }

    private fun memberClosure(start: String, adj: Map<*, *>): Set<String> {
        val seen = HashSet<String>()
        seen.add(start)
        val queue = ArrayDeque<String>()
        queue.add(start)
        var visited = 0
        while (queue.isNotEmpty() && visited < MAX_MEMBER_CLOSURE_NODES) {
            visited++
            val node = queue.removeFirst()
            for (n in neighboursOf(adj, node)) if (seen.add(n)) queue.add(n)
        }
        return seen
    }

    private fun paramsUnavailable(ctx: Map<String, Any?>?): Boolean {
        val a = ctx?.get("action")
        val p = if (a is Map<*, *>) a["params"] else null
        return !isJsObject(p)
    }

    private fun paramsRooted(path: String): Boolean = path == "action.params" || path.startsWith("action.params.")

    private fun tri(b: Boolean): Tri = if (b) Tri.TRUE else Tri.FALSE

    private fun triLeaf(c: Map<*, *>, ctx: Map<String, Any?>?): Tri {
        val field = c["field"]
        val op = c["op"]
        if (field !is String || field.isEmpty()) return Tri.UNKNOWN
        if (op !is String) return Tri.UNKNOWN
        if (paramsRooted(field) && paramsUnavailable(ctx)) return Tri.UNKNOWN
        val ref = c["ref"]
        if (ref is String && paramsRooted(ref) && paramsUnavailable(ctx)) return Tri.UNKNOWN
        val f = resolvePath(ctx, field)
        if (op == "exists") return tri(if (c["value"] == false) !f.found else f.found)
        if (!f.found) return Tri.UNKNOWN
        val v = f.value
        val hasRef = c.containsKey("ref")

        if (op == "member_of") {
            if (v !is String) return Tri.UNKNOWN
            val coll = c["collection"]
            if (coll !is String || coll.isEmpty()) return Tri.UNKNOWN
            val cr = resolvePath(ctx, coll)
            if (!cr.found || !isObjRec(cr.value)) return Tri.UNKNOWN
            val target: Any?
            if (hasRef) {
                val r = resolvePath(ctx, ref)
                if (!r.found) return Tri.UNKNOWN
                target = r.value
            } else {
                if (!c.containsKey("value")) return Tri.UNKNOWN
                target = c["value"]
            }
            val targets = ArrayList<String>()
            if (target is List<*>) { for (x in target) if (x is String) targets.add(x) }
            else if (target is String) targets.add(target)
            if (targets.isEmpty()) return Tri.UNKNOWN
            val reach = memberClosure(v, cr.value as Map<*, *>)
            for (t in targets) if (t in reach) return Tri.TRUE
            return Tri.FALSE
        }

        val operand: Any?
        if (hasRef) {
            val r = resolvePath(ctx, ref)
            if (!r.found) return Tri.UNKNOWN
            operand = r.value
        } else {
            if (!c.containsKey("value")) return Tri.UNKNOWN
            operand = c["value"]
        }

        when (op) {
            "eq" -> return tri(deepEq(v, operand))
            "ne" -> return tri(!deepEq(v, operand))
            "in", "nin" -> {
                if (operand !is List<*>) return Tri.UNKNOWN
                val any = operand.any { deepEq(v, it) }
                return tri((op == "in") == any)
            }
            "lt", "lte", "gt", "gte" -> {
                val o = ordered(v, operand) ?: return Tri.UNKNOWN
                return when (op) {
                    "lt" -> tri(o < 0)
                    "lte" -> tri(o <= 0)
                    "gt" -> tri(o > 0)
                    else -> tri(o >= 0)
                }
            }
            "prefix" -> {
                if (v !is String || operand !is String) return Tri.UNKNOWN
                return tri(v.startsWith(operand))
            }
            "like" -> {
                if (v !is String || operand !is String) return Tri.UNKNOWN
                if (operand.length > MAX_LIKE_PATTERN_LEN || v.length > MAX_PATTERN_SUBJECT_LEN) return Tri.UNKNOWN
                val m = globMatch(operand, v) ?: return Tri.UNKNOWN
                return tri(m)
            }
            "matches" -> {
                if (v !is String || operand !is String) return Tri.UNKNOWN
                if (operand.length > MAX_MATCHES_PATTERN_LEN || v.length > MAX_PATTERN_SUBJECT_LEN) return Tri.UNKNOWN
                if (!SafeRegex.isSafeSource(operand)) return Tri.UNKNOWN
                if (!SafeRegex.charge(operand, v.length)) return Tri.UNKNOWN
                val r = SafeRegex.fullMatch(operand, v) ?: return Tri.UNKNOWN
                return tri(r)
            }
            "is_a" -> {
                if (operand !is String || operand.isEmpty()) return Tri.UNKNOWN
                val t = typeTagMatch(v, operand) ?: return Tri.UNKNOWN
                return tri(t)
            }
            else -> return Tri.UNKNOWN
        }
    }

    /** Three-valued evaluation of a condition (leaf or grouping). Total. */
    fun evaluateConditionTri(c: Any?, ctx: Map<String, Any?>?): Tri = SafeRegex.withBudget { conditionInner(c, ctx) }

    private fun conditionInner(c: Any?, ctx: Map<String, Any?>?): Tri {
        try {
            if (!isJsObject(c)) return Tri.UNKNOWN
            if (c is Map<*, *>) {
                if (c.containsKey("all_of") || c.containsKey("any_of") || c.containsKey("not")) {
                    if (c.containsKey("all_of")) {
                        val xs = c["all_of"]
                        if (xs !is List<*> || xs.isEmpty()) return Tri.UNKNOWN
                        var sawUnknown = false
                        for (x in xs) {
                            val t = evaluateConditionTri(x, ctx)
                            if (t == Tri.FALSE) return Tri.FALSE
                            if (t == Tri.UNKNOWN) sawUnknown = true
                        }
                        return if (sawUnknown) Tri.UNKNOWN else Tri.TRUE
                    }
                    if (c.containsKey("any_of")) {
                        val xs = c["any_of"]
                        if (xs !is List<*> || xs.isEmpty()) return Tri.UNKNOWN
                        var sawUnknown = false
                        for (x in xs) {
                            val t = evaluateConditionTri(x, ctx)
                            if (t == Tri.TRUE) return Tri.TRUE
                            if (t == Tri.UNKNOWN) sawUnknown = true
                        }
                        return if (sawUnknown) Tri.UNKNOWN else Tri.FALSE
                    }
                    val inner = evaluateConditionTri(c["not"], ctx)
                    return if (inner == Tri.TRUE) Tri.FALSE else if (inner == Tri.FALSE) Tri.TRUE else Tri.UNKNOWN
                }
                return triLeaf(c, ctx)
            }
            return Tri.UNKNOWN // an array is no condition (no string field)
        } catch (e: RuntimeException) {
            return Tri.UNKNOWN
        } catch (e: StackOverflowError) {
            return Tri.UNKNOWN
        }
    }

    /** One condition: true iff cleanly decided true. */
    fun evaluateCondition(c: Any?, ctx: Map<String, Any?>?): Boolean = evaluateConditionTri(c, ctx) == Tri.TRUE

    private fun verbMatches(p: Any?, verb: String): Boolean {
        if (p is String) return p == "*" || p == verb
        if (p is List<*>) for (x in p) if (x is String && (x == "*" || x == verb)) return true
        return false
    }

    private fun resourceMatches(p: Map<*, *>, resource: String): Boolean {
        if (!p.containsKey("resource")) return true
        val pat = p["resource"] as? String ?: return false
        if (pat == "*") return true
        if (pat.startsWith("re:")) {
            val src = pat.substring(3)
            if (src.length > 200) return false
            if (resource.length > MAX_RE_RESOURCE_LEN) return false
            if (!SafeRegex.isSafeSource(src)) return false
            if (!SafeRegex.charge(src, resource.length)) return false
            return SafeRegex.fullMatch(src, resource) == true
        }
        if (pat.endsWith("*")) return resource.startsWith(pat.substring(0, pat.length - 1))
        return pat == resource
    }

    /** Does a single predicate permit the action? */
    fun predicateMatches(p: Any?, ctx: Map<String, Any?>?): Boolean = SafeRegex.withBudget { predicateInner(p, ctx) }

    private fun predicateInner(p: Any?, ctx: Map<String, Any?>?): Boolean {
        try {
            if (p !is Map<*, *>) return false // an array has no verb
            val a = ctx?.get("action")
            if (a !is Map<*, *>) return false
            val verb = a["verb"]
            val resource = a["resource"]
            if (verb !is String || resource !is String) return false
            if (!verbMatches(p["verb"], verb)) return false
            if (!resourceMatches(p, resource)) return false
            if (p.containsKey("where")) {
                val w = p["where"]
                if (w !is List<*>) return false
                for (c in w) if (!evaluateCondition(c, ctx)) return false
            }
            return true
        } catch (e: RuntimeException) {
            return false
        } catch (e: StackOverflowError) {
            return false
        }
    }

    /** An action is allowed iff it matches AT LEAST ONE predicate. Default-deny: an empty or non-list set allows nothing. */
    fun evaluatePredicates(predicates: Any?, ctx: Map<String, Any?>?): Boolean = SafeRegex.withBudget {
        try {
            if (predicates !is List<*> || predicates.isEmpty()) false
            else predicates.any { predicateMatches(it, ctx) }
        } catch (e: RuntimeException) {
            false
        }
    }

    // ---- limit-naming denial reasons (0.5) ----

    private val OP_TEXT: Map<String, String> = mapOf(
        "eq" to "==", "ne" to "!=", "lt" to "<", "lte" to "<=", "gt" to ">", "gte" to ">=", "in" to "in", "nin" to "not in",
        "prefix" to "starts with", "like" to "like", "matches" to "matches", "is_a" to "is a", "member_of" to "member of",
    )
    private const val MAX_SHOWN_STRING = 64
    private const val MAX_SHOWN_ITEMS = 8

    private fun isGroup(c: Any?): Boolean = c is Map<*, *> && (c.containsKey("all_of") || c.containsKey("any_of") || c.containsKey("not"))

    /** A scalar operand in a denial reason: safe integers, booleans, null and plain short strings are spelled out. */
    internal fun showValue(v: Any?, depth: Int = 0): String = when {
        v == null -> "null"
        v is Boolean -> v.toString()
        v is Json.Num || v is Number -> if (Json.isSafeInt(v)) Json.asLong(v).toString() else "<number>"
        v is String ->
            if (v.length <= MAX_SHOWN_STRING && v.none { it < ' ' || it == '"' || it == '\\' || it in '\uD800'..'\uDFFF' }) "\"$v\"" else "\"...\""
        v is List<*> && depth == 0 -> if (v.size <= MAX_SHOWN_ITEMS) v.joinToString(", ", "[", "]") { showValue(it, 1) } else "[...]"
        else -> "<value>"
    }

    /** The condition as the limit a reader recognises: `amount <= 500`, `currency in ["usd", "eur"]`. */
    internal fun describeCondition(c: Any?, depth: Int = 0): String {
        if (!isJsObject(c)) return "<condition>"
        if (isGroup(c)) {
            val m = c as Map<*, *>
            if (depth >= 2) return "(...)"
            val all = m["all_of"]
            val any = m["any_of"]
            return when {
                all is List<*> -> "all of (" + describeAll(all, depth) + ")"
                any is List<*> -> "any of (" + describeAll(any, depth) + ")"
                m.containsKey("not") -> "not (" + describeCondition(m["not"], depth + 1) + ")"
                else -> "<condition>"
            }
        }
        val m: Map<*, *> = c as? Map<*, *> ?: emptyMap<Any?, Any?>()
        val f = m["field"] as? String ?: "<field>"
        val name = if (f.startsWith("action.params.")) f.substring("action.params.".length) else f
        val op = m["op"]
        if (op == "exists") return if (m["value"] == false) "$name absent" else "$name present"
        val text = (op as? String)?.let { OP_TEXT[it] } ?: return "$name <condition>"
        val operand = when {
            m.containsKey("ref") -> m["ref"] as? String ?: "<ref>"
            m.containsKey("value") -> showValue(m["value"])
            else -> "<value>"
        }
        return "$name $text $operand"
    }

    private fun describeAll(xs: List<*>, depth: Int): String = xs.take(MAX_SHOWN_ITEMS).joinToString("; ") { describeCondition(it, depth + 1) }

    /** Inside an unmet top-level condition, the narrowest part that failed (an `all_of` points at its first unmet child). */
    private fun narrowestUnmet(c: Any?, ctx: Map<String, Any?>?, depth: Int = 0): Any? {
        val xs = (c as? Map<*, *>)?.get("all_of")
        if (depth < 4 && xs is List<*>) for (x in xs) if (!evaluateCondition(x, ctx)) return narrowestUnmet(x, ctx, depth + 1)
        return c
    }

    /**
     * When a predicate's verb and resource are in scope but a `where` limit is not met, that limit described
     * (`amount <= 100`); null when no predicate is in scope (the plain "no predicate permits" wording stays).
     */
    fun firstUnmetLimit(predicates: Any?, ctx: Map<String, Any?>?): String? = SafeRegex.withBudget {
        try {
            val a = ctx?.get("action")
            if (a !is Map<*, *> || predicates !is List<*>) return@withBudget null
            val verb = a["verb"]
            val resource = a["resource"]
            if (verb !is String || resource !is String) return@withBudget null
            for (p in predicates) {
                if (p !is Map<*, *> || !verbMatches(p["verb"], verb) || !resourceMatches(p, resource)) continue
                val w = p["where"] as? List<*> ?: continue
                for (c in w) if (!evaluateCondition(c, ctx)) return@withBudget describeCondition(narrowestUnmet(c, ctx))
            }
            null
        } catch (e: RuntimeException) {
            null
        } catch (e: StackOverflowError) {
            null
        }
    }

    /**
     * Why [evaluatePredicates] denied, or null when it allows: `envelope grants no predicates` for an empty set,
     * `<limit> not satisfied for <verb> on <resource>` when a limit in scope is unmet, else `no predicate permits <verb> on <resource>`.
     */
    fun denialReason(predicates: Any?, ctx: Map<String, Any?>?): String? {
        if (evaluatePredicates(predicates, ctx)) return null
        if (predicates !is List<*> || predicates.isEmpty()) return "envelope grants no predicates"
        val a = ctx?.get("action") as? Map<*, *> ?: emptyMap<Any?, Any?>()
        val vr = IntentRevocation.jsText(IntentJs.normalize(a["verb"]), a.containsKey("verb")) + " on " +
            IntentRevocation.jsText(IntentJs.normalize(a["resource"]), a.containsKey("resource"))
        val limit = firstUnmetLimit(predicates, ctx)
        return if (limit != null) "$limit not satisfied for $vr" else "no predicate permits $vr"
    }
}
