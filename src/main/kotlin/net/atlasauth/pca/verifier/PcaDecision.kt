package net.atlasauth.pca.verifier

/**
 * The ternary decision, the tighten-only model rule (rule 21) and the units check (rule 20): a port of
 * packages/pca/src/decision.ts (the TypeScript is authoritative; goal-to-decision track, contracts C-50..C-55).
 *
 * `deny < escalate < allow`; [meet] (the minimum) is the only combinator, so `escalate` never becomes `allow`. Every function
 * is total (never throws); anything malformed fails closed (deny / `ok = false`). Inputs are JSON trees ([Json.parseLenient]).
 */
object PcaDecision {
    private val RANK = mapOf("deny" to 0, "escalate" to 1, "allow" to 2)

    /** The lower of two decisions; an unknown value is `deny`. */
    fun meet(a: String, b: String): String {
        val x = RANK[a]
        val y = RANK[b]
        if (x == null || y == null) return "deny"
        return if (x <= y) a else b
    }

    /** The highest decision a model signal permits: ok -> allow, escalate -> escalate, anything else -> deny. */
    fun signalCeiling(s: Any?): String = if (s == "ok") "allow" else if (s == "escalate") "escalate" else "deny"

    /** G-T9: a model can only tighten. */
    fun tighten(base: String, signal: Any?): String = meet(base, signalCeiling(signal))

    /** An escalate with a verified answer is allow; an answer never upgrades deny; any other string is returned as is (the reference). */
    fun pepDecision(d: String, answered: Boolean): String = if (d == "escalate" && answered) "allow" else d

    /** A failing check is escalate-class iff its reason (after `<check>: `) starts with one of these. */
    val ESCALATE_REASON_PREFIXES: List<String> = listOf("intent_required:", "escalate:")

    /**
     * The decision of a verdict: allow -> allow; at least one failing check and EVERY failing check escalate-class ->
     * escalate; otherwise deny. A failing check is escalate-class iff it has at least one reason `<check>: <body>` and every
     * such body starts with an escalate prefix; a failing check with no reason of its own is a hard failure (deny).
     */
    fun decisionOf(allow: Boolean, checks: Map<String, String>, reasons: List<String>): String {
        if (allow) return "allow"
        var failing = 0
        for ((name, status) in checks) {
            if (status != "fail") continue
            failing++
            val head = "$name: "
            val own = reasons.filter { it.startsWith(head) }
            if (own.isEmpty()) return "deny"
            if (!own.all { r -> ESCALATE_REASON_PREFIXES.any { r.substring(head.length).startsWith(it) } }) return "deny"
        }
        return if (failing > 0) "escalate" else "deny"
    }

    /** [decisionOf] over a JSON verdict `{allow, checks: {name: "pass"|"fail"|...}, reasons: [...]}`; malformed is deny. */
    fun decisionOf(v: Any?): String {
        if (v !is Map<*, *>) return "deny"
        if (v["allow"] == true) return "allow"
        val c = v["checks"] as? Map<*, *> ?: return "deny"
        val checks = LinkedHashMap<String, String>()
        for ((k, s) in c) if (k is String && s is String) checks[k] = s else if (k is String) checks[k] = "?"
        val reasons = (v["reasons"] as? List<*>).orEmpty().filterIsInstance<String>()
        return decisionOf(false, checks, reasons)
    }

    /** One reported intent-v2 check: `reason` is null for a failing check that gave none. */
    class V2Check(val name: String, val ok: Boolean, val reason: String?)

    /**
     * The ordered reason list of a verdict (decision.ts `foldV2Reasons`): `base` (the core's own reasons), then one
     * `<check>: <reason>` for EVERY failing intent-v2 check not already listed, in pipeline order. A failing check with no reason
     * adds nothing (the decision then reads it as a hard failure).
     */
    fun foldV2Reasons(base: List<String>, v2: List<V2Check>): List<String> {
        val out = ArrayList<String>(base)
        for (c in v2) {
            if (c.ok || c.reason == null) continue
            val r = "${c.name}: ${c.reason}"
            if (!out.contains(r)) out.add(r)
        }
        return out
    }

    // ---------------------------------------------------------------------------------------------- shared validators

    private val NAME_RE = Regex("[a-z][a-z0-9_]{0,63}")
    private val PARAM_PATH_RE = Regex("action\\.params\\.[A-Za-z0-9_-]{1,64}")
    const val MAX_TIGHTEN_RULES = 64
    private val MODEL_ENV_ROOTS = setOf("class", "prov", "judge")

    private fun isObj(v: Any?): Boolean = v is Map<*, *>

    private fun closedMembers(o: Map<*, *>, required: List<String>, optional: List<String>, where: String): String? {
        for (k in o.keys) if (k !in required && k !in optional) return "unknown member '$where.$k'"
        for (k in required) if (!o.containsKey(k)) return "missing member '$where.$k'"
        return null
    }

    private fun js(v: Any?): String = IntentRevocation.jsText(IntentJs.normalize(v), true)

    /** Null = well-formed. `absent` = the member is missing (JSON null is malformed, as in TypeScript). */
    fun tightenListError(t: Any?, absent: Boolean = false): String? {
        if (absent) return null
        if (t !is List<*>) return "tighten must be an array"
        if (t.size > MAX_TIGHTEN_RULES) return "tighten has more than $MAX_TIGHTEN_RULES rules"
        val ids = HashSet<String>()
        for ((i, r) in t.withIndex()) {
            if (r !is Map<*, *>) return "tighten[$i] must be an object"
            val e = closedMembers(r, listOf("id", "when", "signal"), listOf("reason"), "tighten[$i]")
            if (e != null) return e
            val id = r["id"]
            if (id !is String || !NAME_RE.matches(id)) return "tighten[$i].id must match ^[a-z][a-z0-9_]{0,63}$"
            if (!ids.add(id)) return "tighten[$i].id '$id' is a duplicate"
            if (!isObj(r["when"])) return "tighten[$i].when must be a condition object"
            if (r["signal"] != "escalate" && r["signal"] != "deny") return "tighten[$i].signal must be 'escalate' or 'deny'"
            if (r.containsKey("reason")) {
                val rs = r["reason"]
                if (rs !is String || rs.length > 256) return "tighten[$i].reason must be a string of at most 256 characters"
            }
        }
        return null
    }

    /** Null = well-formed policy unit tags `{ "action.params.<name>": {kind, currency?, exponent?} }`, closed. */
    fun unitTagsError(u: Any?): String? {
        if (u !is Map<*, *>) return "units must be an object"
        if (u.size > 64) return "units has more than 64 entries"
        for ((kk, t) in u) {
            val k = kk as String
            if (!PARAM_PATH_RE.matches(k)) return "units key '$k' must be an action.params.<name> path"
            if (t !is Map<*, *>) return "units['$k'] must be an object"
            val e = closedMembers(t, listOf("kind"), listOf("currency", "exponent"), "units['$k']")
            if (e != null) return e
            val kind = t["kind"]
            if (kind !is String || kind.isEmpty() || kind.length > 64) return "units['$k'].kind must be a string of 1..64 characters"
            if (t.containsKey("currency")) {
                val c = t["currency"]
                if (c !is String || c.isEmpty() || c.length > 16) return "units['$k'].currency must be a string of 1..16 characters"
            }
            if (t.containsKey("exponent")) {
                val x = t["exponent"]
                if (!(IntentJs.isInt(x) && IntentJs.num(x)!! >= 0 && IntentJs.num(x)!! <= 18)) return "units['$k'].exponent must be an integer in [0, 18]"
            }
        }
        return null
    }

    // ---------------------------------------------------------------------------------------------- rule 21

    /** `env.<root>` paths whose values come from a model: `env.class|prov|judge.*`, and `env.world.<w>` for a single-oracle world. */
    fun isModelDerivedPath(path: Any?, singleSource: List<String> = emptyList()): Boolean {
        if (path !is String) return false
        val seg = path.split(".")
        if (seg[0] != "env" || seg.size < 2) return false
        if (seg[1] in MODEL_ENV_ROOTS) return true
        if (seg[1] == "world") return if (seg.size == 2) singleSource.isNotEmpty() else singleSource.contains(seg[2])
        return false
    }

    private fun collectPaths(c: Any?, out: MutableSet<String>, depth: Int) {
        if (depth > 64 || c !is Map<*, *>) return
        for (k in listOf("all_of", "any_of")) {
            val xs = c[k]
            if (xs is List<*>) for (x in xs) collectPaths(x, out, depth + 1)
        }
        if (c.containsKey("not")) collectPaths(c["not"], out, depth + 1)
        for (k in listOf("field", "ref", "collection")) {
            val s = c[k]
            if (s is String) out.add(s)
        }
    }

    private fun collectPredicatePaths(lists: List<*>, inScope: ((Any?) -> Boolean)?, out: MutableSet<String>) {
        for (l in lists) {
            if (l !is List<*>) continue
            for (p in l) {
                if (inScope != null && !inScope(p)) continue
                val w = IntentJs.get(p, "where")
                if (w is List<*>) for (c in w) collectPaths(c, out, 0)
            }
        }
    }

    /** Every model-derived env path a list of predicate lists reads, sorted by UTF-8 byte order and de-duplicated. */
    fun modelPathsRead(predicateLists: List<*>, singleSource: List<String> = emptyList()): List<String> {
        val found = LinkedHashSet<String>()
        collectPredicatePaths(predicateLists, null, found)
        return found.filter { isModelDerivedPath(it, singleSource) }.sortedWith { a, b -> Json.compareUtf8(a, b) }
    }

    /** The outcome of rule 21: `outcome` is `ok` | `escalate` | `deny`; `reason` is null on `ok`. */
    class TightenResult(val outcome: String, val legacy: Boolean, val offending: List<String>, val reason: String?) {
        override fun toString(): String = "TightenResult(outcome=$outcome, legacy=$legacy, offending=$offending, reason=$reason)"
    }

    /**
     * Rule 21 over `{predicates?, tighten?, polarity?, single_source?, context?}`. Typing first: a grant-side `where` that reads a
     * model-derived path is a refusal unless the polarity is `legacy`; then each rule in order (`when` true -> its signal,
     * unknown -> escalate); the outcome is the meet. A present non-`legacy` polarity or a malformed (or null) `tighten` is a refusal.
     */
    fun decideTighten(input: Map<String, Any?>): TightenResult = try {
        decideTightenUnchecked(input)
    } catch (e: RuntimeException) {
        TightenResult("deny", false, emptyList(), "evaluation error (fail closed): ${e.message ?: "unknown"}")
    } catch (e: StackOverflowError) {
        TightenResult("deny", false, emptyList(), "evaluation error (fail closed): unknown")
    }

    private fun decideTightenUnchecked(input: Map<String, Any?>): TightenResult {
        val ss = input["single_source"]
        val single = if (ss is List<*>) ss.filterIsInstance<String>() else emptyList()
        val hasPol = input.containsKey("polarity")
        val pol = input["polarity"]
        if (hasPol && pol != "legacy") return TightenResult("deny", false, emptyList(), "model_polarity must be 'legacy' when present")
        val le = tightenListError(input["tighten"], !input.containsKey("tighten"))
        if (le != null) return TightenResult("deny", false, emptyList(), "malformed tighten list: $le")
        val preds = input["predicates"]
        val offending = modelPathsRead(if (preds is List<*>) preds else emptyList<Any?>(), single)
        val legacy = pol == "legacy" && offending.isNotEmpty()
        if (offending.isNotEmpty() && !legacy)
            return TightenResult("deny", false, offending, "a grant's where reads model-derived path(s) ${offending.joinToString(", ")}: a model may only tighten (move them into tighten[]) (rule 21)")
        var out = "ok"
        var reason: String? = null
        val ctxIn = input["context"]
        @Suppress("UNCHECKED_CAST")
        val ctx: Map<String, Any?> = if (ctxIn is Map<*, *>) ctxIn as Map<String, Any?> else emptyMap()
        val rules = input["tighten"] as? List<*> ?: emptyList<Any?>()
        for (x in rules) {
            val r = x as Map<*, *>
            val sig = r["signal"] as String
            val id = r["id"] as String
            fun lower(s: String, why: String) {
                if (RANK.getValue(signalCeiling(s)) < RANK.getValue(signalCeiling(out))) {
                    out = s
                    reason = why
                }
            }
            when (Predicates.evaluateConditionTri(r["when"], ctx)) {
                Predicates.Tri.TRUE -> {
                    val rs = if (r.containsKey("reason")) " (${r["reason"]})" else ""
                    lower(sig, "${if (sig == "deny") "denied by" else "escalate: asked by"} tighten rule '$id'$rs")
                }
                Predicates.Tri.UNKNOWN -> lower("escalate", "escalate: rule '$id' could not be decided (a value it reads is missing or ill-typed)")
                Predicates.Tri.FALSE -> {}
            }
        }
        return TightenResult(out, legacy, offending, reason)
    }

    // ---------------------------------------------------------------------------------------------- rule 20

    /** `ok` iff the policy's unit tags equal the unit the action schema declares and every unit-bearing term is tagged. */
    class UnitsResult(val ok: Boolean, val reason: String?) {
        override fun toString(): String = "UnitsResult(ok=$ok, reason=$reason)"
    }

    private fun tagText(t: Map<*, *>?): String {
        if (t == null) return "no unit"
        val kind = if (t.containsKey("kind") && t["kind"] != null) js(t["kind"]) else "?"
        val cur = if (t.containsKey("currency")) "/${js(t["currency"])}" else ""
        val ex = if (t.containsKey("exponent")) "/e${js(t["exponent"])}" else ""
        return "$kind$cur$ex"
    }

    /** Strict `===` on a unit-tag member (numbers by value, everything else by type and value; absent only equals absent). */
    private fun sameMember(a: Map<*, *>, b: Map<*, *>, k: String): Boolean {
        if (a.containsKey(k) != b.containsKey(k)) return false
        val x = a[k]
        val y = b[k]
        val nx = IntentJs.num(x)
        val ny = IntentJs.num(y)
        if (nx != null || ny != null) return nx != null && ny != null && nx == ny
        return x == y
    }

    private fun sameTag(a: Map<*, *>, b: Map<*, *>): Boolean = listOf("kind", "currency", "exponent").all { sameMember(a, b, it) }

    private fun verbInScope(p: Any?, verb: String): Boolean {
        val v = IntentJs.get(p, "verb")
        return v == "*" || v == verb || (v is List<*> && v.contains(verb))
    }

    /**
     * Rule 20 over `{units, schema_units?, verb_params, verb, predicates?}`: `ok` iff every policy tag whose parameter the
     * verb declares equals the schema's unit for it, and no grant-side `where` term in scope of the verb reads a unit-bearing
     * parameter without a tag. Tags for parameters the verb does not declare are ignored. Total.
     */
    fun decideUnits(input: Map<String, Any?>): UnitsResult = try {
        decideUnitsUnchecked(input)
    } catch (e: RuntimeException) {
        UnitsResult(false, "evaluation error (fail closed): ${e.message ?: "unknown"}")
    } catch (e: StackOverflowError) {
        UnitsResult(false, "evaluation error (fail closed): unknown")
    }

    private fun decideUnitsUnchecked(input: Map<String, Any?>): UnitsResult {
        fun fail(m: String) = UnitsResult(false, m)
        val te = unitTagsError(input["units"])
        if (te != null) return fail(te)
        val tags = input["units"] as Map<*, *>
        val verb = input["verb"]
        if (verb !is String || verb.isEmpty()) return fail("the verb is missing")
        val sUnits: Any? = if (input.containsKey("schema_units")) input["schema_units"] else emptyMap<String, Any?>()
        if (sUnits !is Map<*, *>) return fail("the schema units table must be an object")
        val params = input["verb_params"]
        if (params !is Map<*, *>) return fail("the schema does not declare verb '$verb'")
        class Decl(val has: Boolean, val tag: Map<*, *>?)
        fun declared(path: String): Decl {
            val d = if (params.containsKey(path)) params[path] else null
            if (d !is Map<*, *>) return Decl(false, null)
            val id = d["unit"]
            val tag = if (id is String && sUnits.containsKey(id)) sUnits[id] else null
            return Decl(true, tag as? Map<*, *>)
        }
        for (path in tags.keys.map { it as String }.sorted()) {
            val d = declared(path)
            if (!d.has) continue
            val mine = tags[path] as Map<*, *>
            if (d.tag == null || !sameTag(d.tag, mine))
                return fail("'$path' is declared as ${tagText(d.tag)} by the action schema but the policy term is tagged ${tagText(mine)} (unit confusion)")
        }
        val read = LinkedHashSet<String>()
        val preds = input["predicates"]
        if (preds is List<*>) collectPredicatePaths(preds, { p -> verbInScope(p, verb) }, read)
        for (path in read.sorted()) {
            if (!PARAM_PATH_RE.matches(path)) continue
            val d = declared(path)
            if (d.has && d.tag != null && !tags.containsKey(path)) return fail("a policy term reads '$path' (${tagText(d.tag)}) without a unit tag")
        }
        return UnitsResult(true, null)
    }
}
