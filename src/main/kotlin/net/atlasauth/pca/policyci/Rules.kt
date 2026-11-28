package net.atlasauth.pca.policyci

import net.atlasauth.pca.analyzer.Analyzer
import net.atlasauth.pca.analyzer.Field

/**
 * The policy-safety rules, each driving the static analyzer. Every rule is sound: a hard error is only emitted from a PROVEN analyzer
 * verdict (its result is not approximate); an undecidable feature downgrades to a warning or note that says so. A finding is
 * `{rule, severity, message, where?}`.
 */
object Rules {
    /** Scope-narrowing caveat types (constrain WHAT or HOW MUCH, not merely WHEN). */
    val SCOPE_NARROWING_CAVEATS: List<String> = listOf("max_blast_radius", "rate", "reversibility_max", "budget_alloc", "delegation_depth")

    /** Blast, rate and budget gate caveat types (the safety-floor gates, distinct from a time bound). */
    val BUDGET_GATE_CAVEATS: List<String> = listOf("max_blast_radius", "rate", "budget_alloc")

    // ---- util ----

    /** A predicate's verb as a list of concrete strings. */
    internal fun verbsOf(verb: Any?): List<String> {
        val out = ArrayList<String>()
        if (verb is String) out.add(verb)
        else if (verb is List<*>) for (x in verb) if (x is String) out.add(x)
        return out
    }

    /** Case-insensitive `includes` of a verb against a dangerous-substring set. */
    internal fun isDangerousVerb(verb: String, dangerous: List<String>): Boolean {
        val v = verb.lowercase(java.util.Locale.ROOT)
        for (kw in dangerous) if (v.contains(kw.lowercase(java.util.Locale.ROOT))) return true
        return false
    }

    /** A resource matcher that admits every resource: omitted or `*`. */
    internal fun isWildcardResource(predicate: Any?): Boolean = !PcJs.has(predicate, "resource") || "*" == PcJs.get(predicate, "resource")

    internal fun hasCaveatOfType(caveats: List<*>, types: List<String>): Boolean {
        for (c in caveats) if (c is Map<*, *> && c["type"] is String && types.contains(c["type"])) return true
        return false
    }

    /** A one-line rendering of an analyzer witness / counterexample action. */
    internal fun describeAction(a: Map<String, Any?>): String {
        val parts = ArrayList<Any?>()
        parts.add(a["verb"])
        parts.add(a["resource"])
        val params = a["params"]
        if ((params is Map<*, *> && params.isNotEmpty()) || (params is List<*> && params.isNotEmpty())) parts.add(PcJs.stringify(params))
        if (a.containsKey("reversibilityClass")) parts.add("[" + PcJs.str(a["reversibilityClass"]) + "]")
        return PcJs.joinSpace(parts)
    }

    private fun uniq(xs: List<String>): List<String> = ArrayList(LinkedHashSet(xs))

    private fun find(rule: String, severity: String, message: Any?, where: String?): Map<String, Any?> {
        val f = PcJs.obj("rule", rule, "severity", severity, "message", message)
        if (where != null) f["where"] = where
        return f
    }

    private fun analyzerInput(p: Map<String, Any?>): Map<String, Any?> = PcJs.obj("predicates", p["predicates"], "caveats", p["caveats"])

    @Suppress("UNCHECKED_CAST") private fun predicatesOf(p: Map<String, Any?>): List<Any?> = p["predicates"] as List<Any?>
    @Suppress("UNCHECKED_CAST") private fun caveatsOf(p: Map<String, Any?>): List<Any?> = p["caveats"] as List<Any?>

    /** Every concrete verb named across the predicate set. */
    private fun declaredVerbs(predicates: List<Any?>): List<String> {
        val concrete = ArrayList<String>()
        for (p in predicates) {
            if (!PcJs.isObject(p)) continue
            for (v in verbsOf(PcJs.get(p, "verb"))) if (v != "*") concrete.add(v)
        }
        return uniq(concrete)
    }

    /** The budget / step-up gate that bounds a dangerous action, or null. */
    private fun gateDescription(policy: Map<String, Any?>): String? {
        val gates = ArrayList<String>()
        val caveats = caveatsOf(policy)
        if (hasCaveatOfType(caveats, BUDGET_GATE_CAVEATS)) {
            val types = ArrayList<String>()
            for (c in caveats) {
                // the reference reads c.type on every element: a null one throws
                if (c == null) throw IllegalStateException("Cannot read properties of null (reading 'type')")
                val t = PcJs.get(c, "type")
                if (t is String && BUDGET_GATE_CAVEATS.contains(t)) types.add(t)
            }
            gates.add(types.joinToString("/"))
        }
        val rp = policy["riskPolicy"]
        if (rp != null || policy.containsKey("riskPolicy")) {
            val theta2 = PcJs.finite(PcJs.get(rp, "theta2"))
            if (theta2 != null && theta2 < 1) gates.add("risk step-up (theta2 < 1)")
        }
        return if (gates.isEmpty()) null else gates.joinToString(", ")
    }

    // ---- 1. over-broad grant ----

    fun ruleOverBroadGrant(policy: Map<String, Any?>, dangerous: List<String>, opts: Map<String, Any?>?): List<Any?> {
        val out = ArrayList<Any?>()
        val input = analyzerInput(policy)
        val hasScopeNarrowing = hasCaveatOfType(caveatsOf(policy), SCOPE_NARROWING_CAVEATS)

        val preds = predicatesOf(policy)
        for (i in preds.indices) {
            val p = preds[i]
            if (!PcJs.isObject(p)) continue
            val verbs = verbsOf(PcJs.get(p, "verb"))
            val where = "predicates[$i]"
            val w = PcJs.get(p, "where")
            val hasWhere = w is List<*> && w.isNotEmpty()

            if (verbs.contains("*")) {
                out.add(find("over-broad-grant", "error", "predicate grants a WILDCARD verb '*' — authority over any action", where))
            }
            if (isWildcardResource(p)) {
                val dangerousVerbs = ArrayList<Any?>()
                for (v in verbs) if (isDangerousVerb(v, dangerous)) dangerousVerbs.add(v)
                if (dangerousVerbs.isNotEmpty()) {
                    out.add(find("over-broad-grant", "error", "dangerous verb(s) " + PcJs.stringify(dangerousVerbs) + " granted on a WILDCARD resource ('*')", where))
                } else if (!verbs.contains("*")) {
                    out.add(find("over-broad-grant", "warn", "predicate matches ANY resource ('*') — consider a resource prefix", where))
                }
            }
            for (v in verbs) {
                if (v != "*" && isDangerousVerb(v, dangerous) && !hasWhere && !hasScopeNarrowing) {
                    out.add(find("over-broad-grant", "error",
                        "dangerous verb '$v' is granted with NO narrowing `where` and no scope-narrowing caveat (" + SCOPE_NARROWING_CAVEATS.joinToString("/") + ")", where))
                }
            }
        }

        // Semantic always-allow: a verb the analyzer PROVES is total (admits every action of that verb).
        for (v in declaredVerbs(preds)) {
            val aa = Analyzer.alwaysAllows(input, v, opts)
            if (aa["alwaysAllows"] == true && aa["approximate"] != true) {
                out.add(find("over-broad-grant", "error", "grants EVERY action of '$v' — the authority has no effective constraint (always-allow)", null))
            }
        }
        return out
    }

    // ---- 2. privilege escalation in a chain ----

    @Suppress("UNCHECKED_CAST")
    fun rulePrivilegeEscalation(hops: List<Any?>, opts: Map<String, Any?>?): List<Any?> {
        val out = ArrayList<Any?>()
        for (i in 1 until hops.size) {
            val parent = hops[i - 1] as Map<String, Any?>
            val child = hops[i] as Map<String, Any?>
            val s = Analyzer.subsumes(analyzerInput(parent), analyzerInput(child), opts)
            val where = "hop[$i]"
            if (s["subsumes"] == true) continue
            if (s["approximate"] == true) {
                out.add(find("privilege-escalation", "warn", "could not prove hop $i attenuation (undecidable" + reasonSuffix(s["reason"]) + ") — attenuation not verified", where))
            } else {
                val cx = s["counterexample"]
                val ex = if (cx != null) " — child admits '" + describeAction(cx as Map<String, Any?>) + "' which its parent denies" else ""
                out.add(find("privilege-escalation", "error",
                    "delegation hop $i ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)$ex", where))
            }
        }
        return out
    }

    /** `reason ? ": " + reason : ""` (a non-empty string; absent or empty is nothing). */
    internal fun reasonSuffix(reason: Any?): String = if (reason is String && reason.isNotEmpty()) ": $reason" else ""

    // ---- 3. unused / redundant caveat ----

    private val ORDERED_CAVEATS = listOf(
        arrayOf("expires", "at", "min"), arrayOf("not_before", "at", "max"), arrayOf("max_blast_radius", "max", "min"),
        arrayOf("delegation_depth", "max", "min"), arrayOf("budget_alloc", "limit", "min"),
    )

    private fun caveatKey(cv: Any?): String = PcJs.stringify(cv)

    fun ruleRedundantCaveat(policy: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        val caveats = caveatsOf(policy)

        // (a) exact-duplicate caveats
        val seen = LinkedHashMap<String, Int>()
        for (i in caveats.indices) {
            val cv = caveats[i]
            if (!PcJs.isObject(cv)) continue
            val k = caveatKey(cv)
            val first = seen[k]
            if (first != null) {
                out.add(find("redundant-caveat", "warn", "caveat $i ('" + PcJs.str(PcJs.get(cv, "type"), PcJs.has(cv, "type")) + "') is an exact duplicate of caveat $first — dead policy", "caveats[$i]"))
            } else {
                seen[k] = i
            }
        }

        // (b) same-type domination: a looser caveat that a stricter one of the same type always subsumes
        for (spec in ORDERED_CAVEATS) {
            val type = spec[0]
            val field = spec[1]
            val keepMin = spec[2] == "min"
            val idx = ArrayList<Int>()
            val vals = ArrayList<Double>()
            for (i in caveats.indices) {
                val cv = caveats[i]
                if (cv !is Map<*, *> || type != cv["type"]) continue
                val v = PcJs.finite(cv[field])
                if (v != null) { idx.add(i); vals.add(v) }
            }
            if (vals.size < 2) continue
            var binding = vals[0]
            for (v in vals) binding = if (keepMin) Math.min(binding, v) else Math.max(binding, v)
            for (j in vals.indices) {
                if (vals[j] != binding) {
                    val i = idx[j]
                    out.add(find("redundant-caveat", "warn",
                        "caveat $i ('$type' $field=" + PcJs.numStr(vals[j]) + ") is subsumed by a stricter '$type' ($field=" + PcJs.numStr(binding) + ") — it can never bite",
                        "caveats[$i]"))
                }
            }
        }

        // (c) a predicate whose numeric `where` conjunction is UNSATISFIABLE never matches
        val preds = predicatesOf(policy)
        for (i in preds.indices) {
            val p = preds[i]
            if (!PcJs.isObject(p) || PcJs.get(p, "where") !is List<*>) continue
            val where = PcJs.get(p, "where") as List<*>
            if (!Analyzer.predicateNumericSatisfiable(where)) {
                out.add(find("redundant-caveat", "warn", "predicate $i can never match — its numeric `where` constraints are unsatisfiable (dead policy)", "predicates[$i]"))
            } else {
                out.addAll(nonBindingConditions(where, i))
            }
        }
        return out
    }

    private val NUMERIC_OPS = setOf("lt", "lte", "gt", "gte", "eq")

    private fun isGroupCondition(c: Any?): Boolean = c is Map<*, *> && (PcJs.has(c, "all_of") || PcJs.has(c, "any_of") || PcJs.has(c, "not"))
    private fun isLeafCondition(c: Any?): Boolean = c is Map<*, *> && !isGroupCondition(c) && PcJs.get(c, "field") is String

    private fun intervalEq(a: Field.NumInterval, b: Field.NumInterval): Boolean =
        a.lo == b.lo && a.loInclusive == b.loInclusive && a.hi == b.hi && a.hiInclusive == b.hiInclusive

    /** A numeric leaf condition that does not tighten its field's interval is redundant (never binds). */
    private fun nonBindingConditions(where: List<*>, predIndex: Int): List<Any?> {
        val byField = LinkedHashMap<String, MutableList<Pair<Any?, Int>>>()
        for (i in where.indices) {
            val c = where[i]
            if (!isLeafCondition(c)) continue
            if (PcJs.has(c, "ref")) continue
            val op = PcJs.get(c, "op")
            if (op !is String || !NUMERIC_OPS.contains(op)) continue
            if (PcJs.finite(PcJs.get(c, "value")) == null) continue
            byField.getOrPut(PcJs.get(c, "field") as String) { ArrayList() }.add(Pair(c, i))
        }

        val out = ArrayList<Any?>()
        for ((fieldName, conds) in byField) {
            if (conds.size < 2) continue
            var full = Field.FULL_INTERVAL
            for (e in conds) full = Field.tightenInterval(full, PcJs.get(e.first, "op"), PcJs.get(e.first, "value"))
            if (Field.intervalEmpty(full)) continue
            for (e in conds) {
                var without = Field.FULL_INTERVAL
                for (x in conds) if (x !== e) without = Field.tightenInterval(without, PcJs.get(x.first, "op"), PcJs.get(x.first, "value"))
                if (intervalEq(without, full)) {
                    out.add(find("redundant-caveat", "info",
                        "condition on '$fieldName' (" + PcJs.str(PcJs.get(e.first, "op")) + " " + PcJs.str(PcJs.get(e.first, "value")) + ") does not tighten the authority — redundant with the other bounds on this field",
                        "predicates[$predIndex].where[" + e.second + "]"))
                }
            }
        }
        return out
    }

    // ---- 4. dangerous reachability ----

    fun ruleDangerousReachability(policy: Map<String, Any?>, dangerous: List<String>, extraTargets: List<*>, opts: Map<String, Any?>?): List<Any?> {
        val out = ArrayList<Any?>()
        val input = analyzerInput(policy)
        val targets = ArrayList<Any?>()
        for (v in declaredVerbs(predicatesOf(policy))) if (isDangerousVerb(v, dangerous)) targets.add(PcJs.obj("verb", v))
        targets.addAll(extraTargets)
        val gate = gateDescription(policy)

        for (t in targets) {
            val verb = PcJs.get(t, "verb") as String
            val proven: Boolean
            val approximate: Boolean
            val reason: Any?
            val witness: String
            if (PcJs.has(t, "resource")) {
                val resource = PcJs.get(t, "resource")
                val r = Analyzer.reachable(input, PcJs.obj("verb", verb, "resource", resource), opts)
                proven = r["reachable"] == true && r["approximate"] != true
                approximate = r["approximate"] == true
                reason = r["reason"]
                witness = verb + " " + PcJs.str(resource)
            } else {
                val ad = Analyzer.alwaysDenies(input, verb, opts)
                proven = ad["alwaysDenies"] == false && ad["approximate"] != true
                approximate = ad["approximate"] == true
                reason = ad["reason"]
                @Suppress("UNCHECKED_CAST") val w = ad["witness"] as Map<String, Any?>?
                witness = if (w != null) describeAction(w) else verb
            }

            if (approximate) {
                out.add(find("dangerous-reachability", "warn", "could not decide reachability of dangerous verb '$verb' (undecidable" + reasonSuffix(reason) + ")", null))
            } else if (proven) {
                if (gate == null) out.add(find("dangerous-reachability", "error", "dangerous action '$witness' is REACHABLE with no budget / rate / step-up gate", null))
                else out.add(find("dangerous-reachability", "info", "dangerous action '$witness' is reachable but gated by $gate", null))
            }
        }
        return out
    }

    // ---- 5. missing safety floor ----

    /** A grant is non-trivial when any predicate grants a dangerous or wildcard verb, a wildcard resource, or is unconstrained. */
    private fun isNonTrivial(policy: Map<String, Any?>, dangerous: List<String>): Boolean {
        for (p in predicatesOf(policy)) {
            if (!PcJs.isObject(p)) continue
            val verbs = verbsOf(PcJs.get(p, "verb"))
            val w = PcJs.get(p, "where")
            val hasWhere = w is List<*> && w.isNotEmpty()
            var dangerousVerb = false
            for (v in verbs) if (isDangerousVerb(v, dangerous)) { dangerousVerb = true; break }
            if (verbs.contains("*") || dangerousVerb || isWildcardResource(p) || !hasWhere) return true
        }
        return false
    }

    fun ruleMissingSafetyFloor(policy: Map<String, Any?>, requireExpiry: Boolean, requireScopeGate: Boolean, dangerous: List<String>): List<Any?> {
        val out = ArrayList<Any?>()
        if (predicatesOf(policy).isEmpty()) return out
        if (requireExpiry && !hasCaveatOfType(caveatsOf(policy), listOf("expires"))) {
            out.add(find("missing-safety-floor", "warn", "grant has no `expires` caveat — the authority never expires", null))
        }
        if (requireScopeGate && isNonTrivial(policy, dangerous) && !hasCaveatOfType(caveatsOf(policy), BUDGET_GATE_CAVEATS)) {
            out.add(find("missing-safety-floor", "warn", "non-trivial grant has no blast-radius / rate / budget gate (" + BUDGET_GATE_CAVEATS.joinToString("/") + ")", null))
        }
        return out
    }

    // ---- schema-mismatch ----

    /** Checks a policy against an action schema (`validatePolicyAgainstSchema`): `{findings: [{code, severity, message, where?}]}`. */
    fun interface SchemaValidator {
        fun validate(policy: Map<String, Any?>, schema: Any?, options: Map<String, Any?>?): Map<String, Any?>
    }

    /** The policy compared with the action schema it is written for. */
    @Suppress("UNCHECKED_CAST")
    fun ruleSchemaMismatch(policy: Map<String, Any?>, schema: Any?, options: Map<String, Any?>?, validator: SchemaValidator): List<Any?> {
        val r = validator.validate(analyzerInput(policy), schema, options)
        val out = ArrayList<Any?>()
        for (fo in r["findings"] as List<Any?>) {
            val f = fo as Map<String, Any?>
            val m = PcJs.obj("rule", "schema-mismatch", "severity", f["severity"], "message", PcJs.str(f["code"]) + ": " + PcJs.str(f["message"], f.containsKey("message")))
            if (f.containsKey("where")) m["where"] = f["where"]
            out.add(m)
        }
        return out
    }
}
