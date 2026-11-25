package net.atlasauth.pca.analyzer

import net.atlasauth.pca.analyzer.Enumerate.PolicyModel
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs
import net.atlasauth.pca.analyzer.Enumerate.Probes
import net.atlasauth.pca.verifier.Predicates
import net.atlasauth.pca.verifier.SafeRegex

/**
 * STATIC ANALYZABILITY OF AUTHORITY: what can this whole delegated authority EVER do? A sound, bounded decision procedure over PCA's
 * predicate / caveat policy (no SMT dependency): reachability, vacuity / totality, delegation-safety subsumption, disjointness,
 * equivalence, and conformance to a declared intent envelope. A verdict is reported as proven only when the fragment is fully
 * decided; otherwise it fails safe and carries `approximate: true` with a reason.
 *
 * Policies, actions, intents, options and results are JSON trees (Map / List / String / Boolean / Json.Num / null). Options are
 * optional (null = defaults); `maxCombinations` caps the representative grid (a larger grid fails safe).
 */
object Analyzer {
    /** Reversibility classes in increasing severity. */
    val REVERSIBILITY_ORDER: List<String> = listOf("reversible", "rate_limited", "irreversible")

    const val DEFAULT_MAX_COMBINATIONS: Double = Enumerate.DEFAULT_MAX_COMBINATIONS

    /** The grid bound: a finite non-negative `maxCombinations`, else the default (0 is allowed: every grid overflows and fails safe). */
    internal fun boundOf(opts: Map<String, Any?>?): Double {
        val m = AJs.get(opts, "maxCombinations")
        return if (AJs.isFin(m) && AJs.num(m)!! >= 0) AJs.num(m)!! else DEFAULT_MAX_COMBINATIONS
    }

    private fun orderList(): List<Any?> = ArrayList<Any?>(REVERSIBILITY_ORDER)

    private fun unsat(model: PolicyModel): String = "caveats unsatisfiable: " + (model.caveatReason ?: "unknown")

    // ---- reachable ----

    /**
     * Can any input complete `action` into one the policy ALLOWs (some predicate matches AND the caveats are satisfiable)? Verb and
     * resource are taken as given; unspecified params / subject / env fields are searched. A returned `witness` is a concrete
     * action verified against the real evaluator. `reachable: false` is proven only for the decided fragment; otherwise it fails
     * safe to `reachable: true, approximate: true`.
     */
    fun reachable(policy: Any?, action: Map<String, Any?>?, opts: Map<String, Any?>?): Map<String, Any?> {
        AJs.req(action)
        val model = Enumerate.toModel(policy)
        val max = boundOf(opts)
        if (!model.caveatSat) return AJs.obj("reachable", false, "reason", unsat(model))
        val cap = model.revCap
        if (AJs.has(action, "reversibilityClass") && cap != null) {
            val rc = AJs.get(action, "reversibilityClass")
            val idx = if (rc is String) REVERSIBILITY_ORDER.indexOf(rc) else -1
            if (idx < 0 || idx > cap) {
                return AJs.obj("reachable", false, "reason", "reversibility class '" + CaveatAnalysis.jsString(rc, true) + "' exceeds the caveat cap")
            }
        }
        if (Enumerate.admitsAction(model, action)) return AJs.obj("reachable", true, "witness", action)

        val input = ProbeInputs()
        input.predicateSets.add(Enumerate.probeSet(model))
        input.varyReversibility = cap != null
        val base = Enumerate.collectProbes(input)
        val providedO = AJs.get(action, "params")
        val provided: Map<String, Any?> = if (providedO is Map<*, *>) AJs.map(providedO) else LinkedHashMap()
        val fields = ArrayList<Enumerate.FieldProbe>()
        for (f in base.fields) {
            if (f.path.startsWith("action.params.")) {
                val key = f.path.substring("action.params.".length)
                if (provided.containsKey(key)) {
                    val one = ArrayList<Any?>()
                    one.add(provided[key])
                    fields.add(Enumerate.FieldProbe(f.path, one))
                    continue
                }
            }
            fields.add(f)
        }
        val pr = Probes()
        pr.verbs.add(AJs.get(action, "verb"))
        pr.resources.add(AJs.get(action, "resource"))
        if (AJs.has(action, "reversibilityClass")) pr.revClasses.add(AJs.get(action, "reversibilityClass"))
        else if (cap != null) pr.revClasses.addAll(orderList())
        else pr.revClasses.add(null)
        pr.fields = fields

        val outcome = Enumerate.search(pr, { rep -> Enumerate.admits(model, rep) }, max)
        val hit = outcome.hit
        if (hit != null) return AJs.obj("reachable", true, "witness", mergeWitness(Enumerate.repToAction(hit), action!!))
        if (outcome.overflow) {
            return AJs.obj("reachable", true, "approximate", true, "reason", "representative grid exceeded the bound; could not prove unreachable")
        }
        if (model.undecidable.isNotEmpty()) {
            return AJs.obj("reachable", true, "approximate", true, "reason",
                "over-approximated (" + model.undecidable.joinToString("; ") + "); could not construct a witness but cannot prove unreachable")
        }
        return AJs.obj("reachable", false, "reason", "no predicate admits this action for any input (proven over the decided fragment)")
    }

    private fun mergeWitness(witness: Map<String, Any?>, provided: Map<String, Any?>): Map<String, Any?> {
        val params = AJs.copy(AJs.get(witness, "params"))
        val pp = AJs.get(provided, "params")
        if (pp is Map<*, *>) params.putAll(AJs.map(pp))
        val out = AJs.obj()
        AJs.putIf(out, "verb", provided, "verb")
        AJs.putIf(out, "resource", provided, "resource")
        out["params"] = params
        var rc = AJs.get(provided, "reversibilityClass")
        if (rc == null) rc = AJs.get(witness, "reversibilityClass")
        if (rc != null) out["reversibilityClass"] = rc
        AJs.putIf(out, "subject", witness, "subject")
        AJs.putIf(out, "env", witness, "env")
        return out
    }

    // ---- alwaysDenies / alwaysAllows ----

    /**
     * Is the policy vacuous (does it deny everything, optionally only for `verb`)? Proven only for the decided fragment; any
     * undecidable feature or grid overflow fails safe to `alwaysDenies: false`.
     */
    fun alwaysDenies(policy: Any?, verb: String? = null, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val model = Enumerate.toModel(policy)
        val max = boundOf(opts)
        if (!model.caveatSat) return AJs.obj("alwaysDenies", true, "reason", unsat(model))
        val pr = probesFor(listOf(model), verb)
        val outcome = Enumerate.search(pr, { rep -> Enumerate.admits(model, rep) }, max)
        val hit = outcome.hit
        if (hit != null) return AJs.obj("alwaysDenies", false, "witness", Enumerate.repToAction(hit))
        if (outcome.overflow) return AJs.obj("alwaysDenies", false, "approximate", true, "reason", "grid exceeded the bound; cannot prove vacuity")
        if (model.undecidable.isNotEmpty()) {
            return AJs.obj("alwaysDenies", false, "approximate", true, "reason", "over-approximated (" + model.undecidable.joinToString("; ") + "); cannot prove vacuity")
        }
        return AJs.obj("alwaysDenies", true)
    }

    /**
     * Is the policy total for `verb` (does it admit EVERY action of that verb)? Proven only for the decided fragment; any
     * undecidable feature or grid overflow fails safe to `alwaysAllows: false`.
     */
    fun alwaysAllows(policy: Any?, verb: String? = null, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val model = Enumerate.toModel(policy)
        val max = boundOf(opts)
        if (!model.caveatSat) return AJs.obj("alwaysAllows", false, "reason", unsat(model))
        val pr = probesFor(listOf(model), verb)
        val outcome = Enumerate.search(pr, { rep -> !Enumerate.admits(model, rep) }, max)
        val hit = outcome.hit
        if (hit != null) return AJs.obj("alwaysAllows", false, "counterexample", Enumerate.repToAction(hit))
        if (outcome.overflow) return AJs.obj("alwaysAllows", false, "approximate", true, "reason", "grid exceeded the bound; cannot prove totality")
        if (model.undecidable.isNotEmpty()) {
            return AJs.obj("alwaysAllows", false, "approximate", true, "reason", "over-approximated (" + model.undecidable.joinToString("; ") + "); cannot prove totality")
        }
        return AJs.obj("alwaysAllows", true)
    }

    internal fun probesFor(models: List<PolicyModel>, verb: String?): Probes {
        var anyRev = false
        val input = ProbeInputs()
        for (m in models) { anyRev = anyRev or (m.revCap != null); input.predicateSets.add(Enumerate.probeSet(m)) }
        input.varyReversibility = anyRev
        val pr = Enumerate.collectProbes(input)
        if (verb != null) { pr.verbs = ArrayList(); pr.verbs.add(verb) }
        return pr
    }

    // ---- subsumes / disjoint / equivalent ----

    /**
     * Does policy `a` permit everything `b` permits (admitted(b) is a subset of admitted(a))? The delegation-safety check: a
     * child capability must be subsumed by its parent. A counterexample is an action `b` admits that `a` denies.
     */
    fun subsumes(a: Any?, b: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val ma = Enumerate.toModel(a)
        val mb = Enumerate.toModel(b)
        val max = boundOf(opts)
        val pr = probesFor(listOf(ma, mb), null)
        val outcome = Enumerate.search(pr, { rep -> Enumerate.admits(mb, rep) && !Enumerate.admits(ma, rep) }, max)
        val hit = outcome.hit
        if (hit != null) return AJs.obj("subsumes", false, "counterexample", Enumerate.repToAction(hit))
        val note = approxNote(listOf(ma, mb), outcome.overflow)
        if (note != null) return AJs.obj("subsumes", false, "approximate", true, "reason", note)
        return AJs.obj("subsumes", true)
    }

    /** Are the two admitted sets disjoint (no action both admit)? A witness is an action both admit. */
    fun disjoint(a: Any?, b: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val ma = Enumerate.toModel(a)
        val mb = Enumerate.toModel(b)
        val max = boundOf(opts)
        val pr = probesFor(listOf(ma, mb), null)
        val outcome = Enumerate.search(pr, { rep -> Enumerate.admits(ma, rep) && Enumerate.admits(mb, rep) }, max)
        val hit = outcome.hit
        if (hit != null) return AJs.obj("disjoint", false, "witness", Enumerate.repToAction(hit))
        val note = approxNote(listOf(ma, mb), outcome.overflow)
        if (note != null) return AJs.obj("disjoint", false, "approximate", true, "reason", note)
        return AJs.obj("disjoint", true)
    }

    /** Do the two policies admit exactly the same actions? A counterexample is an action admitted by exactly one. */
    fun equivalent(a: Any?, b: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val ma = Enumerate.toModel(a)
        val mb = Enumerate.toModel(b)
        val max = boundOf(opts)
        val pr = probesFor(listOf(ma, mb), null)
        val outcome = Enumerate.search(pr, { rep -> Enumerate.admits(ma, rep) != Enumerate.admits(mb, rep) }, max)
        val hit = outcome.hit
        if (hit != null) return AJs.obj("equivalent", false, "counterexample", Enumerate.repToAction(hit))
        val note = approxNote(listOf(ma, mb), outcome.overflow)
        if (note != null) return AJs.obj("equivalent", false, "approximate", true, "reason", note)
        return AJs.obj("equivalent", true)
    }

    private fun approxNote(models: List<PolicyModel>, overflow: Boolean): String? {
        if (overflow) return "representative grid exceeded the bound; cannot prove the relation"
        val reasons = LinkedHashSet<String>()
        for (m in models) reasons.addAll(m.undecidable)
        if (reasons.isNotEmpty()) return "over-approximated (" + reasons.joinToString("; ") + "); cannot prove the relation"
        return null
    }

    // ---- intentConformance ----

    /**
     * Does the policy admit ONLY actions inside the declared intent envelope (allowed verbs, resource scopes, an amount ceiling)? Each
     * reported violation is a concrete admitted action outside the envelope, so `conforms: false` with violations is always proven;
     * `conforms: true` is proven only for the decided fragment (an undecidable feature, a `re:` intent scope or a grid
     * overflow fails safe to `conforms: false, approximate: true` with no violations listed).
     */
    fun intentConformance(policy: Any?, intent: Map<String, Any?>?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        AJs.req(intent)
        val model = Enumerate.toModel(policy)
        val max = boundOf(opts)
        val af = AJs.get(intent, "amountField")
        val amountField = if (af == null) "amount" else if (af is String) af else CaveatAnalysis.jsString(af, true)
        val minAmount: Any? = AJs.get(intent, "minAmount") ?: AJs.n(0)
        if (!model.caveatSat) return AJs.obj("conforms", true, "violations", ArrayList<Any?>())

        val verbsO = AJs.get(intent, "verbs")
        if (verbsO !is List<*>) throw IllegalArgumentException("intent.verbs is not an array")
        val verbs: List<Any?> = AJs.list(verbsO)
        val scopesO = AJs.get(intent, "resourceScopes")
        val scopes: List<Any?> = if (scopesO == null) ArrayList() else if (scopesO is List<*>) AJs.list(scopesO)
        else throw IllegalArgumentException("intent.resourceScopes is not an array")

        val input = ProbeInputs()
        input.predicateSets.add(Enumerate.probeSet(model))
        for (v in verbs) if ("*" != v) input.extraVerbs.add(v)
        input.extraResources.addAll(scopes)
        if (AJs.has(intent, "maxAmount")) {
            val path = "action.params.$amountField"
            input.extraFieldConditions.add(arrayOf(path, AJs.obj("field", path, "op", "lte", "value", AJs.get(intent, "maxAmount"))))
            input.extraFieldConditions.add(arrayOf(path, AJs.obj("field", path, "op", "gte", "value", minAmount)))
        }
        input.varyReversibility = model.revCap != null
        val pr = Enumerate.collectProbes(input)

        if (fieldProduct(pr) * pr.verbs.size * pr.resources.size * pr.revClasses.size > max) {
            return AJs.obj("conforms", false, "approximate", true, "violations", ArrayList<Any?>(), "reason", "grid exceeded the bound; cannot prove conformance")
        }
        val violations = ArrayList<Any?>()
        Enumerate.forEachRep(pr) { rep ->
            if (!Enumerate.admits(model, rep)) {
                false
            } else {
                val action = Enumerate.repToAction(rep)
                val kinds = intentViolationKinds(action, intent!!, verbs, scopes, amountField, minAmount)
                if (kinds.isNotEmpty()) {
                    violations.add(AJs.obj("action", action, "kinds", kinds))
                    violations.size >= 16
                } else false
            }
        }
        if (violations.isNotEmpty()) return AJs.obj("conforms", false, "violations", violations)
        var intentRegex = false
        for (s in scopes) if ((s as String).startsWith("re:")) intentRegex = true
        if (model.undecidable.isNotEmpty() || intentRegex) {
            val reasons = ArrayList<String>(model.undecidable)
            if (intentRegex) reasons.add("re: intent resource scope not enumerated soundly")
            return AJs.obj("conforms", false, "approximate", true, "violations", ArrayList<Any?>(),
                "reason", "over-approximated (" + reasons.joinToString("; ") + "); cannot prove conformance")
        }
        return AJs.obj("conforms", true, "violations", ArrayList<Any?>())
    }

    private fun fieldProduct(pr: Probes): Double {
        var n = 1.0
        for (f in pr.fields) n *= f.values.size
        return n
    }

    private fun scopeMatches(scope: String, resource: String): Boolean {
        if (scope == "*") return true
        if (scope.startsWith("re:")) {
            val src = scope.substring(3)
            // the verifier's own guard: a hostile grant under analysis must not hang the analyzer
            if (src.length > 200 || resource.length > Predicates.MAX_RE_RESOURCE_LEN || !SafeRegex.isSafeSource(src)) return false
            return SafeRegex.fullMatch(src, resource) == true
        }
        if (scope.endsWith("*")) return resource.startsWith(scope.substring(0, scope.length - 1))
        return scope == resource
    }

    private fun intentViolationKinds(action: Map<String, Any?>, intent: Map<String, Any?>, verbs: List<Any?>, scopes: List<Any?>, amountField: String, minAmount: Any?): List<Any?> {
        val kinds = ArrayList<Any?>()
        val verb = action["verb"]
        if (!(AJs.includes(verbs, "*") || AJs.includes(verbs, verb))) kinds.add("off-verb")
        if (scopes.isNotEmpty()) {
            var any = false
            for (s in scopes) if (scopeMatches(s as String, action["resource"] as String)) { any = true; break }
            if (!any) kinds.add("off-scope")
        }
        if (AJs.has(intent, "maxAmount")) {
            val amt = AJs.copy(action["params"])[amountField]
            if (AJs.isFin(amt)) {
                val a: Double = AJs.num(amt)!!
                if (a > AJs.toNum(AJs.get(intent, "maxAmount"))) kinds.add("over-amount")
                else if (a < AJs.toNum(minAmount)) kinds.add("under-amount")
            }
        }
        return kinds
    }

    // ---- convenience ----

    /** Concrete, exact admission check for a fully-specified action (no existential search). */
    fun admitsConcrete(policy: Any?, action: Map<String, Any?>?): Boolean {
        AJs.req(action)
        return Enumerate.admitsAction(Enumerate.toModel(policy), action)
    }

    /** Is a predicate's own numeric `where` conjunction satisfiable (e.g. `amount >= 100 AND amount <= 10` is not)? */
    fun predicateNumericSatisfiable(where: Any?): Boolean {
        if (where !is List<*>) return true
        return Field.numericConjunctionSatisfiable(where)
    }
}
