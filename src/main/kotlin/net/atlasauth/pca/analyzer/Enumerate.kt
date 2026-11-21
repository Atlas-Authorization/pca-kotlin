package net.atlasauth.pca.analyzer

import net.atlasauth.pca.verifier.ForbidWins
import net.atlasauth.pca.verifier.Predicates

/**
 * The bounded decision engine. It builds a finite grid of representative actions from the literals, thresholds, prefixes, verbs and
 * resource matchers of the policies, and evaluates the real predicate evaluator at each. Every query (reachability, subsumption,
 * disjointness, equivalence, ...) is decided EXACTLY on the decided fragment and fails safe (`approximate`) outside it
 * (`re:` resources, cross-field `ref`, `like` / `matches` / `is_a` / `member_of`, a grid over the bound).
 *
 * Policies, actions and results are JSON trees (Map / List / String / Boolean / Json.Num / null), as the evaluator takes them.
 */
object Enumerate {
    /** The "field absent" representative. */
    val ABSENT: Any = object { override fun toString(): String = "ABSENT" }
    internal const val FRESH_VERB = "\u0000atlas-analyzer::fresh-verb\u0000"
    internal const val FRESH_RESOURCE = "\u0000atlas-analyzer::fresh-resource\u0000"

    /** Default cap on the representative grid size (product of all dimensions). */
    const val DEFAULT_MAX_COMBINATIONS: Double = 200_000.0

    /** A policy in analyzable form. */
    class PolicyModel {
        var predicates: MutableList<Any?> = ArrayList()
        var caveats: MutableList<Any?> = ArrayList()
        var vetoes: MutableList<Any?> = ArrayList()
        var tighten: MutableList<Any?> = ArrayList()

        /** Policies that must also admit; their static gates are already folded into caveatSat / revCap. */
        var meets: MutableList<PolicyModel> = ArrayList()
        var caveatSat: Boolean = false
        var caveatReason: String? = null

        /** Strictest reversibility_max cap (index into the order), or null. */
        var revCap: Int? = null

        /** Non-empty when the policy uses features the analyzer cannot decide exactly. */
        var undecidable: List<String> = ArrayList()

        fun copy(): PolicyModel {
            val m = PolicyModel()
            m.predicates = predicates; m.caveats = caveats; m.vetoes = vetoes; m.tighten = tighten; m.meets = meets
            m.caveatSat = caveatSat; m.caveatReason = caveatReason; m.revCap = revCap; m.undecidable = undecidable
            return m
        }

        fun toJson(): Map<String, Any?> {
            val ms = ArrayList<Any?>()
            for (x in meets) ms.add(x.toJson())
            val o = AJs.obj("predicates", predicates, "caveats", caveats, "vetoes", vetoes, "tighten", tighten, "meets", ms, "caveatSat", caveatSat)
            if (caveatReason != null) o["caveatReason"] = caveatReason
            if (revCap != null) o["revCap"] = AJs.n(revCap!!)
            o["undecidable"] = ArrayList<Any?>(undecidable)
            return o
        }
    }

    /** {predicates, caveats, vetoes, tighten} of a policy input; anything that is no policy is the empty policy. */
    fun normalizePolicy(p: Any?): PolicyModel {
        val m = PolicyModel()
        if (!(p is Map<*, *> || p is List<*>)) return m
        if (AJs.get(p, "predicates") is List<*>) m.predicates = AJs.list(AJs.get(p, "predicates"))
        if (AJs.get(p, "caveats") is List<*>) m.caveats = AJs.list(AJs.get(p, "caveats"))
        if (AJs.get(p, "vetoes") is List<*>) m.vetoes = AJs.list(AJs.get(p, "vetoes"))
        if (AJs.get(p, "tighten") is List<*>) m.tighten = AJs.list(AJs.get(p, "tighten"))
        return m
    }

    internal fun predicateList(o: Any?): MutableList<Any?> = if (o is List<*>) AJs.list(o) else ArrayList()

    /** The predicates whose literals shape the grid: the permits plus every veto and tighten trigger. */
    fun probeSet(m: PolicyModel): MutableList<Any?> {
        val out = ArrayList<Any?>(m.predicates)
        for (v in m.vetoes) {
            if (v == null) throw IllegalArgumentException("veto is null")
            out.add(AJs.get(v, "when"))
            val un = AJs.get(v, "unless")
            if (un is List<*> && un.isNotEmpty()) out.add(AJs.obj("verb", "*", "where", un))
            val over = AJs.get(v, "over")
            if (AJs.truthy(over)) {
                out.add(AJs.obj("verb", "*", "where", AJs.arr(AJs.obj("field", AJs.get(over, "path"), "op", "gt", "value", AJs.get(over, "threshold")))))
            }
        }
        for (t in m.tighten) {
            if (t == null) throw IllegalArgumentException("tighten rule is null")
            out.add(AJs.obj("verb", "*", "where", AJs.arr(AJs.get(t, "when"))))
        }
        for (x in m.meets) out.addAll(probeSet(x))
        return out
    }

    private fun conditionUndecidable(c: Any?, reasons: MutableSet<String>) {
        if (!(c is Map<*, *> || c is List<*>)) return
        if (Field.isGroup(c)) {
            if (AJs.has(c, "all_of") && AJs.get(c, "all_of") is List<*>) { for (x in AJs.get(c, "all_of") as List<*>) conditionUndecidable(x, reasons) }
            else if (AJs.has(c, "any_of") && AJs.get(c, "any_of") is List<*>) { for (x in AJs.get(c, "any_of") as List<*>) conditionUndecidable(x, reasons) }
            else if (AJs.has(c, "not")) conditionUndecidable(AJs.get(c, "not"), reasons)
            return
        }
        if (!Field.isLeaf(c)) return
        if (AJs.has(c, "ref")) reasons.add("cross-field `ref` condition — the relation between two fields is not resolved")
        if ("action.params" == AJs.get(c, "field")) reasons.add("condition on the whole `action.params` object is not enumerated precisely")
        val op = AJs.get(c, "op")
        if (op is String) {
            if ((op == "lt" || op == "lte" || op == "gt" || op == "gte") && !AJs.isFin(AJs.get(c, "value"))) {
                reasons.add("`$op` against a non-numeric operand — string ordering is not enumerated exactly")
            }
            if (op == "like" || op == "matches" || op == "is_a" || op == "member_of") {
                reasons.add("`$op` condition — matched by over-approximation, not enumerated exactly")
            }
        }
    }

    private fun detectUndecidable(predicates: List<Any?>): List<String> {
        val reasons = LinkedHashSet<String>()
        for (p in predicates) {
            if (!(p is Map<*, *> || p is List<*>)) continue
            val r = AJs.get(p, "resource")
            if (r is String && r.startsWith("re:")) reasons.add("re: regex resource matcher — resource dimension cannot be soundly enumerated")
            val w = AJs.get(p, "where")
            if (w is List<*>) for (c in w) conditionUndecidable(c, reasons)
        }
        return ArrayList(reasons)
    }

    fun toModel(p: Any?): PolicyModel {
        val m = normalizePolicy(p)
        val ca = CaveatAnalysis.analyzeCaveats(m.caveats)
        val meets = ArrayList<PolicyModel>()
        if (p is Map<*, *> && AJs.get(p, "meet") is List<*>) for (x in AJs.list(AJs.get(p, "meet"))) meets.add(toModel(x))
        m.meets = meets
        var meetsSat = true
        var meetReason: String? = null
        var foundBad = false
        for (x in meets) {
            if (!x.caveatSat) { meetsSat = false; if (!foundBad) { meetReason = x.caveatReason; foundBad = true } }
        }
        m.caveatSat = ca.sat && meetsSat
        m.caveatReason = if (ca.sat) meetReason else ca.reason
        var cap: Int? = ca.revCap
        for (x in meets) {
            val xc = x.revCap
            if (cap == null) cap = xc
            else if (xc != null) cap = Math.min(cap, xc)
        }
        m.revCap = cap
        val und = LinkedHashSet<String>(detectUndecidable(probeSet(m)))
        for (x in meets) und.addAll(x.undecidable)
        m.undecidable = ArrayList(und)
        return m
    }

    // ---- probe collection ----

    /** The grid: one list of values per dimension. `revClasses` holds null for "no reversibility dimension". */
    class Probes {
        var verbs: MutableList<Any?> = ArrayList()
        var resources: MutableList<Any?> = ArrayList()
        var revClasses: MutableList<Any?> = ArrayList()
        var fields: MutableList<FieldProbe> = ArrayList()

        fun copy(): Probes {
            val p = Probes()
            p.verbs = ArrayList(verbs); p.resources = ArrayList(resources); p.revClasses = ArrayList(revClasses); p.fields = ArrayList(fields)
            return p
        }
    }

    /** The values of one field path (may contain [ABSENT]). */
    class FieldProbe(val path: String, val values: MutableList<Any?>)

    /** Inputs of [collectProbes]. */
    class ProbeInputs {
        var predicateSets: MutableList<List<Any?>> = ArrayList()
        var extraVerbs: MutableList<Any?> = ArrayList()
        var extraResources: MutableList<Any?> = ArrayList()
        /** {path (String), cond (Map)} pairs. */
        var extraFieldConditions: MutableList<Array<Any?>> = ArrayList()
        var varyReversibility: Boolean = false
    }

    private fun addVerbLiterals(c: Any?, into: MutableSet<String>) {
        val v = AJs.get(c, "value")
        val op = AJs.get(c, "op").let { if (it is String) it else "" }
        if (op == "eq" || op == "ne" || op == "prefix" || op == "like" || op == "is_a") {
            if (v is String) into.add(v)
        } else if ((op == "in" || op == "nin") && v is List<*>) {
            for (x in v) if (x is String) into.add(x)
        }
    }

    private fun classifyResource(r: Any?, present: Boolean, resourceLiterals: MutableSet<String>) {
        if (!present) return
        if ("*" == r) return
        if (r !is String) throw IllegalArgumentException("resource matcher is not a string")
        if (r.startsWith("re:")) return
        if (r.endsWith("*")) {
            val body = r.substring(0, r.length - 1)
            resourceLiterals.add(body)
            resourceLiterals.add(body + "x")
            return
        }
        resourceLiterals.add(r)
    }

    private fun handleCond(c: Any?, verbLiterals: MutableSet<String>, resourceLiterals: MutableSet<String>, fieldConds: MutableMap<String, MutableList<Any?>>) {
        if (!(c is Map<*, *> || c is List<*>)) return
        if (Field.isGroup(c)) {
            if (AJs.has(c, "all_of") && AJs.get(c, "all_of") is List<*>) { for (x in AJs.get(c, "all_of") as List<*>) handleCond(x, verbLiterals, resourceLiterals, fieldConds) }
            else if (AJs.has(c, "any_of") && AJs.get(c, "any_of") is List<*>) { for (x in AJs.get(c, "any_of") as List<*>) handleCond(x, verbLiterals, resourceLiterals, fieldConds) }
            else if (AJs.has(c, "not")) handleCond(AJs.get(c, "not"), verbLiterals, resourceLiterals, fieldConds)
            return
        }
        if (!Field.isLeaf(c)) return
        val field = AJs.get(c, "field") as String
        if (field == "action.verb") { addVerbLiterals(c, verbLiterals); return }
        if (field == "action.resource") {
            val v = AJs.get(c, "value")
            if ("prefix" == AJs.get(c, "op") && v is String) classifyResource("$v*", true, resourceLiterals)
            else if (v is String) classifyResource(v, true, resourceLiterals)
            else if (v is List<*>) for (x in v) if (x is String) classifyResource(x, true, resourceLiterals)
            return
        }
        fieldConds.getOrPut(field) { ArrayList() }.add(c)
    }

    fun collectProbes(input: ProbeInputs): Probes {
        val verbLiterals = LinkedHashSet<String>()
        for (v in input.extraVerbs) {
            if (v !is String) throw IllegalArgumentException("extra verb is not a string")
            verbLiterals.add(v)
        }
        val resourceLiterals = LinkedHashSet<String>()
        val fieldConds = LinkedHashMap<String, MutableList<Any?>>()
        for (list in input.predicateSets) {
            for (p in list) {
                if (!(p is Map<*, *> || p is List<*>)) continue
                val pv = AJs.get(p, "verb")
                if (pv is String) { if (pv != "*") verbLiterals.add(pv) }
                else if (pv is List<*>) { for (v in pv) if (v is String && v != "*") verbLiterals.add(v) }
                classifyResource(AJs.get(p, "resource"), AJs.has(p, "resource"), resourceLiterals)
                val w = AJs.get(p, "where")
                if (w is List<*>) for (c in w) handleCond(c, verbLiterals, resourceLiterals, fieldConds)
            }
        }
        for (r in input.extraResources) classifyResource(r, true, resourceLiterals)
        for (ec in input.extraFieldConditions) {
            val cond = AJs.copy(ec[1])
            cond["field"] = ec[0]
            handleCond(cond, verbLiterals, resourceLiterals, fieldConds)
        }
        val pr = Probes()
        for ((k, v) in fieldConds) {
            val vals = ArrayList<Any?>(Field.fieldProbes(v))
            vals.add(ABSENT)
            pr.fields.add(FieldProbe(k, vals))
        }
        pr.verbs = ArrayList<Any?>(verbLiterals)
        pr.verbs.add(FRESH_VERB)
        pr.resources = ArrayList<Any?>(resourceLiterals)
        pr.resources.add(FRESH_RESOURCE)
        if (input.varyReversibility) pr.revClasses = ArrayList<Any?>(Analyzer.REVERSIBILITY_ORDER)
        else pr.revClasses.add(null)
        return pr
    }

    fun productSize(pr: Probes): Double {
        var n = pr.verbs.size.toDouble() * pr.resources.size * pr.revClasses.size
        for (f in pr.fields) n *= f.values.size
        return n
    }

    // ---- representatives ----

    /** One representative action of the grid. */
    class Rep internal constructor(
        val verb: Any?,
        val resource: Any?,
        /** null = no class. */
        val revClass: Any?,
        /** Field path to value, excluding absent fields. */
        val assignments: Map<String, Any?>,
    )

    private fun walkFields(fields: List<FieldProbe>, i: Int, acc: MutableMap<String, Any?>, verb: Any?, resource: Any?, rev: Any?, vis: (Rep) -> Boolean): Boolean {
        if (i >= fields.size) return vis(Rep(verb, resource, rev, LinkedHashMap(acc)))
        val f = fields[i]
        for (v in f.values) {
            if (v === ABSENT) acc.remove(f.path) else acc[f.path] = v
            if (walkFields(fields, i + 1, acc, verb, resource, rev, vis)) return true
        }
        return false
    }

    /** Walk the grid in order (verbs, resources, reversibility classes, fields), stopping when the visitor returns true. */
    fun forEachRep(pr: Probes, vis: (Rep) -> Boolean) {
        for (verb in pr.verbs) for (resource in pr.resources) for (rc in pr.revClasses) {
            if (walkFields(pr.fields, 0, LinkedHashMap(), verb, resource, rc, vis)) return
        }
    }

    /** The whole grid as a list (callers bound the grid first). */
    fun representatives(pr: Probes): List<Rep> {
        val out = ArrayList<Rep>()
        forEachRep(pr) { r -> out.add(r); false }
        return out
    }

    // ---- context building ----

    private class Node(val leaf: Boolean, val value: Any?) {
        val children: MutableMap<String, Node> = LinkedHashMap()
    }

    private fun insert(root: Node, segs: List<String>, value: Any?) {
        var node = root
        for (i in 0 until segs.size - 1) {
            if (node.leaf) return
            val key = segs[i]
            val next = node.children[key]
            if (next == null || next.leaf) {
                val created = Node(false, null)
                node.children[key] = created
                node = created
            } else node = next
        }
        if (!segs.isEmpty() && !node.leaf) node.children[segs[segs.size - 1]] = Node(true, value)
    }

    private fun materialize(node: Node): MutableMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        if (node.leaf) return out
        for ((k, v) in node.children) out[k] = if (v.leaf) v.value else materialize(v)
        return out
    }

    /** The context roots of a representative. */
    internal class Roots(val action: MutableMap<String, Any?>, val subject: MutableMap<String, Any?>, val env: MutableMap<String, Any?>)

    internal fun buildRoots(rep: Rep): Roots {
        val roots = LinkedHashMap<String, Node>()
        roots["action"] = Node(false, null)
        roots["subject"] = Node(false, null)
        roots["env"] = Node(false, null)
        for ((k, value) in rep.assignments) {
            val segs = k.split(".")
            if (segs.size < 2) continue
            val root = roots[segs[0]] ?: continue
            insert(root, segs.subList(1, segs.size), value)
        }
        val action = AJs.obj("verb", rep.verb, "resource", rep.resource, "params", LinkedHashMap<String, Any?>())
        val at = roots["action"]!!
        for ((key, v) in at.children) {
            if (key == "verb" || key == "resource") continue
            if (key == "params") { if (!v.leaf) action["params"] = materialize(v) }
            else action[key] = if (v.leaf) v.value else materialize(v)
        }
        if (rep.revClass != null) action["reversibility_class"] = rep.revClass
        return Roots(action, materialize(roots["subject"]!!), materialize(roots["env"]!!))
    }

    private fun contextFromRoots(r: Roots): Map<String, Any?> = AJs.obj("action", r.action, "subject", r.subject, "env", r.env)

    private fun reversibilityOk(model: PolicyModel, revClass: Any?): Boolean {
        val cap = model.revCap ?: return true
        if (revClass !is String) return false
        val idx = Analyzer.REVERSIBILITY_ORDER.indexOf(revClass)
        return idx >= 0 && idx <= cap
    }

    /** Does a veto apply to this action? Veto polarity: whatever cannot be decided counts as applying. */
    fun vetoApplies(v: Any?, ctx: Map<String, Any?>): Boolean {
        if (!ForbidWins.whenMatches(AJs.get(v, "when"), ctx)) return false
        val over = AJs.get(v, "over")
        if (AJs.truthy(over)) {
            val r = Predicates.resolvePath(ctx, AJs.get(over, "path"))
            val thr = if (AJs.has(over, "threshold")) AJs.toNum(AJs.get(over, "threshold")) else Double.NaN
            var isOver = !r.found || !AJs.isFin(r.value)
            if (!isOver) {
                val rv: Double = AJs.num(r.value)!!
                isOver = rv < 0 || rv > thr
            }
            if (!isOver) return false
        }
        val unless = AJs.get(v, "unless")
        if ("approval" != AJs.get(v, "kind") && AJs.truthy(unless)) {
            if (unless !is List<*>) throw IllegalArgumentException("unless is not an array")
            var all = true
            for (c in unless) if (!Predicates.evaluateCondition(c, ctx)) { all = false; break }
            if (all) return false
        }
        return true
    }

    /** The ternary decision of the permission layer at a concrete context: "allow" / "escalate" / "deny". */
    fun decisionAtContext(model: PolicyModel, ctx: Map<String, Any?>): String {
        if (!Predicates.evaluatePredicates(model.predicates, ctx)) return "deny"
        var escalate = false
        for (v in model.vetoes) {
            if (!vetoApplies(v, ctx)) continue
            if ("deny" == AJs.get(v, "kind")) return "deny"
            escalate = true
        }
        for (t in model.tighten) {
            if (Predicates.evaluateConditionTri(AJs.get(t, "when"), ctx) == Predicates.Tri.FALSE) continue
            if ("deny" == AJs.get(t, "signal")) return "deny"
            escalate = true
        }
        var own = if (escalate) "escalate" else "allow"
        for (x in model.meets) {
            val d = decisionAtContext(x, ctx)
            if (d == "deny") return "deny"
            if (d == "escalate") own = "escalate"
        }
        return own
    }

    /** Ternary decision of a representative (the static caveat gate first). */
    fun decide(model: PolicyModel, rep: Rep): String {
        if (!model.caveatSat) return "deny"
        if (!reversibilityOk(model, rep.revClass)) return "deny"
        return decisionAtContext(model, contextFromRoots(buildRoots(rep)))
    }

    /** Does the policy admit this representative (allow OR escalate)? */
    fun admits(model: PolicyModel, rep: Rep): Boolean = decide(model, rep) != "deny"

    fun contextOfAction(action: Any?): Map<String, Any?> {
        val act = AJs.obj("verb", AJs.get(action, "verb"), "resource", AJs.get(action, "resource"))
        act["params"] = AJs.copy(AJs.get(action, "params"))
        if (AJs.has(action, "reversibilityClass")) act["reversibility_class"] = AJs.get(action, "reversibilityClass")
        return AJs.obj("action", act, "subject", AJs.copy(AJs.get(action, "subject")), "env", AJs.copy(AJs.get(action, "env")))
    }

    /** Ternary decision of a fully-specified action. */
    fun decideAction(model: PolicyModel, action: Any?): String {
        if (!model.caveatSat) return "deny"
        if (!reversibilityOk(model, AJs.get(action, "reversibilityClass"))) return "deny"
        return decisionAtContext(model, contextOfAction(action))
    }

    /** Concrete admission of a fully-specified action (exact). */
    fun admitsAction(model: PolicyModel, action: Any?): Boolean = decideAction(model, action) != "deny"

    /** The representative as an action {verb, resource, params, reversibilityClass?, subject?, env?}. */
    fun repToAction(rep: Rep): Map<String, Any?> {
        val roots = buildRoots(rep)
        val action = AJs.obj("verb", rep.verb, "resource", rep.resource, "params", LinkedHashMap(AJs.map(roots.action["params"])))
        if (rep.revClass != null) action["reversibilityClass"] = rep.revClass
        if (roots.subject.isNotEmpty()) action["subject"] = roots.subject
        if (roots.env.isNotEmpty()) action["env"] = roots.env
        return action
    }

    // ---- bounded search ----

    class SearchOutcome internal constructor(
        /** The representative the predicate accepted, or null. */
        val hit: Rep?,
        /** The grid exceeded the bound; nothing was enumerated. */
        val overflow: Boolean,
    )

    /** Walk the grid and stop at the first representative the predicate accepts; overflow (without walking) when the grid exceeds `max`. */
    fun search(pr: Probes, predicate: (Rep) -> Boolean, max: Double): SearchOutcome {
        if (productSize(pr) > max) return SearchOutcome(null, true)
        var hit: Rep? = null
        forEachRep(pr) { r -> if (predicate(r)) { hit = r; true } else false }
        return SearchOutcome(hit, false)
    }

    class Collected internal constructor(val hits: List<Rep>, val overflow: Boolean)

    /** Like [search], but collects up to `limit` accepted representatives (at least one when the limit is below one). */
    fun collect(pr: Probes, predicate: (Rep) -> Boolean, max: Double, limit: Double): Collected {
        if (productSize(pr) > max) return Collected(ArrayList(), true)
        val hits = ArrayList<Rep>()
        forEachRep(pr) { r ->
            if (predicate(r)) { hits.add(r); hits.size >= limit } else false
        }
        return Collected(hits, false)
    }
}
