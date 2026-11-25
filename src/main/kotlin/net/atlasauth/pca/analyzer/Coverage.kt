package net.atlasauth.pca.analyzer

import java.math.BigDecimal
import java.math.RoundingMode
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel
import net.atlasauth.pca.verifier.Predicates

/**
 * POLICY COVERAGE (`opa test --coverage` for PCA). Over a body of traffic it reports which clauses of a policy ever DECIDED, which
 * never even matched, which the analyzer says are unreachable, how close the traffic came to each numeric threshold, and which single-edit
 * mutations of the policy (widen a cap, drop a prohibition, flip `<=` to `<`) the traffic cannot tell from the original. A
 * surviving mutant is a missing test and comes with the action that would kill it; a mutant proven equivalent is not a gap.
 */
object Coverage {
    fun permitId(i: Int): String = "permit[$i]"

    private fun idStr(o: Any?, present: Boolean): String = CaveatAnalysis.jsString(o, present)

    /**
     * The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit. Returns
     * {decision, winner: {kind: permit | veto | tighten | caveat | none, id}, also: [other clauses that fired]}.
     */
    fun witnessOf(model: PolicyModel, action: Map<String, Any?>): Map<String, Any?> {
        val decision = Enumerate.decideAction(model, action)
        val ctx = Enumerate.contextOfAction(action)
        val permits = ArrayList<Any?>()
        for (i in model.predicates.indices) if (Predicates.predicateMatches(model.predicates[i], ctx)) permits.add(permitId(i))
        val vetoes = ArrayList<Any?>()
        for (v in model.vetoes) if (Enumerate.vetoApplies(v, ctx)) vetoes.add(v)
        val tighten = ArrayList<Any?>()
        for (t in model.tighten) if (Predicates.evaluateConditionTri(AJs.get(t, "when"), ctx) != Predicates.Tri.FALSE) tighten.add(t)

        if (!model.caveatSat || decision == "deny") {
            if (!model.caveatSat) return done(decision, "caveat", "caveats", permits, vetoes, tighten)
            if (permits.isEmpty()) return done(decision, "none", null, permits, vetoes, tighten)
            for (v in vetoes) if ("deny" == AJs.get(v, "kind")) return done(decision, "veto", AJs.get(v, "id"), permits, vetoes, tighten)
            for (t in tighten) if ("deny" == AJs.get(t, "signal")) return done(decision, "tighten", AJs.get(t, "id"), permits, vetoes, tighten)
            return done(decision, "caveat", "caveats", permits, vetoes, tighten) // reversibility cap or an ancestor of the chain
        }
        if (decision == "escalate") {
            for (v in vetoes) if ("approval" == AJs.get(v, "kind")) return done(decision, "veto", AJs.get(v, "id"), permits, vetoes, tighten)
            return done(decision, "tighten", if (tighten.isEmpty()) null else AJs.get(tighten[0], "id"), permits, vetoes, tighten)
        }
        return done(decision, "permit", if (permits.isEmpty()) null else permits[0], permits, vetoes, tighten)
    }

    private fun done(decision: String, kind: String, id: Any?, permits: List<Any?>, vetoes: List<Any?>, tighten: List<Any?>): Map<String, Any?> {
        val also = ArrayList<Any?>()
        val all = ArrayList<Any?>(permits)
        for (v in vetoes) all.add(AJs.get(v, "id"))
        for (t in tighten) all.add(AJs.get(t, "id"))
        for (x in all) if (!AJs.strictEq(x, id)) also.add(x)
        return AJs.obj("decision", decision, "winner", AJs.obj("kind", kind, "id", id), "also", also)
    }

    // ---- mutation operators ----

    private class Variant(val cond: Any?, val what: String)

    private val FLIP: Map<String, String> = mapOf("lt" to "lte", "lte" to "lt", "gt" to "gte", "gte" to "gt", "eq" to "ne", "ne" to "eq", "in" to "nin", "nin" to "in")
    private val SHIFTABLE = listOf("lt", "lte", "gt", "gte", "eq")
    private val WALKABLE = listOf("lt", "lte", "gt", "gte", "eq", "in", "nin")

    private fun variantsOfCond(c: Any?, eps: Double): List<Variant> {
        val out = ArrayList<Variant>()
        if (!(c is Map<*, *> || c is List<*>)) return out
        if (Field.isGroup(c)) {
            if (AJs.has(c, "not")) {
                for (v in variantsOfCond(AJs.get(c, "not"), eps)) out.add(Variant(AJs.obj("not", v.cond), "not(" + v.what + ")"))
                return out
            }
            val isAll = AJs.has(c, "all_of")
            val kidsO = AJs.get(c, if (isAll) "all_of" else "any_of")
            if (kidsO !is List<*>) throw IllegalArgumentException("group children are not an array")
            val kids = AJs.list(kidsO)
            for (i in kids.indices) {
                for (v in variantsOfCond(kids[i], eps)) {
                    val next = ArrayList<Any?>(kids)
                    next[i] = v.cond
                    val key = if (isAll) "all_of" else "any_of"
                    out.add(Variant(AJs.obj(key, next), "$key[$i] " + v.what))
                }
            }
            return out
        }
        if (!Field.isLeaf(c) || AJs.has(c, "ref")) return out
        val field = AJs.get(c, "field") as String
        val name = if (field.startsWith("action.params.")) field.substring("action.params.".length) else field
        val op = AJs.get(c, "op")
        val value = AJs.get(c, "value")
        if (AJs.isFin(value) && op is String && SHIFTABLE.contains(op)) {
            val d = AJs.num(value)!!
            val up = AJs.copy(c)
            up["value"] = AJs.n(d + eps)
            out.add(Variant(up, name + " " + op + " " + AJs.fmt(d) + " -> " + AJs.fmt(d + eps)))
            val down = AJs.copy(c)
            down["value"] = AJs.n(d - eps)
            out.add(Variant(down, name + " " + op + " " + AJs.fmt(d) + " -> " + AJs.fmt(d - eps)))
        }
        if (op is String && FLIP.containsKey(op)) {
            val fl = AJs.copy(c)
            fl["op"] = FLIP[op]
            out.add(Variant(fl, name + " " + op + " -> " + FLIP[op]))
        }
        return out
    }

    private class Mutant(val id: String, val description: String, val policy: Any?)

    private fun mk(p: PolicyModel, predicates: List<Any?>, vetoes: List<Any?>, tighten: List<Any?>): Map<String, Any?> =
        AJs.obj("predicates", predicates, "caveats", p.caveats, "vetoes", vetoes, "tighten", tighten)

    private fun without(xs: List<Any?>, i: Int): List<Any?> {
        val out = ArrayList<Any?>(xs)
        out.removeAt(i)
        return out
    }

    private fun replaced(xs: List<Any?>, i: Int, v: Any?): List<Any?> {
        val out = ArrayList<Any?>(xs)
        out[i] = v
        return out
    }

    private fun mutantsOf(policy: PolicyModel, eps: Double): List<Mutant> {
        val out = ArrayList<Mutant>()
        for (i in policy.predicates.indices) {
            val p = policy.predicates[i]
            out.add(Mutant("drop-" + permitId(i), "drop " + permitId(i), mk(policy, without(policy.predicates, i), policy.vetoes, policy.tighten)))
            val w = AJs.get(p, "where")
            if (w is List<*>) {
                val where = AJs.list(w)
                for (j in where.indices) {
                    for (v in variantsOfCond(where[j], eps)) {
                        val np = AJs.copy(p)
                        np["where"] = replaced(where, j, v.cond)
                        out.add(Mutant(permitId(i) + ".where[" + j + "]:" + v.what, permitId(i) + ": " + v.what, mk(policy, replaced(policy.predicates, i, np), policy.vetoes, policy.tighten)))
                    }
                    val np2 = AJs.copy(p)
                    np2["where"] = without(where, j)
                    out.add(Mutant(permitId(i) + ".where[" + j + "]:drop", permitId(i) + ": drop condition " + j, mk(policy, replaced(policy.predicates, i, np2), policy.vetoes, policy.tighten)))
                }
            }
        }
        for (i in policy.vetoes.indices) {
            val v = policy.vetoes[i]
            val id = idStr(AJs.get(v, "id"), AJs.has(v, "id"))
            out.add(Mutant("drop-veto:$id", "drop prohibition $id", mk(policy, policy.predicates, without(policy.vetoes, i), policy.tighten)))
            val over = AJs.get(v, "over")
            if (AJs.truthy(over)) {
                val nv = AJs.copy(v)
                val no = AJs.copy(over)
                no["threshold"] = AJs.n(AJs.numOrNaN(over, "threshold") + eps)
                nv["over"] = no
                out.add(Mutant("veto:$id:threshold+", "raise the $id threshold by " + AJs.fmt(eps), mk(policy, policy.predicates, replaced(policy.vetoes, i, nv), policy.tighten)))
            }
        }
        for (i in policy.tighten.indices) {
            val t = policy.tighten[i]
            val id = idStr(AJs.get(t, "id"), AJs.has(t, "id"))
            out.add(Mutant("drop-tighten:$id", "drop tighten rule $id", mk(policy, policy.predicates, policy.vetoes, without(policy.tighten, i))))
        }
        return out
    }

    private fun walkParams(c: Any?, paths: MutableSet<String>) {
        if (!(c is Map<*, *> || c is List<*>)) return
        if (Field.isGroup(c)) {
            if (AJs.has(c, "all_of")) { for (x in listOrThrow(AJs.get(c, "all_of"))) walkParams(x, paths) }
            else if (AJs.has(c, "any_of")) { for (x in listOrThrow(AJs.get(c, "any_of"))) walkParams(x, paths) }
            else walkParams(AJs.get(c, "not"), paths)
        } else if (Field.isLeaf(c)) {
            val f = AJs.get(c, "field") as String
            val op = AJs.get(c, "op")
            if (f.startsWith("action.params.") && op is String && WALKABLE.contains(op)) paths.add(f)
        }
    }

    private fun listOrThrow(o: Any?): List<*> {
        if (o !is List<*>) throw IllegalArgumentException("group children are not an array")
        return o
    }

    private fun reach(model: PolicyModel, kind: String, idx: Int): Any {
        if (kind == "permit") {
            val r = Analyzer.alwaysDenies(AJs.obj("predicates", AJs.arr(model.predicates[idx]), "caveats", model.caveats))
            return if (AJs.truthy(r["approximate"])) "unknown" else (r["alwaysDenies"] != true)
        }
        if (kind == "veto") {
            val r = Analyzer.alwaysDenies(AJs.obj("predicates", AJs.arr(AJs.get(model.vetoes[idx], "when"))))
            return if (AJs.truthy(r["approximate"])) "unknown" else (r["alwaysDenies"] != true)
        }
        return "unknown"
    }

    private fun ratio(n: Double, d: Double): Double = if (d == 0.0) 1.0 else n / d

    /** Coverage of `policy` by `traffic` (production traffic, simulated actions or the cases of a test document). Options: epsilon (default 1), maxMutants (200). */
    fun coverage(policy: Any?, traffic: List<Any?>, o: Map<String, Any?>? = null): Map<String, Any?> {
        val model = Enumerate.toModel(policy)
        val eps = if (AJs.get(o, "epsilon") == null) 1.0 else AJs.toNum(AJs.get(o, "epsilon"))
        val idObjs = ArrayList<Any?>()
        val kinds = ArrayList<String>()
        for (i in model.predicates.indices) { idObjs.add(permitId(i)); kinds.add("permit") }
        for (v in model.vetoes) { idObjs.add(AJs.get(v, "id")); kinds.add("veto") }
        for (t in model.tighten) { idObjs.add(AJs.get(t, "id")); kinds.add("tighten") }
        val matched = HashMap<Any?, Int>()
        val decisive = HashMap<Any?, Int>()
        for (a in traffic) {
            val w = witnessOf(model, AJs.map(AJs.req(a)))
            val win = AJs.get(AJs.get(w, "winner"), "id")
            if (win != null) decisive[win] = (decisive[win] ?: 0) + 1
            val all = ArrayList<Any?>()
            all.add(win)
            all.addAll(AJs.list(w["also"]))
            for (id in all) if (id != null) matched[id] = (matched[id] ?: 0) + 1
        }
        val clauses = ArrayList<Any?>()
        val cl = ArrayList<Map<String, Any?>>()
        for (n in idObjs.indices) {
            val kind = kinds[n]
            val idx = if (kind == "permit") n else if (kind == "veto") n - model.predicates.size else n - model.predicates.size - model.vetoes.size
            val id = idObjs[n]
            val c = AJs.obj("id", id, "kind", kind, "matched", AJs.n(matched[id] ?: 0), "decisive", AJs.n(decisive[id] ?: 0), "reachable", reach(model, kind, idx))
            clauses.add(c)
            cl.add(c)
        }
        val paths = java.util.TreeSet<String>() // default string order
        for (p in Enumerate.probeSet(model)) {
            val w = AJs.get(p, "where")
            if (w is List<*>) for (c in w) walkParams(c, paths)
        }
        for (v in model.vetoes) {
            val over = AJs.get(v, "over")
            if (AJs.truthy(over) && AJs.get(over, "path") is String) paths.add(AJs.get(over, "path") as String)
        }
        val boundaries = ArrayList<Any?>()
        for (path in paths) {
            val name = path.substring("action.params.".length)
            val vals = ArrayList<Double>()
            for (a in traffic) {
                val pp = AJs.get(a, "params")
                val v = if (pp is Map<*, *>) AJs.map(pp)[name] else null
                if (AJs.isNum(v)) vals.add(AJs.num(v)!!)
            }
            for (t in Exposure.thresholds(model, path)) {
                var at = false
                var below = false
                var above = false
                for (v in vals) {
                    if (v == t) at = true
                    if (v < t && v >= t - eps) below = true
                    if (v > t && v <= t + eps) above = true
                }
                boundaries.add(AJs.obj("path", path, "threshold", AJs.n(t), "below", below, "at", at, "above", above))
            }
        }
        val survivors = ArrayList<Any?>()
        var killed = 0
        var equiv = 0
        var all = mutantsOf(model, eps)
        val maxM = if (AJs.get(o, "maxMutants") == null) 200.0 else AJs.toNum(AJs.get(o, "maxMutants"))
        if (all.size > maxM) all = all.subList(0, Math.max(0.0, maxM).toInt())
        val base = ArrayList<String>()
        for (a in traffic) base.add(Enumerate.decideAction(model, a))
        for (m in all) {
            val mm = Enumerate.toModel(m.policy)
            var differs = false
            for (i in traffic.indices) if (Enumerate.decideAction(mm, traffic[i]) != base[i]) { differs = true; break }
            if (differs) { killed++; continue }
            val eq = Analyzer.equivalent(policy, m.policy)
            if (eq["equivalent"] == true) { equiv++; continue }
            val s = AJs.obj("id", m.id, "description", m.description)
            if (AJs.truthy(eq["counterexample"])) s["killer"] = eq["counterexample"]
            survivors.add(s)
        }
        val live = ArrayList<Map<String, Any?>>()
        for (c in cl) if (c["reachable"] != false) live.add(c)
        var liveDecisive = 0
        for (c in live) if (AJs.num(c["decisive"])!! > 0) liveDecisive++
        var bFull = 0
        for (b in boundaries) if (AJs.get(b, "at") == true && AJs.get(b, "below") == true && AJs.get(b, "above") == true) bFull++
        val neverMatched = ArrayList<Any?>()
        val neverDecisive = ArrayList<Any?>()
        val untested = ArrayList<Any?>()
        val unreachable = ArrayList<Any?>()
        for (c in cl) {
            if (AJs.num(c["matched"])!! == 0.0) neverMatched.add(c["id"])
            if (AJs.num(c["decisive"])!! == 0.0) neverDecisive.add(c["id"])
            if (c["reachable"] != false && AJs.num(c["matched"])!! == 0.0) untested.add(c["id"])
            if (c["reachable"] == false) unreachable.add(c["id"])
        }
        return AJs.obj("traffic", AJs.n(traffic.size), "policyDigest", Residual.policyDigestOf(model), "clauses", clauses,
            "neverMatched", neverMatched, "neverDecisive", neverDecisive, "untested", untested, "unreachable", unreachable, "boundaries", boundaries,
            "mutants", AJs.obj("total", AJs.n(all.size), "killed", AJs.n(killed), "equivalent", AJs.n(equiv), "survivors", survivors),
            "score", AJs.obj("clauses", AJs.n(ratio(liveDecisive.toDouble(), live.size.toDouble())), "boundaries", AJs.n(ratio(bFull.toDouble(), boundaries.size.toDouble())),
                "mutation", AJs.n(ratio(killed.toDouble(), (all.size - equiv).toDouble()))))
    }

    private fun toFixed2(x: Double): String = BigDecimal(x).setScale(2, RoundingMode.HALF_UP).toPlainString()

    /** A CI gate over a coverage report: {ok, reasons}. `min`: clauses, boundaries, mutation, maxSurvivors. */
    fun coverageGate(r: Map<String, Any?>, min: Map<String, Any?>? = null): Map<String, Any?> {
        val reasons = ArrayList<Any?>()
        val score = AJs.get(r, "score")
        val sc = AJs.toNum(AJs.get(score, "clauses"))
        val sb = AJs.toNum(AJs.get(score, "boundaries"))
        val sm = AJs.toNum(AJs.get(score, "mutation"))
        if (sc < (if (AJs.get(min, "clauses") == null) 0.0 else AJs.toNum(AJs.get(min, "clauses")))) reasons.add("clause coverage " + toFixed2(sc) + " < " + idStr(AJs.get(min, "clauses"), AJs.has(min, "clauses")))
        if (sb < (if (AJs.get(min, "boundaries") == null) 0.0 else AJs.toNum(AJs.get(min, "boundaries")))) reasons.add("boundary coverage " + toFixed2(sb) + " < " + idStr(AJs.get(min, "boundaries"), AJs.has(min, "boundaries")))
        if (sm < (if (AJs.get(min, "mutation") == null) 0.0 else AJs.toNum(AJs.get(min, "mutation")))) reasons.add("mutation score " + toFixed2(sm) + " < " + idStr(AJs.get(min, "mutation"), AJs.has(min, "mutation")))
        val survivors = AJs.get(AJs.get(r, "mutants"), "survivors")
        if (AJs.has(min, "maxSurvivors") && AJs.list(survivors).size.toDouble() > AJs.toNum(AJs.get(min, "maxSurvivors"))) {
            reasons.add(AJs.list(survivors).size.toString() + " surviving mutants > " + idStr(AJs.get(min, "maxSurvivors"), true))
        }
        val unr = AJs.list(AJs.get(r, "unreachable"))
        if (unr.isNotEmpty()) {
            val s = ArrayList<String>()
            for (u in unr) s.add(if (u == null) "" else idStr(u, true))
            reasons.add("unreachable clauses: " + s.joinToString(", "))
        }
        return AJs.obj("ok", reasons.isEmpty(), "reasons", reasons)
    }
}
