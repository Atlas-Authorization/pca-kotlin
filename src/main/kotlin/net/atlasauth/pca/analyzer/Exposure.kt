package net.atlasauth.pca.analyzer

import net.atlasauth.pca.analyzer.Enumerate.FieldProbe
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs
import net.atlasauth.pca.analyzer.Enumerate.Probes
import net.atlasauth.pca.verifier.Catalog

/**
 * QUANTITATIVE AND TERNARY STATIC QUERIES: the most that can ever be spent under a policy, the actions that need a human, the reach of
 * a delegation chain, and a first-class diff. Every witness is re-checked by the real evaluator; a number is exact only on the decided
 * fragment, otherwise the result carries `approximate: true` and the bound errs on the high side.
 */
object Exposure {
    private const val HUGE = 9007199254740991.0 // Number.MAX_SAFE_INTEGER

    // ---- thresholds ----

    private fun condThresholds(c: Any?, path: String, into: MutableList<Double>) {
        if (!(c is Map<*, *> || c is List<*>)) return
        if (Field.isGroup(c)) {
            if (AJs.has(c, "all_of") && AJs.get(c, "all_of") is List<*>) { for (x in AJs.get(c, "all_of") as List<*>) condThresholds(x, path, into) }
            else if (AJs.has(c, "any_of") && AJs.get(c, "any_of") is List<*>) { for (x in AJs.get(c, "any_of") as List<*>) condThresholds(x, path, into) }
            else if (AJs.has(c, "not")) condThresholds(AJs.get(c, "not"), path, into)
            return
        }
        if (!Field.isLeaf(c) || path != AJs.get(c, "field")) return
        val v = AJs.get(c, "value")
        if (AJs.isFin(v)) into.add(AJs.num(v)!!)
        else if (v is List<*>) for (x in v) if (AJs.isFin(x)) into.add(AJs.num(x)!!)
    }

    /** Every numeric literal the policy compares `path` against (permits, vetoes and tighten rules), ascending and distinct. */
    internal fun thresholds(model: PolicyModel, path: String): List<Double> {
        val out = ArrayList<Double>()
        for (p in Enumerate.probeSet(model)) {
            AJs.req(p) // `p.where`: a veto without a `when` trigger is an undefined entry and the read throws
            val w = AJs.get(p, "where")
            if (w is List<*>) for (c in w) condThresholds(c, path, out)
        }
        for (v in model.vetoes) {
            val over = AJs.get(v, "over")
            if (AJs.truthy(over) && path == AJs.get(over, "path") && AJs.has(over, "threshold") && AJs.isNum(AJs.get(over, "threshold"))) out.add(AJs.num(AJs.get(over, "threshold"))!!)
        }
        return distinctSorted(out)
    }

    internal fun distinctSorted(xs: List<Double>): List<Double> {
        val seen = HashSet<Double>()
        val out = ArrayList<Double>()
        for (d in xs) { val k = if (d == 0.0) 0.0 else d; if (!k.isNaN() && seen.add(k)) out.add(k) }
        out.sort()
        return out
    }

    /** [thresholds] as JSON numbers. */
    fun thresholdsOf(model: PolicyModel, path: String): List<Any?> {
        val out = ArrayList<Any?>()
        for (d in thresholds(model, path)) out.add(AJs.n(d))
        return out
    }

    // ---- per-action peak ----

    /** The largest amount of one verb: admitted or autonomous, whether a supremum is attained, and a verified witness. */
    class Peak internal constructor(
        val admitted: Boolean,
        /** Largest amount (Infinity = unbounded); a supremum no action reaches when `attained` is false. */
        val max: Double,
        val attained: Boolean,
        val witness: Map<String, Any?>?,
    ) {
        fun toJson(): Map<String, Any?> {
            val m = AJs.obj("admitted", admitted, "max", AJs.n(max), "attained", attained)
            if (witness != null) m["witness"] = witness
            return m
        }
    }

    private class PeakOutcome(val peak: Peak, val overflow: Boolean)

    private fun amountFieldOf(o: Map<String, Any?>): String {
        val f = AJs.get(o, "amountField")
        return if (f == null) "amount" else if (f is String) f else CaveatAnalysis.jsString(f, true)
    }

    private fun pinned(pr: Probes, path: String, value: Double, hasResource: Boolean, resource: Any?): Probes {
        val p = pr.copy()
        val fields = ArrayList<FieldProbe>()
        for (f in pr.fields) if (f.path != path) fields.add(f)
        val one = ArrayList<Any?>()
        one.add(AJs.n(value))
        fields.add(FieldProbe(path, one))
        p.fields = fields
        if (hasResource) { p.resources = ArrayList(); p.resources.add(resource) }
        return p
    }

    private fun peakAt(model: PolicyModel, o: Map<String, Any?>, allowOnly: Boolean): PeakOutcome {
        val field = amountFieldOf(o)
        val path = "action.params.$field"
        val max = Analyzer.boundOf(o)
        val input = ProbeInputs()
        input.predicateSets.add(Enumerate.probeSet(model))
        input.varyReversibility = model.revCap != null
        val base = Enumerate.collectProbes(input)
        base.verbs = ArrayList()
        base.verbs.add(AJs.get(o, "verb"))
        val t = thresholds(model, path)
        val lo = Math.max(0.0, if (AJs.get(o, "min") == null) 0.0 else AJs.toNum(AJs.get(o, "min")))
        val hi = if (AJs.get(o, "max") == null) Double.POSITIVE_INFINITY else AJs.toNum(AJs.get(o, "max"))
        val raw = ArrayList<Double>()
        for (i in t.indices) {
            val ti = t[i]
            raw.add(ti - 1)
            raw.add(ti)
            if (i + 1 < t.size) raw.add((ti + t[i + 1]) / 2)
        }
        raw.add(if (t.isNotEmpty()) t[t.size - 1] + 1 else 0.0)
        raw.add(HUGE)
        raw.add(lo)
        if (!hi.isNaN() && !hi.isInfinite()) raw.add(hi)
        val cands = ArrayList<Double>()
        for (c in distinctSorted(raw)) if (c >= lo && c <= hi && !c.isInfinite()) cands.add(c)
        cands.reverse() // largest first
        val hasRes = AJs.has(o, "resource")
        val res = AJs.get(o, "resource")
        val integer = AJs.get(o, "integer") == true
        var overflow = false
        val top = if (t.isEmpty()) Double.NEGATIVE_INFINITY else t[t.size - 1]
        for (c in cands) {
            val out = Enumerate.search(pinned(base, path, c, hasRes, res), { rep ->
                val d = Enumerate.decide(model, rep)
                if (allowOnly) d == "allow" else d != "deny"
            }, max)
            if (out.overflow) { overflow = true; break }
            val hit = out.hit ?: continue
            val act = { v: Double ->
                val a = LinkedHashMap(Enumerate.repToAction(hit))
                val params = AJs.copy(a["params"])
                params[field] = AJs.n(v)
                a["params"] = params
                a
            }
            val holds = { a: Map<String, Any?> ->
                val d = Enumerate.decideAction(model, a)
                if (allowOnly) d == "allow" else d != "deny"
            }
            if (c > top) {
                if (!hi.isNaN() && !hi.isInfinite()) {
                    val w = act(hi)
                    return PeakOutcome(Peak(true, hi, holds(w), act(hi)), false)
                }
                return PeakOutcome(Peak(true, Double.POSITIVE_INFINITY, false, act(HUGE)), false)
            }
            if (t.contains(if (c == 0.0) 0.0 else c)) return PeakOutcome(Peak(true, c, true, act(c)), false)
            var next = Double.NaN
            for (x in t) if (x > c) { next = x; break }
            if (integer) {
                val m = Math.ceil(next) - 1
                if (m >= c && holds(act(m))) return PeakOutcome(Peak(true, m, true, act(m)), false)
            }
            return PeakOutcome(Peak(true, next, false, act(c)), false)
        }
        return PeakOutcome(Peak(false, 0.0, false, null), overflow)
    }

    // ---- windowed exposure ----

    /** An invariant trigger that provably applies to every action of the verb. */
    private fun universal(p: Any?, verb: Any?): Boolean {
        AJs.req(p)
        val pv = AJs.get(p, "verb")
        val verbOk = "*" == pv || AJs.strictEq(pv, verb) || (pv is List<*> && (AJs.includes(pv, "*") || AJs.includes(pv, verb)))
        val where = AJs.get(p, "where")
        val noWhere = !AJs.has(p, "where") || (where is List<*> && where.isEmpty())
        val noRes = !AJs.has(p, "resource") || "*" == AJs.get(p, "resource")
        return verbOk && noRes && noWhere
    }

    private fun windowBound(model: PolicyModel, constitution: Any?, o: Map<String, Any?>, peak: Peak): Map<String, Any?> {
        val hasW = AJs.has(o, "windowSecs")
        val w = if (hasW) AJs.toNum(AJs.get(o, "windowSecs")) else Double.NaN
        val path = "action.params." + amountFieldOf(o)
        val per = if (peak.admitted) peak.max else 0.0
        val basis = ArrayList<Any?>()
        val notApplied = ArrayList<Any?>()
        val maxActions = doubleArrayOf(Double.POSITIVE_INFINITY)
        val caveats = ArrayList<Any?>(model.caveats)
        for (m in model.meets) caveats.addAll(m.caveats)
        val invs = if (constitution == null) null else AJs.get(constitution, "invariants")
        val invList: List<*> = if (invs == null) ArrayList<Any?>() else if (invs is List<*>) invs
        else throw IllegalArgumentException("invariants is not iterable")

        for (cv in caveats) {
            if (cv == null) throw IllegalArgumentException("caveat is null")
            if ("rate" == AJs.get(cv, "type") && AJs.isNum(AJs.get(cv, "max")) && AJs.isNum(AJs.get(cv, "per_secs")) && AJs.num(AJs.get(cv, "per_secs"))!! > 0) {
                limitActions(hasW, w, maxActions, basis, AJs.num(AJs.get(cv, "max"))!!, AJs.num(AJs.get(cv, "per_secs"))!!,
                    "rate caveat " + CaveatAnalysis.jsString(AJs.get(cv, "max"), true) + "/" + CaveatAnalysis.jsString(AJs.get(cv, "per_secs"), true) + "s")
            }
        }
        for (inv in invList) {
            if ("rate" != AJs.get(inv, "kind")) continue
            if (universal(AJs.get(inv, "when"), AJs.get(o, "verb"))) {
                limitActions(hasW, w, maxActions, basis, AJs.numOrNaN(inv, "max"), AJs.numOrNaN(inv, "window_secs"), "rate invariant " + CaveatAnalysis.jsString(AJs.get(inv, "id"), AJs.has(inv, "id")))
            } else notApplied.add(AJs.get(inv, "id"))
        }
        var bound = if (per == 0.0) 0.0 else if (maxActions[0] == Double.POSITIVE_INFINITY) Double.POSITIVE_INFINITY else per * maxActions[0]
        if (!per.isInfinite() && !per.isNaN() && per > 0) basis.add(0, "per-action ceiling")
        val budgetModel: String? = AJs.get(o, "budgetModel") as? String
        for (cv in caveats) {
            if ("budget_alloc" != AJs.get(cv, "type") || !AJs.isNum(AJs.get(cv, "limit"))) continue
            val limit = AJs.num(AJs.get(cv, "limit"))!!
            if ("dollars" == budgetModel) {
                if (limit < bound) {
                    bound = limit // in the dollar model the allocation is a lifetime cap on the total
                    basis.add("budget_alloc limit " + AJs.fmt(limit))
                }
            } else if ("risk" == budgetModel && AJs.isNum(AJs.get(o, "kappa")) && AJs.num(AJs.get(o, "kappa"))!! > 0) {
                val r: Double
                if (AJs.get(o, "blastRadius") != null) r = AJs.toNum(AJs.get(o, "blastRadius"))
                else {
                    val verb = AJs.get(o, "verb")
                    val spec = if (verb is String) Catalog.DEFAULT.get(verb) else null
                    r = spec?.blastRadius ?: 1.0 // an uncatalogued verb is treated as maximum blast radius
                }
                val cost = AJs.num(AJs.get(o, "kappa"))!! * Math.min(1.0, Math.max(0.0, r))
                val n = if (cost > 0) Math.floor(limit / cost) else Double.POSITIVE_INFINITY
                if (n < maxActions[0]) {
                    maxActions[0] = n
                    bound = if (n == 0.0) 0.0 else (if (!per.isInfinite() && !per.isNaN() && per > 0) per * n else bound)
                    basis.add("budget_alloc " + AJs.fmt(limit) + " / cost " + AJs.fmt(cost) + " = " + AJs.fmt(n) + " actions")
                }
            } else notApplied.add("budget_alloc " + AJs.fmt(limit) + " (trust-budget units; pass budgetModel and kappa)")
        }
        for (inv in invList) {
            if ("cap" != AJs.get(inv, "kind")) continue
            if (!universal(AJs.get(inv, "when"), AJs.get(o, "verb")) || path != AJs.get(inv, "amount")) {
                notApplied.add(AJs.get(inv, "id"))
                continue
            }
            val hasWin = AJs.has(inv, "window_secs")
            if (hasWin && !hasW) continue // a windowed cap says nothing about a lifetime total
            val imax = AJs.numOrNaN(inv, "max")
            val cap = if (!hasWin || !hasW) imax else imax * Math.ceil(w / AJs.toNum(AJs.get(inv, "window_secs")))
            if (cap < bound) {
                bound = cap
                basis.add("cap invariant " + CaveatAnalysis.jsString(AJs.get(inv, "id"), AJs.has(inv, "id")))
            }
        }
        val out = AJs.obj("maxActions", AJs.n(maxActions[0]), "bound", AJs.n(bound), "basis", basis, "notApplied", notApplied)
        if (hasW) out["secs"] = AJs.get(o, "windowSecs")
        val pw = peak.witness
        if (peak.admitted && pw != null && !maxActions[0].isInfinite() && !maxActions[0].isNaN() && !peak.max.isInfinite() && !peak.max.isNaN() && peak.max > 0) {
            out["sequence"] = AJs.obj("action", pw, "repeat", AJs.n(maxActions[0]))
        }
        return out
    }

    private fun limitActions(hasW: Boolean, w: Double, maxActions: DoubleArray, basis: MutableList<Any?>, n: Double, perSecs: Double, why: String) {
        val k = if (!hasW) Double.POSITIVE_INFINITY else n * Math.ceil(w / perSecs) // a sliding limit of n per perSecs: at most n per started period
        if (k < maxActions[0]) {
            maxActions[0] = k
            basis.add(why)
        }
    }

    /**
     * The most that can ever leave under a policy: the largest single action, the largest autonomous action, and the total over a window,
     * composing the per-action ceiling with rate limits, the grant's `budget_alloc` and a constitution's `cap` / `rate`
     * invariants. A cap or rate invariant counts only when it provably applies to every action of the verb. Options: verb, resource,
     * amountField, integer, min, max, maxCombinations, windowSecs, constitution, budgetModel, kappa, blastRadius.
     */
    fun maxExposure(policy: Any?, given: Map<String, Any?>? = null): Map<String, Any?> {
        AJs.req(policy)
        val o = AJs.copy(given)
        if (!AJs.has(given, "budgetModel")) {
            val bm = AJs.get(policy, "budgetModel")
            if ("dollars" == bm || "risk" == bm) o["budgetModel"] = bm
        }
        if (!AJs.has(given, "kappa")) {
            val k = AJs.get(AJs.get(policy, "riskPolicy"), "kappa")
            if (AJs.isNum(k)) o["kappa"] = k
        }
        val cv: Map<String, Any?>? = if (AJs.has(o, "constitution")) Constitution.vetoesFromConstitution(AJs.get(o, "constitution")) else null
        val base = Enumerate.toModel(policy)
        var model = base
        if (cv != null) {
            model = base.copy()
            model.vetoes = ArrayList(base.vetoes)
            model.vetoes.addAll(AJs.list(cv["vetoes"]))
        }
        val field = amountFieldOf(o)
        val admit = peakAt(model, o, false)
        val auto = peakAt(model, o, true)
        val approximate = admit.overflow || auto.overflow || model.undecidable.isNotEmpty()
        val unbounded = Peak(true, Double.POSITIVE_INFINITY, false, null)
        val pa = if (admit.overflow) unbounded else admit.peak
        val ap = if (auto.overflow) unbounded else auto.peak
        val c = AJs.get(o, "constitution")
        val unmodeled = ArrayList<Any?>()
        if (cv != null) {
            for (u in AJs.list(cv["unmodeled"])) {
                val kind = AJs.get(u, "kind")
                if ("cap" == kind || "rate" == kind) continue
                unmodeled.add(CaveatAnalysis.jsString(AJs.get(u, "id"), AJs.has(u, "id")) + ": " + CaveatAnalysis.jsString(AJs.get(u, "reason"), AJs.has(u, "reason")))
            }
        }
        val e = AJs.obj()
        AJs.putIf(e, "verb", o, "verb")
        e["amountField"] = field
        e["perAction"] = pa.toJson()
        e["autonomousPerAction"] = ap.toJson()
        e["window"] = windowBound(model, c, o, pa)
        e["autonomousWindow"] = windowBound(model, c, o, ap)
        e["unmodeled"] = unmodeled
        if (approximate) {
            e["approximate"] = true
            e["reason"] = if (admit.overflow || auto.overflow) "representative grid exceeded the bound; exposure reported as unbounded" else "over-approximated (" + model.undecidable.joinToString("; ") + ")"
        }
        return e
    }

    // ---- escalation surface ----

    /** The set of actions that escalate (admitted, but not autonomous): witnesses (at most `limit`, default 8) verified. Options: verb, limit, maxCombinations. */
    fun escalationSurface(policy: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val model = Enumerate.toModel(policy)
        val input = ProbeInputs()
        input.predicateSets.add(Enumerate.probeSet(model))
        input.varyReversibility = model.revCap != null
        val base = Enumerate.collectProbes(input)
        if (AJs.has(opts, "verb")) { base.verbs = ArrayList(); base.verbs.add(AJs.get(opts, "verb")) }
        val limit = if (AJs.get(opts, "limit") == null) 8.0 else AJs.toNum(AJs.get(opts, "limit"))
        val r = Enumerate.collect(base, { rep -> Enumerate.decide(model, rep) == "escalate" }, Analyzer.boundOf(opts), limit)
        val witnesses = ArrayList<Any?>()
        for (h in r.hits) {
            val a = Enumerate.repToAction(h)
            if (Enumerate.decideAction(model, a) == "escalate") witnesses.add(a)
        }
        val out = AJs.obj("escalates", witnesses.isNotEmpty(), "witnesses", witnesses)
        if (r.overflow || model.undecidable.isNotEmpty()) {
            out["approximate"] = true
            out["reason"] = if (r.overflow) "representative grid exceeded the bound" else "over-approximated (" + model.undecidable.joinToString("; ") + ")"
        }
        return out
    }

    // ---- delegation envelope ----

    /**
     * The join of everything any holder of the leaf could do: the meet of the chain's policies (every hop must admit) with the remaining
     * `delegation_depth`. A sub-delegate can only narrow it, so it is the ceiling for the whole subtree.
     */
    fun delegationEnvelope(chain: List<Any?>?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        AJs.req(chain)
        chain!!
        val leaf = if (chain.isEmpty()) null else chain[chain.size - 1]
        val policy: Any?
        if (leaf is Map<*, *> || leaf is List<*>) {
            val p: MutableMap<String, Any?> = if (leaf is Map<*, *>) AJs.copy(leaf) else AJs.obj()
            val meet = ArrayList<Any?>(chain.subList(0, chain.size - 1))
            val lm = AJs.get(leaf, "meet")
            if (AJs.truthy(lm)) {
                if (lm !is List<*>) throw IllegalArgumentException("meet is not iterable")
                meet.addAll(lm)
            }
            p["meet"] = meet
            policy = p
        } else policy = AJs.obj("predicates", ArrayList<Any?>())
        val model = Enumerate.toModel(policy)
        val input = ProbeInputs()
        input.predicateSets.add(Enumerate.probeSet(model))
        input.varyReversibility = model.revCap != null
        val base = Enumerate.collectProbes(input)
        val max = Analyzer.boundOf(opts)
        val verbs = ArrayList<Any?>()
        var anyVerb = false
        var overflow = false
        for (verb in base.verbs) {
            val pr = base.copy()
            pr.verbs = ArrayList()
            pr.verbs.add(verb)
            val r = Enumerate.collect(pr, { rep -> Enumerate.decide(model, rep) != "deny" }, max, 1.0)
            if (r.overflow) { overflow = true; break }
            if (r.hits.isEmpty()) continue
            val hit = r.hits[0]
            val w = Enumerate.repToAction(hit)
            if ((verb as String).startsWith("\u0000")) anyVerb = true
            else verbs.add(AJs.obj("verb", verb, "witness", w, "autonomous", Enumerate.decide(model, hit) == "allow"))
        }
        val violations = ArrayList<Any?>()
        for (i in 0 until chain.size - 1) {
            val a = Enumerate.toModel(chain[i])
            val b = Enumerate.toModel(chain[i + 1])
            val pin = ProbeInputs()
            pin.predicateSets.add(Enumerate.probeSet(a))
            pin.predicateSets.add(Enumerate.probeSet(b))
            pin.varyReversibility = a.revCap != null || b.revCap != null
            val pr = Enumerate.collectProbes(pin)
            val out = Enumerate.search(pr, { rep -> Enumerate.decide(b, rep) != "deny" && Enumerate.decide(a, rep) == "deny" }, max)
            if (out.hit != null || out.overflow) violations.add(AJs.n(i + 1))
        }
        val depths = ArrayList<Double>()
        for (p in chain) {
            if (p !is Map<*, *> || AJs.get(p, "caveats") !is List<*>) continue
            for (c in AJs.get(p, "caveats") as List<*>) {
                if ("delegation_depth" == AJs.get(c, "type") && AJs.isNum(AJs.get(c, "max"))) depths.add(AJs.num(AJs.get(c, "max"))!!)
            }
        }
        val used = Math.max(0.0, (chain.size - 1).toDouble())
        val depth = AJs.obj("used", AJs.n(used))
        if (depths.isNotEmpty()) {
            var allowed = depths[0]
            for (d in depths) allowed = Math.min(allowed, d)
            depth["allowed"] = AJs.n(allowed)
            depth["remaining"] = AJs.n(Math.max(0.0, allowed - used))
        }
        val out = AJs.obj("violations", violations, "verbs", verbs, "anyVerb", anyVerb, "depth", depth)
        if (overflow || model.undecidable.isNotEmpty()) {
            out["approximate"] = true
            out["reason"] = if (overflow) "representative grid exceeded the bound" else "over-approximated (" + model.undecidable.joinToString("; ") + ")"
        }
        return out
    }

    // ---- semantic diff ----

    private val WIDEN = listOf("deny->allow", "deny->escalate", "escalate->allow")

    private fun sub(x: Double, y: Double): Double = if (x == y) 0.0 else x - y // Infinity - Infinity is no change

    private fun numAt(e: Any?, a: String, b: String): Double = AJs.toNum(AJs.get(AJs.get(e, a), b))

    /**
     * `diff(A, B)`: what moved between two policies (ternary-aware) with verified witnesses per kind of shift. Options: limit (witnesses
     * per kind, default 4), maxCombinations, exposure (options of [maxExposure]: also report how the exposure of that verb moved).
     */
    fun diffPolicies(a: Any?, b: Any?, o: Map<String, Any?>? = null): Map<String, Any?> {
        val ma = Enumerate.toModel(a)
        val mb = Enumerate.toModel(b)
        val input = ProbeInputs()
        input.predicateSets.add(Enumerate.probeSet(ma))
        input.predicateSets.add(Enumerate.probeSet(mb))
        input.varyReversibility = ma.revCap != null || mb.revCap != null
        val pr = Enumerate.collectProbes(input)
        val limit = if (AJs.get(o, "limit") == null) 4.0 else AJs.toNum(AJs.get(o, "limit"))
        val shifts = LinkedHashMap<String, Any?>()
        val counts = LinkedHashMap<String, Int>()
        val walk = Enumerate.collect(pr, { rep ->
            val x = Enumerate.decide(ma, rep)
            val y = Enumerate.decide(mb, rep)
            if (x == y) {
                false
            } else {
                val k = "$x->$y"
                val n = counts[k] ?: 0
                counts[k] = n + 1
                if (n < limit) {
                    @Suppress("UNCHECKED_CAST")
                    val l = shifts.getOrPut(k) { ArrayList<Any?>() } as MutableList<Any?>
                    l.add(Enumerate.repToAction(rep))
                }
                false // walk the whole grid
            }
        }, Analyzer.boundOf(o), 1.0)
        val overflow = walk.overflow
        val kinds = ArrayList(shifts.keys)
        var widens = false
        var narrows = false
        for (k in kinds) { if (WIDEN.contains(k)) widens = true else narrows = true }
        val summary = ArrayList<Any?>()
        for (k in kinds) {
            val l = AJs.list(shifts[k])
            val first = AJs.map(l[0])
            val p = first["params"]
            summary.add("$k: ${l.size}+ action(s), e.g. ${first["verb"]} ${first["resource"]} " + AJs.stringify(p ?: AJs.obj()))
        }
        val d = AJs.obj("equivalent", kinds.isEmpty() && !overflow && ma.undecidable.isEmpty() && mb.undecidable.isEmpty(),
            "shifts", shifts, "widens", widens, "narrows", narrows, "summary", summary)
        if (AJs.has(o, "exposure")) {
            val eo = AJs.map(AJs.get(o, "exposure"))
            val before = maxExposure(a, eo)
            val after = maxExposure(b, eo)
            val perAction = sub(numAt(after, "perAction", "max"), numAt(before, "perAction", "max"))
            val auton = sub(numAt(after, "autonomousWindow", "bound"), numAt(before, "autonomousWindow", "bound"))
            val delta = sub(numAt(after, "window", "bound"), numAt(before, "window", "bound"))
            d["exposure"] = AJs.obj("before", before, "after", after, "perActionDelta", AJs.n(perAction), "delta", AJs.n(delta), "autonomousDelta", AJs.n(auton))
            val worst = Math.max(Math.max(delta, perAction), auton)
            val best = Math.min(delta, perAction)
            val verb = CaveatAnalysis.jsString(AJs.get(eo, "verb"), AJs.has(eo, "verb"))
            if (worst > 0) summary.add("max exposure of $verb rises by " + AJs.fmt(worst))
            else if (best < 0) summary.add("max exposure of $verb falls by " + AJs.fmt(-best))
        }
        if (overflow || ma.undecidable.isNotEmpty() || mb.undecidable.isNotEmpty()) {
            d["approximate"] = true
            val rs = LinkedHashSet<String>(ma.undecidable)
            rs.addAll(mb.undecidable)
            d["reason"] = if (overflow) "representative grid exceeded the bound" else "over-approximated (" + rs.joinToString("; ") + ")"
        }
        return d
    }

    /** A CI gate over a diff: fails when the change widens authority beyond what the reviewer allowed (`widen`, `maxExposureIncrease`). */
    fun diffGate(d: Map<String, Any?>, allow: Map<String, Any?>? = null): Map<String, Any?> {
        val reasons = ArrayList<Any?>()
        if (AJs.truthy(AJs.get(d, "widens")) && AJs.get(allow, "widen") != true) {
            val ws = ArrayList<String>()
            val sm = AJs.get(d, "summary")
            if (sm is List<*>) for (s in sm) for (k in WIDEN) if ((s as String).startsWith(k)) { ws.add(s); break }
            reasons.add("widens authority: " + ws.joinToString("; "))
        }
        var rise = 0.0
        val ex = AJs.get(d, "exposure")
        if (AJs.truthy(ex)) rise = Math.max(Math.max(AJs.toNum(AJs.get(ex, "delta")), AJs.toNum(AJs.get(ex, "perActionDelta"))), AJs.toNum(AJs.get(ex, "autonomousDelta")))
        val allowed = if (AJs.get(allow, "maxExposureIncrease") == null) 0.0 else AJs.toNum(AJs.get(allow, "maxExposureIncrease"))
        if (rise > allowed) reasons.add("max exposure rises by " + AJs.fmt(rise))
        if (AJs.truthy(AJs.get(d, "approximate"))) {
            val r = AJs.get(d, "reason")
            reasons.add("inconclusive: " + (if (r == null) "approximate" else CaveatAnalysis.jsString(r, true)))
        }
        return AJs.obj("ok", reasons.isEmpty(), "reasons", reasons)
    }

    // ---- optional solver backend ----

    /**
     * An optional external solver (cvc5, z3, ...) consulted ONLY to look for a counterexample when the grid overflows. It is never trusted:
     * a witness it returns is re-checked by the real evaluator and discarded if wrong, and an "unsat" claim is returned labelled as
     * solver-claimed, never as a proved verdict. The built-in search needs no backend.
     */
    interface WitnessBackend {
        fun name(): String

        /** {witness?: action, unsat?: boolean} for a query {kind: "reachable" | "differs", a, b?, verb?}. */
        fun find(query: Map<String, Any?>): Map<String, Any?>
    }

    fun findWithBackend(backend: WitnessBackend, q: Map<String, Any?>): Map<String, Any?> {
        val r = backend.find(q)
        val w = AJs.get(r, "witness")
        if (AJs.has(r, "witness")) {
            val ma = Enumerate.toModel(AJs.get(q, "a"))
            val ok: Boolean = if ("reachable" == AJs.get(q, "kind")) {
                Enumerate.decideAction(ma, w) != "deny" && (!AJs.has(q, "verb") || AJs.strictEq(AJs.get(w, "verb"), AJs.get(q, "verb")))
            } else {
                AJs.has(q, "b") && (Enumerate.decideAction(ma, w) != "deny") != (Enumerate.decideAction(Enumerate.toModel(AJs.get(q, "b")), w) != "deny")
            }
            return if (ok) AJs.obj("witness", w) else AJs.obj("rejected", true)
        }
        if (AJs.get(r, "unsat") == true) {
            return AJs.obj("claimedUnsat", AJs.obj("by", backend.name(), "proof", "solver-claimed, not machine-checked"))
        }
        return AJs.obj()
    }
}
