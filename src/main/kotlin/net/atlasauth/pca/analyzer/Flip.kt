package net.atlasauth.pca.analyzer

import net.atlasauth.pca.analyzer.Enumerate.PolicyModel
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs
import net.atlasauth.pca.verifier.Caveats

/**
 * MINIMAL-CHANGE COUNTERFACTUAL SEARCH on a deny or escalate: "what is the smallest thing the agent can change to be allowed?", as a typed
 * patch ordered by cost: wait, lower a parameter to the nearest admissible value, pick another allowed value or resource, obtain a named
 * fact, split the action (opt-in), and only then ask a human. The search PROPOSES; the real decision VERIFIES: every candidate is re-run
 * through the evaluator and only one that reaches the wanted decision is returned. A counterfactual teaches the holder about the policy, so
 * it is shown only to the authenticated holder, is rate-limited by a probe budget, and redacts critical values.
 */
object Flip {
    private fun rank(d: Any?): Double = if ("deny" == d) 0.0 else if ("escalate" == d) 1.0 else if ("allow" == d) 2.0 else Double.NaN

    /** A repair candidate being assembled. */
    private class Cand(val repair: Map<String, Any?>, val cost: Double, val decision: String, val action: Map<String, Any?>) {
        fun toJson(): Map<String, Any?> = AJs.obj("repair", repair, "cost", AJs.n(cost), "decision", decision, "action", action)
    }

    private fun withParam(action: Map<String, Any?>, params: Map<String, Any?>, name: String, v: Any?): Map<String, Any?> {
        val p = LinkedHashMap<String, Any?>(params)
        p[name] = v
        val a = AJs.copy(action)
        a["params"] = p
        return a
    }

    /** The reference's `CaveatContext` (camelCase) as the evaluator's context. */
    private fun caveatCtx(c: Any?, nowOverride: Any?, override: Boolean): Map<String, Any?> {
        val m = AJs.obj()
        if (override) m["now"] = nowOverride else AJs.putIf(m, "now", c, "now")
        AJs.putIf(m, "blast_radius", c, "blastRadius")
        AJs.putIf(m, "reversibility_class", c, "reversibilityClass")
        AJs.putIf(m, "delegation_depth", c, "delegationDepth")
        AJs.putIf(m, "recent_action_times", c, "recentActionTimes")
        return m
    }

    private fun caveatsOkAt(model: PolicyModel, ctx: Any?, now: Any?, override: Boolean): Boolean =
        Caveats.evaluateCaveats(model.caveats, caveatCtx(ctx, now, override)).ok

    private fun meters(m: PolicyModel): Boolean {
        val cs = ArrayList<Any?>(m.caveats)
        for (x in m.meets) cs.addAll(x.caveats)
        for (c in cs) {
            val t = AJs.get(c, "type")
            if ("rate" == t || "budget_alloc" == t || "max_blast_radius" == t) return true
        }
        return false
    }

    private fun waitTime(caveats: List<Any?>, ctx: Any?): Double? {
        var at: Double? = null
        val now = AJs.toNum(AJs.get(ctx, "now"))
        for (c in caveats) {
            val type = AJs.get(c, "type")
            if ("not_before" == type && AJs.isNum(AJs.get(c, "at")) && AJs.num(AJs.get(c, "at"))!! > now) at = Math.max(at ?: 0.0, AJs.num(AJs.get(c, "at"))!!)
            if ("rate" == type && AJs.isNum(AJs.get(c, "max")) && AJs.isNum(AJs.get(c, "per_secs"))) {
                val span = AJs.num(AJs.get(c, "per_secs"))!! * 1000
                val recent = ArrayList<Double>()
                val rt = AJs.get(ctx, "recentActionTimes")
                if (rt is List<*>) for (t in rt) if (AJs.toNum(t) > now - span) recent.add(AJs.toNum(t))
                recent.sort()
                val max = AJs.num(AJs.get(c, "max"))!!
                if (recent.size >= max) {
                    val idx = recent.size - max
                    val v = if (idx >= 0 && idx == Math.rint(idx) && idx < recent.size) recent[idx.toInt()] + span else Double.NaN
                    at = Math.max(at ?: 0.0, v)
                }
            }
        }
        return at
    }

    private fun setPath(o: MutableMap<String, Any?>, path: List<String>, v: Any?) {
        if (path.isEmpty()) return
        val k = path[0]
        val rest = path.subList(1, path.size)
        if (rest.isEmpty()) o[k] = v
        else {
            val inner = AJs.copy(o[k])
            setPath(inner, rest, v)
            o[k] = inner
        }
    }

    private fun <T> distinct(xs: List<T>): List<T> {
        val out = ArrayList<T>()
        for (x in xs) { var dup = false; for (y in out) if (AJs.strictEq(x, y)) { dup = true; break }; if (!dup) out.add(x) }
        return out
    }

    /** First-occurrence-ordered distinct numbers (a JavaScript Set of numbers: -0 and 0 are one value). */
    private fun distinctNums(xs: List<Double>): List<Double> {
        val seen = LinkedHashSet<Double>()
        for (d in xs) seen.add(if (d == 0.0) 0.0 else d)
        return ArrayList(seen)
    }

    /**
     * Search for the smallest verified change that gets `action` to the wanted decision. Options: desired ("allow" | "escalate"), schema
     * (verb shapes), holderAuthenticated (required), probe {limit, windowSecs, history, now}, changeable, caveatContext, allowSplit, redact
     * ("none" | "critical" | "all"), maxCandidates. Returns {current, repairs, humanFree?, humanAsk?, redacted?, repairExists, refused?, probe?}.
     */
    fun minimalFlip(policy: Any?, action: Map<String, Any?>?, o: Map<String, Any?>? = null): Map<String, Any?> {
        val act: Map<String, Any?> = AJs.req(action)
        val model = Enumerate.toModel(policy)
        val hasCtx = AJs.has(o, "caveatContext")
        val cctx = AJs.get(o, "caveatContext")
        val caveatsOk = !hasCtx || caveatsOkAt(model, cctx, null, false)
        val current = if (caveatsOk) Enumerate.decideAction(model, act) else "deny"
        val wantO = AJs.get(o, "desired")
        val want: Any = wantO ?: "allow"
        val res = AJs.obj("current", current, "repairs", ArrayList<Any?>(), "repairExists", false)
        if (!AJs.truthy(AJs.get(o, "holderAuthenticated"))) {
            res["refused"] = "counterfactuals are shown only to the authenticated holder"
            return res
        }
        val probe = AJs.get(o, "probe")
        if (AJs.truthy(probe)) {
            val recent = ArrayList<Any?>()
            val now = AJs.toNum(AJs.get(probe, "now"))
            val windowSecs = AJs.toNum(AJs.get(probe, "windowSecs"))
            val history = AJs.list(AJs.get(probe, "history"))
            // A clock, window or history stamp that is not finite cannot say what is still inside the window: refuse (a +Infinity limit stays an unbounded cap).
            if (!now.isFinite() || !windowSecs.isFinite() || !history.all { AJs.num(it)?.isFinite() == true }) {
                res["refused"] = "probe budget exhausted"
                res["probe"] = AJs.obj("history", history)
                return res
            }
            for (t in history) if (AJs.toNum(t) > now - windowSecs * 1000) recent.add(t)
            if (!(recent.size < AJs.toNum(AJs.get(probe, "limit")))) {
                res["refused"] = "probe budget exhausted"
                res["probe"] = AJs.obj("history", recent)
                return res
            }
            val h = ArrayList<Any?>(recent)
            h.add(AJs.get(probe, "now"))
            res["probe"] = AJs.obj("history", h)
        }
        val policyDigest = Residual.policyDigestOf(model)
        if (rank(current) >= rank(want)) return res

        var shape: Any? = null
        val schema = AJs.get(o, "schema")
        if (AJs.truthy(schema)) for (s in AJs.list(schema)) if (AJs.strictEq(AJs.get(s, "verb"), AJs.get(act, "verb"))) { shape = s; break }
        val shapeF = shape
        val cands = ArrayList<Cand>()
        val reaches = { a: Map<String, Any?> ->
            val d = Enumerate.decideAction(model, a)
            if (rank(d) >= rank(want)) d else null
        }

        val input = ProbeInputs()
        input.predicateSets.add(Enumerate.probeSet(model))
        input.varyReversibility = model.revCap != null
        val pr = Enumerate.collectProbes(input)
        val paramsO = AJs.get(act, "params")
        val params: Map<String, Any?> = if (paramsO is Map<*, *>) AJs.map(paramsO) else LinkedHashMap()
        val names = ArrayList<String>()
        val ch = AJs.get(o, "changeable")
        if (ch != null) for (n in AJs.list(ch)) names.add(n as String)
        else if (shape != null) names.addAll(AJs.keys(AJs.copy(AJs.get(shape, "params"))))
        else names.addAll(AJs.keys(params))

        // 1. wait: a time caveat that is not open yet, or a rate window that will reset
        if (!caveatsOk && hasCtx && AJs.truthy(cctx)) {
            val at = waitTime(model.caveats, cctx)
            val d = Enumerate.decideAction(model, act)
            if (at != null && caveatsOkAt(model, cctx, AJs.n(at), true) && rank(d) >= rank(want)) {
                cands.add(Cand(AJs.obj("kind", "wait_until", "at", AJs.n(at), "reason", "a time or rate caveat opens then"), 1.0, d, act))
            }
        }
        val finish = !caveatsOk // nothing else helps while a caveat is closed

        // 2. one parameter changed: the nearest verified value, per parameter
        for (name in (if (finish) ArrayList<String>() else names)) {
            val path = "action.params.$name"
            val decl = AJs.get(AJs.get(shape, "params"), name)
            val cur = params[name]
            val hasCur = params.containsKey(name)
            var field: Enumerate.FieldProbe? = null
            for (f in pr.fields) if (f.path == path) { field = f; break }
            val pool = ArrayList<Any?>()
            if (field != null) for (v in field.values) if (v !== Enumerate.ABSENT) pool.add(v)
            if (decl != null && AJs.get(decl, "values") is List<*>) pool.addAll(AJs.list(AJs.get(decl, "values")))
            if (decl != null && AJs.has(decl, "min")) pool.add(AJs.get(decl, "min"))
            if (decl != null && AJs.has(decl, "max")) pool.add(AJs.get(decl, "max"))
            val nums = ArrayList<Double>()
            for (v in pool) if (AJs.isFin(v)) nums.add(AJs.num(v)!!)
            val t = Exposure.thresholds(model, path)
            val integer = (decl != null && "integer" == AJs.get(decl, "type")) || (AJs.isFin(cur) && AJs.num(cur)!! == Math.rint(AJs.num(cur)!!))
            val ints = ArrayList<Double>()
            if (integer) for (x in t) { ints.add(x - 1); ints.add(x + 1) }
            val all = ArrayList<Double>(nums)
            all.addAll(ints)
            val numeric = ArrayList<Double>()
            val hasMin = decl != null && AJs.has(decl, "min")
            val hasMax = decl != null && AJs.has(decl, "max")
            for (v in distinctNums(all)) {
                if ((!hasMin || v >= AJs.toNum(AJs.get(decl, "min"))) && (!hasMax || v <= AJs.toNum(AJs.get(decl, "max")))) numeric.add(v)
            }
            val curN = if (AJs.isNum(cur)) AJs.num(cur)!! else 0.0
            numeric.sortWith(Comparator { a, b ->
                val d = Math.abs(a - curN) - Math.abs(b - curN)
                if (d != 0.0 && !d.isNaN()) {
                    if (d < 0) -1 else 1
                } else {
                    val e = a - b
                    if (e < 0) -1 else if (e > 0) 1 else 0
                }
            })
            val strs = ArrayList<String>()
            for (v in pool) if (v is String && !v.startsWith("\u0000") && !strs.contains(v)) strs.add(v)
            val order = ArrayList<Any?>()
            for (v in numeric) order.add(v)
            order.addAll(strs)
            for (v0 in order) {
                val v: Any? = if (v0 is Double) AJs.n(v0) else v0
                if (hasCur && AJs.strictEq(v, cur)) continue
                val a = withParam(act, params, name, v)
                val d = reaches(a)
                if (d != null) {
                    val extra = if (AJs.isNum(v) && AJs.isNum(cur)) Math.min(1.0, Math.abs(AJs.num(v)!! - AJs.num(cur)!!) / (Math.abs(AJs.num(cur)!!) + 1)) else 0.5
                    val repair = AJs.obj("kind", "set_param", "param", name)
                    if (hasCur) repair["from"] = cur
                    repair["to"] = v
                    cands.add(Cand(repair, 2 + extra, d, a))
                    break // the pool is ordered nearest first
                }
            }
        }

        // 2b. when no single edit works, the cheapest PAIR of edits
        if (!finish && cands.isEmpty()) {
            val dimValues = ArrayList<List<Any?>>()
            val dimCost = ArrayList<Double>()
            val make = ArrayList<(Map<String, Any?>, Any?) -> Map<String, Any?>>()
            val step = ArrayList<(Any?) -> Map<String, Any?>>()
            for (name in names) {
                val path = "action.params.$name"
                val decl = AJs.get(AJs.get(shape, "params"), name)
                var field: Enumerate.FieldProbe? = null
                for (f in pr.fields) if (f.path == path) { field = f; break }
                val vals = ArrayList<Any?>()
                val src = ArrayList<Any?>()
                if (field != null) src.addAll(field.values)
                if (decl != null && AJs.get(decl, "values") is List<*>) src.addAll(AJs.list(AJs.get(decl, "values")))
                for (v in src) {
                    val ok = if (v is String) !v.startsWith("\u0000") else v !== Enumerate.ABSENT && AJs.isNum(v)
                    if (ok && !AJs.strictEq(v, params[name])) vals.add(v)
                }
                val dv = distinct(vals)
                dimValues.add(if (dv.size > 6) ArrayList(dv.subList(0, 6)) else dv)
                dimCost.add(2.0)
                make.add { a, v -> withParam(a, if (a["params"] is Map<*, *>) AJs.map(a["params"]) else LinkedHashMap(), name, v) }
                step.add { v ->
                    val s = AJs.obj("kind", "set_param", "param", name)
                    if (params.containsKey(name)) s["from"] = params[name]
                    s["to"] = v
                    s
                }
            }
            val resVals = ArrayList<Any?>()
            for (x in pr.resources) if (!(x as String).startsWith("\u0000") && !AJs.strictEq(x, AJs.get(act, "resource"))) resVals.add(x)
            dimValues.add(if (resVals.size > 6) ArrayList(resVals.subList(0, 6)) else resVals)
            dimCost.add(3.0)
            make.add { a, v -> val c = AJs.copy(a); c["resource"] = v; c }
            step.add { v -> AJs.obj("kind", "set_resource", "from", AJs.get(act, "resource"), "to", v) }
            for (i in dimValues.indices) {
                for (j in i + 1 until dimValues.size) {
                    for (x in dimValues[i]) {
                        for (y in dimValues[j]) {
                            val a = make[j](make[i](act, x), y)
                            val d = reaches(a)
                            if (d != null) cands.add(Cand(AJs.obj("kind", "combine", "steps", AJs.arr(step[i](x), step[j](y))), dimCost[i] + dimCost[j], d, a))
                        }
                    }
                }
            }
        }

        // 3. another allowed resource
        if (!finish) {
            for (r in pr.resources) {
                if ((r as String).startsWith("\u0000") || AJs.strictEq(r, AJs.get(act, "resource"))) continue
                val a = AJs.copy(act)
                a["resource"] = r
                val d = reaches(a)
                if (d != null) cands.add(Cand(AJs.obj("kind", "set_resource", "from", AJs.get(act, "resource"), "to", r), 3.0, d, a))
            }
        }

        // 4. a named fact that is missing: a subject or env field the policy reads
        if (!finish) {
            for (f in pr.fields) {
                if (!f.path.startsWith("subject.") && !f.path.startsWith("env.")) continue
                val segs = f.path.split(".")
                val root = segs[0]
                val rest = ArrayList(segs.subList(1, segs.size))
                for (v in f.values) {
                    if (v === Enumerate.ABSENT) continue
                    val sub = AJs.copy(AJs.get(act, root))
                    setPath(sub, rest, v)
                    val a = AJs.copy(act)
                    a[root] = sub
                    val before = reaches(act)
                    val d = reaches(a)
                    if (d != null && before == null) {
                        cands.add(Cand(AJs.obj("kind", "obtain_fact", "path", f.path, "value", v), 4.0, d, a))
                        break
                    }
                }
            }
        }

        // 5. split (opt-in, and only when nothing meters the total)
        if (AJs.get(o, "allowSplit") == true && !meters(model)) {
            for (name in names) {
                val cur = params[name]
                if (!AJs.isNum(cur)) continue
                var part: Double? = null
                for (c in cands) {
                    if ("set_param" == c.repair["kind"] && name == c.repair["param"] && AJs.isNum(c.repair["to"])) { part = AJs.num(c.repair["to"]); break }
                }
                val cn = AJs.num(cur)!!
                if (part == null || part <= 0 || part >= cn) continue
                val n = Math.ceil(cn / part)
                if (n > 8) continue
                val parts = ArrayList<Any?>()
                var allOk = true
                var i = 0
                while (i < n) {
                    val v: Any? = AJs.n(if (i < n - 1) part else cn - part * (n - 1))
                    parts.add(AJs.obj(name, v))
                    val merged = LinkedHashMap<String, Any?>(params)
                    merged[name] = v
                    val a = AJs.copy(act)
                    a["params"] = merged
                    if (reaches(a) == null) allOk = false
                    i++
                }
                if (allOk) cands.add(Cand(AJs.obj("kind", "split", "param", name, "parts", parts), 3 + n, want as String, act))
            }
        }

        cands.sortWith(Comparator { a, b -> if (java.lang.Double.compare(a.cost, b.cost) < 0) -1 else if (a.cost == b.cost) 0 else 1 })
        val maxC = if (AJs.get(o, "maxCandidates") == null) 8.0 else AJs.toNum(AJs.get(o, "maxCandidates"))
        val top: List<Cand> = if (cands.size > maxC) ArrayList(cands.subList(0, Math.max(0.0, maxC).toInt())) else cands
        res["repairExists"] = top.isNotEmpty()
        val redO = AJs.get(o, "redact")
        val redact = if (redO == null) "critical" else if (redO is String) redO else ""
        val redacted = booleanArrayOf(false)
        val hide = { c: Cand ->
            if (redact == "none" || "set_param" != c.repair["kind"]) {
                c.toJson()
            } else {
                val sens = AJs.get(AJs.get(AJs.get(shapeF, "params"), c.repair["param"] as String), "sensitivity")
                if (redact == "critical" && "critical" != sens) {
                    c.toJson()
                } else {
                    redacted[0] = true
                    AJs.obj("repair", AJs.obj("kind", "set_param", "param", c.repair["param"], "redacted", true), "cost", AJs.n(c.cost), "decision", c.decision, "action", AJs.copy(act))
                }
            }
        }
        if (redact == "all") redacted[0] = true
        else {
            val reps = ArrayList<Any?>()
            for (c in top) reps.add(hide(c))
            res["repairs"] = reps
        }
        var free: Cand? = null
        for (c in top) if ("allow" == c.decision && "split" != c.repair["kind"]) { free = c; break }
        if (free != null && current == "escalate") res["humanFree"] = hide(free)
        if (redacted[0]) res["redacted"] = true
        if (current == "escalate" || top.isEmpty()) {
            val ask = AJs.obj()
            AJs.putIf(ask, "verb", act, "verb")
            AJs.putIf(ask, "resource", act, "resource")
            ask["params"] = LinkedHashMap<String, Any?>(params)
            ask["kind"] = if (current == "escalate") "approval" else "access-request"
            ask["policyDigest"] = policyDigest
            res["humanAsk"] = ask
        }
        return res
    }
}
