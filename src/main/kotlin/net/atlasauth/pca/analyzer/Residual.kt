package net.atlasauth.pca.analyzer

import net.atlasauth.pca.analyzer.Enumerate.PolicyModel
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Predicates

/**
 * PARTIAL EVALUATION, RESIDUAL POLICIES AND "WHAT MAY I DO?" DISCOVERY. `residual(policy, known, {unknown})` specialises the policy
 * to what is known about a request and leaves the unknown parameters symbolic; the residual is itself a policy, evaluated by the same
 * evaluator, and is exact for every completion of the unknowns. Only constants are folded, with the evaluator's own three-valued rules; a
 * veto that reads an unknown field stays and keeps firing. Everything here is advisory and outside the verifier.
 */
object Residual {
    private const val UNKNOWN_VERB = "\u0000unknown-verb\u0000"
    private const val UNKNOWN_RESOURCE = "\u0000unknown-resource\u0000"

    private fun isUnknownPath(path: Any?, unknown: List<String>): Boolean {
        if (path !is String) return false
        for (u in unknown) if (path == u || path.startsWith("$u.") || u.startsWith("$path.")) return true
        return false
    }

    /** A partially evaluated condition: a constant (with its source condition) or a symbolic remainder. */
    private class PE(val v: String?, val src: Any?, val c: Any?) {
        fun isConst(): Boolean = v != null
        fun cond(): Any? = if (isConst()) src else c
    }

    private fun cst(v: String, src: Any?) = PE(v, src, null)
    private fun sym(c: Any?) = PE(null, null, c)

    private fun triName(t: Predicates.Tri): String = if (t == Predicates.Tri.TRUE) "true" else if (t == Predicates.Tri.FALSE) "false" else "unknown"

    private fun pe(c: Any?, ctx: Map<String, Any?>, unk: List<String>): PE {
        if (!(c is Map<*, *> || c is List<*>)) return cst("unknown", c)
        if (Field.isGroup(c)) {
            if (AJs.has(c, "all_of")) {
                val xs = AJs.get(c, "all_of")
                if (xs !is List<*> || xs.isEmpty()) return cst("unknown", c)
                val rs = ArrayList<PE>()
                for (x in xs) rs.add(pe(x, ctx, unk))
                for (r in rs) if (r.isConst() && r.v == "false") return cst("false", c)
                val kept = ArrayList<PE>()
                for (r in rs) if (!(r.isConst() && r.v == "true")) kept.add(r)
                if (kept.isEmpty()) return cst("true", c)
                if (allConst(kept)) return cst("unknown", c)
                val cs = ArrayList<Any?>()
                for (r in kept) cs.add(r.cond())
                return sym(if (cs.size == 1) cs[0] else AJs.obj("all_of", cs))
            }
            if (AJs.has(c, "any_of")) {
                val xs = AJs.get(c, "any_of")
                if (xs !is List<*> || xs.isEmpty()) return cst("unknown", c)
                val rs = ArrayList<PE>()
                for (x in xs) rs.add(pe(x, ctx, unk))
                for (r in rs) if (r.isConst() && r.v == "true") return cst("true", c)
                val kept = ArrayList<PE>()
                for (r in rs) if (!(r.isConst() && r.v == "false")) kept.add(r)
                if (kept.isEmpty()) return cst("false", c)
                if (allConst(kept)) return cst("unknown", c)
                val cs = ArrayList<Any?>()
                for (r in kept) cs.add(r.cond())
                return sym(if (cs.size == 1) cs[0] else AJs.obj("any_of", cs))
            }
            val r = pe(AJs.get(c, "not"), ctx, unk)
            if (!r.isConst()) return sym(AJs.obj("not", r.c))
            return cst(if (r.v == "true") "false" else if (r.v == "false") "true" else "unknown", c)
        }
        if (Field.isLeaf(c) && (isUnknownPath(AJs.get(c, "field"), unk) || isUnknownPath(AJs.get(c, "ref"), unk) || isUnknownPath(AJs.get(c, "collection"), unk))) return sym(c)
        return cst(triName(Predicates.evaluateConditionTri(c, ctx)), c)
    }

    private fun allConst(xs: List<PE>): Boolean { for (r in xs) if (!r.isConst()) return false; return true }

    /** The AND of a `where` list: a constant ("true" / "false" / "unknown") or the symbolic remainder. */
    private class PeAll(val v: String?, val cs: List<Any?>?)

    private fun peAll(where: Any?, present: Boolean, ctx: Map<String, Any?>, unk: List<String>): PeAll {
        if (!present) return PeAll("true", null)
        if (where !is List<*>) return PeAll("unknown", null)
        val rs = ArrayList<PE>()
        for (w in where) rs.add(pe(w, ctx, unk))
        for (r in rs) if (r.isConst() && r.v == "false") return PeAll("false", null)
        val kept = ArrayList<PE>()
        for (r in rs) if (!(r.isConst() && r.v == "true")) kept.add(r)
        if (kept.isEmpty()) return PeAll("true", null)
        if (allConst(kept)) return PeAll("unknown", null)
        val cs = ArrayList<Any?>()
        for (r in kept) cs.add(r.cond())
        return PeAll(null, cs)
    }

    private fun contextOf(k: Any?): Map<String, Any?> {
        val v = AJs.get(k, "verb")
        val r = AJs.get(k, "resource")
        val action = AJs.obj("verb", v ?: UNKNOWN_VERB, "resource", r ?: UNKNOWN_RESOURCE, "params", AJs.copy(AJs.get(k, "params")))
        if (AJs.has(k, "reversibilityClass")) action["reversibility_class"] = AJs.get(k, "reversibilityClass")
        return AJs.obj("action", action, "subject", AJs.copy(AJs.get(k, "subject")), "env", AJs.copy(AJs.get(k, "env")))
    }

    /** hashCanonical of a policy: the digest a PCActn cites to say which policy it was planned against. */
    fun policyDigestOf(model: PolicyModel): String {
        val meet = ArrayList<Any?>()
        for (m in model.meets) meet.add(policyDigestOf(m))
        return Pca.hashCanonical(AJs.obj("predicates", model.predicates, "caveats", model.caveats, "vetoes", model.vetoes, "tighten", model.tighten, "meet", meet))
    }

    private fun flatten(m: PolicyModel, out: MutableList<PolicyModel>) {
        out.add(m)
        for (x in m.meets) flatten(x, out)
    }

    private fun verbResource(verb: Any?, hasVerb: Boolean, resource: Any?, hasResource: Boolean): Map<String, Any?> {
        val m = AJs.obj()
        if (hasVerb) m["verb"] = verb
        if (hasResource) m["resource"] = resource
        return m
    }

    private fun residualPart(part: PolicyModel, ctx: Map<String, Any?>, unk: List<String>, verbKnown: Boolean, resKnown: Boolean): Map<String, Any?> {
        val predicates = ArrayList<Any?>()
        for (p in part.predicates) {
            if (!(p is Map<*, *> || p is List<*>)) continue
            if (verbKnown && !Predicates.predicateMatches(verbResource(AJs.get(p, "verb"), AJs.has(p, "verb"), "*", true), ctx)) continue
            if (resKnown && !Predicates.predicateMatches(verbResource("*", true, AJs.get(p, "resource"), AJs.has(p, "resource")), ctx)) continue
            val w = peAll(AJs.get(p, "where"), AJs.has(p, "where"), ctx, unk)
            if (w.v != null && w.v != "true") continue // false and unknown both fail closed for a permit
            val np = AJs.obj()
            if (verbKnown) np["verb"] = "*" else AJs.putIf(np, "verb", p, "verb")
            if (!resKnown && AJs.has(p, "resource")) np["resource"] = AJs.get(p, "resource")
            if (w.cs != null) np["where"] = w.cs
            predicates.add(np)
        }
        val vetoes = ArrayList<Any?>()
        for (v in part.vetoes) {
            val r = peVeto(v, ctx, unk, verbKnown, resKnown)
            if (r != null) vetoes.add(r)
        }
        val tighten = ArrayList<Any?>()
        for (t in part.tighten) {
            val r = pe(AJs.get(t, "when"), ctx, unk)
            if (r.isConst() && r.v == "false") continue // a veto-polarity rule that cleanly cannot hold
            val nt = AJs.copy(t)
            nt["when"] = if (!r.isConst()) r.c else AJs.get(t, "when")
            tighten.add(nt)
        }
        return AJs.obj("predicates", predicates, "caveats", part.caveats, "vetoes", vetoes, "tighten", tighten)
    }

    private fun peVeto(v: Any?, ctx: Map<String, Any?>, unk: List<String>, verbKnown: Boolean, resKnown: Boolean): Map<String, Any?>? {
        val `when` = AJs.req(AJs.get(v, "when"))
        if (verbKnown && !Predicates.predicateMatches(verbResource(AJs.get(`when`, "verb"), AJs.has(`when`, "verb"), "*", true), ctx)) return null
        if (resKnown && AJs.has(`when`, "resource") && !Predicates.predicateMatches(verbResource("*", true, AJs.get(`when`, "resource"), true), ctx)) return null
        val w = peAll(AJs.get(`when`, "where"), AJs.has(`when`, "where"), ctx, unk)
        // veto polarity: a clean false removes the veto; true and unknown mean it applies
        if (w.v != null && w.v == "false") return null
        val nw = AJs.obj()
        if (verbKnown) nw["verb"] = "*" else AJs.putIf(nw, "verb", `when`, "verb")
        if (!resKnown && AJs.has(`when`, "resource")) nw["resource"] = AJs.get(`when`, "resource")
        if (w.cs != null) nw["where"] = w.cs
        val out = AJs.obj()
        AJs.putIf(out, "id", v, "id")
        AJs.putIf(out, "kind", v, "kind")
        out["when"] = nw
        val over = AJs.get(v, "over")
        if (AJs.truthy(over)) {
            if (isUnknownPath(AJs.get(over, "path"), unk)) out["over"] = over
            else {
                val r = Predicates.resolvePath(ctx, AJs.get(over, "path"))
                val thr = if (AJs.has(over, "threshold")) AJs.toNum(AJs.get(over, "threshold")) else Double.NaN
                var isOver = !r.found || !AJs.isFin(r.value)
                if (!isOver) {
                    val rv: Double = AJs.num(r.value)!!
                    isOver = rv < 0 || rv > thr
                }
                if (!isOver) return null
            }
        }
        val unless = AJs.get(v, "unless")
        if (AJs.truthy(unless) && "approval" == AJs.get(v, "kind")) out["unless"] = unless // the evidence of approval: carried, never used to drop the veto
        else if (AJs.truthy(unless)) {
            val u = peAll(unless, true, ctx, unk)
            if (u.cs != null) out["unless"] = u.cs
            else if ("true" == u.v) return null // the exception certainly holds: the veto never applies
            // an exception that certainly fails (false / unknown) leaves the veto unconditional
        }
        return out
    }

    /**
     * Specialise `policy` to `known` ({verb, resource, params, subject, env, reversibilityClass}); everything under
     * `opts.unknown` (default `["action.params"]`) stays symbolic. Returns {decision: never | always | conditional, reason?,
     * policy, policyDigest}.
     */
    fun residual(policy: Any?, known: Map<String, Any?>?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val model = Enumerate.toModel(policy)
        val digest = policyDigestOf(model)
        val verbKnown = AJs.has(known, "verb")
        val resKnown = AJs.has(known, "resource") && AJs.get(opts, "resourceUnknown") != true
        val unk = ArrayList<String>()
        val uo = AJs.get(opts, "unknown")
        if (uo == null) unk.add("action.params")
        else for (u in AJs.list(uo)) {
            if (u !is String) throw IllegalArgumentException("unknown path is not a string")
            unk.add(u)
        }
        if (!verbKnown) unk.add("action.verb")
        if (!resKnown) unk.add("action.resource")
        val ctx = contextOf(known)
        if (!model.caveatSat) return never("caveats unsatisfiable: " + (model.caveatReason ?: "unknown"), digest)
        val cap = model.revCap
        if (AJs.has(known, "reversibilityClass") && cap != null) {
            val rc = AJs.get(known, "reversibilityClass")
            val idx = if (rc is String) Analyzer.REVERSIBILITY_ORDER.indexOf(rc) else -1
            if (idx < 0 || idx > cap) return never("reversibility class exceeds the caveat cap", digest)
        }
        val flat = ArrayList<PolicyModel>()
        flatten(model, flat)
        val parts = ArrayList<Map<String, Any?>>()
        for (m in flat) parts.add(residualPart(m, ctx, unk, verbKnown, resKnown))
        val policyOut = AJs.copy(parts[0])
        if (parts.size > 1) policyOut["meet"] = ArrayList<Any?>(parts.subList(1, parts.size))
        val res = AJs.obj("decision", "conditional", "policy", policyOut, "policyDigest", digest)
        for (p in parts) if (AJs.list(p["predicates"]).isEmpty()) return never("no permit survives the known facts", digest)
        for (p in parts) {
            for (v in AJs.list(p["vetoes"])) {
                val w = AJs.get(v, "when")
                val noWhere = !AJs.has(w, "where") || (AJs.get(w, "where") is List<*> && (AJs.get(w, "where") as List<*>).isEmpty())
                val noRes = !AJs.has(w, "resource") || "*" == AJs.get(w, "resource")
                if ("deny" == AJs.get(v, "kind") && noRes && noWhere && !AJs.has(v, "unless") && !AJs.has(v, "over")) {
                    return never("veto " + CaveatAnalysis.jsString(AJs.get(v, "id"), AJs.has(v, "id")) + " applies to every completion", digest)
                }
            }
        }
        var always = true
        for (p in parts) {
            var anyOpen = false
            for (x in AJs.list(p["predicates"])) if (!AJs.has(x, "where")) anyOpen = true
            if (!(anyOpen && AJs.list(p["vetoes"]).isEmpty() && AJs.list(p["tighten"]).isEmpty())) { always = false; break }
        }
        if (always) res["decision"] = "always"
        return res
    }

    private fun never(reason: String, digest: String): Map<String, Any?> {
        val empty = AJs.obj("predicates", ArrayList<Any?>(), "caveats", ArrayList<Any?>(), "vetoes", ArrayList<Any?>(), "tighten", ArrayList<Any?>())
        return AJs.obj("decision", "never", "reason", reason, "policy", empty, "policyDigest", digest)
    }

    /** The residual as a policy the analyzer and the real evaluator both understand. */
    fun residualPolicy(r: Map<String, Any?>): Map<String, Any?> {
        val own = AJs.copy(AJs.get(r, "policy"))
        val meet = own.remove("meet")
        if (AJs.truthy(meet)) {
            val ms = ArrayList<Any?>()
            for (m in AJs.list(meet)) ms.add(AJs.copy(m))
            own["meet"] = ms
        }
        return own
    }

    /** Ternary decision of a residual once the unknown fields are bound: `ctx` is {action: {verb, resource, params?, reversibility_class?}, subject?, env?}. */
    fun evaluateResidual(r: Map<String, Any?>, ctx: Map<String, Any?>): String {
        if ("never" == AJs.get(r, "decision")) return "deny"
        val action = AJs.req(AJs.get(ctx, "action"))
        val a = AJs.obj()
        AJs.putIf(a, "verb", action, "verb")
        AJs.putIf(a, "resource", action, "resource")
        if (AJs.truthy(AJs.get(action, "params"))) a["params"] = AJs.get(action, "params")
        if (AJs.truthy(AJs.get(ctx, "subject"))) a["subject"] = AJs.get(ctx, "subject")
        if (AJs.truthy(AJs.get(ctx, "env"))) a["env"] = AJs.get(ctx, "env")
        if (AJs.truthy(AJs.get(action, "reversibility_class"))) a["reversibilityClass"] = AJs.get(action, "reversibility_class")
        return Enumerate.decideAction(Enumerate.toModel(residualPolicy(r)), a)
    }

    // ---- "what may I do?" ----

    /** A numeric range; null bounds are open (undefined). */
    private class NumRange(var lo: Double?, var hi: Double?, var loInc: Boolean, var hiInc: Boolean) {
        fun copy() = NumRange(lo, hi, loInc, hiInc)
        fun toJson(): Map<String, Any?> {
            val m = AJs.obj()
            if (lo != null) m["lo"] = AJs.n(lo!!)
            if (hi != null) m["hi"] = AJs.n(hi!!)
            if (loInc) m["loInclusive"] = true
            if (hiInc) m["hiInclusive"] = true
            return m
        }
    }

    private fun orD(d: Double?, dflt: Double): Double = d ?: dflt

    private fun mergeRanges(rs: List<NumRange>): List<NumRange> {
        val sorted = ArrayList(rs)
        sorted.sortWith(Comparator { a, b ->
            val d = orD(a.lo, Double.NEGATIVE_INFINITY) - orD(b.lo, Double.NEGATIVE_INFINITY)
            if (!d.isNaN() && d != 0.0) {
                if (d < 0) -1 else 1
            } else {
                val x = (if (b.loInc) 1 else 0) - (if (a.loInc) 1 else 0)
                if (x < 0) -1 else if (x > 0) 1 else 0
            }
        })
        val out = ArrayList<NumRange>()
        for (r in sorted) {
            val last = if (out.isEmpty()) null else out[out.size - 1]
            val lastHi = if (last == null) 0.0 else orD(last.hi, Double.POSITIVE_INFINITY)
            val rLo = orD(r.lo, Double.NEGATIVE_INFINITY)
            if (last != null && lastHi >= rLo && !(lastHi == rLo && !last.hiInc && !r.loInc)) {
                val rHi = orD(r.hi, Double.POSITIVE_INFINITY)
                if (rHi > lastHi || (rHi == lastHi && r.hiInc)) {
                    last.hi = r.hi // null when r.hi is undefined
                    last.hiInc = r.hiInc
                }
            } else out.add(r.copy())
        }
        return out
    }

    private fun cellRange(value: Double, t: List<Double>): NumRange {
        if (t.contains(if (value == 0.0) 0.0 else value)) return NumRange(value, value, true, true)
        var below: Double? = null
        var above: Double? = null
        for (i in t.indices.reversed()) if (t[i] < value) { below = t[i]; break }
        for (x in t) if (x > value) { above = x; break }
        return NumRange(below, above, false, false)
    }

    private class Seen(val value: Any?) {
        var allow = false
        var escalate = false
    }

    private val ABSENT_VALUE = Any()

    /**
     * Per verb shape ({verb, params: {name: {type?, values?, min?, max?, ...}}}): is it autonomous, approval-only or denied for the known
     * principal, and which parameter values are still allowed. Enumerates the grid of the residual policy (exact on the decided fragment;
     * otherwise `approximate`). Options: remaining, missingDischarges, maxCombinations.
     */
    fun whatMayIDo(policy: Any?, verbs: List<Any?>, known: Map<String, Any?>?, o: Map<String, Any?>? = null): List<Any?> {
        val out = ArrayList<Any?>()
        val max = if (AJs.isNum(AJs.get(o, "maxCombinations"))) AJs.num(AJs.get(o, "maxCombinations"))!! else Enumerate.DEFAULT_MAX_COMBINATIONS
        for (shape in verbs) {
            val verb = AJs.get(AJs.req(shape), "verb")
            val k2 = AJs.copy(known)
            k2["verb"] = verb
            val res = residual(policy, k2, null)
            val env = AJs.obj("verb", verb, "status", "denied", "params", LinkedHashMap<String, Any?>(),
                "resources", AJs.obj("autonomous", ArrayList<Any?>(), "withApproval", ArrayList<Any?>(), "other", false),
                "policyDigest", res["policyDigest"], "advisory", true)
            if (AJs.truthy(AJs.get(o, "remaining"))) env["remaining"] = AJs.copy(AJs.get(o, "remaining"))
            if (AJs.truthy(AJs.get(o, "missingDischarges"))) env["missingDischarges"] = ArrayList<Any?>(AJs.list(AJs.get(o, "missingDischarges")))
            if ("never" == res["decision"]) {
                env["reason"] = res["reason"]
                out.add(env)
                continue
            }
            val rp = Enumerate.toModel(residualPolicy(res))
            val sparams = AJs.copy(AJs.get(shape, "params"))
            val declared = AJs.keys(sparams)
            val input = ProbeInputs()
            input.predicateSets.add(Enumerate.probeSet(rp))
            for (name in declared) {
                val d = sparams[name]
                val path = "action.params.$name"
                if (AJs.has(d, "values")) input.extraFieldConditions.add(arrayOf(path, AJs.obj("field", path, "op", "in", "value", AJs.get(d, "values"))))
            }
            for (name in declared) {
                val d = sparams[name]
                val path = "action.params.$name"
                if (AJs.has(d, "min")) input.extraFieldConditions.add(arrayOf(path, AJs.obj("field", path, "op", "gte", "value", AJs.get(d, "min"))))
                if (AJs.has(d, "max")) input.extraFieldConditions.add(arrayOf(path, AJs.obj("field", path, "op", "lte", "value", AJs.get(d, "max"))))
            }
            input.varyReversibility = rp.revCap != null
            val pr = Enumerate.collectProbes(input)
            pr.verbs = ArrayList()
            pr.verbs.add(verb)
            if (Enumerate.productSize(pr) > max) {
                env["status"] = "needs-approval"
                env["approximate"] = true
                env["reason"] = "representative grid exceeded the bound; no domain is claimed"
                out.add(env)
                continue
            }
            if (AJs.has(known, "resource")) { pr.resources = ArrayList(); pr.resources.add(AJs.get(known, "resource")) }
            val seen = LinkedHashMap<String, LinkedHashMap<String, Seen>>()
            val resSeen = LinkedHashMap<String, Seen>()
            val flags = BooleanArray(3) // anyAllow, anyEscalate, freshResAllow
            Enumerate.forEachRep(pr) { rep ->
                val d = Enumerate.decide(rp, rep)
                if (d == "deny") {
                    false
                } else {
                    if (d == "allow") flags[0] = true else flags[1] = true
                    val act = Enumerate.repToAction(rep)
                    val ap = AJs.copy(act["params"])
                    for (name in declared) {
                        val m = seen.getOrPut(name) { LinkedHashMap() }
                        val present = ap.containsKey(name)
                        val key = if (present) AJs.stringify(ap[name]) else "\u0000absent"
                        val cur = m.getOrPut(key) { Seen(if (present) ap[name] else ABSENT_VALUE) }
                        if (d == "allow") cur.allow = true else cur.escalate = true
                    }
                    val res0 = act["resource"] as String
                    val rr = resSeen.getOrPut(res0) { Seen(null) }
                    if (d == "allow") rr.allow = true else rr.escalate = true
                    if (res0.startsWith("\u0000")) flags[2] = true
                    false
                }
            }
            env["status"] = if (flags[0]) "autonomous" else if (flags[1]) "needs-approval" else "denied"
            val penv = AJs.map(env["params"])
            for (name in declared) {
                val decl = sparams[name]
                val path = "action.params.$name"
                val t = Exposure.thresholds(rp, path)
                val m: Map<String, Seen> = seen[name] ?: LinkedHashMap()
                val vals = ArrayList(m.values)
                val dmin = AJs.get(decl, "min")
                val dmax = AJs.get(decl, "max")
                val hasMin = AJs.has(decl, "min")
                val hasMax = AJs.has(decl, "max")
                val nums = ArrayList<Seen>()
                val strs = ArrayList<Seen>()
                for (x in vals) {
                    if (AJs.isNum(x.value) && (!hasMin || AJs.num(x.value)!! >= AJs.toNum(dmin)) && (!hasMax || AJs.num(x.value)!! <= AJs.toNum(dmax))) nums.add(x)
                    if (x.value is String) strs.add(x)
                }
                if ("integer" == AJs.get(decl, "type") || nums.isNotEmpty()) {
                    penv[name] = AJs.obj("kind", "numeric",
                        "autonomous", ranges(nums, t, hasMin, dmin, hasMax, dmax) { x -> x.allow },
                        "withApproval", ranges(nums, t, hasMin, dmin, hasMax, dmax) { x -> x.escalate && !x.allow })
                } else if (AJs.has(decl, "values") || strs.isNotEmpty()) {
                    var fresh: Seen? = null
                    for (x in strs) if ((x.value as String).startsWith("\u0000")) { fresh = x; break }
                    val noValues = !AJs.has(decl, "values")
                    penv[name] = AJs.obj("kind", "enum",
                        "autonomous", pickList(strs) { x -> x.allow },
                        "withApproval", pickList(strs) { x -> x.escalate && !x.allow },
                        "otherAutonomous", noValues && fresh != null && fresh.allow,
                        "otherWithApproval", noValues && fresh != null && fresh.escalate && !fresh.allow)
                } else penv[name] = AJs.obj("kind", "unconstrained")
            }
            val auto = ArrayList<String>()
            val appr = ArrayList<String>()
            for ((k, v) in resSeen) {
                if (k.startsWith("\u0000")) continue
                if (v.allow) auto.add(k)
                if (v.escalate && !v.allow) appr.add(k)
            }
            auto.sort()
            appr.sort()
            env["resources"] = AJs.obj("autonomous", ArrayList<Any?>(auto), "withApproval", ArrayList<Any?>(appr), "other", flags[2])
            if (rp.undecidable.isNotEmpty()) {
                env["approximate"] = true
                env["reason"] = "over-approximated (" + rp.undecidable.joinToString("; ") + ")"
            }
            out.add(env)
        }
        return out
    }

    private fun pickList(strs: List<Seen>, f: (Seen) -> Boolean): List<Any?> {
        val l = ArrayList<String>()
        for (x in strs) if (f(x) && !(x.value as String).startsWith("\u0000")) l.add(x.value as String)
        l.sort()
        return ArrayList<Any?>(l)
    }

    private fun ranges(nums: List<Seen>, t: List<Double>, hasLo: Boolean, lo: Any?, hasHi: Boolean, hi: Any?, pick: (Seen) -> Boolean): List<Any?> {
        val rs = ArrayList<NumRange>()
        for (x in nums) {
            if (!pick(x)) continue
            val r = cellRange(AJs.num(x.value)!!, t)
            val rlo = r.lo
            if (hasLo && (rlo == null || rlo < AJs.toNum(lo))) { r.lo = AJs.toNum(lo); r.loInc = true }
            val rhi = r.hi
            if (hasHi && (rhi == null || rhi > AJs.toNum(hi))) { r.hi = AJs.toNum(hi); r.hiInc = true }
            rs.add(r)
        }
        val out = ArrayList<Any?>()
        for (r in mergeRanges(rs)) out.add(r.toJson())
        return out
    }
}
