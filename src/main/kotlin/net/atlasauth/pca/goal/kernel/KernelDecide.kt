package net.atlasauth.pca.goal.kernel

import java.math.BigInteger

/** The decision function D_P of the lowered policy, the witness of an Allow and the separate witness checker (GoalIr / GoalCompile / GoalWitness). */
internal object KDecide {
    // decisions 0 Deny, 1 Escalate, 2 Allow; Kleene truth 0 false, 1 unknown, 2 true (meet / join are min / max)
    private const val DENY = 0
    private const val ESCALATE = 1
    private const val ALLOW = 2
    private const val KF = 0
    private const val KU = 1
    private const val KT = 2

    private fun b2t(b: Boolean) = if (b) KT else KF

    private fun eqT(x: GV, y: GV): Int = when (x) {
        is GV.VQ -> if (y is GV.VQ && x.q.u == y.q.u) b2t(x.q.n == y.q.n) else KU
        is GV.VS -> if (y is GV.VS) b2t(x.s == y.s) else KU
        is GV.VSet -> KU
    }

    private fun ltT(x: GV, y: GV): Int = if (x is GV.VQ && y is GV.VQ && x.q.u == y.q.u) b2t(x.q.n < y.q.n) else KU

    private fun inT(x: GV, items: List<GAtom>): Int {
        var r = KF
        for (a in items) r = Math.max(r, eqT(x, KTypes.atomV(a)))
        return r
    }

    private fun cmpT(op: GOp, x: GV?, y: GV?): Int {
        if (x == null || y == null) return KU
        return when (op) {
            GOp.Eq -> eqT(x, y)
            GOp.Ne -> 2 - eqT(x, y)
            GOp.Lt -> ltT(x, y)
            GOp.Gte -> 2 - ltT(x, y)
            GOp.Gt -> ltT(y, x)
            GOp.Lte -> 2 - ltT(y, x)
            GOp.In -> if (y is GV.VSet) inT(x, y.items) else KU
            GOp.Nin -> 2 - (if (y is GV.VSet) inT(x, y.items) else KU)
        }
    }

    private fun evalT(t: GTerm, a: GAct, h: GHist): GV? = when (t) {
        is GTerm.Param -> a.params[t.path]
        is GTerm.Lit -> t.v
        is GTerm.HistAgg -> h.aggs[t.bid]?.let { GV.VQ(it) }
    }

    private fun evalN(c: NC, a: GAct, h: GHist): Int = when (c) {
        NC.NTrue -> KT
        NC.NFalse -> KF
        is NC.NAtom -> cmpT(c.op, evalT(c.l, a, h), evalT(c.r, a, h))
        is NC.NAnd -> Math.min(evalN(c.a, a, h), evalN(c.b, a, h))
        is NC.NOr -> Math.max(evalN(c.a, a, h), evalN(c.b, a, h))
    }

    private fun resOk(p: ResPat, r: String) = p is ResPat.PStar || (p is ResPat.PSet && r in p.ids)

    private fun appliesL(s: LSel, gid: String, verb: String) = gid in s.gids || verb in s.verbs

    private fun inScope(sc: GScope, a: GAct, x: GAct): Boolean = when (sc) {
        GScope.SSession -> a.sess == x.sess
        GScope.SPrincipal -> a.prin == x.prin
        GScope.SOrg -> a.org == x.org
        is GScope.SFleet -> a.agent in sc.agents && x.agent in sc.agents
    }

    private fun inWindow(w: GWindow, a: GAct, x: GAct): Boolean = when (w) {
        GWindow.WTask, GWindow.WLifetime -> true
        is GWindow.WSliding -> x.t > a.t - w.ms && x.t <= a.t
        // ms > 0: Euclidean division is floor division
        is GWindow.WPeriod -> w.ms > 0 && Math.floorDiv(a.t - w.t0, w.ms) == Math.floorDiv(x.t - w.t0, w.ms)
    }

    /** The admitted actions this bound counts, followed by the candidate itself. */
    private fun selItems(core: BCore, s: LSel, adms: List<GAdm>, a: GAct): List<GAct> {
        val out = ArrayList<GAct>()
        for (m in adms) if (appliesL(s, m.gid, m.act.verb) && inScope(core.scope, a, m.act) && inWindow(core.window, a, m.act)) out.add(m.act)
        out.add(a)
        return out
    }

    /** Numeric values of the value term over the items; null as soon as one is unreadable or of another unit. */
    private fun itemVals(core: BCore, items: List<GAct>, h: GHist): List<Long>? {
        val out = ArrayList<Long>(items.size)
        for (x in items) {
            val v = evalT(core.value, x, h)
            if (v !is GV.VQ || v.q.u != core.cap.u) return null
            out.add(v.q.n)
        }
        return out
    }

    private fun exceeded(core: BCore, items: List<GAct>, h: GHist): Int {
        val cap = core.cap.n
        return when (core.agg) {
            GAgg.Count -> b2t(items.size.toLong() > cap)
            GAgg.Sum -> {
                val xs = itemVals(core, items, h) ?: return KU
                var s = BigInteger.ZERO
                for (x in xs) s = s.add(BigInteger.valueOf(x))
                b2t(s > BigInteger.valueOf(cap))
            }
            GAgg.Max -> {
                val xs = itemVals(core, items, h) ?: return KU
                if (xs.isEmpty()) KU else b2t(xs.maxOrNull()!! > cap)
            }
            GAgg.Distinct -> {
                val vs = HashSet<GV>()
                for (x in items) vs.add(x.params[core.key] ?: return KU)
                b2t(vs.size.toLong() > cap)
            }
        }
    }

    /** The decision a bound imposes on a candidate admitted by a grant it applies to. */
    private fun boundStat(core: BCore, s: LSel, a: GAct, h: GHist): Int {
        val e = exceeded(core, selItems(core, s, h.adms, a), h)
        return if (e == KT) (if (core.onExceed == OnExceed.Deny) DENY else ESCALATE) else if (e == KU) ESCALATE else ALLOW
    }

    private fun validityDec(v: GValidity, dg: GDeleg, a: GAct, h: GHist): Int =
        if (a.t < v.notBefore || a.t > v.notAfter) DENY
        else if (v.maxIdle > 0 && h.last >= 0 && a.t - h.last > v.maxIdle) DENY
        else if (a.depth < 0 || a.depth > dg.maxDepth) DENY
        else ALLOW

    private fun delegOk(dg: GDeleg, gid: String, a: GAct) = a.depth == 0L || gid in dg.mayTouch

    private fun prohOne(p: LProh, a: GAct, h: GHist): Int {
        val m = Math.min(b2t(a.verb in p.verbs), Math.min(b2t(resOk(p.res, a.res)), evalN(p.cond, a, h)))
        return if (m == KT) DENY else if (m == KU) ESCALATE else ALLOW
    }

    private fun prohDec(ps: List<LProh>, a: GAct, h: GHist): Int { var d = ALLOW; for (p in ps) d = Math.min(d, prohOne(p, a, h)); return d }

    private fun escDec(cs: List<NC>, a: GAct, h: GHist): Int {
        var d = ALLOW
        for (c in cs) d = Math.min(d, if (evalN(c, a, h) == KF) ALLOW else ESCALATE)
        return d
    }

    private fun ceilsDec(cs: List<LCeil>, gid: String, a: GAct, h: GHist): Int {
        var d = ALLOW
        for (c in cs) d = Math.min(d, if (appliesL(c.sel, gid, a.verb)) boundStat(c.core, c.sel, a, h) else ALLOW)
        return d
    }

    private fun predMatch(p: LPred, dg: GDeleg, a: GAct, h: GHist): Int =
        Math.min(b2t(a.verb == p.verb && delegOk(dg, p.gid, a)), Math.min(b2t(resOk(p.res, a.res)), evalN(p.cond, a, h)))

    private fun predDec(p: LPred, ceils: List<LCeil>, dg: GDeleg, a: GAct, h: GHist): Int =
        Math.min(predMatch(p, dg, a, h), ceilsDec(ceils, p.gid, a, h))

    private fun predsDec(ps: List<LPred>, ceils: List<LCeil>, dg: GDeleg, a: GAct, h: GHist): Int {
        var d = DENY
        for (p in ps) d = Math.max(d, predDec(p, ceils, dg, a, h))
        return d
    }

    /** D_P: Deny < Escalate < Allow; unknown never yields Allow. */
    fun dp(p: Pol, a: GAct, h: GHist): Int =
        Math.min(validityDec(p.validity, p.deleg, a, h),
            Math.min(prohDec(p.prohs, a, h), Math.min(escDec(p.escs, a, h), predsDec(p.preds, p.ceils, p.deleg, a, h))))

    /** The reference semantics D_G; the compiled policy of the goal itself is proved to decide identically (lowering preserves every decision). */
    fun dg(ont: GOntology, g: GGoal, a: GAct, h: GHist): Int = dp(KCompile.lower(ont, g), a, h)

    private fun applicable(cs: List<LCeil>, gid: String, verb: String): List<String> = cs.filter { appliesL(it.sel, gid, verb) }.map { it.bid }

    /** The decision with the witness (grant id, applicable bound ids) of an Allow. */
    class Dw(val decision: Int, val gid: String, val bids: List<String>)

    fun decideW(p: Pol, a: GAct, h: GHist): Dw {
        val d = dp(p, a, h)
        if (d != ALLOW) return Dw(d, "", emptyList())
        val pr = p.preds.firstOrNull { predDec(it, p.ceils, p.deleg, a, h) == ALLOW } ?: return Dw(DENY, "", emptyList())
        return Dw(ALLOW, pr.gid, applicable(p.ceils, pr.gid, a.verb))
    }

    /** The checker re-evaluates ONE grant and the gates, never the whole policy. */
    fun verifyWitness(p: Pol, a: GAct, h: GHist, w: Dw): Boolean =
        validityDec(p.validity, p.deleg, a, h) == ALLOW && prohDec(p.prohs, a, h) == ALLOW && escDec(p.escs, a, h) == ALLOW &&
            p.preds.any { it.gid == w.gid && predDec(it, p.ceils, p.deleg, a, h) == ALLOW } &&
            w.bids == applicable(p.ceils, w.gid, a.verb)
}
