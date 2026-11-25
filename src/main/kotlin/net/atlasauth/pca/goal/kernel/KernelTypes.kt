package net.atlasauth.pca.goal.kernel

/** The typing judgement of the proved compiler (units, currency, closed world, canonical order, wildcards, holes) and its reasons. */
internal object KTypes {
    fun atomV(a: GAtom): GV = when (a) { is GAtom.AQ -> GV.VQ(a.q); is GAtom.AS -> GV.VS(a.s) }

    fun tyOfV(v: GV): GTy? = when (v) { is GV.VQ -> GTy.TyQ(v.q.u); is GV.VS -> GTy.TyS; is GV.VSet -> null }

    fun tyOfTerm(t: GTerm): GTy? = when (t) { is GTerm.Param -> t.ty; is GTerm.Lit -> tyOfV(t.v); is GTerm.HistAgg -> GTy.TyQ(t.u) }

    private fun unitOk(u: GUnit) = u !is GUnit.Money || u.ccy.isNotEmpty()

    private fun tyOk(t: GTy) = t !is GTy.TyQ || unitOk(t.u)

    private fun vOk(v: GV): Boolean = when (v) {
        is GV.VQ -> unitOk(v.q.u)
        is GV.VS -> true
        is GV.VSet -> v.items.all { it !is GAtom.AQ || unitOk(it.q.u) }
    }

    private fun termOk(t: GTerm): Boolean = when (t) {
        is GTerm.Param -> t.path.isNotEmpty() && tyOk(t.ty)
        is GTerm.Lit -> vOk(t.v)
        is GTerm.HistAgg -> t.bid.isNotEmpty() && unitOk(t.u)
    }

    private fun cmpTyped(op: GOp, l: GTerm, r: GTerm): Boolean {
        if (!termOk(l) || !termOk(r)) return false
        val tl = tyOfTerm(l) ?: return false
        return when (op) {
            GOp.Eq, GOp.Ne -> tl == tyOfTerm(r)
            GOp.Lt, GOp.Lte, GOp.Gt, GOp.Gte -> tl == tyOfTerm(r) && tl is GTy.TyQ
            GOp.In, GOp.Nin -> {
                val set = (r as? GTerm.Lit)?.v as? GV.VSet
                set != null && set.items.all { tyOfV(atomV(it)) == tl }
            }
        }
    }

    private fun condTyped(c: GCond, ok: (String, GTy) -> Boolean): Boolean = when (c) {
        GCond.CTrue -> true
        is GCond.Cmp -> cmpTyped(c.op, c.l, c.r) && paramsOk(c.l, ok) && paramsOk(c.r, ok)
        is GCond.And -> condTyped(c.a, ok) && condTyped(c.b, ok)
        is GCond.Or -> condTyped(c.a, ok) && condTyped(c.b, ok)
        is GCond.Not -> condTyped(c.c, ok)
    }

    private fun paramsOk(t: GTerm, ok: (String, GTy) -> Boolean) = t !is GTerm.Param || ok(t.path, t.ty)

    private fun findDecl(vs: List<VerbDecl>, verb: String): VerbDecl? = vs.firstOrNull { it.verb == verb }

    private fun declaredFor(ont: GOntology, verbs: List<String>, p: String, ty: GTy): Boolean =
        verbs.all { v -> findDecl(ont.verbs, v)?.params?.contains(ParamDecl(p, ty)) == true }

    private fun noConflict(vs: List<VerbDecl>, p: String, ty: GTy): Boolean = vs.all { v -> v.params.all { it.path != p || it.ty == ty } }

    private fun hasRel(ont: GOntology, rel: String, anchor: String) = ont.rels.any { it.rel == rel && it.anchor == anchor }

    private fun partOk(ont: GOntology, p: ResPart): Boolean = when (p) {
        is ResPart.PartExact -> p.id.isNotEmpty()
        is ResPart.PartOneOf -> p.ids.isNotEmpty()
        is ResPart.PartRelated -> hasRel(ont, p.rel, p.anchor)
    }

    private fun resSelOk(ont: GOntology, s: ResSel): Boolean = when (s) {
        is ResSel.Exact -> s.id.isNotEmpty()
        is ResSel.OneOf -> s.ids.isNotEmpty()
        is ResSel.Related -> hasRel(ont, s.rel, s.anchor)
        is ResSel.AnyRes -> true
        is ResSel.AllOf -> s.parts.size >= 2 && s.parts.all { partOk(ont, it) }
    }

    fun verbsOfClass(vs: List<VerbDecl>, cls: String): List<String> = vs.filter { it.cls == cls }.map { it.verb }

    fun prohVerbs(ont: GOntology, t: ProhTarget): List<String> = when (t) {
        is ProhTarget.PVerb -> listOf(t.verb)
        is ProhTarget.PEffect -> verbsOfClass(ont.verbs, t.cls)
    }

    private fun grantOk(ont: GOntology, g: GGoal, gr: GGrant): Boolean =
        gr.gid.isNotEmpty() && findDecl(ont.verbs, gr.verb) != null && resSelOk(ont, gr.res) &&
            (gr.res !is ResSel.AnyRes || gr.gid in g.wildcardAck) &&
            condTyped(gr.cond) { p, ty -> declaredFor(ont, listOf(gr.verb), p, ty) }

    private fun prohibitOk(ont: GOntology, p: GProhibit): Boolean {
        val tOk = when (val t = p.target) {
            is ProhTarget.PVerb -> findDecl(ont.verbs, t.verb) != null
            is ProhTarget.PEffect -> t.cls.isNotEmpty() && verbsOfClass(ont.verbs, t.cls).isNotEmpty()
        }
        return p.pid.isNotEmpty() && resSelOk(ont, p.res) && tOk &&
            condTyped(p.cond) { q, ty -> declaredFor(ont, prohVerbs(ont, p.target), q, ty) }
    }

    private fun windowOk(w: GWindow) = when (w) { is GWindow.WSliding -> w.ms > 0; is GWindow.WPeriod -> w.ms > 0; else -> true }

    private fun scopeOk(s: GScope) = s !is GScope.SFleet || s.agents.isNotEmpty()

    private fun hasGid(g: GGoal, gid: String) = g.grants.any { it.gid == gid }

    private fun boundOk(g: GGoal, b: GBound): Boolean {
        val c = b.core
        if (!(b.bid.isNotEmpty() && termOk(c.value) && unitOk(c.cap.u) && c.cap.n >= 0 && windowOk(c.window) && scopeOk(c.scope))) return false
        val selOk = when (val s = b.sel) {
            is GSel.SelGids -> s.gids.isNotEmpty() && s.gids.all { hasGid(g, it) }
            is GSel.SelEffect -> s.cls.isNotEmpty()
        }
        if (!selOk) return false
        return when (c.agg) {
            GAgg.Count -> c.cap.u == GUnit.Count
            GAgg.Sum, GAgg.Max -> tyOfTerm(c.value) == GTy.TyQ(c.cap.u)
            GAgg.Distinct -> c.cap.u == GUnit.Count && c.key.isNotEmpty()
        }
    }

    private fun validityOk(g: GGoal): Boolean =
        g.validity.notBefore <= g.validity.notAfter && g.validity.maxIdle >= 0 &&
            g.deleg.maxDepth in 0L..16L && g.deleg.narrowOnly && g.deleg.mayTouch.all { hasGid(g, it) }

    private fun holeOk(g: GGoal, h: GHole) = h.hid.isNotEmpty() && h.affects.all { hasGid(g, it) }

    private fun escsTyped(ont: GOntology, g: GGoal) = g.escalateOn.all { c -> condTyped(c) { p, ty -> noConflict(ont.verbs, p, ty) } }

    /** Code-point order, as the proved string comparison (a strict total order). */
    fun strLt(a: String, b: String): Boolean {
        var i = 0
        var j = 0
        while (true) {
            if (j >= b.length) return false
            if (i >= a.length) return true
            val x = a.codePointAt(i)
            val y = b.codePointAt(j)
            if (x != y) return x < y
            i += Character.charCount(x)
            j += Character.charCount(y)
        }
    }

    private fun strictlySorted(xs: List<String>): Boolean {
        for (i in 0 until xs.size - 1) if (!strLt(xs[i], xs[i + 1])) return false
        return true
    }

    private fun sorted4(g: GGoal) =
        strictlySorted(g.grants.map { it.gid }) && strictlySorted(g.prohibits.map { it.pid }) &&
            strictlySorted(g.bounds.map { it.bid }) && strictlySorted(g.holes.map { it.hid })

    /** The type reasons of a goal against an ontology, in the proved order; empty = well typed. */
    fun reasons(ont: GOntology, g: GGoal): List<String> {
        val r = ArrayList<String>()
        if (!sorted4(g)) r.add("not_canonical_order")
        if (!g.grants.all { grantOk(ont, g, it) }) r.add("ill_typed_grant")
        if (!g.prohibits.all { prohibitOk(ont, it) }) r.add("ill_typed_prohibit")
        if (!g.bounds.all { boundOk(g, it) }) r.add("ill_typed_bound")
        if (!escsTyped(ont, g)) r.add("ill_typed_escalation")
        if (!validityOk(g)) r.add("bad_validity_or_delegation")
        if (!g.holes.all { holeOk(g, it) }) r.add("bad_hole")
        return r
    }
}
