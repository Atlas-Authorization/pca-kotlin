package net.atlasauth.pca.goal.kernel

/** Negation-normal conditions and the lowered policy (GoalCompile): the compiler is a pure total function of (ontology, goal). */
internal sealed class NC {
    object NTrue : NC()
    object NFalse : NC()
    data class NAtom(val op: GOp, val l: GTerm, val r: GTerm) : NC()
    data class NAnd(val a: NC, val b: NC) : NC()
    data class NOr(val a: NC, val b: NC) : NC()
}

internal sealed class ResPat {
    object PStar : ResPat()
    data class PSet(val ids: List<String>) : ResPat()
}

internal data class LSel(val gids: List<String>, val verbs: List<String>)
internal data class LPred(val gid: String, val verb: String, val res: ResPat, val cond: NC)
internal data class LProh(val pid: String, val verbs: List<String>, val res: ResPat, val cond: NC)
internal data class LCeil(val bid: String, val sel: LSel, val core: BCore)
internal data class Pol(
    val preds: List<LPred>, val prohs: List<LProh>, val ceils: List<LCeil>, val escs: List<NC>,
    val validity: GValidity, val deleg: GDeleg,
)

/** The result of Compile: a policy or the type reasons. */
internal class CResult(val policy: Pol?, val reasons: List<String>)

internal object KCompile {
    private fun negOp(op: GOp): GOp = when (op) {
        GOp.Eq -> GOp.Ne; GOp.Ne -> GOp.Eq; GOp.Lt -> GOp.Gte; GOp.Gte -> GOp.Lt
        GOp.Gt -> GOp.Lte; GOp.Lte -> GOp.Gt; GOp.In -> GOp.Nin; GOp.Nin -> GOp.In
    }

    /** `pos` = the polarity: nnf(c, false) is the normal form of `not c`. */
    fun nnf(c: GCond, pos: Boolean): NC = when (c) {
        GCond.CTrue -> if (pos) NC.NTrue else NC.NFalse
        is GCond.Cmp -> NC.NAtom(if (pos) c.op else negOp(c.op), c.l, c.r)
        is GCond.And -> if (pos) NC.NAnd(nnf(c.a, true), nnf(c.b, true)) else NC.NOr(nnf(c.a, false), nnf(c.b, false))
        is GCond.Or -> if (pos) NC.NOr(nnf(c.a, true), nnf(c.b, true)) else NC.NAnd(nnf(c.a, false), nnf(c.b, false))
        is GCond.Not -> nnf(c.c, !pos)
    }

    private fun relMembers(rels: List<RelDecl>, rel: String, anchor: String): List<String> =
        rels.firstOrNull { it.rel == rel && it.anchor == anchor }?.members ?: emptyList()

    private fun interPat(x: ResPat, y: ResPat): ResPat = when (x) {
        ResPat.PStar -> y
        is ResPat.PSet -> if (y is ResPat.PSet) ResPat.PSet(x.ids.filter { it in y.ids }) else x
    }

    private fun resolvePart(ont: GOntology, p: ResPart): ResPat = when (p) {
        is ResPart.PartExact -> ResPat.PSet(listOf(p.id))
        is ResPart.PartOneOf -> ResPat.PSet(p.ids)
        is ResPart.PartRelated -> ResPat.PSet(relMembers(ont.rels, p.rel, p.anchor))
    }

    fun resolveSel(ont: GOntology, s: ResSel): ResPat = when (s) {
        is ResSel.Exact -> ResPat.PSet(listOf(s.id))
        is ResSel.OneOf -> ResPat.PSet(s.ids)
        is ResSel.Related -> ResPat.PSet(relMembers(ont.rels, s.rel, s.anchor))
        is ResSel.AnyRes -> ResPat.PStar
        is ResSel.AllOf -> {
            var acc: ResPat = ResPat.PStar
            for (i in s.parts.indices.reversed()) acc = interPat(resolvePart(ont, s.parts[i]), acc)
            acc
        }
    }

    private fun resolveBSel(ont: GOntology, s: GSel): LSel = when (s) {
        is GSel.SelGids -> LSel(s.gids, emptyList())
        is GSel.SelEffect -> LSel(emptyList(), KTypes.verbsOfClass(ont.verbs, s.cls))
    }

    private fun dependsOn(hs: List<GHole>, gid: String) = hs.any { it.global || gid in it.affects }

    /** Drop every grant that depends on a hole (the most restrictive completion); the other clauses stay. */
    fun strip(g: GGoal): GGoal = g.copy(grants = g.grants.filter { !dependsOn(g.holes, it.gid) }, holes = emptyList())

    fun lower(ont: GOntology, g: GGoal): Pol = Pol(
        g.grants.map { LPred(it.gid, it.verb, resolveSel(ont, it.res), nnf(it.cond, true)) },
        g.prohibits.map { LProh(it.pid, KTypes.prohVerbs(ont, it.target), resolveSel(ont, it.res), nnf(it.cond, true)) },
        g.bounds.map { LCeil(it.bid, resolveBSel(ont, it.sel), it.core) },
        g.escalateOn.map { nnf(it, true) },
        g.validity, g.deleg,
    )

    /** C: ill-typed goals are rejected with reasons (no coercion); a goal with holes compiles to its most restrictive completion. */
    fun compile(ont: GOntology, g: GGoal): CResult {
        val rs = KTypes.reasons(ont, g)
        return if (rs.isNotEmpty()) CResult(null, rs) else CResult(lower(ont, strip(g)), rs)
    }

    // ---- encoders of the compiled policy ----

    private fun resPat(o: MutableList<Tok>, p: ResPat) {
        when (p) {
            ResPat.PStar -> KEnc.kw(o, 630)
            is ResPat.PSet -> { KEnc.kw(o, 631); KEnc.strs(o, p.ids) }
        }
    }

    private fun nc(o: MutableList<Tok>, c: NC) {
        when (c) {
            NC.NTrue -> KEnc.kw(o, 600)
            NC.NFalse -> KEnc.kw(o, 601)
            is NC.NAtom -> { KEnc.kw(o, 602); KEnc.op(o, c.op); KEnc.term(o, c.l); KEnc.term(o, c.r) }
            is NC.NAnd -> { KEnc.kw(o, 603); nc(o, c.a); nc(o, c.b) }
            is NC.NOr -> { KEnc.kw(o, 604); nc(o, c.a); nc(o, c.b) }
        }
    }

    fun encPol(p: Pol): List<Tok> {
        val o = ArrayList<Tok>()
        KEnc.kw(o, 650)
        KEnc.int(o, p.preds.size.toLong())
        for (x in p.preds) { KEnc.kw(o, 620); KEnc.str(o, x.gid); KEnc.str(o, x.verb); resPat(o, x.res); nc(o, x.cond) }
        KEnc.int(o, p.prohs.size.toLong())
        for (x in p.prohs) { KEnc.kw(o, 640); KEnc.str(o, x.pid); KEnc.strs(o, x.verbs); resPat(o, x.res); nc(o, x.cond) }
        KEnc.int(o, p.ceils.size.toLong())
        for (x in p.ceils) { KEnc.kw(o, 610); KEnc.str(o, x.bid); KEnc.strs(o, x.sel.gids); KEnc.strs(o, x.sel.verbs); KEnc.bcore(o, x.core) }
        KEnc.int(o, p.escs.size.toLong())
        for (x in p.escs) nc(o, x)
        KEnc.validity(o, p.validity)
        KEnc.deleg(o, p.deleg)
        return o
    }
}
