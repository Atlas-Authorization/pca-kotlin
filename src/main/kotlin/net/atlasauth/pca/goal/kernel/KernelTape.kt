package net.atlasauth.pca.goal.kernel

/** A tape that does not parse (the kernel answers i9). */
internal class TapeFail : RuntimeException(null, null, false, false)

internal class Rd(private val ts: List<Tok>) {
    private var p = 0
    fun left(): Int = ts.size - p
    fun done(): Boolean = p >= ts.size
    fun next(): Tok { if (p >= ts.size) throw TapeFail(); return ts[p++] }
}

/** Decoders of the token tapes (the Dec* functions of the proved renderer and the entry module); any deviation fails the whole parse. */
internal object KDec {
    private fun fail(): Nothing = throw TapeFail()

    fun str(r: Rd): String = (r.next() as? Tok.S ?: fail()).s
    fun int(r: Rd): Long = (r.next() as? Tok.I ?: fail()).i
    fun kw(r: Rd): Long = (r.next() as? Tok.Kw ?: fail()).k
    private fun expect(r: Rd, k: Long) { if (kw(r) != k) fail() }
    private fun bool(r: Rd): Boolean { val i = int(r); if (i != 0L && i != 1L) fail(); return i == 1L }

    private inline fun <T> list(r: Rd, f: (Rd) -> T): List<T> {
        val n = int(r)
        if (n < 0) fail()
        val out = ArrayList<T>()
        var i = 0L
        while (i < n) { out.add(f(r)); i++ }
        return out
    }

    fun strs(r: Rd): List<String> = list(r) { str(it) }

    fun unit(r: Rd): GUnit = when (kw(r)) {
        300L -> GUnit.Money(str(r))
        301L -> GUnit.Count
        302L -> GUnit.Duration
        303L -> GUnit.Instant
        304L -> GUnit.Bytes
        305L -> GUnit.Ratio
        else -> fail()
    }

    fun q(r: Rd): GQ { val u = unit(r); return GQ(u, int(r)) }

    fun ty(r: Rd): GTy = when (kw(r)) {
        310L -> GTy.TyQ(unit(r))
        311L -> GTy.TyS
        else -> fail()
    }

    private fun atom(r: Rd): GAtom = when (kw(r)) {
        320L -> GAtom.AQ(q(r))
        321L -> GAtom.AS(str(r))
        else -> fail()
    }

    fun v(r: Rd): GV = when (kw(r)) {
        330L -> GV.VQ(q(r))
        331L -> GV.VS(str(r))
        332L -> GV.VSet(list(r) { atom(it) })
        else -> fail()
    }

    fun term(r: Rd): GTerm = when (kw(r)) {
        340L -> { val p = str(r); GTerm.Param(p, ty(r)) }
        341L -> GTerm.Lit(v(r))
        342L -> { val b = str(r); GTerm.HistAgg(b, unit(r)) }
        else -> fail()
    }

    private fun op(r: Rd): GOp { val k = kw(r); if (k < 350L || k > 357L) fail(); return GOp.values()[(k - 350L).toInt()] }

    /** fuel = the remaining token count: it bounds the depth, exactly as the proved decoder. */
    private fun cond(r: Rd, fuel: Long): GCond {
        if (fuel == 0L) fail()
        return when (kw(r)) {
            360L -> GCond.CTrue
            361L -> { val o = op(r); val l = term(r); GCond.Cmp(o, l, term(r)) }
            362L -> { val x = cond(r, fuel - 1); GCond.And(x, cond(r, fuel - 1)) }
            363L -> { val x = cond(r, fuel - 1); GCond.Or(x, cond(r, fuel - 1)) }
            364L -> GCond.Not(cond(r, fuel - 1))
            else -> fail()
        }
    }

    // fuel counts the keyword about to be read, so the cursor must not have advanced
    private fun condTop(r: Rd): GCond = cond(r, r.left().toLong())

    private fun part(r: Rd): ResPart = when (kw(r)) {
        375L -> ResPart.PartExact(str(r))
        376L -> ResPart.PartOneOf(strs(r))
        377L -> { val rel = str(r); ResPart.PartRelated(rel, str(r)) }
        else -> fail()
    }

    private fun resSel(r: Rd): ResSel = when (kw(r)) {
        370L -> ResSel.Exact(str(r))
        371L -> ResSel.OneOf(strs(r))
        372L -> { val rel = str(r); ResSel.Related(rel, str(r)) }
        373L -> ResSel.AnyRes(str(r))
        374L -> ResSel.AllOf(list(r) { part(it) })
        else -> fail()
    }

    private fun grant(r: Rd): GGrant {
        expect(r, 380)
        val gid = str(r); val verb = str(r); val res = resSel(r)
        return GGrant(gid, verb, res, condTop(r))
    }

    private fun prohTarget(r: Rd): ProhTarget = when (kw(r)) {
        390L -> ProhTarget.PVerb(str(r))
        391L -> ProhTarget.PEffect(str(r))
        else -> fail()
    }

    private fun prohibit(r: Rd): GProhibit {
        expect(r, 392)
        val pid = str(r); val tg = prohTarget(r); val res = resSel(r)
        return GProhibit(pid, tg, res, condTop(r))
    }

    private fun agg(r: Rd): GAgg { val k = kw(r); if (k < 400L || k > 403L) fail(); return GAgg.values()[(k - 400L).toInt()] }

    private fun sel(r: Rd): GSel = when (kw(r)) {
        410L -> GSel.SelGids(strs(r))
        411L -> GSel.SelEffect(str(r))
        else -> fail()
    }

    private fun window(r: Rd): GWindow = when (kw(r)) {
        420L -> GWindow.WTask
        421L -> GWindow.WSliding(int(r))
        422L -> { val ms = int(r); GWindow.WPeriod(ms, int(r)) }
        423L -> GWindow.WLifetime
        else -> fail()
    }

    private fun scope(r: Rd): GScope = when (kw(r)) {
        430L -> GScope.SSession
        431L -> GScope.SPrincipal
        432L -> GScope.SOrg
        433L -> GScope.SFleet(strs(r))
        else -> fail()
    }

    private fun onExceed(r: Rd): OnExceed = when (kw(r)) {
        440L -> OnExceed.Deny
        441L -> OnExceed.Escalate
        else -> fail()
    }

    private fun bcore(r: Rd): BCore {
        expect(r, 450)
        val a = agg(r); val value = term(r); val key = str(r); val w = window(r); val sc = scope(r); val cap = q(r)
        return BCore(a, value, key, w, sc, cap, onExceed(r))
    }

    private fun bound(r: Rd): GBound {
        expect(r, 451)
        val bid = str(r); val s = sel(r)
        return GBound(bid, s, bcore(r))
    }

    private fun validity(r: Rd): GValidity {
        expect(r, 460)
        val nb = int(r); val na = int(r)
        return GValidity(nb, na, int(r))
    }

    private fun deleg(r: Rd): GDeleg {
        expect(r, 461)
        val md = int(r); val no = bool(r)
        return GDeleg(md, no, strs(r))
    }

    private fun hole(r: Rd): GHole {
        expect(r, 470)
        val hid = str(r); val q = str(r); val dom = strs(r); val aff = strs(r)
        return GHole(hid, q, dom, aff, bool(r))
    }

    /** The whole-tape parse of a goal; null unless the tape is exactly one goal. */
    fun goal(ts: List<Tok>): GGoal? = whole(ts) { r ->
        expect(r, 480)
        val v = int(r); val principal = str(r); val od = str(r); val nd = str(r)
        val sources = strs(r)
        val grants = list(r) { grant(it) }
        val prohibits = list(r) { prohibit(it) }
        val bounds = list(r) { bound(it) }
        val vd = validity(r)
        val dl = deleg(r)
        val esc = list(r) { condTop(it) }
        val ack = strs(r)
        val holes = list(r) { hole(it) }
        GGoal(v, principal, od, nd, sources, grants, prohibits, bounds, vd, dl, esc, ack, holes)
    }

    private inline fun <T> whole(ts: List<Tok>, f: (Rd) -> T): T? {
        val r = Rd(ts)
        return try {
            val x = f(r)
            if (r.done()) x else null
        } catch (e: TapeFail) {
            null
        }
    }

    private fun paramDecl(r: Rd): ParamDecl { expect(r, 500); val p = str(r); return ParamDecl(p, ty(r)) }

    private fun verbDecl(r: Rd): VerbDecl {
        expect(r, 501)
        val v = str(r); val c = str(r)
        return VerbDecl(v, c, list(r) { paramDecl(it) })
    }

    private fun relDecl(r: Rd): RelDecl {
        expect(r, 502)
        val rel = str(r); val an = str(r)
        return RelDecl(rel, an, strs(r))
    }

    fun ontology(ts: List<Tok>): GOntology? = whole(ts) { r ->
        expect(r, 510)
        val vs = list(r) { verbDecl(it) }
        GOntology(vs, list(r) { relDecl(it) })
    }

    // a later entry for the same key replaces an earlier one
    private fun params(r: Rd): Map<String, GV> {
        val m = LinkedHashMap<String, GV>()
        val n = int(r)
        if (n < 0) fail()
        var i = 0L
        while (i < n) { expect(r, 520); val k = str(r); m[k] = v(r); i++ }
        return m
    }

    private fun act(r: Rd): GAct {
        expect(r, 530)
        val verb = str(r); val res = str(r); val ps = params(r); val t = int(r)
        val sess = str(r); val prin = str(r); val org = str(r); val agent = str(r)
        return GAct(verb, res, ps, t, sess, prin, org, agent, int(r))
    }

    fun act(ts: List<Tok>): GAct? = whole(ts) { act(it) }

    private fun adm(r: Rd): GAdm { expect(r, 531); val gid = str(r); return GAdm(gid, act(r)) }

    fun hist(ts: List<Tok>): GHist? = whole(ts) { r ->
        expect(r, 541)
        val adms = list(r) { adm(it) }
        val last = int(r)
        val aggs = LinkedHashMap<String, GQ>()
        val n = int(r)
        if (n < 0) fail()
        var i = 0L
        while (i < n) { expect(r, 540); val k = str(r); aggs[k] = q(r); i++ }
        GHist(adms, last, aggs)
    }
}

/** Encoders (the Enc* functions): tokens appended to [o]. */
internal object KEnc {
    fun str(o: MutableList<Tok>, s: String) { o.add(Tok.S(s)) }
    fun int(o: MutableList<Tok>, i: Long) { o.add(Tok.I(i)) }
    fun kw(o: MutableList<Tok>, k: Long) { o.add(Tok.Kw(k)) }
    private fun bool(o: MutableList<Tok>, b: Boolean) { o.add(Tok.I(if (b) 1L else 0L)) }

    private inline fun <T> list(o: MutableList<Tok>, xs: List<T>, f: (T) -> Unit) { int(o, xs.size.toLong()); for (x in xs) f(x) }

    fun strs(o: MutableList<Tok>, xs: List<String>) = list(o, xs) { str(o, it) }

    fun unit(o: MutableList<Tok>, u: GUnit) {
        when (u) {
            is GUnit.Money -> { kw(o, 300); str(o, u.ccy) }
            GUnit.Count -> kw(o, 301)
            GUnit.Duration -> kw(o, 302)
            GUnit.Instant -> kw(o, 303)
            GUnit.Bytes -> kw(o, 304)
            GUnit.Ratio -> kw(o, 305)
        }
    }

    fun q(o: MutableList<Tok>, q: GQ) { unit(o, q.u); int(o, q.n) }

    fun ty(o: MutableList<Tok>, t: GTy) {
        when (t) {
            is GTy.TyQ -> { kw(o, 310); unit(o, t.u) }
            GTy.TyS -> kw(o, 311)
        }
    }

    private fun atom(o: MutableList<Tok>, a: GAtom) {
        when (a) {
            is GAtom.AQ -> { kw(o, 320); q(o, a.q) }
            is GAtom.AS -> { kw(o, 321); str(o, a.s) }
        }
    }

    fun v(o: MutableList<Tok>, v: GV) {
        when (v) {
            is GV.VQ -> { kw(o, 330); q(o, v.q) }
            is GV.VS -> { kw(o, 331); str(o, v.s) }
            is GV.VSet -> { kw(o, 332); list(o, v.items) { atom(o, it) } }
        }
    }

    fun term(o: MutableList<Tok>, t: GTerm) {
        when (t) {
            is GTerm.Param -> { kw(o, 340); str(o, t.path); ty(o, t.ty) }
            is GTerm.Lit -> { kw(o, 341); v(o, t.v) }
            is GTerm.HistAgg -> { kw(o, 342); str(o, t.bid); unit(o, t.u) }
        }
    }

    fun op(o: MutableList<Tok>, op: GOp) { kw(o, 350L + op.ordinal) }

    fun cond(o: MutableList<Tok>, c: GCond) {
        when (c) {
            GCond.CTrue -> kw(o, 360)
            is GCond.Cmp -> { kw(o, 361); op(o, c.op); term(o, c.l); term(o, c.r) }
            is GCond.And -> { kw(o, 362); cond(o, c.a); cond(o, c.b) }
            is GCond.Or -> { kw(o, 363); cond(o, c.a); cond(o, c.b) }
            is GCond.Not -> { kw(o, 364); cond(o, c.c) }
        }
    }

    private fun part(o: MutableList<Tok>, p: ResPart) {
        when (p) {
            is ResPart.PartExact -> { kw(o, 375); str(o, p.id) }
            is ResPart.PartOneOf -> { kw(o, 376); strs(o, p.ids) }
            is ResPart.PartRelated -> { kw(o, 377); str(o, p.rel); str(o, p.anchor) }
        }
    }

    private fun resSel(o: MutableList<Tok>, s: ResSel) {
        when (s) {
            is ResSel.Exact -> { kw(o, 370); str(o, s.id) }
            is ResSel.OneOf -> { kw(o, 371); strs(o, s.ids) }
            is ResSel.Related -> { kw(o, 372); str(o, s.rel); str(o, s.anchor) }
            is ResSel.AnyRes -> { kw(o, 373); str(o, s.reason) }
            is ResSel.AllOf -> { kw(o, 374); list(o, s.parts) { part(o, it) } }
        }
    }

    private fun grant(o: MutableList<Tok>, g: GGrant) { kw(o, 380); str(o, g.gid); str(o, g.verb); resSel(o, g.res); cond(o, g.cond) }

    private fun prohibit(o: MutableList<Tok>, p: GProhibit) {
        kw(o, 392); str(o, p.pid)
        when (val t = p.target) {
            is ProhTarget.PVerb -> { kw(o, 390); str(o, t.verb) }
            is ProhTarget.PEffect -> { kw(o, 391); str(o, t.cls) }
        }
        resSel(o, p.res); cond(o, p.cond)
    }

    fun window(o: MutableList<Tok>, w: GWindow) {
        when (w) {
            GWindow.WTask -> kw(o, 420)
            is GWindow.WSliding -> { kw(o, 421); int(o, w.ms) }
            is GWindow.WPeriod -> { kw(o, 422); int(o, w.ms); int(o, w.t0) }
            GWindow.WLifetime -> kw(o, 423)
        }
    }

    fun scope(o: MutableList<Tok>, s: GScope) {
        when (s) {
            GScope.SSession -> kw(o, 430)
            GScope.SPrincipal -> kw(o, 431)
            GScope.SOrg -> kw(o, 432)
            is GScope.SFleet -> { kw(o, 433); strs(o, s.agents) }
        }
    }

    fun bcore(o: MutableList<Tok>, b: BCore) {
        kw(o, 450); kw(o, 400L + b.agg.ordinal); term(o, b.value); str(o, b.key); window(o, b.window); scope(o, b.scope); q(o, b.cap)
        kw(o, if (b.onExceed == OnExceed.Deny) 440L else 441L)
    }

    private fun bound(o: MutableList<Tok>, b: GBound) {
        kw(o, 451); str(o, b.bid)
        when (val s = b.sel) {
            is GSel.SelGids -> { kw(o, 410); strs(o, s.gids) }
            is GSel.SelEffect -> { kw(o, 411); str(o, s.cls) }
        }
        bcore(o, b.core)
    }

    fun validity(o: MutableList<Tok>, v: GValidity) { kw(o, 460); int(o, v.notBefore); int(o, v.notAfter); int(o, v.maxIdle) }

    fun deleg(o: MutableList<Tok>, d: GDeleg) { kw(o, 461); int(o, d.maxDepth); bool(o, d.narrowOnly); strs(o, d.mayTouch) }

    private fun hole(o: MutableList<Tok>, h: GHole) { kw(o, 470); str(o, h.hid); str(o, h.q); strs(o, h.domain); strs(o, h.affects); bool(o, h.global) }

    /** The card: the goal as its canonical token stream. */
    fun goal(g: GGoal): List<Tok> {
        val o = ArrayList<Tok>()
        kw(o, 480); int(o, g.v); str(o, g.principal); str(o, g.ontDigest); str(o, g.nlDigest)
        strs(o, g.sources)
        list(o, g.grants) { grant(o, it) }
        list(o, g.prohibits) { prohibit(o, it) }
        list(o, g.bounds) { bound(o, it) }
        validity(o, g.validity)
        deleg(o, g.deleg)
        list(o, g.escalateOn) { cond(o, it) }
        strs(o, g.wildcardAck)
        list(o, g.holes) { hole(o, it) }
        return o
    }
}
