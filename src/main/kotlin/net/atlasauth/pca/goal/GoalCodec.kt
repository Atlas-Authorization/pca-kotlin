package net.atlasauth.pca.goal

/**
 * The token-tape form of the Goal IR. A tape is a list of tokens; a token is a two-element list `["k", n]` (keyword),
 * `["i", n]` (integer) or `["s", text]`. Encoding is strict: anything that is not exactly an IR value throws [IrError].
 * Goals, ontologies, acts and histories are parsed-JSON maps shaped like the TypeScript IR.
 */
@Suppress("UNCHECKED_CAST")
object GoalCodec {
    @JvmField
    val OPS: List<String> = listOf("eq", "ne", "lt", "lte", "gt", "gte", "in", "nin")

    @JvmField
    val AGGS: List<String> = listOf("count", "sum", "max", "distinct")

    private fun tok(t: String, v: Any?): MutableList<Any?> {
        val x = ArrayList<Any?>(2)
        x.add(t)
        x.add(v)
        return x
    }

    private fun kw(n: Long): MutableList<Any?> = tok("k", G.num(n))

    private fun iv(v: Any?): MutableList<Any?> {
        val n = G.safeInt(v) ?: throw IrError(G.jsStr(v) + " is not a safe integer")
        return tok("i", G.num(n))
    }

    private fun iv(n: Long): MutableList<Any?> = tok("i", G.num(n))

    private fun sv(s: Any?): MutableList<Any?> {
        if (s !is String) throw IrError("string expected")
        return tok("s", s)
    }

    private fun bad(what: String, v: Any?): IrError {
        val s = try {
            G.stringify(v)
        } catch (e: RuntimeException) {
            v.toString()
        }
        return IrError("unknown $what: $s")
    }

    private fun <T> list(out: MutableList<Any?>, xs: Any?, f: (MutableList<Any?>, Any?) -> T) {
        val a = G.l(xs) ?: throw IrError("array expected")
        out.add(iv(a.size.toLong()))
        for (x in a) f(out, x)
    }

    private fun strs(out: MutableList<Any?>, xs: Any?) = list(out, xs) { o, s -> o.add(sv(s)) }

    private fun unit(out: MutableList<Any?>, u: Any?) {
        when (G.kind(u)) {
            "money" -> {
                out.add(kw(300))
                out.add(sv(G.get(u, "ccy")))
            }
            "count" -> out.add(kw(301))
            "duration" -> out.add(kw(302))
            "instant" -> out.add(kw(303))
            "bytes" -> out.add(kw(304))
            "ratio" -> out.add(kw(305))
            else -> throw bad("unit", u)
        }
    }

    private fun quantity(out: MutableList<Any?>, q: Any?) {
        unit(out, G.get(q, "u"))
        out.add(iv(G.get(q, "n")))
    }

    private fun ty(out: MutableList<Any?>, t: Any?) {
        val k = G.kind(t)
        if (k == "q") {
            out.add(kw(310))
            unit(out, G.get(t, "u"))
        } else if (k == "s") out.add(kw(311)) else throw bad("type", t)
    }

    private fun atom(out: MutableList<Any?>, a: Any?) {
        val k = G.kind(a)
        if (k == "q") {
            out.add(kw(320))
            quantity(out, G.get(a, "q"))
        } else if (k == "s") {
            out.add(kw(321))
            out.add(sv(G.get(a, "s")))
        } else throw bad("set member (sets hold quantities and strings only)", a)
    }

    private fun value(out: MutableList<Any?>, v: Any?) {
        when (G.kind(v)) {
            "q" -> {
                out.add(kw(330))
                quantity(out, G.get(v, "q"))
            }
            "s" -> {
                out.add(kw(331))
                out.add(sv(G.get(v, "s")))
            }
            "set" -> {
                out.add(kw(332))
                list(out, G.get(v, "items")) { o, x -> atom(o, x) }
            }
            else -> throw bad("value", v)
        }
    }

    private fun term(out: MutableList<Any?>, t: Any?) {
        when (G.kind(t)) {
            "param" -> {
                out.add(kw(340))
                out.add(sv(G.get(t, "path")))
                ty(out, G.get(t, "ty"))
            }
            "lit" -> {
                out.add(kw(341))
                value(out, G.get(t, "v"))
            }
            "hist" -> {
                out.add(kw(342))
                out.add(sv(G.get(t, "bid")))
                unit(out, G.get(t, "u"))
            }
            else -> throw bad("term", t)
        }
    }

    private fun op(out: MutableList<Any?>, o: Any?) {
        val i = if (o is String) OPS.indexOf(o) else -1
        if (i < 0) throw bad("operator", o)
        out.add(kw(350L + i))
    }

    private fun cond(out: MutableList<Any?>, c: Any?) {
        when (G.kind(c)) {
            "true" -> out.add(kw(360))
            "cmp" -> {
                out.add(kw(361))
                op(out, G.get(c, "op"))
                term(out, G.get(c, "l"))
                term(out, G.get(c, "r"))
            }
            "and" -> {
                out.add(kw(362))
                cond(out, G.get(c, "a"))
                cond(out, G.get(c, "b"))
            }
            "or" -> {
                out.add(kw(363))
                cond(out, G.get(c, "a"))
                cond(out, G.get(c, "b"))
            }
            "not" -> {
                out.add(kw(364))
                cond(out, G.get(c, "c"))
            }
            else -> throw bad("condition", c)
        }
    }

    private fun part(out: MutableList<Any?>, s: Any?) {
        when (G.kind(s)) {
            "exact" -> {
                out.add(kw(375))
                out.add(sv(G.get(s, "id")))
            }
            "oneof" -> {
                out.add(kw(376))
                strs(out, G.get(s, "ids"))
            }
            "related" -> {
                out.add(kw(377))
                out.add(sv(G.get(s, "rel")))
                out.add(sv(G.get(s, "anchor")))
            }
            else -> throw bad("resource part", s)
        }
    }

    private fun res(out: MutableList<Any?>, s: Any?) {
        when (G.kind(s)) {
            "exact" -> {
                out.add(kw(370))
                out.add(sv(G.get(s, "id")))
            }
            "oneof" -> {
                out.add(kw(371))
                strs(out, G.get(s, "ids"))
            }
            "related" -> {
                out.add(kw(372))
                out.add(sv(G.get(s, "rel")))
                out.add(sv(G.get(s, "anchor")))
            }
            "any" -> {
                out.add(kw(373))
                out.add(sv(G.get(s, "reason")))
            }
            "all_of" -> {
                out.add(kw(374))
                list(out, G.get(s, "parts")) { o, x -> part(o, x) }
            }
            else -> throw bad("resource selector", s)
        }
    }

    private fun grant(out: MutableList<Any?>, g: Any?) {
        out.add(kw(380))
        out.add(sv(G.get(g, "gid")))
        out.add(sv(G.get(g, "verb")))
        res(out, G.get(g, "res"))
        cond(out, G.get(g, "cond"))
    }

    private fun target(out: MutableList<Any?>, t: Any?) {
        val k = G.kind(t)
        if (k == "verb") {
            out.add(kw(390))
            out.add(sv(G.get(t, "verb")))
        } else if (k == "effect") {
            out.add(kw(391))
            out.add(sv(G.get(t, "cls")))
        } else throw bad("prohibit target", t)
    }

    private fun prohibit(out: MutableList<Any?>, p: Any?) {
        out.add(kw(392))
        out.add(sv(G.get(p, "pid")))
        target(out, G.get(p, "target"))
        res(out, G.get(p, "res"))
        cond(out, G.get(p, "cond"))
    }

    private fun sel(out: MutableList<Any?>, s: Any?) {
        val k = G.kind(s)
        if (k == "gids") {
            out.add(kw(410))
            strs(out, G.get(s, "gids"))
        } else if (k == "effect") {
            out.add(kw(411))
            out.add(sv(G.get(s, "cls")))
        } else throw bad("selection", s)
    }

    private fun window(out: MutableList<Any?>, w: Any?) {
        when (G.kind(w)) {
            "task" -> out.add(kw(420))
            "sliding" -> {
                out.add(kw(421))
                out.add(iv(G.get(w, "ms")))
            }
            "period" -> {
                out.add(kw(422))
                out.add(iv(G.get(w, "ms")))
                out.add(iv(G.get(w, "t0")))
            }
            "lifetime" -> out.add(kw(423))
            else -> throw bad("window", w)
        }
    }

    private fun scope(out: MutableList<Any?>, s: Any?) {
        when (G.kind(s)) {
            "session" -> out.add(kw(430))
            "principal" -> out.add(kw(431))
            "org" -> out.add(kw(432))
            "fleet" -> {
                out.add(kw(433))
                strs(out, G.get(s, "agents"))
            }
            else -> throw bad("scope", s)
        }
    }

    private fun onExceed(out: MutableList<Any?>, o: Any?) {
        if ("deny" == o) out.add(kw(440)) else if ("escalate" == o) out.add(kw(441)) else throw bad("on_exceed", o)
    }

    private fun bcore(out: MutableList<Any?>, b: Any?) {
        val agg = G.get(b, "agg")
        val a = if (agg is String) AGGS.indexOf(agg) else -1
        if (a < 0) throw bad("aggregate", agg)
        out.add(kw(450))
        out.add(kw(400L + a))
        term(out, G.get(b, "value"))
        out.add(sv(G.get(b, "key")))
        window(out, G.get(b, "window"))
        scope(out, G.get(b, "scope"))
        quantity(out, G.get(b, "cap"))
        onExceed(out, G.get(b, "onExceed"))
    }

    private fun bound(out: MutableList<Any?>, b: Any?) {
        out.add(kw(451))
        out.add(sv(G.get(b, "bid")))
        sel(out, G.get(b, "sel"))
        bcore(out, b)
    }

    private fun validity(out: MutableList<Any?>, v: Any?) {
        out.add(kw(460))
        out.add(iv(G.get(v, "notBefore")))
        out.add(iv(G.get(v, "notAfter")))
        out.add(iv(G.get(v, "maxIdle")))
    }

    private fun deleg(out: MutableList<Any?>, d: Any?) {
        out.add(kw(461))
        out.add(iv(G.get(d, "maxDepth")))
        out.add(iv(if (G.truthy(G.get(d, "narrowOnly"))) 1L else 0L))
        strs(out, G.get(d, "mayTouch"))
    }

    private fun hole(out: MutableList<Any?>, h: Any?) {
        out.add(kw(470))
        out.add(sv(G.get(h, "hid")))
        out.add(sv(G.get(h, "q")))
        strs(out, G.get(h, "domain"))
        strs(out, G.get(h, "affects"))
        out.add(iv(if (G.truthy(G.get(h, "global"))) 1L else 0L))
    }

    /** The goal as a token tape. */
    @JvmStatic
    fun encodeGoal(g: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        out.add(kw(480))
        out.add(iv(G.get(g, "v")))
        out.add(sv(G.get(g, "principal")))
        out.add(sv(G.get(g, "ontDigest")))
        out.add(sv(G.get(g, "nlDigest")))
        strs(out, G.get(g, "sources"))
        list(out, G.get(g, "grants")) { o, x -> grant(o, x) }
        list(out, G.get(g, "prohibits")) { o, x -> prohibit(o, x) }
        list(out, G.get(g, "bounds")) { o, x -> bound(o, x) }
        validity(out, G.get(g, "validity"))
        deleg(out, G.get(g, "deleg"))
        list(out, G.get(g, "escalateOn")) { o, x -> cond(o, x) }
        strs(out, G.get(g, "wildcardAck"))
        list(out, G.get(g, "holes")) { o, x -> hole(o, x) }
        return out
    }

    @JvmStatic
    fun encodeOntology(o: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        out.add(kw(510))
        list(out, G.get(o, "verbs")) { t, v ->
            t.add(kw(501))
            t.add(sv(G.get(v, "verb")))
            t.add(sv(G.get(v, "cls")))
            list(t, G.get(v, "params")) { u, p ->
                u.add(kw(500))
                u.add(sv(G.get(p, "path")))
                ty(u, G.get(p, "ty"))
            }
        }
        list(out, G.get(o, "rels")) { t, r ->
            t.add(kw(502))
            t.add(sv(G.get(r, "rel")))
            t.add(sv(G.get(r, "anchor")))
            strs(t, G.get(r, "members"))
        }
        return out
    }

    /** `Object.keys(o).sort()`: null throws (TypeError), arrays and strings expose their indices, other scalars have none. */
    private fun sortedKeys(o: Any?): List<String> {
        if (o == null) throw IrError("object expected")
        val ks = ArrayList<String>()
        if (o is Map<*, *>) {
            for (k in o.keys) ks.add(k as String)
        } else if (o is List<*>) {
            for (i in o.indices) ks.add(i.toString())
        }
        ks.sort()
        return ks
    }

    private fun member(o: Any?, k: String): Any? = if (o is List<*>) o[k.toInt()] else G.get(o, k)

    private fun act(out: MutableList<Any?>, a: Any?) {
        val params = G.get(a, "params")
        val keys = sortedKeys(params)
        out.add(kw(530))
        out.add(sv(G.get(a, "verb")))
        out.add(sv(G.get(a, "res")))
        out.add(iv(keys.size.toLong()))
        for (k in keys) {
            out.add(kw(520))
            out.add(sv(k))
            value(out, member(params, k))
        }
        out.add(iv(G.get(a, "t")))
        out.add(sv(G.get(a, "sess")))
        out.add(sv(G.get(a, "prin")))
        out.add(sv(G.get(a, "org")))
        out.add(sv(G.get(a, "agent")))
        out.add(iv(G.get(a, "depth")))
    }

    @JvmStatic
    fun encodeAct(a: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        act(out, a)
        return out
    }

    @JvmStatic
    fun encodeHist(h: Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        val aggs = G.get(h, "aggs")
        val keys = sortedKeys(aggs)
        out.add(kw(541))
        list(out, G.get(h, "adms")) { t, a ->
            t.add(kw(531))
            t.add(sv(G.get(a, "gid")))
            act(t, G.get(a, "act"))
        }
        out.add(iv(G.get(h, "last")))
        out.add(iv(keys.size.toLong()))
        for (k in keys) {
            out.add(kw(540))
            out.add(sv(k))
            quantity(out, member(aggs, k))
        }
        return out
    }

    // ---- decoding ----

    /** A cursor over a tape. */
    class Rd(private val t: List<Any?>) {
        private var i = 0

        private fun next(): List<Any?> {
            if (i >= t.size) throw IrError("truncated tape")
            val x = G.l(t[i++])
            if (x == null || x.size != 2) throw IrError("malformed token")
            return x
        }

        fun k(): Long {
            val x = next()
            if ("k" != x[0]) throw IrError("keyword expected")
            return tokInt(x[1])
        }

        fun integer(): Long {
            val x = next()
            if ("i" != x[0]) throw IrError("integer expected")
            return tokInt(x[1])
        }

        fun str(): String {
            val x = next()
            val s = x[1]
            if ("s" != x[0] || s !is String) throw IrError("string expected")
            return s
        }

        fun done(): Boolean = i >= t.size

        private fun tokInt(v: Any?): Long = G.safeInt(v) ?: throw IrError("integer expected")

        fun <T> list(f: () -> T): List<Any?> {
            val n = integer()
            if (n < 0) throw IrError("negative length")
            val out = ArrayList<Any?>()
            var j = 0L
            while (j < n) {
                out.add(f())
                j++
            }
            return out
        }

        fun strs(): List<Any?> = list { str() }
    }

    private fun dUnit(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 300L) return G.map("k" to "money", "ccy" to r.str())
        val u = when (k) {
            301L -> "count"
            302L -> "duration"
            303L -> "instant"
            304L -> "bytes"
            305L -> "ratio"
            else -> throw IrError("bad unit tag $k")
        }
        return G.map("k" to u)
    }

    private fun dQ(r: Rd): Map<String, Any?> {
        val u = dUnit(r)
        return G.map("u" to u, "n" to G.num(r.integer()))
    }

    private fun dTy(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 310L) return G.map("k" to "q", "u" to dUnit(r))
        if (k == 311L) return G.map("k" to "s")
        throw IrError("bad type tag $k")
    }

    private fun dAtom(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 320L) return G.map("k" to "q", "q" to dQ(r))
        if (k == 321L) return G.map("k" to "s", "s" to r.str())
        throw IrError("bad atom tag $k")
    }

    private fun dV(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 330L) return G.map("k" to "q", "q" to dQ(r))
        if (k == 331L) return G.map("k" to "s", "s" to r.str())
        if (k == 332L) return G.map("k" to "set", "items" to r.list { dAtom(r) })
        throw IrError("bad value tag $k")
    }

    private fun dTerm(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 340L) {
            val p = r.str()
            return G.map("k" to "param", "path" to p, "ty" to dTy(r))
        }
        if (k == 341L) return G.map("k" to "lit", "v" to dV(r))
        if (k == 342L) {
            val b = r.str()
            return G.map("k" to "hist", "bid" to b, "u" to dUnit(r))
        }
        throw IrError("bad term tag $k")
    }

    private fun dOp(r: Rd): String {
        val k = r.k() - 350
        if (k < 0 || k >= OPS.size) throw IrError("bad operator")
        return OPS[k.toInt()]
    }

    private fun dN(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 600L) return G.map("k" to "true")
        if (k == 601L) return G.map("k" to "false")
        if (k == 602L) {
            val op = dOp(r)
            val l = dTerm(r)
            return G.map("k" to "atom", "op" to op, "l" to l, "r" to dTerm(r))
        }
        if (k == 603L) {
            val a = dN(r)
            return G.map("k" to "and", "a" to a, "b" to dN(r))
        }
        if (k == 604L) {
            val a = dN(r)
            return G.map("k" to "or", "a" to a, "b" to dN(r))
        }
        throw IrError("bad condition tag $k")
    }

    private fun dResPat(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 630L) return G.map("k" to "star")
        if (k == 631L) return G.map("k" to "set", "ids" to r.strs())
        throw IrError("bad resource pattern tag $k")
    }

    private fun dWindow(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 420L) return G.map("k" to "task")
        if (k == 421L) return G.map("k" to "sliding", "ms" to G.num(r.integer()))
        if (k == 422L) {
            val ms = r.integer()
            return G.map("k" to "period", "ms" to G.num(ms), "t0" to G.num(r.integer()))
        }
        if (k == 423L) return G.map("k" to "lifetime")
        throw IrError("bad window tag $k")
    }

    private fun dScope(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 430L) return G.map("k" to "session")
        if (k == 431L) return G.map("k" to "principal")
        if (k == 432L) return G.map("k" to "org")
        if (k == 433L) return G.map("k" to "fleet", "agents" to r.strs())
        throw IrError("bad scope tag $k")
    }

    /** Remaining fields of a bound core after the 450 tag: agg, value, key, window, scope, cap, onExceed. */
    private fun dBoundCore(r: Rd, into: MutableMap<String, Any?>) {
        val ak = r.k() - 400
        if (ak < 0 || ak >= AGGS.size) throw IrError("bad aggregate")
        into["agg"] = AGGS[ak.toInt()]
        into["value"] = dTerm(r)
        into["key"] = r.str()
        into["window"] = dWindow(r)
        into["scope"] = dScope(r)
        into["cap"] = dQ(r)
        val oe = r.k()
        if (oe != 440L && oe != 441L) throw IrError("bad on_exceed")
        into["onExceed"] = if (oe == 440L) "deny" else "escalate"
    }

    private fun dCeil(r: Rd): Map<String, Any?> {
        if (r.k() != 610L) throw IrError("ceiling expected")
        val m = LinkedHashMap<String, Any?>()
        m["bid"] = r.str()
        m["selGids"] = r.strs()
        m["selVerbs"] = r.strs()
        if (r.k() != 450L) throw IrError("bound core expected")
        dBoundCore(r, m)
        return m
    }

    /** Decode the compiler's policy tape (the leading status token already consumed). */
    @JvmStatic
    fun decodePolicy(t: List<Any?>): Map<String, Any?> {
        val r = Rd(t)
        if (r.k() != 650L) throw IrError("policy expected")
        val preds = r.list {
            if (r.k() != 620L) throw IrError("pred")
            val gid = r.str()
            val verb = r.str()
            val rp = dResPat(r)
            G.map("gid" to gid, "verb" to verb, "res" to rp, "cond" to dN(r))
        }
        val prohs = r.list {
            if (r.k() != 640L) throw IrError("prohibition")
            val pid = r.str()
            val vs = r.strs()
            val rp = dResPat(r)
            G.map("pid" to pid, "verbs" to vs, "res" to rp, "cond" to dN(r))
        }
        val ceils = r.list { dCeil(r) }
        val escs = r.list { dN(r) }
        if (r.k() != 460L) throw IrError("validity")
        val nb = r.integer()
        val na = r.integer()
        val mi = r.integer()
        val validity = G.map("notBefore" to G.num(nb), "notAfter" to G.num(na), "maxIdle" to G.num(mi))
        if (r.k() != 461L) throw IrError("delegation")
        val md = r.integer()
        val no = r.integer() == 1L
        val mt = r.strs()
        val deleg = G.map("maxDepth" to G.num(md), "narrowOnly" to no, "mayTouch" to mt)
        if (!r.done()) throw IrError("trailing tokens after policy")
        return G.map("preds" to preds, "prohs" to prohs, "ceils" to ceils, "escs" to escs, "validity" to validity, "deleg" to deleg)
    }

    private fun dCond(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 360L) return G.map("k" to "true")
        if (k == 361L) {
            val op = dOp(r)
            val l = dTerm(r)
            return G.map("k" to "cmp", "op" to op, "l" to l, "r" to dTerm(r))
        }
        if (k == 362L) {
            val a = dCond(r)
            return G.map("k" to "and", "a" to a, "b" to dCond(r))
        }
        if (k == 363L) {
            val a = dCond(r)
            return G.map("k" to "or", "a" to a, "b" to dCond(r))
        }
        if (k == 364L) return G.map("k" to "not", "c" to dCond(r))
        throw IrError("bad condition tag $k")
    }

    private fun dPart(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 375L) return G.map("k" to "exact", "id" to r.str())
        if (k == 376L) return G.map("k" to "oneof", "ids" to r.strs())
        if (k == 377L) {
            val rel = r.str()
            return G.map("k" to "related", "rel" to rel, "anchor" to r.str())
        }
        throw IrError("bad resource part tag $k")
    }

    private fun dRes(r: Rd): Map<String, Any?> {
        val k = r.k()
        if (k == 370L) return G.map("k" to "exact", "id" to r.str())
        if (k == 371L) return G.map("k" to "oneof", "ids" to r.strs())
        if (k == 372L) {
            val rel = r.str()
            return G.map("k" to "related", "rel" to rel, "anchor" to r.str())
        }
        if (k == 373L) return G.map("k" to "any", "reason" to r.str())
        if (k == 374L) return G.map("k" to "all_of", "parts" to r.list { dPart(r) })
        throw IrError("bad resource selector tag $k")
    }

    private fun expect(r: Rd, k: Long, what: String) {
        if (r.k() != k) throw IrError("$what expected")
    }

    /** Parse a goal tape; throws IrError unless the whole tape is exactly one goal. */
    @JvmStatic
    fun decodeGoal(t: List<Any?>): Map<String, Any?> {
        val r = Rd(t)
        expect(r, 480, "goal")
        val v = r.integer()
        val principal = r.str()
        val ontDigest = r.str()
        val nlDigest = r.str()
        val sources = r.strs()
        val grants = r.list {
            expect(r, 380, "grant")
            val gid = r.str()
            val verb = r.str()
            val rs = dRes(r)
            G.map("gid" to gid, "verb" to verb, "res" to rs, "cond" to dCond(r))
        }
        val prohibits = r.list {
            expect(r, 392, "prohibit")
            val pid = r.str()
            val tk = r.k()
            val target: Map<String, Any?> = when (tk) {
                390L -> G.map("k" to "verb", "verb" to r.str())
                391L -> G.map("k" to "effect", "cls" to r.str())
                else -> throw IrError("bad prohibit target")
            }
            val rs = dRes(r)
            G.map("pid" to pid, "target" to target, "res" to rs, "cond" to dCond(r))
        }
        val bounds = r.list {
            expect(r, 451, "bound")
            val m = LinkedHashMap<String, Any?>()
            m["bid"] = r.str()
            val sk = r.k()
            if (sk == 410L) m["sel"] = G.map("k" to "gids", "gids" to r.strs())
            else if (sk == 411L) m["sel"] = G.map("k" to "effect", "cls" to r.str())
            else throw IrError("bad selection")
            expect(r, 450, "bound core")
            dBoundCore(r, m)
            m
        }
        expect(r, 460, "validity")
        val nb = r.integer()
        val na = r.integer()
        val mi = r.integer()
        val validity = G.map("notBefore" to G.num(nb), "notAfter" to G.num(na), "maxIdle" to G.num(mi))
        expect(r, 461, "delegation")
        val md = r.integer()
        val no = r.integer() == 1L
        val mt = r.strs()
        val deleg = G.map("maxDepth" to G.num(md), "narrowOnly" to no, "mayTouch" to mt)
        val escalateOn = r.list { dCond(r) }
        val wildcardAck = r.strs()
        val holes = r.list {
            expect(r, 470, "hole")
            val hid = r.str()
            val q = r.str()
            val dom = r.strs()
            val aff = r.strs()
            val gl = r.integer() == 1L
            G.map("hid" to hid, "q" to q, "domain" to dom, "affects" to aff, "global" to gl)
        }
        if (!r.done()) throw IrError("trailing tokens after goal")
        val g = LinkedHashMap<String, Any?>()
        g["v"] = G.num(v)
        g["principal"] = principal
        g["ontDigest"] = ontDigest
        g["nlDigest"] = nlDigest
        g["sources"] = sources
        g["grants"] = grants
        g["prohibits"] = prohibits
        g["bounds"] = bounds
        g["validity"] = validity
        g["deleg"] = deleg
        g["escalateOn"] = escalateOn
        g["wildcardAck"] = wildcardAck
        g["holes"] = holes
        return g
    }
}
