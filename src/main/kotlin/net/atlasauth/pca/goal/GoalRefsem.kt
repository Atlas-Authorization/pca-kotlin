package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json

/**
 * An independent reading of the goal semantics D_G for the grammar the tests generate (conditions, grants, prohibitions, count /
 * sum / max / distinct bounds, validity, delegation). Three-valued: 0 false/deny, 1 unknown/escalate, 2 true/allow. Numbers are
 * JavaScript doubles, as in the reference.
 */
object GoalRefsem {
    private fun and(a: Int, b: Int): Int = Math.min(a, b)
    private fun or(a: Int, b: Int): Int = Math.max(a, b)
    private fun not(a: Int): Int = 2 - a
    private fun b2t(b: Boolean): Int = if (b) 2 else 0
    private fun sameUnit(a: Any?, b: Any?): Boolean = G.stringify(a) == G.stringify(b)

    private fun has(m: Map<String, Any?>, k: Any?): Boolean = k is String && m.containsKey(k)

    private fun n(o: Any?): Double = G.toNum(o)

    /** JavaScript `===` on two parsed JSON scalars. */
    private fun seq(a: Any?, b: Any?): Boolean {
        val x = G.strictNum(a)
        val y = G.strictNum(b)
        if (x != null || y != null) return x != null && y != null && x == y
        return a == b
    }

    private fun value(t: Map<String, Any?>?, a: Map<String, Any?>, h: Map<String, Any?>): Map<String, Any?>? {
        val k = G.kind(t)
        if (k == "param") {
            val ps = G.m(a["params"])
            if (a["params"] == null) throw IrError("params expected")
            return if (ps != null && has(ps, t!!["path"])) G.m(ps[t["path"] as String]) else null
        }
        if (k == "lit") return G.m(t!!["v"])
        val aggs = G.m(h["aggs"])
        return if (aggs != null && has(aggs, t!!["bid"])) G.map("k" to "q", "q" to aggs[t["bid"] as String]) else null
    }

    // `v.q.n`: a missing / null q throws, a primitive q has no members (undefined)
    private fun qmember(v: Map<String, Any?>, k: String): Any? {
        val q = v["q"] ?: throw NullPointerException("Cannot read properties of " + (if (v.containsKey("q")) "null" else "undefined") + " (reading '$k')")
        return if (q is Map<*, *>) q[k] else null
    }
    private fun qn(v: Map<String, Any?>): Any? = qmember(v, "n")
    private fun qu(v: Map<String, Any?>): Any? = qmember(v, "u")

    private fun eq(x: Map<String, Any?>, y: Map<String, Any?>): Int {
        val kx = G.kind(x)
        val ky = G.kind(y)
        if (kx == "q" && ky == "q") return if (sameUnit(qu(x), qu(y))) b2t(seq(qn(x), qn(y))) else 1
        if (kx == "s" && ky == "s") return b2t(seq(x["s"], y["s"]))
        return 1
    }

    private fun lt(x: Map<String, Any?>, y: Map<String, Any?>): Int =
        if (G.kind(x) == "q" && G.kind(y) == "q" && sameUnit(qu(x), qu(y))) b2t(n(qn(x)) < n(qn(y))) else 1

    private fun inSet(x: Map<String, Any?>, y: Map<String, Any?>): Int {
        if (G.kind(y) != "set") return 1
        var acc = 0
        for (it in G.arr(y["items"], "items")) acc = or(acc, eq(x, G.m(it)!!))
        return acc
    }

    private fun cmp(op: String, x: Map<String, Any?>?, y: Map<String, Any?>?): Int {
        if (x == null || y == null) return 1
        return when (op) {
            "eq" -> eq(x, y)
            "ne" -> not(eq(x, y))
            "lt" -> lt(x, y)
            "gte" -> not(lt(x, y))
            "gt" -> lt(y, x)
            "lte" -> not(lt(y, x))
            "in" -> inSet(x, y)
            else -> not(inSet(x, y))
        }
    }

    private fun evalC(c: Map<String, Any?>?, a: Map<String, Any?>, h: Map<String, Any?>): Int = when (G.kind(c)) {
        "true" -> 2
        "cmp" -> cmp(c!!["op"].toString(), value(G.m(c["l"]), a, h), value(G.m(c["r"]), a, h))
        "and" -> and(evalC(G.m(c!!["a"]), a, h), evalC(G.m(c["b"]), a, h))
        "or" -> or(evalC(G.m(c!!["a"]), a, h), evalC(G.m(c["b"]), a, h))
        "not" -> not(evalC(G.m(c!!["c"]), a, h))
        else -> throw IrError("unknown condition")
    }

    private fun includes(list: Any?, x: Any?): Boolean {
        val l = G.l(list) ?: return false
        for (o in l) if (o != null && o == x) return true
        return false
    }

    private fun resOk(s: Map<String, Any?>?, ont: Map<String, Any?>, r: Any?): Boolean {
        when (G.kind(s)) {
            "any" -> return true
            "exact" -> return seq(r, s!!["id"])
            "oneof" -> return includes(s!!["ids"], r)
            "related" -> {
                for (x in G.arr(ont["rels"], "rels")) {
                    if (s!!["rel"] != null && s["rel"] == G.get(x, "rel") && s["anchor"] != null && s["anchor"] == G.get(x, "anchor")) return includes(G.get(x, "members"), r)
                }
                return false
            }
            "all_of" -> {
                for (p in G.arr(s!!["parts"], "parts")) if (!resOk(G.m(p), ont, r)) return false
                return true
            }
            else -> throw IrError("unknown selector")
        }
    }

    private fun verbsOf(ont: Map<String, Any?>, cls: Any?): List<Any?> {
        val out = ArrayList<Any?>()
        for (v in G.arr(ont["verbs"], "verbs")) if (cls != null && cls == G.get(v, "cls")) out.add(G.get(v, "verb"))
        return out
    }

    private fun inScope(sc: Map<String, Any?>?, a: Map<String, Any?>, x: Map<String, Any?>): Boolean = when (G.kind(sc)) {
        "session" -> a["sess"] == x["sess"]
        "principal" -> a["prin"] == x["prin"]
        "org" -> a["org"] == x["org"]
        "fleet" -> includes(sc!!["agents"], a["agent"]) && includes(sc["agents"], x["agent"])
        else -> false
    }

    private fun inWin(w: Map<String, Any?>?, a: Map<String, Any?>, x: Map<String, Any?>): Boolean = when (G.kind(w)) {
        "task", "lifetime" -> true
        "sliding" -> n(x["t"]) > n(a["t"]) - n(w!!["ms"]) && n(x["t"]) <= n(a["t"])
        "period" -> {
            val ms = n(w!!["ms"])
            ms > 0 && Math.floor((n(a["t"]) - n(w["t0"])) / ms) == Math.floor((n(x["t"]) - n(w["t0"])) / ms)
        }
        else -> false
    }

    /** The decision (0 deny, 1 escalate, 2 allow); see [refExplain]. */
    @JvmStatic
    fun refDecide(g: Map<String, Any?>, ont: Map<String, Any?>, a: Map<String, Any?>, h: Map<String, Any?>): Int =
        (refExplain(g, ont, a, h)["d"] as Json.Num).raw.toInt()

    /** {d, witness, prohibit}: witness is the first grant whose own decision is allow (only when d = 2); prohibit is the meet over the prohibitions. */
    @JvmStatic
    fun refExplain(g: Map<String, Any?>, ont: Map<String, Any?>, a: Map<String, Any?>, h: Map<String, Any?>): Map<String, Any?> {
        var d = 2
        var prohibit = 2
        var witness: String? = null
        val validity = G.m(g["validity"])!!
        val deleg = G.m(g["deleg"])!!
        val t = n(a["t"])
        val depth = n(a["depth"])
        if (t < n(validity["notBefore"]) || t > n(validity["notAfter"])) d = Math.min(d, 0)
        else if (n(validity["maxIdle"]) > 0 && n(h["last"]) >= 0 && t - n(h["last"]) > n(validity["maxIdle"])) d = Math.min(d, 0)
        else if (depth < 0 || depth > n(deleg["maxDepth"])) d = Math.min(d, 0)
        for (po in G.arr(g["prohibits"], "prohibits")) {
            val p = G.m(po)!!
            val tg = G.m(p["target"])!!
            val verbs: List<Any?> = if (G.kind(tg) == "verb") arrayListOf(tg["verb"]) else verbsOf(ont, tg["cls"])
            val m = and(b2t(includes(verbs, a["verb"])), and(b2t(resOk(G.m(p["res"]), ont, a["res"])), evalC(G.m(p["cond"]), a, h)))
            val pd = if (m == 2) 0 else if (m == 1) 1 else 2
            d = Math.min(d, pd)
            prohibit = Math.min(prohibit, pd)
        }
        for (c in G.arr(g["escalateOn"], "escalateOn")) d = Math.min(d, if (evalC(G.m(c), a, h) == 0) 2 else 1)
        var best = 0
        for (gro in G.arr(g["grants"], "grants")) {
            val gr = G.m(gro)!!
            val m = and(
                b2t(a["verb"] == gr["verb"] && (seq(a["depth"], G.num(0)) || includes(deleg["mayTouch"], gr["gid"]))),
                and(b2t(resOk(G.m(gr["res"]), ont, a["res"])), evalC(G.m(gr["cond"]), a, h)),
            )
            var gd = m
            for (bo in G.arr(g["bounds"], "bounds")) {
                val b = G.m(bo)!!
                val sel = G.m(b["sel"])
                val gids: List<Any?> = if (G.kind(sel) == "gids") G.arr(sel!!["gids"], "gids") else ArrayList()
                val verbs: List<Any?> = if (G.kind(sel) == "effect") verbsOf(ont, sel!!["cls"]) else ArrayList()
                if (!(includes(gids, gr["gid"]) || includes(verbs, a["verb"]))) continue
                val items = ArrayList<Map<String, Any?>>()
                for (ao in G.arr(h["adms"], "adms")) {
                    val x = G.m(G.m(ao)!!["act"])!!
                    if ((includes(gids, G.m(ao)!!["gid"]) || includes(verbs, x["verb"])) && inScope(G.m(b["scope"]), a, x) && inWin(G.m(b["window"]), a, x)) items.add(x)
                }
                items.add(a)
                val cap = G.m(b["cap"])!!
                val agg = b["agg"].toString()
                val ex: Int
                if (agg == "count") ex = b2t(items.size > n(cap["n"]))
                else if (agg == "sum" || agg == "max") {
                    val xs = ArrayList<Double>()
                    var ok = true
                    for (it in items) {
                        val v = value(G.m(b["value"]), it, h)
                        if (v == null || G.kind(v) != "q" || !sameUnit(qu(v), cap["u"])) {
                            ok = false
                            break
                        }
                        xs.add(n(qn(v)))
                    }
                    if (!ok) ex = 1
                    else if (agg == "sum") {
                        var s = 0.0
                        for (x in xs) s += x
                        ex = b2t(s > n(cap["n"]))
                    } else if (xs.isEmpty()) ex = 1
                    else {
                        var mx = Double.NEGATIVE_INFINITY
                        for (x in xs) {
                            if (x.isNaN()) {
                                mx = Double.NaN
                                break
                            }
                            mx = Math.max(mx, x)
                        }
                        ex = b2t(mx > n(cap["n"]))
                    }
                } else {
                    val ks = HashSet<String>()
                    var ok = true
                    for (it in items) {
                        val ps = G.m(it["params"])
                        if (ps == null || !has(ps, b["key"])) {
                            ok = false
                            break
                        }
                        ks.add(G.stringify(ps[b["key"] as String]))
                    }
                    ex = if (ok) b2t(ks.size > n(cap["n"])) else 1
                }
                gd = Math.min(gd, if (ex == 2) (if ("deny" == b["onExceed"]) 0 else 1) else if (ex == 1) 1 else 2)
            }
            if (gd == 2 && witness == null) witness = gr["gid"] as String?
            best = Math.max(best, gd)
        }
        d = Math.min(d, best)
        return G.map("d" to G.num(d), "witness" to (if (d == 2) witness else null), "prohibit" to G.num(prohibit))
    }
}
