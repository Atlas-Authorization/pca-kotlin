package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * Boundary examples and signed goal tests over the IR and its reference semantics. An action is classified per coordinate
 * (verb, resource, relation bits, each parameter) against the literals of the policies; [cells] enumerates one
 * representative per decision cell. Goals, acts and histories are parsed-JSON maps.
 */
@Suppress("UNCHECKED_CAST")
object GoalExamples {
    /** The classification space of one or more goals. */
    class Space {
        @JvmField var verbs: MutableList<String> = ArrayList()
        @JvmField var resources: MutableList<String> = ArrayList()

        /** {rel, anchor} pairs. */
        @JvmField var rels: MutableList<Array<String>> = ArrayList()

        /** param -> (unit key -> sorted distinct values), insertion ordered. */
        @JvmField var q: MutableMap<String, MutableMap<String, MutableList<Long>>> = LinkedHashMap()

        /** param -> sorted distinct discrete keys ("s:" + text). */
        @JvmField var d: MutableMap<String, MutableList<String>> = LinkedHashMap()

        fun toJson(): Map<String, Any?> {
            val rs = ArrayList<Any?>()
            for (r in rels) rs.add(G.map("rel" to r[0], "anchor" to r[1]))
            val qj = LinkedHashMap<String, Any?>()
            for ((k, groups) in q) {
                val inner = LinkedHashMap<String, Any?>()
                for ((gk, gv) in groups) {
                    val ns = ArrayList<Any?>()
                    for (v in gv) ns.add(G.num(v))
                    inner[gk] = ns
                }
                qj[k] = inner
            }
            val dj = LinkedHashMap<String, Any?>()
            for ((k, v) in d) dj[k] = ArrayList<Any?>(v)
            return G.map("verbs" to ArrayList<Any?>(verbs), "resources" to ArrayList<Any?>(resources), "rels" to rs, "q" to qj, "d" to dj)
        }
    }

    private fun emptyHist(): MutableMap<String, Any?> =
        G.map("adms" to ArrayList<Any?>(), "last" to G.num(-1), "aggs" to LinkedHashMap<String, Any?>())

    @JvmStatic
    fun decisionOf(d: Int): String = if (d == 2) "allow" else if (d == 1) "escalate" else "deny"

    @JvmStatic
    fun rankOf(d: String?): Int = if (d == "allow") 0 else if (d == "escalate") 1 else 2

    /** An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0). */
    @JvmStatic
    fun mkAct(verb: String?, res: String?, params: Map<String, Any?>?): MutableMap<String, Any?> =
        G.map("verb" to verb, "res" to res, "params" to params, "t" to G.num(0), "sess" to "s", "prin" to "p", "org" to "o", "agent" to "a", "depth" to G.num(0))

    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    /** The reference decision of a goal for an action, its history and its relation facts: {decision, witness, prohibited}. */
    @JvmStatic
    fun decideCase(g: Map<String, Any?>, ont: Map<String, Any?>, c: Map<String, Any?>): Map<String, Any?> {
        val rels = c["rels"]
        var o: Map<String, Any?> = ont
        if (rels != null) {
            val oo = LinkedHashMap(ont)
            oo["rels"] = rels
            o = oo
        }
        val hist = c["hist"]
        val x = GoalRefsem.refExplain(g, o, mm(c["act"])!!, if (hist == null) emptyHist() else mm(hist)!!)
        val d = (x["d"] as Json.Num).raw.toInt()
        val p = (x["prohibit"] as Json.Num).raw.toInt()
        return G.map("decision" to decisionOf(d), "witness" to x["witness"], "prohibited" to (p < 2))
    }

    /** The history of the admitted prefix of [acts]: an action the goal refuses is not recorded. */
    @JvmStatic
    fun replay(g: Map<String, Any?>, ont: Map<String, Any?>, acts: List<Any?>, rels: List<Any?>?): Map<String, Any?> {
        val h = emptyHist()
        val adms = h["adms"] as MutableList<Any?>
        for (a in acts) {
            val c = G.map("act" to a, "hist" to h, "rels" to rels)
            val v = decideCase(g, ont, c)
            if (v["decision"] == "allow" && v["witness"] != null) {
                adms.add(G.map("gid" to v["witness"], "act" to a))
                h["last"] = G.get(a, "t")
            }
        }
        return h
    }

    // ---- space ----
    private fun qval(q: Map<String, Any?>): Long = G.safeInt(q["n"]) ?: throw IrError("quantity is not a safe integer")

    private fun qkey(q: Map<String, Any?>): String {
        val u = mm(q["u"])
        return if (G.kind(u) == "money") "money:" + G.jsStr(u!!["ccy"]) else G.kind(u)
    }

    private fun unitOfKey(key: String): Map<String, Any?> =
        if (key.startsWith("money:")) G.map("k" to "money", "ccy" to key.substring(6)) else G.map("k" to key)

    private fun dkey(v: Map<String, Any?>?): String? = if (G.kind(v) == "s") "s:" + G.jsStr(v!!["s"]) else null

    private fun walkCond(c: Map<String, Any?>?, f: (String, Map<String, Any?>?) -> Unit) {
        when (G.kind(c)) {
            "cmp" -> {
                val l = mm(c!!["l"])
                val r = mm(c["r"])
                val p = if (G.kind(l) == "param") l!!["path"] as String else if (G.kind(r) == "param") r!!["path"] as String else null
                val other = if (G.kind(l) == "param") r else l
                if (p == null || G.kind(other) != "lit") return
                val v = mm(other!!["v"])
                if (G.kind(v) == "set") {
                    for (i in G.arr(v!!["items"], "items")) f(p, mm(i))
                } else f(p, v)
            }
            "and", "or" -> {
                walkCond(mm(c!!["a"]), f)
                walkCond(mm(c["b"]), f)
            }
            "not" -> walkCond(mm(c!!["c"]), f)
            else -> {}
        }
    }

    private fun parts(s: Map<String, Any?>?): List<Map<String, Any?>?> {
        val out = ArrayList<Map<String, Any?>?>()
        val k = G.kind(s)
        if (k == "all_of") {
            for (p in G.arr(s!!["parts"], "parts")) out.add(mm(p))
        } else if (k != "any") out.add(s)
        return out
    }

    private fun sorted(s: Collection<String>): MutableList<String> {
        val l = ArrayList(s)
        l.sort()
        return l
    }

    /** The space of the goals plus extra verbs. */
    @JvmStatic
    fun buildSpace(goals: List<Map<String, Any?>>, extraVerbs: List<String>): Space {
        val verbs = LinkedHashSet<String>(extraVerbs)
        val resources = LinkedHashSet<String>()
        val rels = LinkedHashMap<String, Array<String>>()
        val q = LinkedHashMap<String, LinkedHashMap<String, LinkedHashSet<Long>>>()
        val d = LinkedHashMap<String, LinkedHashSet<String>>()
        val lit: (String, Map<String, Any?>?) -> Unit = { p, v ->
            if (G.kind(v) == "q") {
                val qq = mm(v!!["q"])!!
                q.getOrPut(p) { LinkedHashMap() }.getOrPut(qkey(qq)) { LinkedHashSet() }.add(qval(qq))
            } else {
                val k = dkey(v)
                if (k != null) d.getOrPut(p) { LinkedHashSet() }.add(k)
            }
        }
        val res: (Map<String, Any?>?) -> Unit = { s ->
            for (x in parts(s)) {
                when (G.kind(x)) {
                    "exact" -> resources.add(x!!["id"] as String)
                    "oneof" -> for (i in G.arr(x!!["ids"], "ids")) resources.add(i as String)
                    else -> rels[G.jsStr(x!!["rel"]) + "\u0000" + G.jsStr(x["anchor"])] = arrayOf(x["rel"] as String, x["anchor"] as String)
                }
            }
        }
        for (g in goals) {
            for (gro in G.arr(g["grants"], "grants")) {
                val gr = mm(gro)!!
                verbs.add(gr["verb"] as String)
                res(mm(gr["res"]))
                walkCond(mm(gr["cond"]), lit)
            }
            for (po in G.arr(g["prohibits"], "prohibits")) {
                val p = mm(po)!!
                val t = mm(p["target"])
                if (G.kind(t) == "verb") verbs.add(t!!["verb"] as String)
                res(mm(p["res"]))
                walkCond(mm(p["cond"]), lit)
            }
            for (c in G.arr(g["escalateOn"], "escalateOn")) walkCond(mm(c), lit)
            for (bo in G.arr(g["bounds"], "bounds")) {
                val b = mm(bo)!!
                val v = mm(b["value"])
                if (b["agg"] == "sum" && G.kind(v) == "param") lit(v!!["path"] as String, G.map("k" to "q", "q" to b["cap"]))
            }
        }
        val sp = Space()
        sp.verbs = sorted(verbs)
        sp.resources = sorted(resources)
        sp.rels = ArrayList(rels.values)
        sp.rels.sortBy { it[0] + it[1] }
        for ((k, groups) in q) {
            val inner = LinkedHashMap<String, MutableList<Long>>()
            for ((gk, gv) in groups) {
                val ns = ArrayList(gv)
                ns.sort()
                inner[gk] = ns
            }
            sp.q[k] = inner
        }
        for ((k, v) in d) sp.d[k] = sorted(v)
        return sp
    }

    private fun classifyLit(sp: Space, p: String, l: Map<String, Any?>?): String {
        if (l == null || G.kind(l) == "set") return "missing"
        val groups = sp.q[p]
        val ds = sp.d[p]
        if (G.kind(l) == "q") {
            val qq = mm(l["q"])!!
            val g = groups?.get(qkey(qq))
            if (g == null) return if (groups != null || ds != null) "unit" else "any"
            val v = qval(qq)
            val i = g.indexOf(v)
            if (i >= 0) return qkey(qq) + "=" + i
            var pos = 0
            while (pos < g.size && g[pos] < v) pos++
            return qkey(qq) + "@" + pos
        }
        val k = dkey(l)
        if (ds == null) return if (groups != null) "unit" else "any"
        return if (k != null && ds.contains(k)) k else "other"
    }

    private fun relBit(c: Map<String, Any?>, rel: String, anchor: String): Int {
        for (xo in G.arr(c["rels"], "rels")) {
            val x = mm(xo)!!
            if (rel == x["rel"] && anchor == x["anchor"]) return if (G.arr(x["members"], "members").contains(mm(c["act"])!!["res"])) 1 else 0
        }
        return 0
    }

    /** The decision cell of a case under a space (canonical string; the unit of precedents). */
    @JvmStatic
    fun cellKey(sp: Space, c: Map<String, Any?>): String {
        val params = LinkedHashSet<String>(sp.q.keys)
        params.addAll(sp.d.keys)
        val act = mm(c["act"])!!
        val l = ArrayList<Any?>()
        for (r in sp.rels) l.add(G.num(relBit(c, r[0], r[1])))
        val pm = LinkedHashMap<String, Any?>()
        val actParams = mm(act["params"])
        for (p in sorted(params)) pm[p] = classifyLit(sp, p, if (actParams == null) null else mm(actParams[p]))
        val verb = act["verb"]
        val res = act["res"]
        return G.stable(G.map("v" to (if (verb is String && sp.verbs.contains(verb)) verb else "*"), "r" to (if (res is String && sp.resources.contains(res)) res else "*"), "l" to l, "p" to pm))
    }

    private const val OTHER = "\u0000other"
    const val MAX_CELLS = 40000

    private fun paramOptions(sp: Space, p: String): List<Map<String, Any?>?> {
        val out = ArrayList<Map<String, Any?>?>()
        out.add(null) // the parameter absent
        val seen = HashSet<String>()
        val add: (Map<String, Any?>) -> Unit = { v -> if (seen.add(G.stable(v))) out.add(v) }
        val groups = sp.q[p]
        if (groups != null) {
            for ((key, vals) in groups) {
                val isInstant = key == "instant"
                for (v in vals) for (x in longArrayOf(v - 1, v, v + 1)) {
                    if (x >= 0 || isInstant) add(G.map("k" to "q", "q" to G.map("u" to unitOfKey(key), "n" to G.num(x))))
                }
                if (key.startsWith("money:")) add(G.map("k" to "q", "q" to G.map("u" to G.map("k" to "money", "ccy" to "ZZZ"), "n" to G.num(0))))
            }
        }
        val ds = sp.d[p]
        if (ds != null) for (k in ds) add(G.map("k" to "s", "s" to k.substring(2)))
        if (sp.d.containsKey(p)) add(G.map("k" to "s", "s" to OTHER))
        return out
    }

    private fun build(sp: Space, params: List<String>, verb: String, resource: String, bits: Int, choice: List<Map<String, Any?>?>): Map<String, Any?> {
        val pr = LinkedHashMap<String, Any?>()
        for (i in params.indices) if (choice[i] != null) pr[params[i]] = choice[i]
        val rels = ArrayList<Any?>()
        for (i in sp.rels.indices) {
            val members = ArrayList<Any?>()
            if ((bits and (1 shl i)) != 0) members.add(resource)
            rels.add(G.map("rel" to sp.rels[i][0], "anchor" to sp.rels[i][1], "members" to members))
        }
        return G.map("act" to mkAct(verb, resource, pr), "rels" to rels)
    }

    /** One representative per decision cell: {cases, complete} (complete false when the grid exceeded MAX_CELLS: then a subset). */
    @JvmStatic
    fun cells(sp: Space, verbsOpt: List<String>?): Map<String, Any?> {
        val verbs: MutableList<String> = if (verbsOpt != null) ArrayList(verbsOpt) else ArrayList(sp.verbs)
        if (verbsOpt == null) verbs.add("\u0000other-verb")
        val resources = ArrayList(sp.resources)
        resources.add("\u0000other-resource")
        val ps = LinkedHashSet<String>(sp.q.keys)
        ps.addAll(sp.d.keys)
        val params = sorted(ps)
        val pOpts = ArrayList<List<Map<String, Any?>?>>()
        for (p in params) pOpts.add(paramOptions(sp, p))
        val relBits = sp.rels.size
        var total = verbs.size.toDouble() * resources.size * Math.pow(2.0, relBits.toDouble())
        for (o in pOpts) total *= o.size
        val complete = total <= MAX_CELLS
        val out = ArrayList<Any?>()
        val seen = HashSet<String>()
        val push: (Map<String, Any?>) -> Unit = { c -> if (seen.add(cellKey(sp, c))) out.add(c) }
        val nbits = 1 shl relBits
        if (complete) {
            val idx = IntArray(params.size)
            for (verb in verbs) for (res in resources) for (bits in 0 until nbits) {
                java.util.Arrays.fill(idx, 0)
                while (true) {
                    val choice = ArrayList<Map<String, Any?>?>()
                    for (i in idx.indices) choice.add(pOpts[i][idx[i]])
                    push(build(sp, params, verb, res, bits, choice))
                    var k = 0
                    while (k < idx.size) {
                        idx[k]++
                        if (idx[k] == pOpts[k].size) {
                            idx[k] = 0
                            k++
                        } else break
                    }
                    if (k == idx.size) break
                }
            }
        } else {
            for (verb in verbs) {
                val base = ArrayList<Map<String, Any?>?>()
                for (o in pOpts) base.add(o[Math.min(2, o.size - 1)])
                push(build(sp, params, verb, resources[0], 0, base))
                for (res in resources) for (bits in 0 until nbits) push(build(sp, params, verb, res, bits, base))
                for (i in pOpts.indices) for (l in pOpts[i]) {
                    val ch = ArrayList(base)
                    ch[i] = l
                    push(build(sp, params, verb, resources[0], 0, ch))
                }
            }
        }
        return G.map("cases" to out, "complete" to complete)
    }

    private fun magnitude(a: Map<String, Any?>): Long {
        var s = 0L
        val ps = mm(a["params"])
        if (ps != null) for (v in ps.values) if (G.kind(v) == "q") s += Math.abs(qval(mm(G.get(v, "q"))!!))
        return s
    }

    /** The smallest-magnitude case the grant admits (a minimal Allow witness), or null if its Allow set is empty. */
    @JvmStatic
    fun allowWitness(g: Map<String, Any?>, gr: Map<String, Any?>, ont: Map<String, Any?>): Map<String, Any?>? {
        val sp = buildSpace(listOf(g), ArrayList())
        var best: Map<String, Any?>? = null
        val cs = cells(sp, arrayListOf(gr["verb"] as String))
        for (co in G.arr(cs["cases"], "cases")) {
            val c = mm(co)!!
            val v = decideCase(g, ont, c)
            if (v["decision"] == "allow" && v["witness"] != null && v["witness"] == gr["gid"] && (best == null || magnitude(mm(c["act"])!!) < magnitude(mm(best["act"])!!))) best = c
        }
        return best
    }

    private fun example(kind: String, why: String, cs: Map<String, Any?>, hist: Map<String, Any?>, g: Map<String, Any?>, ont: Map<String, Any?>): Map<String, Any?> {
        val body = G.map("act" to cs["act"], "hist" to hist, "rels" to cs["rels"])
        val id = kind + ":" + Pca.hashCanonical(body).substring(0, 12)
        val dc = decideCase(g, ont, G.map("act" to cs["act"], "hist" to hist, "rels" to cs["rels"]))
        return G.map("id" to id, "kind" to kind, "why" to why, "act" to cs["act"], "hist" to hist, "rels" to cs["rels"], "decision" to dc["decision"])
    }

    /** The full example set (cell representatives, cap sequences, unmentioned-dimension probes): {examples, complete}. */
    @JvmStatic
    fun boundaryExamples(g: Map<String, Any?>, ont: Map<String, Any?>, extra: List<Map<String, Any?>>?, verbsOpt: List<String>?): Map<String, Any?> {
        val goals = ArrayList<Map<String, Any?>>()
        goals.add(g)
        if (extra != null) goals.addAll(extra)
        val sp = buildSpace(goals, verbsOpt ?: ArrayList())
        val c = cells(sp, null)
        val out = ArrayList<Any?>()
        for (cso in G.arr(c["cases"], "cases")) {
            val cs = mm(cso)!!
            val v = decideCase(g, ont, cs)
            val prohibited = v["prohibited"] == true
            out.add(example(if (prohibited && v["decision"] == "deny") "prohibit_trigger" else if (v["decision"] == "allow") "member" else "boundary", "cell " + v["decision"], cs, emptyHist(), g, ont))
        }
        for (gro in G.arr(g["grants"], "grants")) {
            val w = allowWitness(g, mm(gro)!!, ont)
            if (w != null) out.add(example("allow_witness", "minimal Allow witness of grant " + G.jsStr(G.get(gro, "gid")), w, emptyHist(), g, ont))
        }
        for (bo in G.arr(g["bounds"], "bounds")) {
            val b = mm(bo)!!
            val sel = mm(b["sel"])
            val gids: List<Any?> = if (G.kind(sel) == "gids") G.arr(sel!!["gids"], "gids") else ArrayList()
            var gr: Map<String, Any?>? = null
            for (x in G.arr(g["grants"], "grants")) if (gids.contains(G.get(x, "gid"))) {
                gr = mm(x)
                break
            }
            val w = (if (gr != null) allowWitness(g, gr, ont) else null) ?: continue
            val per: Double
            if (b["agg"] == "count") per = 1.0
            else {
                val v = mm(b["value"])
                val pv = if (G.kind(v) == "param") mm(mm(mm(w["act"])!!["params"])?.get(v!!["path"] as String)) else null
                per = if (pv != null && G.kind(pv) == "q") qval(mm(pv["q"])!!).toDouble() else 0.0
            }
            if (b["agg"] == "sum" && per <= 0) continue
            val n = Math.floor(qval(mm(b["cap"])!!) / per)
            if (n > 60) continue
            val acts = ArrayList<Any?>()
            for (i in 0 until n.toInt()) acts.add(w["act"])
            out.add(example("cap_sequence", "reach the " + G.jsStr(b["bid"]) + " cap with " + n.toLong() + " action(s), then one more", w, replay(g, ont, acts, G.arr(w["rels"], "rels")), g, ont))
        }
        for (gro in G.arr(g["grants"], "grants")) {
            val w = allowWitness(g, mm(gro)!!, ont) ?: continue
            val wact = mm(w["act"])!!
            for ((pk, pv) in mm(wact["params"])!!) {
                val l = mm(pv)
                if (G.kind(l) == "q" && G.kind(mm(mm(l!!["q"])!!["u"])) == "money") {
                    val q2 = LinkedHashMap(mm(l["q"])!!)
                    q2["n"] = G.num(1000000000L)
                    val ps2 = LinkedHashMap(mm(wact["params"])!!)
                    ps2[pk] = G.map("k" to "q", "q" to q2)
                    val act2 = LinkedHashMap(wact)
                    act2["params"] = ps2
                    out.add(example("probe", "extreme $pk", G.map("act" to act2, "rels" to w["rels"]), emptyHist(), g, ont))
                }
            }
            val nothing = ArrayList<Any?>()
            for (ro in G.arr(w["rels"], "rels")) {
                val r2 = LinkedHashMap(mm(ro)!!)
                r2["members"] = ArrayList<Any?>()
                nothing.add(r2)
            }
            val act3 = LinkedHashMap(wact)
            act3["res"] = "\u0000other-resource"
            out.add(example("probe", "other resource", G.map("act" to act3, "rels" to nothing), emptyHist(), g, ont))
            out.add(example("probe", "other customer/anchor", G.map("act" to w["act"], "rels" to nothing), emptyHist(), g, ont))
        }
        val seen = HashSet<String>()
        val uniq = ArrayList<Any?>()
        for (e in out) if (seen.add(G.get(e, "id") as String)) uniq.add(e)
        return G.map("examples" to uniq, "complete" to c["complete"])
    }

    private val KIND_RANK = mapOf("probe" to 0, "cap_sequence" to 1, "allow_witness" to 2, "prohibit_trigger" to 3, "member" to 4, "boundary" to 5)

    /** Review subset: at most [cap] examples, riskiest-looking first (probe, cap_sequence, allow_witness, prohibit_trigger, member, boundary), stable. */
    @JvmStatic
    fun reviewSet(examples: List<Any?>, cap: Int): List<Any?> {
        val s = ArrayList(examples)
        s.sortWith(Comparator { a, b ->
            val r = rankOf(G.get(a, "decision") as String?) - rankOf(G.get(b, "decision") as String?)
            if (r != 0) return@Comparator r
            val k = KIND_RANK[G.get(a, "kind") as String]!! - KIND_RANK[G.get(b, "kind") as String]!!
            if (k != 0) return@Comparator k
            (G.get(a, "id") as String).compareTo(G.get(b, "id") as String)
        })
        return ArrayList(s.subList(0, Math.max(0, Math.min(cap, s.size))))
    }

    // ---- GoalTest and the pin ----
    @JvmStatic
    fun expectedDecision(answer: String?): String = if (answer == "allow") "allow" else if (answer == "deny") "deny" else "escalate"

    /** Order-independent digest of a test list. */
    @JvmStatic
    fun testsDigest(tests: List<Any?>): String {
        val s = ArrayList(tests)
        s.sortWith(Comparator { a, b -> (G.get(a, "id") as String).compareTo(G.get(b, "id") as String) })
        return Pca.hashCanonical(G.map("d" to "atlas-pca/goal-tests/v1", "tests" to s))
    }

    /** confirmed: list of {example, answer}. */
    @JvmStatic
    fun makeGoalTests(g: Map<String, Any?>, confirmed: List<Any?>): Map<String, Any?> {
        val tests = ArrayList<Any?>()
        for (co in confirmed) {
            val ex = mm(G.get(co, "example"))!!
            tests.add(G.map("id" to ex["id"], "act" to ex["act"], "hist" to ex["hist"], "rels" to ex["rels"], "answer" to G.get(co, "answer")))
        }
        return G.map("goal_digest" to GoalDigests.goalDigest(g), "ontology_digest" to g["ontDigest"], "tests" to tests, "tests_digest" to testsDigest(tests))
    }

    @JvmStatic
    fun signGoalTests(s: Map<String, Any?>, seed: ByteArray): Map<String, Any?> = GoalSign.signPayload("goal-tests", s, seed)

    /** Recompile check: every confirmed test must be reproduced by [decideFn] (test -> decision). {ok, reason?, failures}. */
    @JvmStatic
    fun checkGoalTests(s: Map<String, Any?>, pins: List<*>, decideFn: (Map<String, Any?>) -> String): Map<String, Any?> {
        if (!GoalSign.verifyPayload(s, "goal-tests", pins)) return G.map("ok" to false, "reason" to "signature", "failures" to ArrayList<Any?>())
        val payload = mm(s["payload"])!!
        val tests = G.arr(payload["tests"], "tests")
        if (testsDigest(tests) != payload["tests_digest"]) return G.map("ok" to false, "reason" to "tests_digest", "failures" to ArrayList<Any?>())
        val failures = ArrayList<Any?>()
        for (to in tests) {
            val t = mm(to)!!
            val got = decideFn(t)
            val want = expectedDecision(t["answer"] as String?)
            if (want != got) failures.add(G.map("id" to t["id"], "expected" to want, "got" to got))
        }
        return if (failures.isEmpty()) G.map("ok" to true, "failures" to failures) else G.map("ok" to false, "reason" to "test_regression", "failures" to failures)
    }

    @JvmStatic
    fun signPin(p: Map<String, Any?>, seed: ByteArray): Map<String, Any?> = GoalSign.signPayload("policy-pin", p, seed)

    /** cur: {goal, policy_digest, tests}. {ok, reason?}. */
    @JvmStatic
    fun checkPin(pin: Map<String, Any?>, pins: List<*>, cur: Map<String, Any?>): Map<String, Any?> {
        if (!GoalSign.verifyPayload(pin, "policy-pin", pins)) return G.map("ok" to false, "reason" to "signature")
        val p = mm(pin["payload"])!!
        val goal = mm(cur["goal"])!!
        val tests = mm(cur["tests"])!!
        if (p["goal_digest"] != GoalDigests.goalDigest(goal)) return G.map("ok" to false, "reason" to "goal changed under the pin")
        if (p["policy_digest"] != cur["policy_digest"]) return G.map("ok" to false, "reason" to "policy changed under the pin")
        if (p["tests_digest"] != tests["tests_digest"] || p["tests_digest"] != testsDigest(G.arr(tests["tests"], "tests"))) return G.map("ok" to false, "reason" to "tests changed under the pin")
        if (p["ontology_digest"] != goal["ontDigest"]) return G.map("ok" to false, "reason" to "ontology changed under the pin")
        return G.map("ok" to true)
    }
}
