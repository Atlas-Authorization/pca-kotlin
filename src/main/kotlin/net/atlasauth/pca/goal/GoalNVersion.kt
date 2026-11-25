package net.atlasauth.pca.goal

/**
 * N-version interpretation: the enforced policy is the semantic meet of the readings. Allow(meet gs) a implies Allow(g) a for
 * every g in gs. Grants are the cross product of the readings' grants on equal verbs (a merged grant is named `x&y&z`),
 * resources intersect through `all_of`, conditions conjoin; a bound counts the admitted actions of the merged grants
 * derived from the grants it selected, so the merged goal never admits more than any reading.
 */
@Suppress("UNCHECKED_CAST")
object GoalNVersion {
    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    private fun partsOf(s: Map<String, Any?>?): List<Map<String, Any?>?> {
        val out = ArrayList<Map<String, Any?>?>()
        val k = G.kind(s)
        if (k == "all_of") {
            for (p in G.arr(s!!["parts"], "parts")) out.add(mm(p))
        } else if (k != "any") out.add(s)
        return out
    }

    private fun intersect(a: Map<String, Any?>?, b: Map<String, Any?>?): Map<String, Any?>? {
        if (G.kind(a) == "any") return b
        if (G.kind(b) == "any") return a
        val uniq = LinkedHashMap<String, Map<String, Any?>?>()
        for (p in partsOf(a)) uniq[G.stable(p)] = p
        for (p in partsOf(b)) uniq[G.stable(p)] = p
        if (uniq.size == 1) return uniq.values.iterator().next()
        return G.map("k" to "all_of", "parts" to ArrayList<Any?>(uniq.values))
    }

    private fun conj(a: Map<String, Any?>?, b: Map<String, Any?>?): Map<String, Any?>? {
        if (G.kind(a) == "true") return b
        if (G.kind(b) == "true") return a
        return G.map("k" to "and", "a" to a, "b" to b)
    }

    /** A merged grant and, per reading, the gid of the grant it was derived from. */
    private class Tracked(val g: Map<String, Any?>, val from: List<String>)

    private fun cross(a: List<Tracked>, b: List<Tracked>): List<Tracked> {
        val out = ArrayList<Tracked>()
        for (x in a) for (y in b) {
            if (x.g["verb"] != y.g["verb"]) continue
            val g = G.map(
                "gid" to (G.jsStr(x.g["gid"]) + "&" + G.jsStr(y.g["gid"])), "verb" to x.g["verb"],
                "res" to intersect(mm(x.g["res"]), mm(y.g["res"])), "cond" to conj(mm(x.g["cond"]), mm(y.g["cond"])),
            )
            val from = ArrayList(x.from)
            from.addAll(y.from)
            out.add(Tracked(g, from))
        }
        return out
    }

    private fun track(grants: List<Any?>): List<Tracked> {
        val out = ArrayList<Tracked>()
        for (g in grants) out.add(Tracked(mm(g)!!, arrayListOf(G.get(g, "gid") as String)))
        return out
    }

    /** Meet of grants: cross product on equal verbs, resource intersection, conjoined conditions. */
    @JvmStatic
    fun meetGrants(a: List<Any?>, b: List<Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (t in cross(track(a), track(b))) out.add(t.g)
        return out
    }

    private fun derived(tracked: List<Tracked>, i: Int, gids: List<Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (t in tracked) if (gids.contains(t.from[i])) out.add(t.g["gid"])
        return out
    }

    private fun sortedStrings(xs: List<Any?>): List<Any?> {
        val s = ArrayList(xs)
        s.sortWith(Comparator { a, b -> (a as String).compareTo(b as String) })
        return s
    }

    private fun num(o: Any?): Double = G.toNum(o)

    private fun numOut(d: Double): Any? {
        if (d == Math.rint(d) && Math.abs(d) <= G.MAX_SAFE) return G.num(d.toLong())
        throw IrError("non-integer result")
    }

    @JvmStatic
    fun meet(goals: List<Map<String, Any?>>): Map<String, Any?> {
        if (goals.isEmpty()) throw IrError("meet: no goals")
        val first = goals[0]
        for (g in goals) {
            if (g["principal"] != first["principal"] || g["ontDigest"] != first["ontDigest"] || g["nlDigest"] != first["nlDigest"]) throw IrError("meet: readings must share principal, ontology and text")
        }
        if (goals.size == 1) return first
        var tracked = track(G.arr(first["grants"], "grants"))
        for (g in goals.subList(1, goals.size)) tracked = cross(tracked, track(G.arr(g["grants"], "grants")))
        val grants = ArrayList<Any?>()
        for (t in tracked) grants.add(t.g)

        val prohibits = ArrayList<Any?>()
        val pseen = LinkedHashMap<String, Any?>()
        for (i in goals.indices) {
            for (po in G.arr(goals[i]["prohibits"], "prohibits")) {
                val p = mm(po)!!
                val bodyMap = LinkedHashMap(p)
                bodyMap["pid"] = ""
                val body = G.stable(bodyMap)
                if (pseen.containsKey(body)) continue
                val taken = pseen.containsValue(p["pid"])
                pseen[body] = p["pid"]
                if (taken) {
                    val np = LinkedHashMap(p)
                    np["pid"] = G.jsStr(p["pid"]) + "#" + i
                    prohibits.add(np)
                } else prohibits.add(p)
            }
        }

        val bounds = ArrayList<Any?>()
        val bseen = LinkedHashMap<String, MutableMap<String, Any?>>()
        for (i in goals.indices) {
            for (bo in G.arr(goals[i]["bounds"], "bounds")) {
                val b = mm(bo)!!
                val bsel = mm(b["sel"])
                var sel = bsel
                if (G.kind(bsel) == "gids") sel = G.map("k" to "gids", "gids" to sortedStrings(derived(tracked, i, G.arr(bsel!!["gids"], "gids"))))
                if (G.kind(sel) == "gids" && G.arr(sel!!["gids"], "gids").isEmpty()) continue
                val key = G.stable(G.map("sel" to sel, "agg" to b["agg"], "value" to b["value"], "key" to b["key"], "window" to b["window"], "scope" to b["scope"], "unit" to mm(b["cap"])!!["u"]))
                val prev = bseen[key]
                if (prev != null) {
                    if (num(mm(b["cap"])!!["n"]) < num(mm(prev["cap"])!!["n"])) prev["cap"] = b["cap"]
                    if ("deny" == b["onExceed"]) prev["onExceed"] = "deny"
                    continue
                }
                val nb = LinkedHashMap(b)
                nb["sel"] = sel
                var dup = false
                for (x in bounds) if (G.get(x, "bid") == b["bid"]) dup = true
                nb["bid"] = if (dup) G.jsStr(b["bid"]) + "#" + i else b["bid"]
                bounds.add(nb)
                bseen[key] = nb
            }
        }

        val escSeen = LinkedHashMap<String, Any?>()
        for (g in goals) for (c in G.arr(g["escalateOn"], "escalateOn")) escSeen[G.stable(c)] = c

        val idle = ArrayList<Double>()
        for (g in goals) {
            val x = num(mm(g["validity"])!!["maxIdle"])
            if (x > 0) idle.add(x)
        }
        val touch = ArrayList<Any?>()
        for (t in tracked) {
            var all = true
            for (i in goals.indices) if (!G.arr(mm(goals[i]["deleg"])!!["mayTouch"], "mayTouch").contains(t.from[i])) {
                all = false
                break
            }
            if (all) touch.add(t.g["gid"])
        }
        val ack = ArrayList<Any?>()
        for (t in tracked) {
            if (G.kind(t.g["res"]) != "any") continue
            var all = true
            for (i in goals.indices) {
                var src: Map<String, Any?>? = null
                for (x in G.arr(goals[i]["grants"], "grants")) if (t.from[i] == G.get(x, "gid")) {
                    src = mm(x)
                    break
                }
                val notAny = src == null || G.kind(src["res"]) != "any"
                if (!(notAny || G.arr(goals[i]["wildcardAck"], "wildcardAck").contains(t.from[i]))) {
                    all = false
                    break
                }
            }
            if (all) ack.add(t.g["gid"])
        }
        val holes = LinkedHashMap<String, Map<String, Any?>>()
        for (i in goals.indices) {
            for (ho in G.arr(goals[i]["holes"], "holes")) {
                val h = mm(ho)!!
                val hid = h["hid"] as String
                val prev = holes[hid]
                val aff = LinkedHashSet<String>()
                if (prev != null) for (a in G.arr(prev["affects"], "affects")) aff.add(a as String)
                for (a in derived(tracked, i, G.arr(h["affects"], "affects"))) aff.add(a as String)
                val affects = sortedStrings(ArrayList<Any?>(aff))
                val nh = LinkedHashMap(h)
                nh["affects"] = affects
                nh["global"] = if (G.truthy(h["global"])) h["global"] else if (prev != null && prev["global"] != null) prev["global"] else false
                holes[hid] = nh
            }
        }
        val sources = LinkedHashSet<String>()
        for (g in goals) for (s in G.arr(g["sources"], "sources")) sources.add(s as String)
        var nb = Double.NEGATIVE_INFINITY
        var na = Double.POSITIVE_INFINITY
        var md = Double.POSITIVE_INFINITY
        for (g in goals) {
            val v = mm(g["validity"])!!
            nb = Math.max(nb, num(v["notBefore"]))
            na = Math.min(na, num(v["notAfter"]))
            md = Math.min(md, num(mm(g["deleg"])!!["maxDepth"]))
        }
        var mi = 0.0
        if (idle.isNotEmpty()) {
            mi = Double.POSITIVE_INFINITY
            for (x in idle) mi = Math.min(mi, x)
        }
        val out = LinkedHashMap(first)
        out["grants"] = grants
        out["prohibits"] = prohibits
        out["bounds"] = bounds
        out["escalateOn"] = ArrayList<Any?>(escSeen.values)
        out["sources"] = ArrayList<Any?>(sources)
        out["validity"] = G.map("notBefore" to numOut(nb), "notAfter" to numOut(na), "maxIdle" to numOut(mi))
        out["deleg"] = G.map("maxDepth" to numOut(md), "narrowOnly" to true, "mayTouch" to touch)
        out["holes"] = ArrayList<Any?>(holes.values)
        out["wildcardAck"] = ack
        return GoalNormalize.canonicalizeGoal(out)
    }

    /** Panel requirements: at least 3 interpreters, one deterministic non-LLM interpreter, two distinct model families. Issues {code, msg}. */
    @JvmStatic
    fun checkPanel(readings: List<Map<String, Any?>>): List<Any?> {
        val out = ArrayList<Any?>()
        if (readings.size < 3) out.add(G.map("code" to "too_few", "msg" to "need at least 3 interpreters"))
        var det = false
        val fams = LinkedHashSet<Any?>()
        for (r in readings) {
            if (G.truthy(r["deterministic"])) det = true else fams.add(r["family"] ?: "\u0000undefined")
        }
        if (!det) out.add(G.map("code" to "no_deterministic", "msg" to "need at least one deterministic template interpreter"))
        if (fams.size < 2) out.add(G.map("code" to "no_family_diversity", "msg" to "need at least two distinct model families"))
        return out
    }

    /** {merged, panelIssues, disagreementHoles, mass, signable}. */
    @JvmStatic
    fun nVersion(readings: List<Map<String, Any?>>, opts: GoalDisambiguate.Opts, massThreshold: Double?): Map<String, Any?> {
        val goals = ArrayList<Map<String, Any?>>()
        for (r in readings) goals.add(mm(r["goal"])!!)
        val merged = meet(goals)
        val panelIssues = checkPanel(readings)
        val verbSets = ArrayList<Set<String>>()
        val allVerbs = java.util.TreeSet<String>()
        for (g in goals) {
            val s = LinkedHashSet<String>()
            for (gr in G.arr(g["grants"], "grants")) s.add(G.get(gr, "verb") as String)
            verbSets.add(s)
            allVerbs.addAll(s)
        }
        val holes = ArrayList<Any?>()
        for (v in allVerbs) {
            var some = false
            for (s in verbSets) if (!s.contains(v)) some = true
            if (some) holes.add(G.map("hid" to "nv:verb:$v", "q" to "Only some readings allow \"$v\". Should it be allowed at all?", "domain" to ArrayList<Any?>(), "affects" to ArrayList<Any?>(), "global" to false))
        }
        val mass = GoalDisambiguate.disagreementMass(readings, opts.ont)
        if (mass > (massThreshold ?: 0.0)) {
            val qs = GoalDisambiguate.questions(readings, opts)
            holes.add(G.map("hid" to "nv:split", "q" to (if (qs.isEmpty()) "The readings disagree." else qs[0]["text"]), "domain" to ArrayList<Any?>(), "affects" to ArrayList<Any?>(), "global" to true))
        }
        val all = ArrayList(G.arr(merged["holes"], "holes"))
        all.addAll(holes)
        val byHid = LinkedHashMap<String, Any?>()
        for (h in all) byHid[G.get(h, "hid") as String] = h
        val m2 = LinkedHashMap(merged)
        m2["holes"] = ArrayList<Any?>(byHid.values)
        return G.map("merged" to GoalNormalize.canonicalizeGoal(m2), "panelIssues" to panelIssues, "disagreementHoles" to holes, "mass" to mass, "signable" to (panelIssues.isEmpty() && all.isEmpty()))
    }
}
