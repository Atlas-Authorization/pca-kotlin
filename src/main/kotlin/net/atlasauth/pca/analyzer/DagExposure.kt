package net.atlasauth.pca.analyzer

/**
 * What a committed workflow (DAG) can EVER do, decided statically from its body. Deterministic and total: every number is a function of
 * the declared steps, edges and budget. Reports max steps, depth, widest level, maximal-path count (capped), per-cap cost, steps no run
 * can reach, sink lineage and label protection, ordering-only steps and pipelinable edges. Throws [IllegalArgumentException] on a
 * body that is not a DAG.
 */
object DagExposure {
    private const val PATH_CAP = 1_000_000.0

    private fun listOf(o: Any?, what: String): MutableList<Any?> {
        if (o !is List<*>) throw IllegalArgumentException("dagExposure: $what is not an array")
        return AJs.list(o)
    }

    private fun idOf(s: Any?): String {
        val id = AJs.get(AJs.req(s), "id")
        if (id !is String) throw IllegalArgumentException("dagExposure: step id is not a string")
        return id
    }

    /** `.length` of a value; reading it on null / undefined throws, as in JavaScript. */
    private fun len(o: Any?): Double {
        if (o is List<*>) return o.size.toDouble()
        if (o is String) return o.length.toDouble()
        if (o == null) throw IllegalArgumentException("cannot read length of null")
        return Double.NaN
    }

    fun dagExposure(b: Map<String, Any?>?): Map<String, Any?> {
        AJs.req(b)
        val steps = listOf(AJs.get(b, "steps"), "steps")
        val budget = AJs.map(AJs.req(AJs.get(b, "budget")))
        val byId = LinkedHashMap<String, Any?>()
        for (s in steps) byId[idOf(s)] = s
        if (byId.size != steps.size) throw IllegalArgumentException("dagExposure: duplicate step id")
        val level = HashMap<String, Int>()
        val anc = HashMap<String, Set<String>>()
        val visiting = HashSet<String>()
        for (s in steps) visit(idOf(s), byId, level, anc, visiting)
        var maxLevel = 0
        for (l in level.values) maxLevel = Math.max(maxLevel, l)
        val depth = (maxLevel + 1).toDouble()
        val widths = HashMap<Int, Int>()
        for (l in level.values) widths[l] = (widths[l] ?: 0) + 1
        var levelWidth = Double.NEGATIVE_INFINITY
        for (w in widths.values) levelWidth = Math.max(levelWidth, w.toDouble())

        // maximal paths: the number of paths from a source to each leaf
        val children = LinkedHashMap<String, MutableList<String>>()
        for (s in steps) children[idOf(s)] = ArrayList()
        for (s in steps) for (d in listOf(AJs.get(s, "deps"), "deps")) children[d as String]!!.add(idOf(s))
        val memo = HashMap<String, Double>()
        val capped = booleanArrayOf(false)
        var paths = 0.0
        for (s in steps) if (listOf(AJs.get(s, "deps"), "deps").isEmpty()) paths = Math.min(PATH_CAP, paths + toLeaves(idOf(s), children, memo, capped))

        val cost = LinkedHashMap<String, Any?>()
        val capsO = AJs.get(budget, "caps")
        if (capsO !is Map<*, *>) throw IllegalArgumentException("dagExposure: caps is not an object")
        val caps = AJs.map(capsO)
        for (name in AJs.keys(caps)) {
            var total = 0.0
            for (s in steps) {
                val c = AJs.get(AJs.get(s, "cost"), name)
                total = total + (if (c == null) 0.0 else AJs.toNum(c))
            }
            val cap = AJs.toNum(caps[name])
            cost[name] = AJs.obj("cap", caps[name], "total", AJs.n(total), "maxSpend", AJs.n(Math.min(cap, total)))
        }
        val neverRunnable = ArrayList<Any?>()
        val maxStepsB = AJs.numOrNaN(budget, "max_steps")
        for (s in steps) {
            var over = false
            val sc = AJs.get(s, "cost")
            if (sc is Map<*, *>) {
                for (n in AJs.keys(AJs.map(sc))) {
                    val cap = caps[n]
                    if (AJs.toNum(AJs.map(sc)[n]) > (if (cap == null) 0.0 else AJs.toNum(cap))) { over = true; break }
                }
            }
            if (over) neverRunnable.add(AJs.obj("step", idOf(s), "reason", "cost_over_cap"))
            else if (anc[idOf(s)]!!.size + 1 > maxStepsB) neverRunnable.add(AJs.obj("step", idOf(s), "reason", "needs_more_steps_than_budget"))
        }

        // data lineage: a step's outputs reach `t` along edges (transitively through steps that consume them)
        val edges = listOf(AJs.get(b, "edges"), "edges")
        val feeds = HashMap<String?, MutableSet<String?>>()
        for (s in steps) feeds[idOf(s)] = LinkedHashSet()
        for (e in edges) {
            val f = feeds[AJs.get(AJs.get(e, "to"), "step") as String?] ?: throw IllegalArgumentException("dagExposure: edge to an unknown step")
            f.add(AJs.get(AJs.get(e, "from"), "step") as String?)
        }
        val sinks = ArrayList<Any?>()
        val unprotected = ArrayList<Any?>()
        for (s in steps) {
            if (AJs.has(s, "sink") && AJs.get(s, "sink") == null) continue
            val id = idOf(s)
            var incomingDeny = false
            for (e in edges) if (id == AJs.get(AJs.get(e, "to"), "step") && len(AJs.get(e, "deny_labels")) > 0) incomingDeny = true
            val seen = LinkedHashSet<String?>()
            lineageOf(id, seen, feeds)
            val lineage = ArrayList<String>()
            for (x in seen) lineage.add(x!!)
            lineage.sort()
            val prot = len(AJs.get(s, "deny_labels")) > 0 || len(AJs.get(s, "escalate_labels")) > 0 || incomingDeny
            val k = AJs.obj("step", id)
            AJs.putIf(k, "sink", s, "sink")
            k["lineage"] = ArrayList<Any?>(lineage)
            k["protected"] = prot
            sinks.add(k)
            if (!prot && lineage.isNotEmpty()) unprotected.add(id)
        }
        val orderingOnly = ArrayList<Any?>()
        for (s in steps) {
            if (listOf(AJs.get(s, "deps"), "deps").isEmpty()) continue
            var has = false
            for (e in edges) if (idOf(s) == AJs.get(AJs.get(e, "to"), "step")) has = true
            if (!has) orderingOnly.add(idOf(s))
        }
        val pipelinable = ArrayList<Any?>()
        for (i in edges.indices) {
            val e = edges[i]
            if (!(AJs.has(e, "promise") && AJs.get(e, "promise") == null)) pipelinable.add(AJs.n(i))
        }
        return AJs.obj("steps", AJs.n(steps.size), "maxSteps", AJs.n(Math.min(steps.size.toDouble(), maxStepsB)), "depth", AJs.n(depth), "levelWidth", AJs.n(levelWidth),
            "paths", AJs.n(paths), "pathsCapped", capped[0], "cost", cost, "neverRunnable", neverRunnable, "sinks", sinks,
            "unprotectedSinks", unprotected, "orderingOnly", orderingOnly, "pipelinable", pipelinable)
    }

    private fun visit(id: String, byId: Map<String, Any?>, level: MutableMap<String, Int>, anc: MutableMap<String, Set<String>>, visiting: MutableSet<String>) {
        if (level.containsKey(id)) return
        if (visiting.contains(id)) throw IllegalArgumentException("dagExposure: cycle")
        visiting.add(id)
        val s = byId[id] ?: throw IllegalArgumentException("dagExposure: unknown step $id")
        val a = LinkedHashSet<String>()
        var l = 0
        for (d in listOf(AJs.get(s, "deps"), "deps")) {
            if (d !is String) throw IllegalArgumentException("dagExposure: dependency is not a step id")
            visit(d, byId, level, anc, visiting)
            a.add(d)
            a.addAll(anc[d]!!)
            l = Math.max(l, level[d]!! + 1)
        }
        visiting.remove(id)
        anc[id] = a
        level[id] = l
    }

    private fun toLeaves(id: String, children: Map<String, List<String>>, memo: MutableMap<String, Double>, capped: BooleanArray): Double {
        val m = memo[id]
        if (m != null) return m
        val kids = children[id]!!
        var n = if (kids.isEmpty()) 1.0 else 0.0
        for (k in kids) n += toLeaves(k, children, memo, capped)
        if (n > PATH_CAP) { n = PATH_CAP; capped[0] = true }
        memo[id] = n
        return n
    }

    private fun lineageOf(id: String?, seen: MutableSet<String?>, feeds: Map<String?, MutableSet<String?>>) {
        val fs = feeds[id] ?: throw IllegalArgumentException("dagExposure: lineage through an unknown step")
        for (f in ArrayList(fs)) if (!seen.contains(f)) { seen.add(f); lineageOf(f, seen, feeds) }
    }
}
