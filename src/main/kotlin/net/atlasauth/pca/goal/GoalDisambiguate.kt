package net.atlasauth.pca.goal

import net.atlasauth.pca.intent.IntentMath

/**
 * Active disambiguation by version-space halving over a finite class of readings. A reading is a map
 * {id, family, deterministic, goal, notes}; a distinguishing case is {act, prior, rels}.
 */
@Suppress("UNCHECKED_CAST")
object GoalDisambiguate {
    @JvmField
    val DEFAULT_RISK: Map<String, Int> = mapOf("read" to 1, "reversible" to 2, "external_send" to 8, "irreversible" to 10)

    /** Question options: the IR ontology the readings are decided against and optional risk / mass of an action (default risk by effect class, mass 1). */
    class Opts(@JvmField var ont: Map<String, Any?>) {
        @JvmField var riskOf: ((Map<String, Any?>) -> Double)? = null
        @JvmField var massOf: ((Map<String, Any?>) -> Double)? = null
        @JvmField var budget: Int? = null
    }

    private fun mx(o: Any?): Map<String, Any?> = G.m(o) ?: throw NullPointerException("object expected")

    private fun h2(p: Double): Double = if (p <= 0 || p >= 1) 0.0 else -(p * IntentMath.log2(p) + (1 - p) * IntentMath.log2(1 - p))

    @JvmStatic
    fun allowsWitness(g: Map<String, Any?>, ont: Map<String, Any?>, w: Map<String, Any?>): Boolean {
        val hist = GoalExamples.replay(g, ont, G.arr(w["prior"], "prior"), G.arr(w["rels"], "rels"))
        return "allow" == GoalExamples.decideCase(g, ont, G.map("act" to w["act"], "hist" to hist, "rels" to w["rels"]))["decision"]
    }

    private fun allowSet(r: Map<String, Any?>, w: Map<String, Any?>, ont: Map<String, Any?>): Boolean = allowsWitness(mx(r["goal"]), ont, w)

    private fun goalsOf(readings: List<Map<String, Any?>>): List<Map<String, Any?>> {
        val goals = ArrayList<Map<String, Any?>>()
        for (r in readings) goals.add(mx(r["goal"]))
        return goals
    }

    /** Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences. */
    internal fun witnesses(readings: List<Map<String, Any?>>, ont: Map<String, Any?>): List<Map<String, Any?>> {
        val goals = goalsOf(readings)
        val out = ArrayList<Map<String, Any?>>()
        for (co in G.arr(GoalExamples.cells(GoalExamples.buildSpace(goals, ArrayList()), null)["cases"], "cases")) {
            out.add(G.map("act" to G.get(co, "act"), "prior" to ArrayList<Any?>(), "rels" to G.get(co, "rels")))
        }
        for (r in readings) {
            for (eo in G.arr(GoalExamples.boundaryExamples(mx(r["goal"]), ont, goals, null)["examples"], "examples")) {
                if ("cap_sequence" != G.get(eo, "kind")) continue
                val prior = ArrayList<Any?>()
                for (a in G.arr(G.get(G.get(eo, "hist"), "adms"), "adms")) prior.add(G.get(a, "act"))
                out.add(G.map("act" to G.get(eo, "act"), "prior" to prior, "rels" to G.get(eo, "rels")))
            }
        }
        return out
    }

    /** Questions over the symmetric difference of the readings, ranked by H2(vote) x risk x mass (best first). */
    @JvmStatic
    fun questions(readings: List<Map<String, Any?>>, opts: Opts): List<Map<String, Any?>> {
        val ont = opts.ont
        val k = readings.size
        val cls = LinkedHashMap<String, Any?>()
        for (v in G.arr(ont["verbs"], "verbs")) cls[G.get(v, "verb") as String] = G.get(v, "cls")
        val out = ArrayList<LinkedHashMap<String, Any?>>()
        val seen = HashSet<String>()
        for (w in witnesses(readings, ont)) {
            val yes = ArrayList<Any?>()
            for (r in readings) if (allowSet(r, w, ont)) yes.add(r["id"])
            if (yes.isEmpty() || yes.size == k) continue
            val id = G.stringify(G.list(w["act"], G.num(G.arr(w["prior"], "prior").size)))
            if (!seen.add(id)) continue
            val act = mx(w["act"])
            val risk: Double
            val riskOf = opts.riskOf
            if (riskOf != null) risk = riskOf(act)
            else {
                val vb = act["verb"]
                val c = if (vb is String) cls[vb] else null
                val r = if (c is String) DEFAULT_RISK[c] else null
                risk = if (r == null) 10.0 else r.toDouble()
            }
            val massOf = opts.massOf
            val mass = if (massOf != null) massOf(act) else 1.0
            val np = G.arr(w["prior"], "prior").size
            val notAllow = ArrayList<Any?>()
            for (r in readings) if (!yes.contains(r["id"])) notAllow.add(r["id"])
            val q = LinkedHashMap<String, Any?>()
            q["id"] = id
            q.putAll(w)
            q["allow"] = yes
            q["notAllow"] = notAllow
            q["text"] = "Should this be allowed: " + GoalFmt.fmtAct(act) + (if (np > 0) " (after $np earlier identical action(s))" else "") + "?"
            q["score"] = h2(yes.size.toDouble() / k) * risk * mass
            out.add(q)
        }
        out.sortWith(
            Comparator { a, b ->
                val d = (b["score"] as Double) - (a["score"] as Double)
                if (d != 0.0) (if (d > 0) 1 else -1)
                else (if ((a["id"] as String).compareTo(b["id"] as String) < 0) -1 else 1)
            },
        )
        return out
    }

    /** Fraction of witness cells on which the readings do not all agree on Allow. */
    @JvmStatic
    fun disagreementMass(readings: List<Map<String, Any?>>, ont: Map<String, Any?>): Double {
        val w = witnesses(readings, ont)
        if (w.isEmpty()) return 0.0
        var split = 0
        for (x in w) {
            var n = 0
            for (r in readings) if (allowSet(r, x, ont)) n++
            if (n > 0 && n < readings.size) split++
        }
        return split.toDouble() / w.size
    }

    /** Active disambiguation: {status, goal, asked, residualMass, remaining}. [ask] maps a question to "allow" or "deny". */
    @JvmStatic
    fun disambiguate(readings: List<Map<String, Any?>>, ask: (Map<String, Any?>) -> String, opts: Opts): Map<String, Any?> {
        val ont = opts.ont
        val budget = opts.budget ?: readings.size
        var active: List<Map<String, Any?>> = ArrayList(readings)
        val asked = ArrayList<Any?>()
        while (active.size > 1 && asked.size < budget) {
            val qs = questions(active, opts)
            if (qs.isEmpty()) break
            val q = qs[0]
            asked.add(q)
            val allow = "allow" == ask(q)
            val next = ArrayList<Map<String, Any?>>()
            for (r in active) if (allowSet(r, q, ont) == allow) next.add(r)
            active = next
        }
        val mass = disagreementMass(active, ont)
        val g = GoalNVersion.meet(goalsOf(active))
        val remaining = ArrayList<Any?>()
        for (r in active) remaining.add(r["id"])
        if (mass > 0) {
            val hs = ArrayList<Any?>(G.arr(g["holes"], "holes"))
            hs.add(G.map("hid" to "budget", "q" to "Question budget exhausted with disagreement left.", "domain" to ArrayList<Any?>(), "affects" to ArrayList<Any?>(), "global" to true))
            hs.sortWith(Comparator { a, b -> (G.get(a, "hid") as String).compareTo(G.get(b, "hid") as String) })
            val g2 = LinkedHashMap<String, Any?>(g)
            g2["holes"] = hs
            return G.map("status" to "budget_exhausted", "goal" to g2, "asked" to asked, "residualMass" to mass, "remaining" to remaining)
        }
        return G.map("status" to "resolved", "goal" to g, "asked" to asked, "residualMass" to 0, "remaining" to remaining)
    }
}
