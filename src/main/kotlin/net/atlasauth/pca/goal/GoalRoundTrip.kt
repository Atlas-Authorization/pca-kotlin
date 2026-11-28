package net.atlasauth.pca.goal

/**
 * Round-trip checks. (a) The card's lossless token tape decodes back to the goal. (b) An explainer sees only the compiled card
 * lines and a comparator judges the explanation against the principal's text: a detector, tighten-only (it can only escalate),
 * measured by semantic mutations that WIDEN the policy.
 */
@Suppress("UNCHECKED_CAST")
object GoalRoundTrip {
    @JvmField
    val MUTATION_KINDS: List<String> = listOf("widen_cap", "widen_where", "drop_prohibit", "drop_bound", "swap_resource", "add_grant")

    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    private fun mut(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>

    private fun mlist(o: Any?): MutableList<Any?> = G.arr(o, "").let { if (it is MutableList<*>) it as MutableList<Any?> else ArrayList(it) }

    /** decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape. */
    @JvmStatic
    fun cardRoundTrips(g: Map<String, Any?>): Boolean = G.stable(GoalCodec.decodeGoal(GoalCodec.encodeGoal(g))) == G.stable(g)

    private fun copy(o: Any?): Any? = when (o) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { r -> for ((k, v) in o) r[k as String] = copy(v) }
        is List<*> -> ArrayList<Any?>().also { r -> for (x in o) r.add(copy(x)) }
        else -> o
    }

    private fun numOut(d: Double): Any? {
        if (d == Math.rint(d) && Math.abs(d) <= G.MAX_SAFE) return G.num(d.toLong())
        throw IrError("non-integer result")
    }

    private fun scale(x: Map<String, Any?>, f: Double): Map<String, Any?> {
        val uk = G.kind(mm(x["u"]))
        if (uk != "money" && uk != "count") return x
        val r = LinkedHashMap(x)
        r["n"] = numOut(G.toNum(x["n"]) * f)
        return r
    }

    private fun mapLitsInCond(c: Map<String, Any?>): Map<String, Any?> {
        val k = G.kind(c)
        if (k == "cmp") {
            val r = mm(c["r"])
            val out = LinkedHashMap(c)
            val lit = G.kind(r) == "lit" && G.kind(mm(r!!["v"])) == "q" && ("lte" == c["op"] || "lt" == c["op"])
            if (lit) out["r"] = G.map("k" to "lit", "v" to G.map("k" to "q", "q" to scale(mm(mm(r!!["v"])!!["q"])!!, 10.0)))
            return out
        }
        if (k == "and" || k == "or") {
            val out = LinkedHashMap(c)
            out["a"] = mapLitsInCond(mm(c["a"])!!)
            out["b"] = mapLitsInCond(mm(c["b"])!!)
            return out
        }
        return c
    }

    /** A semantic mutation that WIDENS the policy (or leaves it equal); null when the goal has nothing to mutate. */
    @JvmStatic
    fun mutateGoal(g: Map<String, Any?>, kind: String, ontology: Map<String, Any?>?): Map<String, Any?>? {
        val x = mut(copy(g))
        when (kind) {
            "widen_cap" -> {
                val bounds = G.arr(x["bounds"], "bounds")
                if (bounds.isEmpty()) return null
                mut(bounds[0])["cap"] = scale(mm(mm(bounds[0])!!["cap"])!!, 10.0)
                return x
            }
            "widen_where" -> {
                for (yo in G.arr(x["grants"], "grants")) {
                    val y = mut(yo)
                    val mapped = mapLitsInCond(mm(y["cond"])!!)
                    if (G.stringify(mapped) != G.stringify(y["cond"])) {
                        y["cond"] = mapped
                        return x
                    }
                }
                return null
            }
            "drop_prohibit" -> {
                val ps = mlist(x["prohibits"])
                if (ps.isEmpty()) return null
                ps.removeAt(ps.size - 1)
                return x
            }
            "drop_bound" -> {
                val bs = mlist(x["bounds"])
                if (bs.isEmpty()) return null
                bs.removeAt(bs.size - 1)
                return x
            }
            "swap_resource" -> {
                for (yo in G.arr(x["grants"], "grants")) {
                    val y = mut(yo)
                    if (G.kind(y["res"]) == "exact") {
                        y["res"] = G.map("k" to "exact", "id" to (G.jsStr(mm(y["res"])!!["id"]) + "9"))
                        return x
                    }
                }
                return null
            }
            "add_grant" -> {
                val have = LinkedHashSet<Any?>()
                for (y in G.arr(x["grants"], "grants")) have.add(G.get(y, "verb"))
                var v: Map<String, Any?>? = null
                for (yo in G.arr(ontology!!["verbs"], "verbs")) {
                    val y = mm(yo)!!
                    if ("read" == y["effect"] || have.contains(y["id"])) continue
                    var prohibited = false
                    for (p in G.arr(x["prohibits"], "prohibits")) if (G.kind(G.get(p, "target")) == "verb" && mm(G.get(p, "target"))!!["verb"] == y["id"]) prohibited = true
                    if (!prohibited) {
                        v = y
                        break
                    }
                }
                if (v == null) return null
                mlist(x["grants"]).add(G.map("gid" to "injected", "verb" to v["id"], "res" to G.map("k" to "any", "reason" to "injected"), "cond" to G.map("k" to "true")))
                mlist(x["wildcardAck"]).add("injected")
                return GoalNormalize.canonicalizeGoal(x)
            }
            else -> return null
        }
    }

    /** The reference explainer: the card lines themselves. */
    @JvmStatic
    fun deterministicExplain(proseLines: List<String>): String = proseLines.joinToString("\n")

    /**
     * Round trip (b): the explainer sees ONLY the compiled card lines. `comparator(goalText, explanation)` returns a map with
     * `equivalent`. Any failure escalates. Result: "ok" or "escalate".
     */
    @JvmStatic
    fun roundTrip(goal: Map<String, Any?>, goalText: String, explainer: (List<String>) -> String, comparator: (String, String) -> Map<String, Any?>): String {
        try {
            val lines = ArrayList<String>()
            for (l in G.arr(GoalCard.renderCard(goal)["lines"], "lines")) lines.add(l as String)
            val e = explainer(lines)
            return if (G.truthy(comparator(goalText, e)["equivalent"])) "ok" else "escalate"
        } catch (ex: RuntimeException) {
            return "escalate"
        }
    }

    /** Fraction of semantic widenings the pair flags, per mutation kind: [{kind, applied, detected, rate}]. `cases` = [{goal, text}]. */
    @JvmStatic
    fun measureDetection(cases: List<Any?>, ontology: Map<String, Any?>?, explainer: (List<String>) -> String, comparator: (String, String) -> Map<String, Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (kind in MUTATION_KINDS) {
            var applied = 0
            var detected = 0
            for (co in cases) {
                val m = mutateGoal(mm(G.get(co, "goal"))!!, kind, ontology) ?: continue
                applied++
                if (roundTrip(m, G.get(co, "text") as String, explainer, comparator) == "escalate") detected++
            }
            out.add(G.map("kind" to kind, "applied" to G.num(applied), "detected" to G.num(detected), "rate" to (if (applied > 0) detected.toDouble() / applied else G.num(0))))
        }
        return out
    }
}
