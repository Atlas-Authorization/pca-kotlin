package net.atlasauth.pca.goal

/** The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers. */
object GoalCard {
    @JvmStatic
    fun q(x: Any?): String = G.quote(x)

    private fun s(o: Any?): String = G.jsStr(o)

    private fun mm(o: Any?): Map<String, Any?> = G.obj(o, "value")

    @JvmStatic
    fun unit(u: Map<String, Any?>): String = if (G.kind(u) == "money") s(u["ccy"]) + " minor units" else G.kind(u)

    @JvmStatic
    fun quantity(x: Map<String, Any?>): String = s(x["n"]) + " " + unit(mm(x["u"]))

    @JvmStatic
    fun value(v: Map<String, Any?>): String {
        val k = G.kind(v)
        if (k == "q") return quantity(mm(v["q"]))
        if (k == "s") return q(v["s"])
        return "{" + join(G.arr(v["items"], "items"), { i -> value(mm(i)) }, ", ") + "}"
    }

    private fun join(xs: List<Any?>, f: (Any?) -> String, sep: String): String {
        val out = ArrayList<String>()
        for (x in xs) out.add(f(x))
        return out.joinToString(sep)
    }

    @JvmStatic
    fun term(t: Map<String, Any?>): String {
        val k = G.kind(t)
        if (k == "param") {
            val ty = mm(t["ty"])
            return "param " + q(t["path"]) + " (" + (if (G.kind(ty) == "q") unit(mm(ty["u"])) else "text") + ")"
        }
        if (k == "lit") return value(mm(t["v"]))
        return "running total of bound " + q(t["bid"]) + " (" + unit(mm(t["u"])) + ")"
    }

    private val OPW: Map<String, String> = linkedMapOf(
        "eq" to "=", "ne" to "!=", "lt" to "<", "lte" to "<=", "gt" to ">", "gte" to ">=", "in" to "is one of", "nin" to "is none of",
    )

    @JvmStatic
    fun cond(c: Map<String, Any?>): String = when (G.kind(c)) {
        "true" -> "always"
        "cmp" -> term(mm(c["l"])) + " " + (OPW[s(c["op"])] ?: "undefined") + " " + term(mm(c["r"]))
        "and" -> "(" + cond(mm(c["a"])) + ") AND (" + cond(mm(c["b"])) + ")"
        "or" -> "(" + cond(mm(c["a"])) + ") OR (" + cond(mm(c["b"])) + ")"
        "not" -> "NOT (" + cond(mm(c["c"])) + ")"
        else -> throw IrError("unknown condition")
    }

    @JvmStatic
    fun res(r: Map<String, Any?>): String = when (G.kind(r)) {
        "exact" -> "exactly " + q(r["id"])
        "oneof" -> "one of [" + join(G.arr(r["ids"], "ids"), { x -> q(x) }, ", ") + "]"
        "related" -> s(r["rel"]) + " of " + q(r["anchor"])
        "all_of" -> "ALL OF (" + join(G.arr(r["parts"], "parts"), { p -> res(mm(p)) }, " AND ") + ")"
        else -> "ANY RESOURCE (reason: " + q(r["reason"]) + ")"
    }

    @JvmStatic
    fun win(w: Map<String, Any?>): String = when (G.kind(w)) {
        "task" -> "per task"
        "lifetime" -> "over the lifetime"
        "sliding" -> "in any " + s(w["ms"]) + " ms window"
        else -> "per " + s(w["ms"]) + " ms period starting at " + s(w["t0"])
    }

    @JvmStatic
    fun scope(sc: Map<String, Any?>): String =
        if (G.kind(sc) == "fleet") "fleet [" + join(G.arr(sc["agents"], "agents"), { x -> q(x) }, ", ") + "]" else G.kind(sc)

    @JvmStatic
    fun grantLine(x: Map<String, Any?>): String = "ALLOW " + q(x["gid"]) + ": verb " + q(x["verb"]) + " on " + res(mm(x["res"])) + " when " + cond(mm(x["cond"]))

    @JvmStatic
    fun prohibitLine(x: Map<String, Any?>): String {
        val t = mm(x["target"])
        val tgt = if (G.kind(t) == "verb") "verb " + q(t["verb"]) else "every verb of effect class " + q(t["cls"])
        return "NEVER " + q(x["pid"]) + ": " + tgt + " on " + res(mm(x["res"])) + " when " + cond(mm(x["cond"]))
    }

    @JvmStatic
    fun boundLine(b: Map<String, Any?>): String {
        val sel = mm(b["sel"])
        val over = if (G.kind(sel) == "gids") "grants [" + join(G.arr(sel["gids"], "gids"), { x -> q(x) }, ", ") + "]" else "effect class " + q(sel["cls"])
        val agg = s(b["agg"])
        val of = if (agg == "count") "" else if (agg == "distinct") " of " + q(b["key"]) else " of " + term(mm(b["value"]))
        return "LIMIT " + q(b["bid"]) + ": " + agg + of + " over " + over + ", " + win(mm(b["window"])) + ", scope " + scope(mm(b["scope"])) +
            ", at most " + quantity(mm(b["cap"])) + "; beyond that: " + (if ("deny" == b["onExceed"]) "deny" else "ask the principal")
    }

    @JvmStatic
    fun validityLine(v: Map<String, Any?>): String =
        "VALID from " + s(v["notBefore"]) + " to " + s(v["notAfter"]) + "; idle limit " + (if (G.toNum(v["maxIdle"]) > 0) s(v["maxIdle"]) + " ms" else "none")

    @JvmStatic
    fun delegationLine(d: Map<String, Any?>): String =
        "DELEGATION depth at most " + s(d["maxDepth"]) + ", narrow only " + s(d["narrowOnly"]) + ", delegates may use grants [" +
            join(G.arr(d["mayTouch"], "mayTouch"), { x -> q(x) }, ", ") + "]"

    @JvmStatic
    fun escalateLine(c: Map<String, Any?>): String = "ASK THE PRINCIPAL when " + cond(c)

    @JvmStatic
    fun holeLine(h: Map<String, Any?>): String =
        "UNRESOLVED " + q(h["hid"]) + ": " + q(h["q"]) + " options [" + join(G.arr(h["domain"], "domain"), { x -> q(x) }, ", ") + "] affects " +
            (if (G.truthy(h["global"])) "everything" else "[" + join(G.arr(h["affects"], "affects"), { x -> q(x) }, ", ") + "]")

    /** One line per clause in canonical order, plus the warnings the principal must look at twice: {lines, warnings}. */
    @JvmStatic
    fun renderCard(g: Map<String, Any?>): Map<String, Any?> {
        val lines = ArrayList<Any?>()
        val warnings = ArrayList<Any?>()
        lines.add("Goal v" + s(g["v"]) + " for principal " + q(g["principal"]) + "; ontology " + q(g["ontDigest"]) + "; request text digest " + q(g["nlDigest"]))
        for (x in G.arr(g["sources"], "sources")) lines.add("Source " + q(x))
        val ack = G.arr(g["wildcardAck"], "wildcardAck")
        for (x in G.arr(g["grants"], "grants")) {
            val gr = mm(x)
            lines.add(grantLine(gr))
            if (G.kind(gr["res"]) == "any") warnings.add("grant " + q(gr["gid"]) + " applies to every resource" + (if (ack.contains(gr["gid"])) " (acknowledged)" else " (NOT acknowledged)"))
        }
        for (x in G.arr(g["prohibits"], "prohibits")) lines.add(prohibitLine(mm(x)))
        for (b in G.arr(g["bounds"], "bounds")) lines.add(boundLine(mm(b)))
        lines.add(validityLine(mm(g["validity"])))
        lines.add(delegationLine(mm(g["deleg"])))
        for (c in G.arr(g["escalateOn"], "escalateOn")) lines.add(escalateLine(mm(c)))
        for (a in ack) lines.add("Wildcard acknowledged for " + q(a))
        val holes = G.arr(g["holes"], "holes")
        for (h in holes) lines.add(holeLine(mm(h)))
        if (holes.isNotEmpty()) warnings.add("this goal has unresolved questions and cannot be signed")
        return G.map("lines" to lines, "warnings" to warnings)
    }
}
