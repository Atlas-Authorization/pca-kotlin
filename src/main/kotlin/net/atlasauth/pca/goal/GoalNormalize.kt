package net.atlasauth.pca.goal

import java.util.TreeSet

/** Canonical form of a Goal: id-sorted clauses (code-unit order); duplicated ids are kept (the typechecker refuses them). */
object GoalNormalize {
    /** Stable JSON (sorted keys): an in-memory key for maps and sets, not a signed encoding. */
    @JvmStatic
    fun stable(v: Any?): String = G.stable(v)

    private fun byId(xs: Any?, field: String): List<Any?> {
        val out = ArrayList(G.arr(xs, field))
        // sortWith is stable, like Array.prototype.sort
        out.sortWith(Comparator { a, b -> (G.get(a, field) as String).compareTo(G.get(b, field) as String) })
        return out
    }

    private fun sortedSet(xs: Any?): List<Any?> {
        val s = TreeSet<String>()
        for (o in G.arr(xs, "")) s.add(o as String)
        return ArrayList<Any?>(s)
    }

    @JvmStatic
    fun canonicalizeGoal(g: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap(g)
        out["grants"] = byId(g["grants"], "gid")
        out["prohibits"] = byId(g["prohibits"], "pid")
        out["bounds"] = byId(g["bounds"], "bid")
        out["holes"] = byId(g["holes"], "hid")
        out["wildcardAck"] = sortedSet(g["wildcardAck"])
        val d = LinkedHashMap(G.m(g["deleg"])!!)
        d["mayTouch"] = sortedSet(d["mayTouch"])
        out["deleg"] = d
        return out
    }
}
