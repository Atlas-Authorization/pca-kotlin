package net.atlasauth.pca.actions

import java.util.TreeMap
import java.util.TreeSet
import net.atlasauth.pca.verifier.Actions

/**
 * Keep a platform's action definitions in step with the sources they were imported from. Pure: the caller fetches the source and stores the lock. The lock
 * records, per source, the digest of each operation AS IMPORTED (before any review). On the next sync an operation is `added` (lands as imported,
 * unreviewed, so strict), `changed` (the NEW imported form replaces the reviewed def and is unreviewed until a reviewer confirms it again; the semantic
 * diff is reported), `unchanged` (the current, possibly reviewed, def is kept) or `removed` (deprecated). A def the lock does not attribute to
 * this source is never touched.
 */
object ActionSync {
    /** Strip the review to the imported state: a changed operation is never carried over as confirmed. */
    private fun asImported(d: Map<String, Any?>): Map<String, Any?> {
        val rv = d["review"]
        if (rv !is Map<*, *>) throw IllegalArgumentException("the def has no review")
        if ("confirmed" != rv["state"]) return d
        val c = LinkedHashMap(d)
        c["review"] = J.obj("state", "unreviewed")
        return c
    }

    /**
     * Merge a fresh import of one source into the current defs: `{defs, entries, deprecated, lock, needsReview}`. `lock` may be null;
     * `now`: seconds since the epoch of this sync. `reg` null is the core registry; `attestationVerified` may be null.
     */
    fun syncSource(
        current: List<*>,
        imported: List<*>,
        specDigest: String?,
        lock: Map<String, Any?>?,
        now: Any?,
        reg: Map<String, Map<String, Any?>>?,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): MutableMap<String, Any?> {
        val r = reg ?: Actions.CORE_REGISTRY
        val cur = LinkedHashMap<String, Map<String, Any?>>()
        for (d in current) cur[J.get(d, "verb") as String] = J.m(d)
        val imp = TreeMap<String, Map<String, Any?>>()
        for (d in imported) imp[J.get(d, "verb") as String] = asImported(J.m(d))
        val lockOps: Map<String, Any?> = if (lock != null && lock["ops"] is Map<*, *>) J.m(lock["ops"]) else LinkedHashMap()
        val ops = LinkedHashMap<String, Any?>()
        val entries = ArrayList<Any?>()
        val defs = ArrayList<Any?>()
        for ((verb, d) in imp) {
            val dg = Actions.defDigest(d)
            ops[verb] = dg
            val old = cur[verb]
            val locked = lockOps[verb]
            if (old == null) {
                entries.add(J.obj("verb", verb, "change", "added"))
                defs.add(d)
            } else if (dg == locked || (locked == null && Actions.defDigest(old) == dg)) {
                entries.add(J.obj("verb", verb, "change", "unchanged"))
                defs.add(old)
            } else {
                val diff: Map<String, Any?> = try {
                    ActionDiff.diffDefs(old, d, r, attestationVerified)
                } catch (ex: RuntimeException) {
                    J.obj("class", "incomparable", "reasons", J.list(ex.message))
                }
                entries.add(J.obj("verb", verb, "change", "changed", "diff", diff))
                defs.add(d)
            }
        }
        val deprecated = TreeSet<String>()
        for (v in lockOps.keys) if (!imp.containsKey(v)) deprecated.add(v)
        for (v in deprecated) entries.add(J.obj("verb", v, "change", "removed"))
        var needs = false
        for (e in entries) if ("added" == J.get(e, "change") || "changed" == J.get(e, "change")) needs = true
        return J.obj("defs", defs, "entries", entries, "deprecated", J.objs(ArrayList(deprecated)), "lock", J.obj("spec_digest", specDigest, "ops", ops, "synced_at", now), "needsReview", needs)
    }

    /** One line per entry, then a summary. */
    fun syncText(r: Map<String, Any?>): String {
        val lines = ArrayList<String>()
        var added = 0
        var changed = 0
        var removed = 0
        var unchanged = 0
        for (e0 in J.a(r["entries"])) {
            val change = J.get(e0, "change") as String
            when (change) {
                "added" -> added++
                "changed" -> changed++
                "removed" -> removed++
                else -> unchanged++
            }
            if (change == "unchanged") continue
            val pad = StringBuilder(change)
            while (pad.length < 9) pad.append(' ')
            var suffix = ""
            val diff = J.get(e0, "diff")
            if (diff != null) {
                val rs = J.a(J.get(diff, "reasons"))
                val rss = ArrayList<String>()
                for (x in rs) rss.add(x.toString())
                suffix = "  (" + J.get(diff, "class") + (if (rss.isEmpty()) "" else ": " + rss.joinToString(", ")) + ")"
            }
            lines.add("$pad ${J.get(e0, "verb")}$suffix")
        }
        lines.add(
            "$added added, $changed changed, $removed removed (deprecated), $unchanged unchanged" +
                (if (r["needsReview"] == true) "; added and changed actions are unreviewed (strict) until a reviewer confirms them" else ""),
        )
        return lines.joinToString("\n")
    }
}
