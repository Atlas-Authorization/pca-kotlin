package net.atlasauth.pca.storeconformance

import java.math.BigInteger
import net.atlasauth.pca.doctor.Js
import net.atlasauth.pca.verifier.Json

/**
 * The pure core of the store conformance kit: the register model both store operations share, the budgeted linearizability search,
 * the per-key checker with minimal counterexamples, the recorder's history parser, and the report formatting.
 *
 * ONE MODEL FOR BOTH OPERATIONS. The register `s` starts at -infinity (no record, no counter). A TRUE answer is legal iff
 * `s < lo`, and then `s := max(s, w)`; a FALSE answer is legal iff `s >= lo` and leaves `s` unchanged. An UNKNOWN outcome (error,
 * timeout, killed client) may or may not have taken effect. The register never decreases, which the reductions ([prune],
 * [fastCheck]) rely on. A PASS is evidence, never proof; a FAIL is a recorded history that no sequential order explains.
 */
object Kit {
    /** Default number of distinct search states explored per key before giving up (unresolved). */
    const val DEFAULT_SEARCH_BUDGET: Double = 200_000.0

    val ALL_TESTS: List<String> = listOf("burst", "concurrent", "retention", "durability", "crash")

    // ---- model ----

    /** The register's successor states after [op] from [s] (empty: the answer is impossible from [s]). */
    fun step(s: Double, op: Op): List<Double> {
        val fresh = s < op.lo
        val out = ArrayList<Double>()
        if (op.res == "true") {
            if (fresh) out.add(Math.max(s, op.w))
        } else if (op.res == "false") {
            if (!fresh) out.add(s)
        } else {
            out.add(s)
            if (fresh) out.add(Math.max(s, op.w))
        }
        return out
    }

    private fun cmp(a: Double, b: Double): Int = if (a < b) -1 else if (a > b) 1 else 0

    private fun trues(ops: List<Op>): ArrayList<Op> {
        val ts = ArrayList<Op>()
        for (o in ops) if (o.res == "true") ts.add(o)
        return ts
    }

    /** Two definite TRUE answers whose [lo, w] intervals overlap can never both linearize; returns such a pair, or null. */
    fun overlappingTrues(ops: List<Op>): List<Op>? {
        val ts = trues(ops)
        ts.sortWith(Comparator { a, b -> cmp(a.lo, b.lo) })
        for (i in 1 until ts.size) if (ts[i - 1].w >= ts[i].lo) return listOf(ts[i - 1], ts[i])
        return null
    }

    /** Drop every definite FALSE that a definite TRUE explains (verdict-preserving). */
    fun prune(ops: List<Op>): List<Op> {
        val ts = trues(ops)
        ts.sortWith(Comparator { a, b -> cmp(a.ret, b.ret) })
        val pm = DoubleArray(ts.size)
        for (i in ts.indices) pm[i] = Math.max(ts[i].w, if (i > 0) pm[i - 1] else Double.NEGATIVE_INFINITY)
        val out = ArrayList<Op>()
        for (o in ops) {
            if (o.res != "false") { out.add(o); continue }
            var n = 0
            while (n < ts.size && ts[n].ret < o.call) n++
            if (!(n > 0 && pm[n - 1] >= o.lo)) out.add(o)
        }
        return out
    }

    /** EXACT decision for a history with no unknown operation (null when one is unknown). */
    fun fastCheck(ops: List<Op>): Boolean? {
        for (o in ops) if (o.res == "unknown") return null
        val ts = trues(ops)
        ts.sortWith(Comparator { a, b -> cmp(a.lo, b.lo) })
        val t = DoubleArray(ts.size)
        var prev = Double.NEGATIVE_INFINITY
        for (i in ts.indices) {
            val o = ts[i]
            if (i > 0 && ts[i - 1].w >= o.lo) return false
            val ti = Math.max(o.call, prev)
            if (ti > o.ret) return false
            t[i] = ti
            prev = ti
        }
        for (f in ops) {
            if (f.res != "false") continue
            var j = -1
            for (i in ts.indices) if (ts[i].w >= f.lo) { j = i; break }
            if (j < 0 || t[j] > f.ret) return false
        }
        return true
    }

    // ---- search ----

    /** Linearizability search (Wing-Gong / Lowe) for ONE key: `ok`, `violation` or `unresolved` (over budget, never a pass). */
    fun searchLinearizable(ops: List<Op>, budget: Double = DEFAULT_SEARCH_BUDGET): String {
        val order = ArrayList(ops)
        order.sortWith(Comparator { a, b -> cmp(a.call, b.call) })
        val n = order.size
        val bits = Array<BigInteger>(n) { BigInteger.ONE.shiftLeft(it) }
        val all = BigInteger.ONE.shiftLeft(n).subtract(BigInteger.ONE)
        val seen = HashSet<String>()
        val stack = ArrayList<Pair<BigInteger, Double>>()
        stack.add(Pair(BigInteger.ZERO, Double.NEGATIVE_INFINITY))
        while (stack.isNotEmpty()) {
            val top = stack.removeAt(stack.size - 1)
            val done = top.first
            val s = top.second
            if (done == all) return "ok"
            val id = done.toString(36) + "|" + (if (s == 0.0) 0.0 else s)
            if (seen.contains(id)) continue
            if (seen.size >= budget) return "unresolved"
            seen.add(id)
            var minRet = Double.POSITIVE_INFINITY
            for (i in 0 until n) if (done.and(bits[i]).signum() == 0) minRet = Math.min(minRet, order[i].ret)
            var i = 0
            while (i < n && order[i].call <= minRet) {
                if (done.and(bits[i]).signum() == 0) {
                    for (s2 in step(s, order[i])) stack.add(Pair(done.or(bits[i]), s2))
                }
                i++
            }
        }
        return "violation"
    }

    // ---- check ----

    /** Options of the per-key checker; null members take the reference defaults. */
    class CheckOptions {
        /** Search states per key before the key is unresolved (default 200,000). */
        var budget: Double? = null

        /** Shrink each violating key's history to a 1-minimal counterexample (default true). */
        var minimize: Boolean? = null

        /** Keys with more operations than this (after pruning) are reported without shrinking (default 200). */
        var minimizeLimit: Double? = null

        companion object {
            fun fromJson(o: Any?): CheckOptions {
                val c = CheckOptions()
                if (o !is Map<*, *>) return c
                if (o["budget"] != null) c.budget = Js.toNumber(o["budget"])
                if (o.containsKey("minimize")) c.minimize = o["minimize"] != false
                if (o["minimizeLimit"] != null) c.minimizeLimit = Js.toNumber(o["minimizeLimit"])
                return c
            }
        }
    }

    /** One key's decision: the verdict, how it was reached (`overlap`, `exact`, `search`) and the pruned history. */
    class Decision internal constructor(val verdict: String, val method: String, val kept: List<Op>) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["verdict"] = verdict
            m["method"] = method
            m["kept"] = opsJson(kept)
            return m
        }
    }

    internal fun opsJson(ops: List<Op>): List<Any?> {
        val out = ArrayList<Any?>()
        for (o in ops) out.add(o.toJson())
        return out
    }

    fun opsOf(o: Any?): List<Op> {
        val out = ArrayList<Op>()
        for (x in o as List<*>) out.add(Op.fromJson(x))
        return out
    }

    /** Decide one key's history (all operations share kind and key). */
    fun decideKey(ops: List<Op>, budget: Double): Decision {
        if (overlappingTrues(ops) != null) return Decision("violation", "overlap", ArrayList(ops))
        val kept = prune(ops)
        val exact = fastCheck(kept)
        if (exact != null) return Decision(if (exact) "ok" else "violation", "exact", kept)
        return Decision(searchLinearizable(kept, budget), "search", kept)
    }

    /**
     * The SOUND deletion step for [op]: deleting a FALSE never helps it; deleting a writer (TRUE or unknown) lowers the register,
     * which can only break FALSEs it may have explained (`lo <= w`), so those go with it.
     */
    fun deletion(ops: List<Op>, op: Op): List<Op> {
        val out = ArrayList<Op>()
        if (op.res == "false") {
            for (o in ops) if (o !== op) out.add(o)
            return out
        }
        for (o in ops) if (o !== op && !(o.res == "false" && o.lo <= op.w)) out.add(o)
        return out
    }

    /** Greedy sound deletion to a 1-minimal violating history. */
    fun minimize(ops: List<Op>, budget: Double): List<Op> {
        var cur: List<Op> = ArrayList(ops)
        var changed = true
        while (changed) {
            changed = false
            for (op in ArrayList(cur)) {
                val next = deletion(cur, op)
                if (decideKey(next, budget).verdict == "violation") {
                    cur = next
                    changed = true
                    break
                }
            }
        }
        return cur
    }

    /** One key's result. */
    class KeyResult internal constructor(val key: String, val kind: Any?, val ops: Int, val searched: Int, val verdict: String, val method: String) {
        var counterexample: List<Op>? = null
        var minimized: Boolean? = null

        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["key"] = key
            m["kind"] = kind
            m["ops"] = ops
            m["searched"] = searched
            m["verdict"] = verdict
            m["method"] = method
            val ce = counterexample
            if (ce != null) m["counterexample"] = opsJson(ce)
            val mn = minimized
            if (mn != null) m["minimized"] = mn
            return m
        }
    }

    fun checkKey(ops: List<Op>, opts: CheckOptions?): KeyResult {
        val o = opts ?: CheckOptions()
        val budget = o.budget ?: DEFAULT_SEARCH_BUDGET
        val first = ops[0]
        val d = decideKey(ops, budget)
        val r = KeyResult(first.key, first.kind, ops.size, d.kept.size, d.verdict, d.method)
        if (d.verdict != "violation") return r
        val pair = overlappingTrues(ops)
        if (pair != null) {
            val p = ArrayList(pair)
            p.sortWith(Comparator { a, b -> cmp(a.call, b.call) })
            r.counterexample = p
            r.minimized = true
        } else if (o.minimize != false && d.kept.size <= (o.minimizeLimit ?: 200.0)) {
            r.counterexample = minimize(d.kept, budget)
            r.minimized = true
        } else {
            r.counterexample = d.kept
            r.minimized = false
        }
        return r
    }

    /** The check of a whole history: counts by outcome, the violating keys and the keys over budget. */
    class HistoryCheck internal constructor(
        val ops: Int,
        val keys: Int,
        val ok: Boolean,
        /** true, false, unknown */
        val outcomes: IntArray,
        val violations: List<KeyResult>,
        val unresolved: List<KeyResult>,
    ) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ops"] = ops
            m["keys"] = keys
            m["ok"] = ok
            val oc = LinkedHashMap<String, Any?>()
            oc["true"] = outcomes[0]
            oc["false"] = outcomes[1]
            oc["unknown"] = outcomes[2]
            m["outcomes"] = oc
            m["violations"] = keyResultsJson(violations)
            m["unresolved"] = keyResultsJson(unresolved)
            return m
        }
    }

    internal fun keyResultsJson(l: List<KeyResult>): List<Any?> {
        val out = ArrayList<Any?>()
        for (k in l) out.add(k.toJson())
        return out
    }

    /** Split a history by (kind, key) and check every key. */
    fun checkHistory(ops: List<Op>, opts: CheckOptions?): HistoryCheck {
        val byKey = LinkedHashMap<String, ArrayList<Op>>()
        val outcomes = IntArray(3)
        for (o in ops) {
            outcomes[if (o.res == "true") 0 else if (o.res == "false") 1 else 2]++
            byKey.getOrPut(Js.str(o.kind) + "\u0000" + o.key) { ArrayList() }.add(o)
        }
        val violations = ArrayList<KeyResult>()
        val unresolved = ArrayList<KeyResult>()
        for (list in byKey.values) {
            val r = checkKey(list, opts)
            if (r.verdict == "violation") violations.add(r) else if (r.verdict == "unresolved") unresolved.add(r)
        }
        return HistoryCheck(ops.size, byKey.size, violations.isEmpty() && unresolved.isEmpty(), outcomes, violations, unresolved)
    }

    // ---- formatting ----

    private fun fmtT(t: Double, base: Double): String = if (t == Double.POSITIVE_INFINITY) "open" else "+" + Js.toFixed(t - base, 3) + "ms"

    /** One line per operation, times relative to the first invocation. */
    fun formatOps(ops: List<Op>): List<String> {
        var base = Double.POSITIVE_INFINITY
        for (o in ops) base = Math.min(base, o.call)
        val sorted = ArrayList(ops)
        sorted.sortWith(Comparator { a, b -> cmp(a.call, b.call) })
        val out = ArrayList<String>()
        for (o in sorted) {
            val what = if (o.isConsume()) "consumeOnce(now=" + Js.numStr(o.lo) + ", retainUntil=" + Js.numStr(o.w) + ")" else "advance(" + Js.numStr(o.lo) + ")"
            val res = if (o.res == "true") "TRUE" else if (o.res == "false") "false" else "unknown"
            out.add(o.client + ": " + what + " [" + fmtT(o.call, base) + " .. " + fmtT(o.ret, base) + "] -> " + res)
        }
        return out
    }

    // ---- recorder history ----

    /** The operations rebuilt from recorder lines, how many lines were torn, and how many invocations are pending. */
    class ParsedHistory internal constructor(val ops: List<Op>, val torn: Int, val pending: Int) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ops"] = opsJson(ops)
            m["torn"] = torn
            m["pending"] = pending
            return m
        }
    }

    private fun at(l: List<*>, i: Int): Any? = if (i < l.size) l[i] else Js.UNDEF

    /** `Number(v)` for a JSON value, arrays coerced through their string form. */
    private fun jsNumber(v: Any?): Double = if (v is List<*>) Js.toNumber(Js.str(v)) else Js.toNumber(v)

    /**
     * Rebuild the operations from recorder lines (any number of files concatenated). An invocation without a response is pending
     * (unknown, open-ended); an `unknown` response stays open-ended too. Lines that do not parse are counted as torn.
     */
    fun parseHistory(text: String): ParsedHistory {
        val open = HashMap<String, Op>()
        val ops = ArrayList<Op>()
        var torn = 0
        for (line in text.split("\n")) {
            if (line.isEmpty()) continue
            val e: Any? = try {
                Json.parseLenient(line)
            } catch (ex: RuntimeException) {
                torn++
                continue
            }
            if (e !is List<*>) { torn++; continue }
            val id = Js.str(at(e, 1)) + "/" + Js.str(at(e, 2))
            if ("i" == at(e, 0) && e.size == 9) {
                val op = Op(Js.str(at(e, 4)), e[5], Js.str(at(e, 6)), jsNumber(e[7]), jsNumber(e[8]), jsNumber(e[3]), Double.POSITIVE_INFINITY, "unknown")
                open[id] = op
                ops.add(op)
            } else if ("r" == at(e, 0) && e.size == 5 && open.containsKey(id)) {
                val op = open.remove(id)!!
                if ("unknown" != e[4]) {
                    op.ret = jsNumber(e[3])
                    op.res = if ("true" == e[4]) "true" else "false"
                }
            } else {
                torn++
            }
        }
        return ParsedHistory(ops, torn, open.size)
    }

    // ---- PRNG ----

    /** mulberry32, the workload PRNG: [rand] of n is an integer in [0, n) (as a double). */
    class Prng(seed: Double) {
        private var a: Int

        init {
            var t = if (seed < 0) Math.ceil(seed) else Math.floor(seed)
            if (t.isNaN() || t.isInfinite()) t = 0.0
            var m = t % 4294967296.0
            if (m < 0) m += 4294967296.0
            a = m.toLong().toInt()
        }

        fun rand(n: Double): Double {
            a += 0x6d2b79f5
            var t = a
            t = (t xor (t ushr 15)) * (t or 1)
            t = t xor (t + (t xor (t ushr 7)) * (t or 61))
            return Math.floor((((t xor (t ushr 14)).toLong() and 0xffffffffL) / 4294967296.0) * n)
        }
    }

    // ---- reports ----

    @Suppress("UNCHECKED_CAST")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun decodeNums(v: Any?): Any? {
        if (v is Map<*, *>) {
            val mm = m(v)
            if (mm.size == 1 && mm["\$num"] is String) return Op.numOf(v)
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in mm) out[k] = decodeNums(x)
            return out
        }
        if (v is List<*>) {
            val out = ArrayList<Any?>()
            for (x in v) out.add(decodeNums(x))
            return out
        }
        return v
    }

    /** The folded status of a run: any fail is a fail, else any unresolved is unresolved, else pass (a test is a map with a `status`). */
    fun overall(tests: List<*>): String {
        var unresolved = false
        for (t in tests) {
            val s = m(t)["status"]
            if ("fail" == s) return "fail"
            if ("unresolved" == s) unresolved = true
        }
        return if (unresolved) "unresolved" else "pass"
    }

    /** Human-readable report: one line per test, then each violating key's minimal counterexample (at most [maxKeys] per test). */
    fun formatReport(report: Any?, maxKeys: Double = 3.0): String {
        val r = m(decodeNums(report))
        val out = ArrayList<String>()
        out.add("pca-store-conformance: " + Js.str(r["adapter"]) + " -> " + Js.str(r["status"]).uppercase())
        for (to in r["tests"] as List<*>) {
            val t = m(to)
            val kind = t["kind"]
            val opName = if ("consume" == kind) "consumeOnce" else if ("advance" == kind) "advance" else "undefined"
            val name = Js.padEnd(Js.str(t["test"]) + "/" + opName, 24)
            val status = Js.str(t["status"])
            val stats = if (status == "skip") "" else Js.str(t["ops"]) + " ops, " + Js.str(t["keys"]) + " keys, " + Js.str(t["errors"]) + " errors/timeouts"
            val violations = t["violations"] as List<*>
            val extra = ArrayList<String>()
            if (violations.isNotEmpty()) extra.add(violations.size.toString() + " NON-LINEARIZABLE key(s)")
            if (Js.truthy(t["unresolved"])) extra.add(Js.str(t["unresolved"]) + " unresolved key(s) (over the search budget)")
            if (Js.truthy(t["note"])) extra.add(Js.str(t["note"]))
            val tail = ArrayList<String>()
            if (stats.isNotEmpty()) tail.add(stats)
            if (extra.isNotEmpty()) tail.add(extra.joinToString("; "))
            out.add("  [" + status.uppercase() + "] " + name + " " + tail.joinToString("; "))
            var i = 0
            while (i < violations.size && i < maxKeys) {
                val v = m(violations[i])
                out.add(
                    "      key " + Js.str(v["key"]) + " (" + Js.str(v["ops"]) + " ops, decided by " + Js.str(v["method"]) + "): " +
                        (if (Js.truthy(v["minimized"])) "minimal counterexample" else "violating history (not shrunk)") + ":",
                )
                val ce = if (v["counterexample"] == null) ArrayList<Op>() else opsOf(v["counterexample"])
                for (line in formatOps(ce)) out.add("        $line")
                i++
            }
        }
        return out.joinToString("\n")
    }

    /** JSON-safe form of a report (Infinity becomes null), indented by two spaces. */
    fun reportJson(report: Any?): String = Js.stringify(decodeNums(report))
}
