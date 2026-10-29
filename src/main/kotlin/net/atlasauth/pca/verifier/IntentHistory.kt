package net.atlasauth.pca.verifier

/**
 * Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and
 * monitors. The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from the
 * session's event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are pure: the
 * store, its lock and the reservation are the host's. An event is `{id, verb, resource, params, t, status}`.
 *
 * Where the reference throws (a past event's value or time is unreadable, the candidate's key is missing, a sum leaves the
 * safe-integer range) these throw [IllegalStateException]: fail closed upstream.
 */
object IntentHistory {
    /** A reserved or committed event counts toward a cap (a reservation counts as soon as it is made). */
    fun isCounted(status: Any?): Boolean = status == "reserved" || status == "committed"

    /**
     * Does the counted event stamped `ti` still count at `t`? task: always; sliding(ms): (t-ms, t]; period(ms, t0): the period
     * containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is in no
     * window (fail closed).
     */
    fun inWindow(win: Map<String, Any?>, ti: Any?, t: Any?): Boolean {
        if (!IntentJs.isInt(ti) || !IntentJs.isInt(t)) return false
        val fi = IntentJs.num(ti)!!
        val ft = IntentJs.num(t)!!
        if (fi > ft) return true
        return when (win["kind"]) {
            "task" -> true
            "sliding" -> fi > ft - (IntentJs.num(win["ms"]) ?: Double.NaN)
            "period" -> {
                val ms = IntentJs.num(win["ms"]) ?: Double.NaN
                val t0 = IntentJs.num(win["t0"]) ?: Double.NaN
                Math.floor((fi - t0) / ms) == Math.floor((ft - t0) / ms)
            }
            else -> false
        }
    }

    /** The canonical key of the grouping parameter, `•` when ungrouped, null when the parameter is missing or not a string / safe integer. */
    fun accKeyOf(a: Map<String, Any?>, params: Map<String, Any?>): String? {
        val k = a["key"] as? String ?: return "•"
        val name = k.substring("action.params.".length)
        return if (params.containsKey(name)) IntentAcc.distinctKey(params[name]) else null
    }

    private fun emptyPre(agg: Any?): Map<String, Any?> = when (agg) {
        "sum" -> linkedMapOf("sum" to IntentJs.ofLong(0))
        "count" -> linkedMapOf("count" to IntentJs.ofLong(0))
        "max" -> linkedMapOf("max" to IntentJs.ofLong(0))
        else -> linkedMapOf("values" to ArrayList<Any?>())
    }

    private fun obj(o: Any?): Map<String, Any?> = if (o is Map<*, *>) IntentJs.obj(o) else emptyMap()

    /**
     * The pre-state of the accumulator `a` for a candidate action `(candParams, candT)` over `history` (a list of events).
     * `schema` is the accepted action schema (null: none). Throws [IllegalStateException] where the reference throws.
     */
    fun accPreState(a: Map<String, Any?>, history: List<Any?>, candParams: Map<String, Any?>, candT: Any?, schema: Any?): Map<String, Any?> {
        val key = accKeyOf(a, candParams) ?: throw IllegalStateException("accPreState: the key parameter ${a["key"]} is missing")
        if (!IntentJs.isInt(candT)) throw IllegalStateException("accPreState: the candidate time is not a safe integer")
        val win = obj(a["win"])
        var sum = 0.0
        var count = 0.0
        var mx = 0.0
        val vals = ArrayList<String>()
        for (ev in history) {
            val e = obj(ev)
            val counted = isCounted(e["status"])
            if (counted && !IntentJs.isInt(e["t"])) throw IllegalStateException("accPreState: event ${e["id"]}: the time is not a safe integer")
            if (!counted || !inWindow(win, e["t"], candT)) continue
            val verb = e["verb"] as? String ?: ""
            val params = obj(e["params"])
            if (!IntentAcc.accSelects(a, verb, schema)) continue
            if (accKeyOf(a, params) != key) continue
            val v = IntentAcc.accValueOf(a, verb, params, schema)
            if (v.reason != null) throw IllegalStateException("accPreState: event ${e["id"]}: ${v.reason}")
            sum += v.value.toDouble()
            count += 1
            mx = Math.max(mx, v.value.toDouble())
            if (v.key != null) vals.add(v.key)
        }
        return when (a["agg"]) {
            "sum" -> {
                if (sum > IntentJs.MAX_SAFE) throw IllegalStateException("accPreState: sum exceeds 2^53-1")
                linkedMapOf("sum" to IntentJs.ofLong(sum.toLong()))
            }
            "count" -> linkedMapOf("count" to IntentJs.ofLong(count.toLong()))
            "max" -> linkedMapOf("max" to IntentJs.ofLong(mx.toLong()))
            else -> linkedMapOf("values" to ArrayList<Any?>(vals.sortedWith { x, y -> Json.compareUtf8(x, y) }.distinct()))
        }
    }

    /** `post(history, omega, t)`: the pre-state combined with omega when it is selected, else the pre-state's value. Throws where the reference throws. */
    fun accPost(a: Map<String, Any?>, history: List<Any?>, verb: String, params: Map<String, Any?>, t: Any?, schema: Any?): Long {
        val pre = if (a["key"] is String && accKeyOf(a, params) == null) emptyPre(a["agg"]) else accPreState(a, history, params, t, schema)
        if (!IntentAcc.accSelects(a, verb, schema)) return IntentAcc.preValue(a["agg"], pre)
        val v = IntentAcc.accValueOf(a, verb, params, schema)
        if (v.reason != null) throw IllegalStateException("accPost: ${v.reason}")
        return IntentAcc.combineAcc(a["agg"], pre, v) ?: throw IllegalStateException("accPost: overflow")
    }

    /** The start state of a monitor. */
    fun monitorInitialState(m: Map<String, Any?>): String = when (m["kind"]) {
        "requires_prior", "precedes" -> "unmet"
        "never" -> "clean"
        "always" -> "ok"
        else -> "idle"
    }

    private fun jsNum(d: Double): String = if (d.isNaN()) "NaN" else AttestUtil.jsNumString(d)

    /** One monitor step on one event; statuses that do not count leave the state unchanged. */
    fun monitorStep(m: Map<String, Any?>, q: String, e: Map<String, Any?>): String {
        val counts = if (m["status"] == "committed") e["status"] == "committed" else isCounted(e["status"])
        if (!counts) return q
        val action = linkedMapOf<String, Any?>("verb" to e["verb"], "resource" to e["resource"], "params" to e["params"])
        val ctx = linkedMapOf<String, Any?>("action" to action)
        fun match(p: Any?): Boolean = Predicates.predicateMatches(p, ctx)
        when (m["kind"]) {
            "requires_prior", "precedes" -> return if (q == "met" || match(m["p"])) "met" else "unmet"
            "never" -> return if (q == "seen" || match(m["p"])) "seen" else "clean"
            "always" -> return if (q == "broken" || !match(m["p"])) "broken" else "ok"
            "responds_within" -> {
                if (q == "missed") return "missed"
                val w = IntentJs.num(m["within"]) ?: Double.NaN
                var pending: Double? = if (q.startsWith("pending:")) (q.substring(8).trim().toDoubleOrNull() ?: Double.NaN) else null
                if (pending != null) {
                    if (match(m["q"])) pending = null
                    else if (pending - 1 <= 0) return "missed"
                    else pending -= 1
                }
                if (match(m["p"])) pending = if (pending == null) w else Math.min(pending, w)
                return if (pending == null) "idle" else "pending:" + jsNum(pending)
            }
        }
        return q
    }

    /** The fold of the monitor over the history (admission order, current statuses). */
    fun monitorState(m: Map<String, Any?>, history: List<Any?>): String {
        var q = monitorInitialState(m)
        for (ev in history) q = monitorStep(m, q, obj(ev))
        return q
    }
}
