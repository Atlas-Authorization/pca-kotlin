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
    val EVENT_STATUSES: List<String> = listOf("reserved", "committed", "released", "reverted")
    val COUNTED_STATUSES: List<String> = listOf("reserved", "committed")

    fun isCounted(status: Any?): Boolean = status == "reserved" || status == "committed"

    /**
     * Does the counted event stamped `ti` still count at `t`? task: always; sliding(ms): (t-ms, t]; period(ms, t0): the period
     * containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is in no
     * window (fail closed).
     */
    fun inWindow(win: Map<String, Any?>?, ti: Any?, t: Any?): Boolean {
        if (!IntentJs.isInt(ti) || !IntentJs.isInt(t)) return false
        val fi = IntentJs.num(ti)!!
        val ft = IntentJs.num(t)!!
        if (fi > ft) return true
        // a null window only matters once the integer checks pass (the reference reads win.kind there)
        win!!
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
        return IntentAcc.distinctKey(params[name]) // an absent parameter reads null, which has no distinct key
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
        val win: Map<String, Any?>? = if (a["win"] == null) null else obj(a["win"]) // an absent window fails when read, a non-object has no members
        var sum = 0.0
        var count = 0.0
        var mx = 0.0
        val vals = ArrayList<String>()
        for (ev in history) {
            if (ev == null) throw IllegalStateException("Cannot read properties of null (reading 'status')")
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
        // as the reference accPost (intent-history.ts:115): an unknown agg is refused before any key / pre-state work
        if (a["agg"] !in IntentAcc.ACC_AGGS) throw IllegalStateException("accPost: unknown agg")
        // accKeyOf is null only for a String key whose parameter is missing, so it alone carries the reference's `a.key !== null &&`
        val pre = if (accKeyOf(a, params) == null) emptyPre(a["agg"]) else accPreState(a, history, params, t, schema)
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

    private fun jsNum(d: Double): String = AttestUtil.jsNumString(d) // "NaN", "Infinity", "-Infinity" as JS prints them

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
                // a non-numeric deadline (a malformed declaration) fails closed as missed
                val w = IntentJs.num(m["within"]) ?: return "missed"
                var pending: Double? = if (q.startsWith("pending:")) (AttestNvidia.jsNumberFromString(q.substring(8)) ?: Double.NaN) else null
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

    // ---- the verifier context of a candidate action and the session store port ----

    /** The verifier context (`intentV2.acc`) for a candidate action `{params, t}`: pre-states of the site-local accumulators and the monitors' states. */
    @JvmStatic @JvmOverloads
    fun accContextFor(root: Any?, history: List<Any?>, cand: Map<String, Any?>, schema: Any? = null): Map<String, Any?> {
        val state = LinkedHashMap<String, Any?>()
        val params = obj(cand["params"])
        val accs = IntentJs.get(root, "accumulators") as? List<*> ?: throw IllegalArgumentException("S.accumulators is not iterable")
        for (ao in accs) {
            val a = IntentJs.obj(ao)
            if (IntentJs.get(IntentJs.get(a, "holder"), "kind") != "site_local") continue
            if (a["key"] != null && accKeyOf(a, params) == null) continue // the verifier fails the claim (missing key)
            state[a["id"] as String] = accPreState(a, history, params, cand["t"], schema)
        }
        val monitors = LinkedHashMap<String, Any?>()
        val ms = IntentJs.get(root, "monitors") as? List<*> ?: throw IllegalArgumentException("S.monitors is not iterable")
        for (mo in ms) {
            val m = IntentJs.obj(mo)
            monitors[m["id"] as String] = monitorState(m, history)
        }
        return linkedMapOf("state" to state, "monitors" to monitors)
    }

    /** A transaction on ONE session's history, holding its exclusive lock. */
    interface SessionTx {
        fun events(): List<Map<String, Any?>>
        fun append(e: Map<String, Any?>)
        fun setStatus(id: String, status: String): Boolean
    }

    /**
     * The accumulator state holder. The linearizability of admission holds iff [withSession] serialises every admission of a session: the pre-state read, the verification and
     * the `reserved` append happen under one lock (a row lock in a database, the in-process mutex of [MemoryIntentSessionStore]). [durable] is true when the history survives a
     * restart of the process; [admitIntentAction] refuses a store that does not say so, unless the caller passes `requireDurable = false`.
     */
    interface IntentSessionStore {
        fun <T> withSession(session: String, fn: (SessionTx) -> T): T
        val durable: Boolean? get() = null
    }

    /**
     * In-process store with a per-session lock (tests, single-process sites). It is VOLATILE by default (`durable` false): a restart forgets every session's history, so every cap and
     * monitor starts again from zero. A deployment whose caps must outlive the process implements [IntentSessionStore] over its database.
     */
    class MemoryIntentSessionStore @JvmOverloads constructor(override val durable: Boolean? = false) : IntentSessionStore {
        private val logs = HashMap<String, ArrayList<MutableMap<String, Any?>>>()

        @Synchronized override fun <T> withSession(session: String, fn: (SessionTx) -> T): T {
            val log = logs.getOrPut(session) { ArrayList() }
            return fn(object : SessionTx {
                override fun events(): List<Map<String, Any?>> = log.map { LinkedHashMap(it) }
                override fun append(e: Map<String, Any?>) {
                    if (log.any { it["id"] == e["id"] }) throw IllegalStateException("duplicate event id")
                    log.add(LinkedHashMap(e))
                }
                override fun setStatus(id: String, status: String): Boolean {
                    val e = log.firstOrNull { it["id"] == id } ?: return false
                    e["status"] = status
                    return true
                }
            })
        }

        /** A copy of one session's events. */
        @Synchronized fun snapshot(session: String): List<Map<String, Any?>> = (logs[session] ?: ArrayList()).map { LinkedHashMap(it) }
    }

    /**
     * Admit one action atomically against the session's accumulators (site-local holder): under the session lock compute the pre-states and monitor states from the history, run
     * [verify] with them and, when its verdict's `allow` is truthy, append the event as `reserved`. After the effect the host calls [settleIntentEvent]. A store that is not durable
     * is refused (a restart would reset every cap) unless [requireDurable] is false; a [verify] that throws leaves nothing appended.
     */
    @JvmStatic @JvmOverloads
    fun admitIntentAction(
        store: IntentSessionStore, session: String, root: Any?, event: Map<String, Any?>, verify: (Map<String, Any?>) -> Map<String, Any?>, schema: Any? = null, requireDurable: Boolean = true,
    ): Map<String, Any?> {
        if (requireDurable && store.durable != true) throw IllegalStateException("admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore")
        return store.withSession(session) { tx ->
            val history = tx.events()
            val acc = accContextFor(root, history, event, schema)
            val v = verify(acc)
            if (net.atlasauth.pca.compliance.ComplianceJs.truthy(v["allow"])) {
                val reserved = LinkedHashMap(event)
                reserved["status"] = "reserved"
                tx.append(reserved)
            }
            v
        }
    }

    /** Settle an admitted event as `committed`, `released` or `reverted`; false when the session or event is unknown. */
    @JvmStatic fun settleIntentEvent(store: IntentSessionStore, session: String, id: String, status: String): Boolean = store.withSession(session) { tx -> tx.setStatus(id, status) }
}
