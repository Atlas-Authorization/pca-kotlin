package net.atlasauth.pca.verifier

/**
 * DECISION OBLIGATIONS: an `allow` may carry obligations the policy enforcement point must perform; a PEP that cannot perform every
 * one turns the allow into a `deny` ([pepObligationGate]). Port of packages/pca/src/obligations.ts; replays
 * packages/pca/conformance/obligations-vectors.json. Everything is total. A null list means absent (the empty list).
 */
object Obligations {
    val KINDS = listOf("log", "notify", "redact", "watermark", "require_receipt", "undo_window")
    const val MAX_OBLIGATIONS = 16
    private const val MAX_REDACT_FIELDS = 32
    private val FIELD_RE = Regex("^[A-Za-z_][A-Za-z0-9_]{0,63}(\\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$")
    private val ALLOWED = mapOf(
        "log" to setOf("sink"), "notify" to setOf("to"), "redact" to setOf("fields"), "watermark" to setOf("id"), "require_receipt" to emptySet<String>(),
        "undo_window" to setOf("id", "window_end"),
    )

    private fun paramsError(kind: String, p: Map<String, Any?>): String? {
        for (k in p.keys) if (k !in ALLOWED.getValue(kind)) return "unknown parameter '$k' for '$kind'"
        if (kind == "log" && p.containsKey("sink") && !K3Sig.isStr(p["sink"], 128)) return "log.sink must be a non-empty string of at most 128 characters"
        if (kind == "notify" && !K3Sig.isStr(p["to"], 256)) return "notify.to is required (a non-empty string of at most 256 characters)"
        if (kind == "watermark" && !K3Sig.isStr(p["id"], 128)) return "watermark.id is required (a non-empty string of at most 128 characters)"
        if (kind == "undo_window" && (!K3Sig.isStr(p["id"], 128) || !K3Sig.isSafeInt(p["window_end"])))
            return "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)"
        if (kind == "redact") {
            val f = K3Sig.list(p["fields"])
            if (f == null || f.isEmpty() || f.size > MAX_REDACT_FIELDS || !f.all { it is String && FIELD_RE.matches(it) }) return "redact.fields must be 1..32 dotted field paths"
            if (f.toSet().size != f.size) return "redact.fields has a duplicate"
        }
        return null
    }

    /** Null = well formed. */
    @JvmStatic
    fun obligationError(o: Any?): String? {
        val m = K3Sig.map(o) ?: return "an obligation must be an object"
        for (k in m.keys) if (k != "kind" && k != "params" && k != "due") return "unknown member '$k'"
        val kind = m["kind"]
        if (kind !is String || kind !in KINDS) return "unknown obligation kind '${K3Sig.jsText(kind, m.containsKey("kind"))}'"
        if (m.containsKey("due") && !K3Sig.isSafeInt(m["due"])) return "due must be a non-negative safe integer"
        val p = if (m.containsKey("params")) m["params"] else emptyMap<String, Any?>()
        val pm = K3Sig.map(p) ?: return "params must be an object"
        return paramsError(kind, pm)
    }

    /** Null = a well-formed, duplicate-free list of at most [MAX_OBLIGATIONS]. Null (absent) is the empty list. */
    @JvmStatic
    fun obligationsError(list: Any?): String? {
        if (list == null) return null
        val l = K3Sig.list(list) ?: return "obligations must be an array"
        if (l.size > MAX_OBLIGATIONS) return "more than $MAX_OBLIGATIONS obligations"
        val seen = HashSet<String>()
        for ((i, o) in l.withIndex()) {
            val e = obligationError(o)
            if (e != null) return "obligations[$i]: $e"
            val key = try { obligationKey(o) } catch (ex: RuntimeException) { return "obligations[$i]: not canonicalizable" }
            if (!seen.add(key)) return "obligations[$i] duplicates an earlier obligation"
        }
        return null
    }

    /** The canonical identity of an obligation (kind, parameters, due): equal keys are the same obligation. May throw on out-of-profile text. */
    @JvmStatic
    fun obligationKey(o: Any?): String {
        val m = K3Sig.map(o)!!
        val k = LinkedHashMap<String, Any?>()
        k["kind"] = m["kind"]
        k["params"] = m["params"] ?: emptyMap<String, Any?>()
        if (m.containsKey("due")) k["due"] = m["due"]
        return Json.canonicalizeStrict(k)
    }

    class Merge(val ok: Boolean, val obligations: List<Any?> = emptyList(), val reason: String? = null)

    /** The union of obligation lists, deduplicated by [obligationKey] and sorted by key in UTF-8 byte order. Any malformed input is a refusal. */
    @JvmStatic
    fun mergeObligations(lists: List<Any?>): Merge {
        try {
            val by = LinkedHashMap<String, Any?>()
            for (l in lists) {
                val e = obligationsError(l)
                if (e != null) return Merge(false, reason = e)
                for (o in K3Sig.list(l) ?: emptyList()) by[obligationKey(o)] = o
            }
            if (by.size > MAX_OBLIGATIONS) return Merge(false, reason = "more than $MAX_OBLIGATIONS obligations after merging")
            return Merge(true, by.entries.sortedWith { a, b -> Json.compareUtf8(a.key, b.key) }.map { it.value })
        } catch (e: RuntimeException) {
            return Merge(false, reason = "evaluation error (fail closed)")
        }
    }

    class Gate(val decision: String, val perform: List<Any?> = emptyList(), val unsupported: List<String> = emptyList(), val reason: String? = null)

    /**
     * The PEP rule. [supported] is the set of kinds this PEP performs. An `allow` (or an answered `escalate`) with any obligation outside
     * it is a `deny`, as is a malformed list or [supported]. A `deny` and an unanswered `escalate` pass through with nothing to perform.
     */
    @JvmStatic
    fun pepObligationGate(decision: String, answered: Boolean, obligations: Any?, supported: Any?): Gate {
        try {
            val eff = PcaDecision.pepDecision(decision, answered)
            if (eff != "allow") return Gate(if (eff == "escalate") "escalate" else "deny")
            val e = obligationsError(obligations)
            if (e != null) return Gate("deny", reason = "malformed obligations: $e")
            val sup = K3Sig.list(supported)
            if (sup == null || !sup.all { it is String }) return Gate("deny", reason = "the supported obligation kinds are malformed")
            val list = K3Sig.list(obligations) ?: emptyList()
            val missing = list.map { K3Sig.map(it)!!["kind"] as String }.filter { it !in sup }.distinct().sortedWith { a, b -> Json.compareUtf8(a, b) }
            if (missing.isNotEmpty()) return Gate("deny", unsupported = missing, reason = "the enforcement point does not support obligation(s) ${missing.joinToString(", ")}")
            return Gate("allow", perform = list)
        } catch (e: RuntimeException) {
            return Gate("deny", reason = "evaluation error (fail closed)")
        }
    }

    /** [outcome] is `ok` or `escalate`; [overdue] indexes the overdue obligations; [status] is `obligation_unmet` on escalate. */
    class Outcome(val outcome: String, val overdue: List<Int>, val status: String? = null)

    /** After the action: which obligations are overdue (`due <= now`, not in [fulfilled])? A malformed input is overdue-everything. */
    @JvmStatic
    fun obligationOutcome(obligations: Any?, fulfilled: Any?, now: Any?): Outcome {
        try {
            val list = K3Sig.list(obligations) ?: emptyList()
            val f = K3Sig.list(fulfilled)
            val bad = obligationsError(obligations) != null || f == null || !f.all { K3Sig.isSafeInt(it) } || !K3Sig.isSafeInt(now)
            if (bad) return Outcome("escalate", list.indices.toList(), "obligation_unmet")
            val done = f!!.map { IntentJs.lng(it) }.toSet()
            val n = IntentJs.lng(now)
            val overdue = list.indices.filter { i ->
                val m = K3Sig.map(list[i])!!
                m.containsKey("due") && IntentJs.lng(m["due"]) <= n && i.toLong() !in done
            }
            return if (overdue.isNotEmpty()) Outcome("escalate", overdue, "obligation_unmet") else Outcome("ok", emptyList())
        } catch (e: RuntimeException) {
            return Outcome("escalate", emptyList(), "obligation_unmet")
        }
    }
}
