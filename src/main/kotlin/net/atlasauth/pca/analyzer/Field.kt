package net.atlasauth.pca.analyzer

/**
 * The interval + finite-set engine for a single `where` field: one representative value per cell of the partition a conjunction of
 * threshold / membership / prefix tests induces (a sound and complete probe set for the decided fragment), and the standalone
 * numeric-conjunction satisfiability check.
 */
object Field {
    /** A sentinel string that equals, prefixes and is prefixed by no policy literal. */
    const val FRESH_STRING: String = "\u0000atlas-analyzer::fresh-unmatched\u0000"

    /** A group condition (`all_of` / `any_of` / `not`). */
    internal fun isGroup(c: Any?): Boolean =
        c is Map<*, *> && (AJs.has(c, "all_of") || AJs.has(c, "any_of") || AJs.has(c, "not"))

    /** A leaf condition: an object with a string `field` that is no group. */
    internal fun isLeaf(c: Any?): Boolean = c is Map<*, *> && !isGroup(c) && AJs.get(c, "field") is String

    private fun numericCellReps(thresholds: List<Double>): List<Double> {
        val sorted = ArrayList<Double>()
        val seen = HashSet<Double>()
        for (t in thresholds) {
            val k = if (t == 0.0) 0.0 else t
            if (!k.isNaN() && !k.isInfinite() && seen.add(k)) sorted.add(k)
        }
        sorted.sort()
        val out = ArrayList<Double>()
        if (sorted.isEmpty()) return out
        out.add(sorted[0] - 1)
        for (i in sorted.indices) {
            val ti = sorted[i]
            out.add(ti)
            if (i + 1 < sorted.size) out.add((ti + sorted[i + 1]) / 2)
        }
        out.add(sorted[sorted.size - 1] + 1)
        return out
    }

    private fun typeOf(x: Any?): String = when {
        x is String -> "string"
        x is Boolean -> "boolean"
        AJs.isNum(x) -> "number"
        else -> "object"
    }

    /** A stable key for de-duplicating representative values of mixed type. */
    internal fun valueKey(x: Any?): String {
        if (FRESH_STRING == x) return "s:__fresh__"
        return typeOf(x) + ":" + AJs.stringify(x)
    }

    /** The representative probe values of one field given the conditions on it (the caller adds the absent value itself). */
    fun fieldProbes(conditions: List<*>): List<Any?> {
        val literals = ArrayList<Any?>()
        val thresholds = ArrayList<Double>()
        val prefixes = ArrayList<String>()
        for (c in conditions) {
            if (!isLeaf(c) || AJs.has(c, "ref")) continue
            val v = AJs.get(c, "value")
            val op = AJs.get(c, "op")
            val o = if (op is String) op else ""
            when (o) {
                "eq", "ne" -> {
                    literals.add(v)
                    if (AJs.isFin(v)) thresholds.add(AJs.num(v)!!)
                }
                "in", "nin" -> if (v is List<*>) for (x in v) {
                    literals.add(x)
                    if (AJs.isFin(x)) thresholds.add(AJs.num(x)!!)
                }
                "lt", "lte", "gt", "gte" -> if (AJs.isFin(v)) thresholds.add(AJs.num(v)!!)
                "prefix", "like", "matches", "is_a" -> if (v is String) {
                    literals.add(v)
                    if (o == "prefix") prefixes.add(v)
                }
                "member_of" -> if (v is String) literals.add(v)
                else if (v is List<*>) for (x in v) if (x is String) literals.add(x)
                else -> {}
            }
        }
        val out = ArrayList<Any?>()
        val seen = HashSet<String>()
        val all = ArrayList<Any?>(literals)
        for (n in numericCellReps(thresholds)) all.add(AJs.n(n))
        for (p in prefixes) { all.add(p); all.add(p + "x") }
        all.add(FRESH_STRING)
        for (x in all) if (seen.add(valueKey(x))) out.add(x)
        return out
    }

    // ---- standalone numeric-conjunction satisfiability ----

    /** A numeric interval with open / closed ends. */
    class NumInterval(val lo: Double, val loInclusive: Boolean, val hi: Double, val hiInclusive: Boolean) {
        /** {lo, loInclusive, hi, hiInclusive} as a JSON object. */
        fun toJson(): Map<String, Any?> = AJs.obj("lo", AJs.n(lo), "loInclusive", loInclusive, "hi", AJs.n(hi), "hiInclusive", hiInclusive)
    }

    val FULL_INTERVAL: NumInterval = NumInterval(Double.NEGATIVE_INFINITY, false, Double.POSITIVE_INFINITY, false)

    /** Tighten an interval by one numeric condition; non-numeric operands leave it as it is. */
    fun tightenInterval(iv: NumInterval, op: Any?, value: Any?): NumInterval {
        if (!AJs.isFin(value)) return iv
        val v = AJs.num(value)!!
        var lo = iv.lo
        var hi = iv.hi
        var li = iv.loInclusive
        var hiI = iv.hiInclusive
        when (if (op is String) op else "") {
            "eq" -> {
                if (v > lo || (v == lo && !li)) { lo = v; li = true }
                if (v < hi || (v == hi && !hiI)) { hi = v; hiI = true }
            }
            "gte" -> if (v > lo) { lo = v; li = true }
            "gt" -> if (v > lo || (v == lo && li)) { lo = v; li = false }
            "lte" -> if (v < hi) { hi = v; hiI = true }
            "lt" -> if (v < hi || (v == hi && hiI)) { hi = v; hiI = false }
            else -> {}
        }
        return NumInterval(lo, li, hi, hiI)
    }

    /** Empty iff lo > hi, or lo == hi with an exclusive end. */
    fun intervalEmpty(iv: NumInterval): Boolean {
        if (iv.lo > iv.hi) return true
        if (iv.lo == iv.hi) return !(iv.loInclusive && iv.hiInclusive)
        return false
    }

    /** Is the numeric part of the conjunction (per field) satisfiable? Non-numeric, `ref` and group conditions are ignored. */
    fun numericConjunctionSatisfiable(conditions: List<*>): Boolean {
        val byField = LinkedHashMap<String, NumInterval>()
        for (c in conditions) {
            if (!isLeaf(c) || AJs.has(c, "ref")) continue
            val f = AJs.get(c, "field") as String
            byField[f] = tightenInterval(byField[f] ?: FULL_INTERVAL, AJs.get(c, "op"), AJs.get(c, "value"))
        }
        for (iv in byField.values) if (intervalEmpty(iv)) return false
        return true
    }
}
