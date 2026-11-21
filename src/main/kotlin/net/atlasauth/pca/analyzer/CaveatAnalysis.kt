package net.atlasauth.pca.analyzer

import net.atlasauth.pca.verifier.Json

/**
 * Static satisfiability of a PCA envelope caveat set (the leaf's cumulative, conjunctive caveats): is there ANY runtime context
 * under which they all hold? The one caveat tied to the action itself, `reversibility_max`, is returned as a cap.
 * Unknown or malformed caveats fail closed.
 */
class CaveatAnalysis internal constructor(
    /** Some context satisfies every caveat. */
    val sat: Boolean,
    val reason: String?,
    /** Strictest `reversibility_max` cap as an index into [Analyzer.REVERSIBILITY_ORDER], or null. */
    val revCap: Int?,
) {
    /** {sat, reason?, revCap?} as a JSON object. */
    fun toJson(): Map<String, Any?> {
        val m = AJs.obj("sat", sat)
        if (reason != null) m["reason"] = reason
        if (revCap != null) m["revCap"] = AJs.n(revCap)
        return m
    }

    companion object {
        private fun no(reason: String) = CaveatAnalysis(false, reason, null)

        /** JavaScript `String(x)` of a JSON value (`present` false = undefined). */
        internal fun jsString(x: Any?, present: Boolean): String {
            if (!present) return "undefined"
            if (x == null) return "null"
            val d = AJs.num(x)
            if (d != null) return AJs.fmt(d)
            if (x is List<*>) {
                val sb = StringBuilder()
                var first = true
                for (e in x) {
                    if (!first) sb.append(',')
                    first = false
                    if (e != null) sb.append(jsString(e, true))
                }
                return sb.toString()
            }
            if (x is Map<*, *>) return "[object Object]"
            return x.toString()
        }

        private fun fin(v: Any?): Double? = if (AJs.isFin(v)) AJs.num(v) else null

        private fun s(d: Double): String = Json.esNumber(if (d == 0.0) 0.0 else d)

        fun analyzeCaveats(caveats: Any?): CaveatAnalysis {
            if (caveats !is List<*>) return no("caveats are not an array")
            var notBeforeMax = Double.NEGATIVE_INFINITY
            var expiresMin = Double.POSITIVE_INFINITY
            var revCap: Int? = null
            for (cv in caveats) {
                if (cv !is Map<*, *> || AJs.get(cv, "type") !is String) return no("malformed caveat (not an object with a string type)")
                val type = AJs.get(cv, "type") as String
                when (type) {
                    "expires" -> {
                        val at = fin(AJs.get(cv, "at")) ?: return no("expires.at is not a finite number")
                        expiresMin = Math.min(expiresMin, at)
                    }
                    "not_before" -> {
                        val at = fin(AJs.get(cv, "at")) ?: return no("not_before.at is not a finite number")
                        notBeforeMax = Math.max(notBeforeMax, at)
                    }
                    "rate" -> {
                        val max = fin(AJs.get(cv, "max"))
                        val per = fin(AJs.get(cv, "per_secs"))
                        if (max == null || per == null || per <= 0) return no("rate caveat requires finite max and per_secs > 0")
                        if (max < 1) return no("rate.max " + s(max) + " < 1 forbids every action")
                    }
                    "max_blast_radius" -> {
                        val max = fin(AJs.get(cv, "max")) ?: return no("max_blast_radius.max is not a finite number")
                        if (max < 0) return no("max_blast_radius.max < 0 forbids every action")
                    }
                    "reversibility_max" -> {
                        val cls = jsString(AJs.get(cv, "class"), AJs.has(cv, "class"))
                        val idx = Analyzer.REVERSIBILITY_ORDER.indexOf(cls)
                        if (idx < 0) return no("reversibility_max.class '$cls' is unknown")
                        revCap = if (revCap == null) idx else Math.min(revCap, idx)
                    }
                    "delegation_depth" -> {
                        val max = fin(AJs.get(cv, "max")) ?: return no("delegation_depth.max is not a finite number")
                        if (max < 0) return no("delegation_depth.max < 0 forbids every action")
                    }
                    "budget_alloc" -> {
                        val lim = fin(AJs.get(cv, "limit"))
                        if (lim == null || lim < 0) return no("budget_alloc.limit must be a finite number >= 0")
                    }
                    else -> return no("unknown caveat type '$type' (fail closed)")
                }
            }
            if (notBeforeMax != Double.NEGATIVE_INFINITY && expiresMin != Double.POSITIVE_INFINITY && notBeforeMax >= expiresMin) {
                return no("not_before (" + s(notBeforeMax) + ") >= expires (" + s(expiresMin) + "): the validity window is empty")
            }
            return CaveatAnalysis(true, null, revCap)
        }
    }
}
