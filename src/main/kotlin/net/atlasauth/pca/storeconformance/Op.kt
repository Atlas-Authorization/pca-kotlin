package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.doctor.Js

/**
 * One recorded operation on one key of a replay / counter store. Each carries a threshold [lo] and a write value [w]:
 * `consumeOnce(key, retainUntil, now)` has lo = now, w = retainUntil; `advance(stream, counter)` has lo = w = counter.
 * [call] is recorded BEFORE the request leaves the client; [ret] is the response time, infinite when the outcome is unknown (the
 * operation may still take effect at any later time).
 *
 * [kind] is `consume` or `advance` (any other value is treated as advance by the formatter, as the reference does); [res] is `true`,
 * `false` or `unknown`.
 */
class Op(
    val client: String,
    val kind: Any?,
    val key: String,
    val lo: Double,
    val w: Double,
    val call: Double,
    @Volatile var ret: Double,
    @Volatile var res: String,
) {
    fun toJson(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["client"] = client
        m["kind"] = kind
        m["key"] = key
        m["lo"] = numJson(lo)
        m["w"] = numJson(w)
        m["call"] = numJson(call)
        m["ret"] = numJson(ret)
        m["res"] = res
        return m
    }

    internal fun isConsume(): Boolean = "consume" == kind

    companion object {
        /** A number as the corpus spells it: a finite value, or {"$num": "Infinity"}. */
        fun numJson(d: Double): Any {
            if (d.isNaN() || d.isInfinite()) {
                val m = LinkedHashMap<String, Any?>()
                m["\$num"] = if (d.isNaN()) "NaN" else if (d > 0) "Infinity" else "-Infinity"
                return m
            }
            return d
        }

        /** A number from JSON: a plain number, or {"$num": "Infinity" | "-Infinity"}. */
        fun numOf(o: Any?): Double {
            if (o is Map<*, *> && o["\$num"] is String) {
                val s = o["\$num"] as String
                return if (s == "Infinity") Double.POSITIVE_INFINITY else if (s == "-Infinity") Double.NEGATIVE_INFINITY else Double.NaN
            }
            return Js.toNumber(o)
        }

        fun fromJson(o: Any?): Op {
            val m = o as Map<*, *>
            return Op(Js.str(m["client"]), m["kind"], Js.str(m["key"]), numOf(m["lo"]), numOf(m["w"]), numOf(m["call"]), numOf(m["ret"]), m["res"] as String)
        }
    }
}
