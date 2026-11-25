package net.atlasauth.pca.compliance

import java.util.IdentityHashMap
import net.atlasauth.pca.verifier.Json

/** JavaScript value semantics over parsed JSON trees (Map / List / String / Boolean / Json.Num / null), plus [UNDEF]. */
internal object ComplianceJs {
    /** The JavaScript `undefined` (a missing member). */
    val UNDEF: Any = object : Any() { override fun toString() = "undefined" }

    fun nullish(v: Any?): Boolean = v == null || v === UNDEF

    fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Int, is Long, is Double, is Short -> (o as Number).toDouble()
        else -> null
    }

    fun isNum(o: Any?): Boolean = num(o) != null

    /** `Number.isFinite(v)`. */
    fun finite(o: Any?): Boolean = num(o)?.let { !it.isNaN() && !it.isInfinite() } ?: false

    fun truthy(v: Any?): Boolean {
        if (v == null || v === UNDEF || v == false || v == "") return false
        val d = num(v) ?: return true
        return !(d == 0.0 || d.isNaN())
    }

    /** Own-member read: [UNDEF] when absent or `o` is not an object. */
    fun own(o: Any?, k: String): Any? = if (o is Map<*, *>) (if (o.containsKey(k)) o[k] else UNDEF) else UNDEF

    /** `o.k`: throws on null / undefined, like the reference. */
    fun prop(o: Any?, k: String): Any? {
        if (nullish(o)) throw IllegalStateException("Cannot read properties of " + (if (o == null) "null" else "undefined") + " (reading '" + k + "')")
        return own(o, k)
    }

    /** `o?.k`. */
    fun qprop(o: Any?, k: String): Any? = if (nullish(o)) UNDEF else own(o, k)

    /** ECMAScript ToNumber. */
    fun toNumber(v: Any?): Double {
        if (v === UNDEF) return Double.NaN
        if (v == null) return 0.0
        if (v is Boolean) return if (v) 1.0 else 0.0
        val d = num(v)
        if (d != null) return d
        if (v is String) return strToNumber(v)
        if (v is List<*>) return if (v.isEmpty()) 0.0 else if (v.size == 1) toNumber(v[0] ?: "") else Double.NaN
        return Double.NaN
    }

    private fun isWs(c: Char): Boolean =
        c == ' ' || (c in '\t'..'\r') || c == ' ' || c == ' ' || (c in ' '..' ') ||
            c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿'

    private val HEX = Regex("0[xX][0-9a-fA-F]+")
    private val BIN = Regex("0[bB][01]+")
    private val OCT = Regex("0[oO][0-7]+")
    private val DEC = Regex("[+-]?([0-9]+\\.?[0-9]*|\\.[0-9]+)([eE][+-]?[0-9]+)?")

    private fun strToNumber(s: String): Double {
        val t = s.trim { isWs(it) }
        if (t.isEmpty()) return 0.0
        if (t == "Infinity" || t == "+Infinity") return Double.POSITIVE_INFINITY
        if (t == "-Infinity") return Double.NEGATIVE_INFINITY
        try {
            if (HEX.matches(t)) return java.lang.Long.parseLong(t.substring(2), 16).toDouble()
            if (BIN.matches(t)) return java.lang.Long.parseLong(t.substring(2), 2).toDouble()
            if (OCT.matches(t)) return java.lang.Long.parseLong(t.substring(2), 8).toDouble()
            if (DEC.matches(t)) return t.toDouble()
        } catch (e: NumberFormatException) { /* NaN below */ }
        return Double.NaN
    }

    /** `a > b`: two strings compare by UTF-16 code units, anything else numerically. */
    fun gt(a: Any?, b: Any?): Boolean {
        if (a is String && b is String) return a.compareTo(b) > 0
        return toNumber(a) > toNumber(b)
    }

    /** Math.round: halves round toward +Infinity. */
    fun round(v: Double): Double {
        if (v.isNaN() || v.isInfinite()) return v
        val r = Math.floor(v)
        return if (v - r >= 0.5) r + 1 else r
    }

    /** String(n). */
    fun numStr(d: Double): String = when {
        d.isNaN() -> "NaN"
        d == Double.POSITIVE_INFINITY -> "Infinity"
        d == Double.NEGATIVE_INFINITY -> "-Infinity"
        d == 0.0 -> "0"
        else -> Json.esNumber(d)
    }

    /** A value interpolated into a template literal. */
    fun tpl(v: Any?): String {
        if (v == null) return "null"
        if (v === UNDEF) return "undefined"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = num(v)
        if (d != null) return numStr(d)
        if (v is List<*>) {
            val b = StringBuilder()
            var first = true
            for (x in v) { if (!first) b.append(','); first = false; if (!nullish(x)) b.append(tpl(x)) }
            return b.toString()
        }
        return "[object Object]"
    }

    /** `v.length`: strings (UTF-16 units) and arrays; throws on null / undefined; UNDEF for anything else. */
    fun length(v: Any?): Any? {
        if (nullish(v)) throw IllegalStateException("Cannot read properties of " + (if (v == null) "null" else "undefined") + " (reading 'length')")
        if (v is String) return v.length.toLong()
        if (v is List<*>) return v.size.toLong()
        return UNDEF
    }

    /** Object.keys order: array-index keys ascending, then the rest in insertion order. */
    fun keys(m: Map<*, *>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) { val s = k as String; if (isIndex(s)) idx.add(s) else rest.add(s) }
        idx.sortBy { it.toLong() }
        idx.addAll(rest)
        return idx
    }

    private fun isIndex(k: String): Boolean {
        if (k.isEmpty() || k.length > 10 || (k.length > 1 && k[0] == '0')) return false
        for (c in k) if (c < '0' || c > '9') return false
        return k.toLong() < 4294967295L
    }

    // ---- JSON.stringify ----
    fun quote(s: String): String {
        val b = StringBuilder("\"")
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when (c) {
                '"' -> b.append("\\\"")
                '\\' -> b.append("\\\\")
                '\b' -> b.append("\\b")
                '\u000C' -> b.append("\\f")
                '\n' -> b.append("\\n")
                '\r' -> b.append("\\r")
                '\t' -> b.append("\\t")
                else -> {
                    var lone = false
                    if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { b.append(c).append(s[i + 1]); i += 2; continue }
                        lone = true
                    } else if (Character.isLowSurrogate(c)) lone = true
                    if (c.code < 0x20 || lone) b.append(String.format("\\u%04x", c.code)) else b.append(c)
                }
            }
            i++
        }
        return b.append('"').toString()
    }

    /** JSON.stringify(v) (compact) or, with [pretty], JSON.stringify(v, null, 2). */
    fun stringify(v: Any?, base: String, pretty: Boolean): String {
        if (v == null) return "null"
        if (v is Boolean) return v.toString()
        if (v is String) return quote(v)
        val d = num(v)
        if (d != null) return if (d.isNaN() || d.isInfinite()) "null" else numStr(d)
        if (v is List<*>) {
            if (v.isEmpty()) return "[]"
            val ind = "$base  "
            val parts = v.map { x -> (if (pretty) ind else "") + (if (x === UNDEF) "null" else stringify(x, ind, pretty)) }
            return if (pretty) "[\n" + parts.joinToString(",\n") + "\n" + base + "]" else "[" + parts.joinToString(",") + "]"
        }
        if (v is Map<*, *>) {
            val ind = "$base  "
            val parts = ArrayList<String>()
            for (k in keys(v)) {
                val x = v[k]
                if (x === UNDEF) continue
                parts.add((if (pretty) ind else "") + quote(k) + (if (pretty) ": " else ":") + stringify(x, ind, pretty))
            }
            if (parts.isEmpty()) return "{}"
            return if (pretty) "{\n" + parts.joinToString(",\n") + "\n" + base + "}" else "{" + parts.joinToString(",") + "}"
        }
        throw IllegalStateException("stringify: unsupported value")
    }

    // ---- Set (SameValueZero) ----
    class JsSet {
        private val keys = HashSet<String>()
        private var n = 0
        private val ids = IdentityHashMap<Any, Int>()

        fun add(v: Any?) {
            val d = num(v)
            val k = when {
                v is Boolean -> "b$v"
                d != null -> "n" + (if (d == 0.0) "0" else d.toString())
                v is String -> "s$v"
                v == null -> "z"
                v === UNDEF -> "u"
                else -> { val o: Any = v!!; "o" + (ids[o] ?: (++n).also { ids[o] = it }) }
            }
            keys.add(k)
        }

        fun size(): Int = keys.size
    }

    // ---- dates ----
    /** `new Date(ms).toISOString()`; throws for an invalid time. */
    fun isoString(msO: Any?): String {
        val d = if (msO == null) 0.0 else num(msO)
        if (d == null || d.isNaN() || d.isInfinite() || Math.abs(d) > 8.64e15) throw IllegalArgumentException("Invalid time value")
        val t = d.toLong()
        val days = Math.floorDiv(t, 86400000L)
        val rem = Math.floorMod(t, 86400000L)
        val z = days + 719468
        val era = Math.floorDiv(z, 146097L)
        val doe = z - era * 146097L
        val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        var y = yoe + era * 400
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val day = doy - (153 * mp + 2) / 5 + 1
        val mo = if (mp < 10) mp + 3 else mp - 9
        if (mo <= 2) y++
        val ys = if (y >= 0L && y <= 9999L) String.format("%04d", y) else (if (y > 0) "+" else "-") + String.format("%06d", Math.abs(y))
        return String.format("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", ys, mo, day, rem / 3600000, rem / 60000 % 60, rem / 1000 % 60, rem % 1000)
    }

    fun iso(ms: Any?): String {
        if (!finite(ms)) return "(unknown time)"
        return try { isoString(ms) } catch (e: IllegalArgumentException) { "(unrepresentable time)" }
    }

    fun ts(ms: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        val d = num(ms)
        m["epochMs"] = if (d != null && (d.isNaN() || d.isInfinite())) d else ms
        m["iso"] = iso(ms)
        return m
    }

    fun nowMs(): Any = System.currentTimeMillis()

    /** Abbreviate a long key for display (UTF-16 units). */
    fun shortKey(key: Any?, n: Int): String {
        if (key !is String || key.isEmpty()) return "(none)"
        return if (key.length <= n + 1) key else key.substring(0, n) + "…"
    }

    fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i + 1 < kv.size) { if (kv[i + 1] !== UNDEF) m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }
}
