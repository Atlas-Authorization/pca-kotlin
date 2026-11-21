package net.atlasauth.pca.explain

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json

/** JavaScript value semantics over parsed JSON for the explainer: absent members ([UNDEF]), String(x), JSON.stringify, Number(x). */
internal object ExplainJs {
    /** The JavaScript `undefined`: a member that is absent (distinct from JSON null). Never stored in an output map. */
    val UNDEF: Any = object : Any() { override fun toString() = "undefined" }

    fun isObject(o: Any?): Boolean = o is Map<*, *> || o is List<*>

    /** `o[k]` (no throw): UNDEF for a missing member or a value without members. A list answers array indices. */
    fun get(o: Any?, k: String): Any? {
        if (o is Map<*, *>) return if (o.containsKey(k)) o[k] else UNDEF
        if (o is List<*>) {
            if (k == "length") return Json.Num(o.size.toString())
            val i = index(k)
            return if (i >= 0 && i < o.size) o[i] else UNDEF
        }
        if (o is String) { // a string has a length and one-character index members
            if (k == "length") return Json.Num(o.length.toString())
            val i = index(k)
            return if (i >= 0 && i < o.length) o[i].toString() else UNDEF
        }
        return UNDEF
    }

    /** `o[k]` where o must not be null or undefined (a TypeError otherwise). */
    fun rd(o: Any?, k: String): Any? {
        if (o == null || o === UNDEF) throw IllegalArgumentException("TypeError: cannot read '$k' of $o")
        return get(o, k)
    }

    /** `o?.[k]`. */
    fun opt(o: Any?, k: String): Any? = if (o == null || o === UNDEF) UNDEF else get(o, k)

    private fun index(k: String): Int {
        if (k.isEmpty() || k.length > 9) return -1
        for (c in k) if (c < '0' || c > '9') return -1
        if (k.length > 1 && k[0] == '0') return -1
        return k.toInt()
    }

    /** `a ?? b`. */
    fun nn(a: Any?, b: Any?): Any? = if (a == null || a === UNDEF) b else a

    fun truthy(v: Any?): Boolean = v !== UNDEF && Js.truthy(v)

    fun put(m: MutableMap<String, Any?>, k: String, v: Any?) { if (v !== UNDEF) m[k] = v }

    fun n(v: Long): Json.Num = Json.Num(v.toString())

    /** `Object.keys`: array-index keys ascending first, then the others in insertion order. */
    fun keys(o: Any?): List<String> {
        val out = ArrayList<String>()
        if (o is List<*>) { for (i in o.indices) out.add(i.toString()); return out }
        if (o is String) { for (i in o.indices) out.add(i.toString()); return out }
        if (o !is Map<*, *>) return out
        val idx = ArrayList<String>()
        for (k in o.keys) {
            val s = k as String
            if (isArrayIndex(s)) idx.add(s) else out.add(s)
        }
        idx.sortBy { it.toLong() }
        idx.addAll(out)
        return idx
    }

    private fun isArrayIndex(s: String): Boolean {
        if (s.isEmpty() || s.length > 10) return false
        for (c in s) if (c < '0' || c > '9') return false
        if (s.length > 1 && s[0] == '0') return false
        return s.toLong() < 4294967295L
    }

    // ---- numbers ------------------------------------------------------------------------------------------------------------

    /** The JavaScript number value of a JSON number, else null. */
    fun numOf(o: Any?): Double? = Js.num(o)

    fun isFiniteNumber(o: Any?): Boolean = Js.isFinite(o)

    /** `String(n)` for a number. */
    fun numString(d: Double): String = when {
        d.isNaN() -> "NaN"
        d == Double.POSITIVE_INFINITY -> "Infinity"
        d == Double.NEGATIVE_INFINITY -> "-Infinity"
        d == 0.0 -> "0"
        else -> Json.esNumber(d)
    }

    private val NUMLIT = Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")

    /** `Number(v)` (scalars; objects are NaN). */
    fun toNum(v: Any?): Double {
        if (v === UNDEF) return Double.NaN
        if (v == null) return 0.0
        if (v is Boolean) return if (v) 1.0 else 0.0
        val d = Js.num(v)
        if (d != null) return d
        if (v is String) {
            val s = jsTrim(v)
            if (s.isEmpty()) return 0.0
            if (s == "Infinity" || s == "+Infinity") return Double.POSITIVE_INFINITY
            if (s == "-Infinity") return Double.NEGATIVE_INFINITY
            if (NUMLIT.matches(s)) return s.toDouble()
            return Double.NaN
        }
        return Double.NaN
    }

    /** `a > b` (two strings compare as strings, anything else as numbers). */
    fun gt(a: Any?, b: Any?): Boolean {
        if (a is String && b is String) return a.compareTo(b) > 0
        return toNum(a) > toNum(b)
    }

    /** `Math.round`. */
    fun round(y: Double): Double {
        val f = Math.floor(y)
        return if (y - f >= 0.5) f + 1 else f
    }

    // ---- strings ------------------------------------------------------------------------------------------------------------

    const val WS = " \\t\\n\\u000B\\f\\r\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF"

    fun isWs(c: Char): Boolean =
        c == ' ' || (c in '\t'..'\r') || c == ' ' || c == ' ' || (c in ' '..' ') ||
            c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿'

    /** `String.prototype.trim`. */
    fun jsTrim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isWs(s[a])) a++
        while (b > a && isWs(s[b - 1])) b--
        return s.substring(a, b)
    }

    /** `String(v)`. */
    fun str(v: Any?): String {
        if (v === UNDEF) return "undefined"
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = Js.num(v)
        if (d != null) return numString(d)
        if (v is List<*>) {
            val sb = StringBuilder()
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                if (x != null && x !== UNDEF) sb.append(str(x))
            }
            return sb.toString()
        }
        return "[object Object]"
    }

    /** `${JSON.stringify(v)}`: undefined stringifies to the text "undefined". */
    fun jstr(v: Any?): String = if (v === UNDEF) "undefined" else stringify(v)

    /** JSON.stringify of a parsed value: insertion order (array-index keys first), numbers as JavaScript prints them. */
    fun stringify(v: Any?): String = StringBuilder().also { ser(it, v) }.toString()

    private fun ser(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(v)
            is String -> quote(sb, v)
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for (k in keys(v)) {
                    if (!first) sb.append(',')
                    first = false
                    quote(sb, k)
                    sb.append(':')
                    ser(sb, v[k])
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                var first = true
                for (x in v) {
                    if (!first) sb.append(',')
                    first = false
                    ser(sb, x)
                }
                sb.append(']')
            }
            else -> {
                val d = Js.num(v)
                if (d == null || d.isNaN() || d.isInfinite()) sb.append("null") else sb.append(numString(d))
            }
        }
    }

    private fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        for (i in s.indices) {
            val c = s[i]
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    val lone = Character.isSurrogate(c) &&
                        !(Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) &&
                        !(Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(s[i - 1]))
                    if (c.code < 0x20 || lone) sb.append(String.format("\\u%04x", c.code)) else sb.append(c)
                }
            }
        }
        sb.append('"')
    }

    fun obj(): LinkedHashMap<String, Any?> = LinkedHashMap()
}
