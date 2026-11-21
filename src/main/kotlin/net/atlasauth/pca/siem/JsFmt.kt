package net.atlasauth.pca.siem

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json

/**
 * JavaScript text formatting over parsed JSON trees (Map / List / String / Boolean / Json.Num / null): the number-to-string
 * conversion, the template-literal rendering and `JSON.stringify`, so event lines are byte-identical to the reference.
 */
object JsFmt {
    /** `String(d)` for a number: shortest round-trip digits, plain form for 1e-6 <= |d| < 1e21, else an exponent. */
    fun num(d: Double): String {
        if (d.isNaN()) return "NaN"
        if (d.isInfinite()) return if (d > 0) "Infinity" else "-Infinity"
        if (d == 0.0) return "0"
        return Json.esNumber(d) // esNumber carries the sign
    }

    /** `${v}` of a JSON value: arrays join with commas (null elements are empty), objects print as [object Object]. */
    fun str(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = Js.num(v)
        if (d != null) return num(d)
        if (v is List<*>) return v.joinToString(",") { if (it == null) "" else str(it) }
        return "[object Object]"
    }

    /** `JSON.stringify(v)` of a JSON tree: members in map order, numbers as JavaScript prints them (non-finite becomes null). */
    fun stringify(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        if (v == null) { sb.append("null"); return }
        if (v is String) { quote(sb, v); return }
        if (v is Boolean) { sb.append(v.toString()); return }
        val d = Js.num(v)
        if (d != null) { sb.append(if (d.isNaN() || d.isInfinite()) "null" else num(d)); return }
        if (v is List<*>) {
            sb.append('[')
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                write(sb, x)
            }
            sb.append(']')
            return
        }
        if (v is Map<*, *>) {
            sb.append('{')
            var first = true
            for ((k, x) in v) {
                if (!first) sb.append(',')
                first = false
                quote(sb, k as String)
                sb.append(':')
                write(sb, x)
            }
            sb.append('}')
            return
        }
        throw IllegalArgumentException("not a JSON value: " + v.javaClass.name)
    }

    /** JSON string quoting as `JSON.stringify`: lone surrogates and control characters become lowercase \u escapes. */
    fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c.code < 0x20 -> sb.append(String.format(java.util.Locale.ROOT, "\\u%04x", c.code))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { sb.append(c).append(s[i + 1]); i++ }
                Character.isSurrogate(c) -> sb.append(String.format(java.util.Locale.ROOT, "\\u%04x", c.code))
                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }
}
