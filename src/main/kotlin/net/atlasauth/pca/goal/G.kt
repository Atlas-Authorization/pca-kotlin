package net.atlasauth.pca.goal

import java.math.BigDecimal
import java.math.BigInteger
import net.atlasauth.pca.verifier.Json

/** Small JSON-shaped value helpers shared by the goal modules (a Goal is a Map of parsed JSON, like the TypeScript objects). */
@Suppress("UNCHECKED_CAST")
internal object G {
    const val MAX_SAFE = 9007199254740991L

    fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null

    fun l(o: Any?): List<Any?>? = if (o is List<*>) o as List<Any?> else null

    /** A required object member (IrError when the value is not an object). */
    fun obj(o: Any?, what: String): Map<String, Any?> = m(o) ?: throw IrError("$what expected an object")

    fun arr(o: Any?, what: String): List<Any?> = l(o) ?: throw IrError("array expected" + (if (what.isEmpty()) "" else " ($what)"))

    fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    /** The string at [k]; IrError unless it is a string. */
    fun str(o: Any?, k: String): String = get(o, k) as? String ?: throw IrError("string expected")

    /** The discriminant `k` of a value ("" when absent or not a string). */
    fun kind(o: Any?): String = get(o, "k") as? String ?: ""

    /** Safe-integer value of a JSON number (Json.Num, Long, Integer), or null. -0 and non-integers are null. */
    fun safeInt(v: Any?): Long? {
        if (v is Long) return if (Math.abs(v) <= MAX_SAFE) v else null
        if (v is Int) return v.toLong()
        if (v is Json.Num) {
            val raw = v.raw
            try {
                val d = BigDecimal(raw)
                if (d.signum() == 0 && raw.startsWith("-")) return null
                val i = d.toBigIntegerExact()
                if (i.abs() > BigInteger.valueOf(MAX_SAFE)) return null
                return i.toLong()
            } catch (e: ArithmeticException) {
                return null
            } catch (e: NumberFormatException) {
                return null
            }
        }
        return null
    }

    /** The number as a JavaScript double, or null when it is not a number. */
    fun dbl(v: Any?): Double? {
        if (v is Json.Num) return v.raw.toDoubleOrNull()
        if (v is Number) return v.toDouble()
        return null
    }

    fun num(v: Long): Json.Num = Json.Num(v.toString())

    fun num(v: Int): Json.Num = Json.Num(v.toString())

    fun map(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) r[k] = v
        return r
    }

    fun list(vararg xs: Any?): ArrayList<Any?> {
        val r = ArrayList<Any?>()
        for (x in xs) r.add(x)
        return r
    }

    /** JSON.stringify of a string (no escaping beyond the short forms and \u00XX below 0x20; lone surrogates as \udXXX). */
    fun q(s: String): String {
        val sb = StringBuilder("\"")
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\t' -> sb.append("\\t")
                '\n' -> sb.append("\\n")
                '\u000C' -> sb.append("\\f")
                '\r' -> sb.append("\\r")
                else -> when {
                    c.code < 0x20 -> sb.append(String.format("\\u%04x", c.code))
                    Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                        sb.append(c).append(s[i + 1])
                        i++
                    }
                    Character.isSurrogate(c) -> sb.append(String.format("\\u%04x", c.code))
                    else -> sb.append(c)
                }
            }
            i++
        }
        return sb.append('"').toString()
    }

    /** JSON.stringify of any JSON-shaped value with insertion-order keys (an in-memory comparison key, not a signed form). */
    fun stringify(v: Any?): String {
        val sb = StringBuilder()
        stringify(sb, v, false)
        return sb.toString()
    }

    /** The sorted-key, undefined-dropped stable form (UTF-16 code-unit key order). */
    fun stable(v: Any?): String {
        val sb = StringBuilder()
        stringify(sb, v, true)
        return sb.toString()
    }

    private fun stringify(sb: StringBuilder, v: Any?, sorted: Boolean) {
        when (v) {
            null -> sb.append("null")
            is String -> sb.append(q(v))
            is Boolean -> sb.append(v.toString())
            is Json.Num -> sb.append(v.raw)
            is Number -> sb.append(v.toString())
            is List<*> -> {
                sb.append('[')
                var f = true
                for (x in v) {
                    if (!f) sb.append(',')
                    f = false
                    stringify(sb, x, sorted)
                }
                sb.append(']')
            }
            is Map<*, *> -> {
                val ks = ArrayList<String>()
                for (k in v.keys) ks.add(k as String)
                if (sorted) ks.sort()
                sb.append('{')
                var f = true
                for (k in ks) {
                    if (!f) sb.append(',')
                    f = false
                    sb.append(q(k)).append(':')
                    stringify(sb, v[k], sorted)
                }
                sb.append('}')
            }
            else -> throw IllegalArgumentException("unsupported " + v.javaClass.name)
        }
    }

    /** UTF-16 code-unit comparison (JavaScript `<` on strings). */
    fun cmp(a: String, b: String): Int = a.compareTo(b)

    fun strs(o: Any?): ArrayList<Any?> {
        val r = ArrayList<Any?>()
        val src = l(o)
        if (src != null) r.addAll(src)
        return r
    }

    /** JavaScript truthiness of a parsed JSON value. */
    fun truthy(v: Any?): Boolean {
        if (v == null) return false
        if (v is Boolean) return v
        if (v is String) return v.isNotEmpty()
        val d = dbl(v)
        if (d != null) return d != 0.0 && !d.isNaN()
        return true
    }

    private val NUMERIC = Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")

    /** JavaScript ToNumber of a parsed JSON value (null 0, "" 0, [] 0, [x] ToNumber(x), objects NaN). */
    fun toNum(v: Any?): Double {
        if (v == null) return 0.0
        if (v is Boolean) return if (v) 1.0 else 0.0
        val d = dbl(v)
        if (d != null) return d
        if (v is String) {
            val t = v.trim()
            if (t.isEmpty()) return 0.0
            if (!NUMERIC.matches(t)) return Double.NaN
            return t.toDouble()
        }
        if (v is List<*>) return if (v.isEmpty()) 0.0 else if (v.size == 1) toNum(v[0]) else Double.NaN
        return Double.NaN
    }

    /** JavaScript String(v) of a parsed JSON value (template-literal interpolation). */
    fun jsStr(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Json.Num) return try { Json.fmtNumber(v.raw) } catch (e: IllegalArgumentException) { v.raw }
        if (v is List<*>) {
            val sb = StringBuilder()
            var f = true
            for (x in v) {
                if (!f) sb.append(',')
                f = false
                if (x != null) sb.append(jsStr(x))
            }
            return sb.toString()
        }
        if (v is Map<*, *>) return "[object Object]"
        return v.toString()
    }

    /** JSON.stringify of a value used as a quoted label (strings quoted, everything else as its JSON text). */
    fun quote(v: Any?): String = if (v is String) q(v) else stringify(v)

    /** Strict number (the value when it is a number, else null). */
    fun strictNum(v: Any?): Double? = if (v is Json.Num || v is Number) dbl(v) else null
}
