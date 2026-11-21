package net.atlasauth.pca.doctor

import java.math.BigDecimal
import java.math.BigInteger
import java.math.RoundingMode
import net.atlasauth.pca.verifier.Json

/**
 * JavaScript value semantics the doctor's checks depend on (Number(), String(), Date.parse, toFixed, JSON.stringify), over parsed
 * JSON values (Map, List, String, Boolean, [Json.Num], null) plus [UNDEF] for an absent member.
 */
object Js {
    /** A member that is absent (JavaScript `undefined`); distinct from a JSON null. */
    val UNDEF: Any = object : Any() {
        override fun toString(): String = "undefined"
    }

    fun isUndef(o: Any?): Boolean = o === UNDEF

    fun nullish(o: Any?): Boolean = o == null || o === UNDEF

    /** `o[k]`: [UNDEF] for an absent member or a non-object. */
    fun g(o: Any?, k: String): Any? {
        if (o is Map<*, *>) return if (o.containsKey(k)) o[k] else UNDEF
        return UNDEF
    }

    /** The `??` operator: the default for null / undefined. */
    fun or(v: Any?, dflt: Any?): Any? = if (nullish(v)) dflt else v

    fun num(v: Any?): Double? = when (v) {
        is Json.Num -> v.raw.toDoubleOrNull()
        is Int, is Long, is Double, is Float, is Short -> (v as Number).toDouble()
        else -> null
    }

    /** `Number.isInteger`. */
    fun isInteger(v: Any?): Boolean {
        val d = num(v) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d)
    }

    fun isNegZero(v: Any?): Boolean {
        val d = num(v) ?: return false
        return d == 0.0 && java.lang.Double.doubleToRawLongBits(d) != 0L
    }

    fun truthy(v: Any?): Boolean {
        if (v == null || v === UNDEF || v == false) return false
        if (v is String) return v.isNotEmpty()
        val d = num(v) ?: return true
        return !(d == 0.0 || d.isNaN())
    }

    /** A deep copy of a config / result tree with absent ([UNDEF]) members dropped (an undefined array slot becomes null). */
    fun deepCopy(v: Any?): Any? {
        if (v is Map<*, *>) {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) if (x !== UNDEF) out[k as String] = deepCopy(x)
            return out
        }
        if (v is List<*>) {
            val out = ArrayList<Any?>()
            for (x in v) out.add(if (x === UNDEF) null else deepCopy(x))
            return out
        }
        return v
    }

    // ---- strings and numbers ----

    private const val WS = "\u0009\u000A\u000B\u000C\u000D                  　﻿"

    fun trim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && WS.indexOf(s[a]) >= 0) a++
        while (b > a && WS.indexOf(s[b - 1]) >= 0) b--
        return s.substring(a, b)
    }

    private val DEC = Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")
    private val HEX = Regex("0[xX][0-9a-fA-F]+")
    private val OCT = Regex("0[oO][0-7]+")
    private val BIN = Regex("0[bB][01]+")

    private fun numberOfString(s: String): Double {
        val t = trim(s)
        if (t.isEmpty()) return 0.0
        if (HEX.matches(t)) return BigInteger(t.substring(2), 16).toDouble()
        if (OCT.matches(t)) return BigInteger(t.substring(2), 8).toDouble()
        if (BIN.matches(t)) return BigInteger(t.substring(2), 2).toDouble()
        if (t == "Infinity" || t == "+Infinity") return Double.POSITIVE_INFINITY
        if (t == "-Infinity") return Double.NEGATIVE_INFINITY
        if (DEC.matches(t)) return t.toDouble()
        return Double.NaN
    }

    /** `Number(v)` for a JSON value or a string (objects and arrays are not coerced: NaN). */
    fun toNumber(v: Any?): Double {
        val d = num(v)
        if (d != null) return d
        if (v == null) return 0.0
        if (v is Boolean) return if (v) 1.0 else 0.0
        if (v is String) return numberOfString(v)
        return Double.NaN
    }

    /** JavaScript `String(number)`. */
    fun numStr(d: Double): String {
        if (d.isNaN()) return "NaN"
        if (d.isInfinite()) return if (d > 0) "Infinity" else "-Infinity"
        if (d == 0.0) return "0"
        return Json.esNumber(d)
    }

    /** JavaScript `String(v)` for a JSON value. */
    fun str(v: Any?): String {
        if (v == null) return "null"
        if (v === UNDEF) return "undefined"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = num(v)
        if (d != null) return numStr(d)
        if (v is List<*>) return v.joinToString(",") { if (nullish(it)) "" else str(it) }
        return "[object Object]"
    }

    /** `(x).toFixed(1)` for a finite non-negative double. */
    fun toFixed1(x: Double): String {
        if (x.isNaN()) return "NaN"
        return BigDecimal(x).setScale(1, RoundingMode.HALF_UP).toPlainString()
    }

    /** `x.toFixed(digits)`. */
    fun toFixed(x: Double, digits: Int): String {
        if (x.isNaN()) return "NaN"
        if (x.isInfinite()) return numStr(x)
        val body = BigDecimal(Math.abs(x)).setScale(digits, RoundingMode.HALF_UP).toPlainString()
        return (if (x < 0) "-" else "") + body
    }

    fun padEnd(s: String, n: Int): String = if (s.length >= n) s else s + " ".repeat(n - s.length)

    // ---- Date.parse ----

    private val MONTHS = arrayOf("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
    private val RFC = Regex(
        "(?i)^(?:[A-Za-z]+,?\\s+)?(\\d{1,2})\\s+([A-Za-z]{3})[A-Za-z]*\\s+(\\d{4})\\s+(\\d{1,2}):(\\d{2})(?::(\\d{2}))?\\s*(GMT|UTC|UT|Z|[+-]\\d{4})$",
    )
    private val ISO = Regex("^(\\d{4})-(\\d{2})-(\\d{2})(?:T(\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.(\\d{1,9}))?)?(Z|[+-]\\d{2}:\\d{2}))?$")
    private val ZONE4 = Regex("[+-]\\d{4}")

    /** Days since 1970-01-01 of a proleptic Gregorian date (no java.time on Android API 24). */
    private fun daysFromCivil(year: Int, month: Int, day: Int): Long {
        val y = (if (month <= 2) year - 1 else year).toLong()
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400
        val mp = ((month + 9) % 12).toLong()
        val doy = (153 * mp + 2) / 5 + day - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    private fun lengthOfMonth(y: Int, m: Int): Int {
        val leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        return when (m) {
            2 -> if (leap) 29 else 28
            4, 6, 9, 11 -> 30
            else -> 31
        }
    }

    private fun epoch(y: Int, mo: Int, d: Int, h: Int, mi: Int, s: Int, ms: Long, offsetMin: Int): Double {
        val days = daysFromCivil(y, mo, 1) + (d - 1L)
        return ((days * 24 + h) * 60 + mi) * 60_000.0 + s * 1000.0 + ms - offsetMin * 60_000.0
    }

    private fun grp(m: MatchResult, i: Int): String? = m.groups[i]?.value

    /**
     * `Date.parse`: NaN when unparseable. Covers the HTTP date (RFC 1123 with a zone; a weekday word is ignored, as the reference
     * engine does) and ISO 8601 with a zone or date only (UTC). Known limit: a date without a zone is local time in the reference
     * engine (host-dependent) and is NaN here; other legacy spellings are NaN.
     */
    fun parseDate(s: String): Double {
        val t = trim(s)
        val r = RFC.matchEntire(t)
        if (r != null) {
            var mo = -1
            val mn = grp(r, 2)!!.lowercase()
            for (i in 0 until 12) if (MONTHS[i] == mn) mo = i + 1
            if (mo < 0) return Double.NaN
            val h = grp(r, 4)!!.toInt()
            val mi = grp(r, 5)!!.toInt()
            val sec = grp(r, 6)?.toInt() ?: 0
            if (h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0))) return Double.NaN
            val z = grp(r, 7)!!.uppercase()
            val off = if (ZONE4.matches(z)) (if (z[0] == '-') -1 else 1) * (z.substring(1, 3).toInt() * 60 + z.substring(3, 5).toInt()) else 0
            val day = grp(r, 1)!!.toInt()
            if (day < 1 || day > 31) return Double.NaN
            return epoch(grp(r, 3)!!.toInt(), mo, day, h, mi, sec, 0, off)
        }
        val m = ISO.matchEntire(t) ?: return Double.NaN
        val year = grp(m, 1)!!.toInt()
        val mo = grp(m, 2)!!.toInt()
        val d = grp(m, 3)!!.toInt()
        if (mo < 1 || mo > 12 || d < 1 || d > lengthOfMonth(year, mo)) return Double.NaN
        val h = grp(m, 4)?.toInt() ?: 0
        val mi = grp(m, 5)?.toInt() ?: 0
        val sec = grp(m, 6)?.toInt() ?: 0
        if (h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0 || grp(m, 7) != null))) return Double.NaN
        val frac = grp(m, 7)
        val ms = if (frac == null) 0L else (frac + "00").substring(0, 3).toLong()
        val z = grp(m, 8)
        var off = 0
        if (z != null && z != "Z") off = (if (z[0] == '-') -1 else 1) * (z.substring(1, 3).toInt() * 60 + z.substring(4, 6).toInt())
        return epoch(year, mo, d, h, mi, sec, ms, off)
    }

    // ---- JSON.stringify(v, null, 2) ----

    fun quote(s: String): String {
        val b = StringBuilder("\"")
        for (i in s.indices) {
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
                    val lone = if (c.isHighSurrogate()) !(i + 1 < s.length && s[i + 1].isLowSurrogate())
                    else c.isLowSurrogate() && !(i > 0 && s[i - 1].isHighSurrogate())
                    if (c.code < 0x20 || lone) b.append("\\u").append(c.code.toString(16).padStart(4, '0')) else b.append(c)
                }
            }
        }
        return b.append('"').toString()
    }

    /** `JSON.stringify(v, null, 2)`: members that are [UNDEF] are dropped, an undefined array slot is null. */
    fun stringify(v: Any?): String = StringBuilder().also { write(it, v, "") }.toString()

    private fun write(b: StringBuilder, v: Any?, ind: String) {
        if (v == null || v === UNDEF) { b.append("null"); return }
        if (v is String) { b.append(quote(v)); return }
        if (v is Boolean) { b.append(v.toString()); return }
        val d = num(v)
        if (d != null) { b.append(if (d.isNaN() || d.isInfinite()) "null" else numStr(d)); return }
        val inner = "$ind  "
        if (v is List<*>) {
            if (v.isEmpty()) { b.append("[]"); return }
            b.append("[\n")
            for (i in v.indices) {
                b.append(inner)
                write(b, v[i], inner)
                b.append(if (i + 1 < v.size) ",\n" else "\n")
            }
            b.append(ind).append(']')
            return
        }
        val m = v as Map<*, *>
        val keys = ArrayList<Any?>()
        for ((k, x) in m) if (x !== UNDEF) keys.add(k)
        if (keys.isEmpty()) { b.append("{}"); return }
        b.append("{\n")
        for (i in keys.indices) {
            b.append(inner).append(quote(keys[i] as String)).append(": ")
            write(b, m[keys[i]], inner)
            b.append(if (i + 1 < keys.size) ",\n" else "\n")
        }
        b.append(ind).append('}')
    }
}
