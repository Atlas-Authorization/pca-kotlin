package net.atlasauth.pca.policyci

import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/** JavaScript-flavoured helpers over JSON trees (Map / List / String / Boolean / Json.Num / null) for the policy linter. */
internal object PcJs {
    fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null
    fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    /** `typeof x === 'object' && x !== null`: an object or an array. */
    fun isObject(o: Any?): Boolean = o is Map<*, *> || o is List<*>

    /** A record: a non-null, non-array object. */
    fun isRecord(o: Any?): Boolean = o is Map<*, *>

    fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    /** The binary64 value of a JSON number, else null. */
    fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Int, is Long, is Double, is Short -> (o as Number).toDouble()
        else -> null
    }

    /** The reference `num`: a finite number, else null. */
    fun finite(o: Any?): Double? { val d = num(o); return if (d != null && !d.isNaN() && !d.isInfinite()) d else null }

    fun numStr(d: Double): String = AttestUtil.jsNumString(d)

    /** A number as a JSON value, spelled the way JavaScript prints it. */
    fun n(v: Long): Json.Num = Json.Num(v.toString())

    /** JavaScript `String(v)` for a JSON value; `present = false` is the `undefined` of a missing member. */
    fun str(v: Any?, present: Boolean = true): String {
        if (!present) return "undefined"
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = num(v)
        if (d != null) return numStr(d)
        if (v is List<*>) {
            val sb = StringBuilder()
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                if (x != null) sb.append(str(x, true))
            }
            return sb.toString()
        }
        return "[object Object]"
    }

    /** `JSON.stringify` of a JSON tree (insertion order, no whitespace). */
    fun stringify(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        if (v == null) { sb.append("null"); return }
        if (v is String) { quote(sb, v); return }
        if (v is Boolean) { sb.append(v); return }
        val d = num(v)
        if (d != null) { sb.append(if (d.isNaN() || d.isInfinite()) "null" else if (d == 0.0) "0" else numStr(d)); return }
        if (v is List<*>) {
            sb.append('[')
            var first = true
            for (x in v) { if (!first) sb.append(','); first = false; write(sb, x) }
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
        throw IllegalArgumentException("not JSON")
    }

    private fun hex4(c: Char): String = "\\u" + Integer.toHexString(c.code or 0x10000).substring(1)

    private fun quote(sb: StringBuilder, s: String) {
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
                c < ' ' -> sb.append(hex4(c))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { sb.append(c).append(s[i + 1]); i++ }
                Character.isSurrogate(c) -> sb.append(hex4(c))
                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }

    /** `Array.prototype.join(" ")`: a missing or null element joins as the empty string. */
    fun joinSpace(parts: List<Any?>): String {
        val sb = StringBuilder()
        for (i in parts.indices) {
            if (i > 0) sb.append(' ')
            val p = parts[i]
            if (p != null) sb.append(str(p, true))
        }
        return sb.toString()
    }

    private fun isWs(c: Char): Boolean = when (c) {
        '\t', '\n', '\u000B', '\u000C', '\r', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '　', '﻿' -> true
        else -> c in ' '..' '
    }

    /** `String.prototype.trim`. */
    fun trim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isWs(s[a])) a++
        while (b > a && isWs(s[b - 1])) b--
        return s.substring(a, b)
    }
}
