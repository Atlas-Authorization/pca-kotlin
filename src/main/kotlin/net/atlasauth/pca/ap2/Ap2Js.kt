package net.atlasauth.pca.ap2

import java.nio.charset.StandardCharsets
import net.atlasauth.pca.verifier.Json

/** Every failure raised while parsing or verifying an AP2 mandate carries a human-readable reason (the message). */
open class Ap2Error(message: String) : RuntimeException(message)

/**
 * JavaScript value semantics over parsed JSON (Map, List, String, Boolean, [Json.Num], null) for the AP2 port: number reads by
 * binary64 value, `String(v)`, `JSON.stringify` (insertion order, integer-like keys first), strict equality, truthiness.
 * [UNDEF] stands for an absent member where JSON null is told apart from it.
 */
@Suppress("UNCHECKED_CAST")
internal object Ap2Js {
    val UNDEF: Any = object : Any() {
        override fun toString(): String = "undefined"
    }

    fun obj(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>
    fun arr(o: Any?): List<Any?> = o as List<Any?>

    fun isObj(o: Any?): Boolean = o is Map<*, *>
    fun isArr(o: Any?): Boolean = o is List<*>
    fun isStr(o: Any?): Boolean = o is String
    fun isNonEmptyStr(o: Any?): Boolean = o is String && o.isNotEmpty()

    /** A member read: null for a non-object or an absent key. */
    fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    /** True when the key is present (even with a null value). */
    fun def(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    /** A member read that tells an absent key ([UNDEF]) from JSON null. */
    fun getU(o: Any?, k: String): Any? = if (def(o, k)) get(o, k) else UNDEF

    fun m(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) out[k] = v
        return out
    }

    fun l(vararg xs: Any?): MutableList<Any?> = ArrayList<Any?>().also { it.addAll(xs) }

    // ---- numbers ----
    fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    fun isNumber(o: Any?): Boolean = num(o) != null
    fun isNegZero(d: Double): Boolean = d == 0.0 && java.lang.Double.doubleToRawLongBits(d) != 0L

    fun isFinite(o: Any?): Boolean {
        val d = num(o) ?: return false
        return !d.isNaN() && !d.isInfinite()
    }

    /** Number.isSafeInteger (accepts -0). */
    fun isSafeInteger(o: Any?): Boolean {
        val d = num(o) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0
    }

    /** A safe integer that is not -0. */
    fun isInt(o: Any?): Boolean = isSafeInteger(o) && !isNegZero(num(o)!!)

    fun isNonNegInt(o: Any?): Boolean = isInt(o) && num(o)!! >= 0

    /** `Number::toString`. */
    fun numStr(d: Double): String = when {
        d.isNaN() -> "NaN"
        d.isInfinite() -> if (d > 0) "Infinity" else "-Infinity"
        d == 0.0 -> "0"
        else -> Json.esNumber(d)
    }

    fun n(v: Long): Json.Num = Json.Num(v.toString())
    fun n(v: Double): Json.Num = Json.Num(numStr(v))

    /** Math.round: nearest integer, ties toward +infinity. */
    fun round(x: Double): Double {
        if (x.isNaN() || x.isInfinite()) return x
        val r = Math.floor(x)
        return if (x - r >= 0.5) r + 1 else r
    }

    // ---- String(v), truthiness, strict equality ----
    fun str(v: Any?): String {
        if (v === UNDEF) return "undefined"
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
                if (x != null && x !== UNDEF) sb.append(str(x))
            }
            return sb.toString()
        }
        return "[object Object]"
    }

    fun truthy(o: Any?): Boolean {
        if (o == null || o === UNDEF) return false
        if (o is Boolean) return o
        if (o is String) return o.isNotEmpty()
        val d = num(o)
        if (d != null) return d != 0.0 && !d.isNaN()
        return true
    }

    /** The `===` of two parsed values (objects only equal by identity). */
    fun sEq(a: Any?, b: Any?): Boolean {
        if (a === b) return true
        if (a == null || b == null || a === UNDEF || b === UNDEF) return false
        if (a is String && b is String) return a == b
        if (a is Boolean && b is Boolean) return a == b
        val x = num(a)
        val y = num(b)
        return x != null && y != null && x == y
    }

    // ---- key order and JSON.stringify ----
    private fun isIndex(k: String): Boolean {
        val n = k.length
        if (n == 0 || n > 10 || (n > 1 && k[0] == '0')) return false
        for (c in k) if (c < '0' || c > '9') return false
        return k.toLong() < 4294967295L
    }

    /** Own enumerable keys in ECMAScript order: array indices ascending, then the rest in insertion order. */
    fun keyOrder(m: Map<String, Any?>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) if (isIndex(k)) idx.add(k) else rest.add(k)
        idx.sortBy { it.toLong() }
        idx.addAll(rest)
        return idx
    }

    /** A deep copy whose objects enumerate their keys in ECMAScript order (what JSON.parse yields). */
    fun jsOrder(v: Any?): Any? {
        if (v is Map<*, *>) {
            val src = v as Map<String, Any?>
            val out = LinkedHashMap<String, Any?>()
            for (k in keyOrder(src)) out[k] = jsOrder(src[k])
            return out
        }
        if (v is List<*>) {
            val out = ArrayList<Any?>()
            for (x in v) out.add(jsOrder(x))
            return out
        }
        return v
    }

    /** JSON.stringify; null for undefined. */
    fun stringify(v: Any?): String? {
        if (v === UNDEF) return null
        val sb = StringBuilder()
        ser(sb, v)
        return sb.toString()
    }

    /** JSON.stringify of a value that is never undefined. */
    fun json(v: Any?): String = stringify(v) ?: throw IllegalArgumentException("undefined is not JSON")

    private fun ser(sb: StringBuilder, v: Any?) {
        when {
            v == null -> sb.append("null")
            v is Boolean -> sb.append(v.toString())
            v is String -> jsString(sb, v)
            isNumber(v) -> sb.append(if (isFinite(v)) numStr(num(v)!!) else "null")
            v is List<*> -> {
                sb.append('[')
                var first = true
                for (x in v) {
                    if (!first) sb.append(',')
                    first = false
                    if (x === UNDEF) sb.append("null") else ser(sb, x)
                }
                sb.append(']')
            }
            v is Map<*, *> -> {
                val mm = v as Map<String, Any?>
                sb.append('{')
                var first = true
                for (k in keyOrder(mm)) {
                    val x = mm[k]
                    if (x === UNDEF) continue
                    if (!first) sb.append(',')
                    first = false
                    jsString(sb, k)
                    sb.append(':')
                    ser(sb, x)
                }
                sb.append('}')
            }
            else -> throw IllegalArgumentException("not JSON: " + v.javaClass)
        }
    }

    private fun hex4(sb: StringBuilder, c: Char) {
        val h = Integer.toHexString(c.code)
        sb.append("\\u")
        for (i in h.length until 4) sb.append('0')
        sb.append(h)
    }

    private fun jsString(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> when {
                    c.code < 0x20 -> hex4(sb, c)
                    Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                        sb.append(c).append(s[i + 1])
                        i++
                    }
                    Character.isSurrogate(c) -> hex4(sb, c) // a lone surrogate is escaped
                    else -> sb.append(c)
                }
            }
            i++
        }
        sb.append('"')
    }

    /** UTF-8 of a JavaScript string: a lone surrogate encodes as U+FFFD (what Buffer.from(s, 'utf8') writes). */
    fun utf8(s: String): ByteArray = Json.utf8(s)

    private const val B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    private fun enc(b: ByteArray, alpha: String, pad: Boolean): String {
        val sb = StringBuilder((b.size + 2) / 3 * 4)
        var i = 0
        while (i + 2 < b.size) {
            val v = (b[i].toInt() and 0xff shl 16) or (b[i + 1].toInt() and 0xff shl 8) or (b[i + 2].toInt() and 0xff)
            sb.append(alpha[v ushr 18]).append(alpha[v ushr 12 and 63]).append(alpha[v ushr 6 and 63]).append(alpha[v and 63])
            i += 3
        }
        val rem = b.size - i
        if (rem == 1) {
            val v = b[i].toInt() and 0xff shl 16
            sb.append(alpha[v ushr 18]).append(alpha[v ushr 12 and 63])
            if (pad) sb.append("==")
        } else if (rem == 2) {
            val v = (b[i].toInt() and 0xff shl 16) or (b[i + 1].toInt() and 0xff shl 8)
            sb.append(alpha[v ushr 18]).append(alpha[v ushr 12 and 63]).append(alpha[v ushr 6 and 63])
            if (pad) sb.append('=')
        }
        return sb.toString()
    }

    fun b64u(b: ByteArray): String = enc(b, B64U, false)

    /** Standard base64 with padding (what Buffer.toString('base64') writes). */
    fun b64std(b: ByteArray): String = enc(b, B64, true)

    /**
     * Lenient unpadded base64url decode over a string already known to be in the alphabet: leftover bits are dropped, as
     * java.util.Base64 does; a length of 4k+1 throws. Callers that need canonical input re-encode and compare.
     */
    fun unb64uLenient(s: String): ByteArray {
        if (s.length % 4 == 1) throw IllegalArgumentException("bad base64url length")
        val out = java.io.ByteArrayOutputStream(s.length * 3 / 4)
        var acc = 0
        var bits = 0
        for (c in s) {
            val v = B64U.indexOf(c)
            if (v < 0) throw IllegalArgumentException("not base64url")
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write(acc ushr bits and 0xff)
            }
        }
        return out.toByteArray()
    }
}
