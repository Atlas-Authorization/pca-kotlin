package net.atlasauth.pca.payments

import java.math.BigInteger
import net.atlasauth.pca.gnap.GnapJs
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/** JavaScript value semantics over parsed JSON for the payments port (numbers are binary64, member reads of a non-object are undefined). */
@Suppress("UNCHECKED_CAST")
internal object PayJs {
    const val MAX_SAFE = 9007199254740991.0

    fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    /** Number.isFinite on a value that is a number. */
    fun isFiniteNum(o: Any?): Boolean {
        val d = num(o) ?: return false
        return !d.isNaN() && !d.isInfinite()
    }

    fun isSafeInteger(o: Any?): Boolean {
        val d = num(o) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= MAX_SAFE
    }

    fun isNegZero(o: Any?): Boolean {
        val d = num(o) ?: return false
        return d == 0.0 && java.lang.Double.doubleToRawLongBits(d) != 0L
    }

    /** A number as a JSON value the canonical form accepts (non-finite becomes null, as JSON.stringify prints it). */
    fun jn(d: Double): Any? {
        if (d.isNaN() || d.isInfinite()) return null
        if (d == 0.0) return Json.Num("0")
        return IntentJs.normalize(d)
    }

    fun nz(x: Double): Double = if (!x.isNaN() && !x.isInfinite() && x > 0) x else 0.0

    fun clamp01(x: Double): Double = if (x < 0) 0.0 else if (x > 1) 1.0 else x

    fun truthy(o: Any?): Boolean {
        if (o == null) return false
        if (o is Boolean) return o
        if (o is String) return o.isNotEmpty()
        val d = num(o)
        if (d != null) return d != 0.0 && !d.isNaN()
        return true
    }

    fun isObj(o: Any?): Boolean = o is Map<*, *> || o is List<*>

    fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    fun copy(o: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        if (o is Map<*, *>) m.putAll(o as Map<String, Any?>)
        // object spread of an array / string lists its index members
        else if (o is List<*>) o.forEachIndexed { i, v -> m[i.toString()] = v }
        else if (o is String) o.codePoints().toArray().forEachIndexed { i, c -> m[i.toString()] = String(Character.toChars(c)) }
        return m
    }

    fun map(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) m[k] = v
        return m
    }

    /** JavaScript string conversion as a template literal does it. */
    fun str(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = num(v)
        if (d != null) {
            if (d.isNaN()) return "NaN"
            if (d.isInfinite()) return if (d > 0) "Infinity" else "-Infinity"
            if (d == 0.0) return "0"
            return Json.esNumber(d)
        }
        if (v is List<*>) {
            val sb = StringBuilder()
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                if (x != null) sb.append(str(x))
            }
            return sb.toString()
        }
        return "[object Object]"
    }

    /** A byte array from a ByteArray or the {"$bytes": b64url} wire form; null otherwise. */
    fun bytes(o: Any?): ByteArray? {
        if (o is ByteArray) return o
        val b = get(o, "\$bytes")
        return if (b is String) Keys.unb64u(b) else null
    }

    fun list(vararg xs: Any?): MutableList<Any?> = ArrayList<Any?>().also { it.addAll(xs) }

    private val DEC = Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")
    private val HEX = Regex("0[xX][0-9a-fA-F]+")
    private val BIN = Regex("0[bB][01]+")
    private val OCT = Regex("0[oO][0-7]+")

    /** JavaScript ToNumber over JSON-shaped values (undefined must be handled by the caller: it is NaN). */
    fun toNumber(o: Any?): Double {
        if (o == null) return 0.0
        if (o is Boolean) return if (o) 1.0 else 0.0
        val d = num(o)
        if (d != null) return d
        if (o is String) {
            val t = jsTrim(o)
            if (t.isEmpty()) return 0.0
            if (t == "Infinity" || t == "+Infinity") return Double.POSITIVE_INFINITY
            if (t == "-Infinity") return Double.NEGATIVE_INFINITY
            if (HEX.matches(t)) return BigInteger(t.substring(2), 16).toDouble()
            if (BIN.matches(t)) return BigInteger(t.substring(2), 2).toDouble()
            if (OCT.matches(t)) return BigInteger(t.substring(2), 8).toDouble()
            if (DEC.matches(t)) return t.toDouble()
            return Double.NaN
        }
        if (o is List<*>) return toNumber(str(o))
        return Double.NaN
    }

    /** `m[k]` as a number: undefined (absent key) is NaN, null is 0. */
    fun numOf(m: Map<String, Any?>, k: String): Double = if (m.containsKey(k)) toNumber(m[k]) else Double.NaN

    /** `out[k] = m[mk]` unless the member is undefined (absent), as JSON.stringify drops it. */
    fun putTerm(out: MutableMap<String, Any?>, k: String, m: Map<String, Any?>, mk: String) {
        if (m.containsKey(mk)) out[k] = m[mk]
    }

    /** `x.length` when it is a number (a string or an array), else NaN (undefined). */
    fun jsLength(o: Any?): Double = when (o) {
        is String -> o.length.toDouble()
        is List<*> -> o.size.toDouble()
        else -> Double.NaN
    }

    fun isWs(c: Char): Boolean = GnapJs.isWs(c.code)

    fun jsTrim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isWs(s[a])) a++
        while (b > a && isWs(s[b - 1])) b--
        return s.substring(a, b)
    }
}
