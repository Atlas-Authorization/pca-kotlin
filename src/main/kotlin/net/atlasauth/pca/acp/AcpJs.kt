package net.atlasauth.pca.acp

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import org.bouncycastle.util.encoders.Base64

/** JavaScript value semantics over parsed JSON, shared by the ACP / x402 ports. */
@Suppress("UNCHECKED_CAST")
internal object AcpJs {
    fun isObj(o: Any?): Boolean = o is Map<*, *>

    /** JavaScript "!== undefined" on a member of a JSON-sourced object: the key is present (null counts). */
    fun def(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    fun nonEmpty(o: Any?): Boolean = o is String && o.isNotEmpty()

    /** Number.isSafeInteger over a JSON number (typeof number). */
    fun isSafeInteger(o: Any?): Boolean {
        val d = Js.num(o) ?: return false
        return safe(d)
    }

    fun safe(d: Double): Boolean = !d.isNaN() && !d.isInfinite() && d == Math.floor(d) && Math.abs(d) <= 9007199254740991.0

    /** Safe integer and not -0. */
    fun isInt(o: Any?): Boolean = isSafeInteger(o) && !Js.isNegZero(o)

    /** Positive safe integer (an amount in minor units). */
    fun isAmount(o: Any?): Boolean = isSafeInteger(o) && Js.num(o)!! > 0

    /** JavaScript ToNumber over a parsed value (relational comparison coerces; an absent member is NaN, see [dblField]). */
    fun dbl(o: Any?): Double {
        val d = Js.num(o)
        if (d != null) return d
        return when (o) {
            null -> 0.0
            is Boolean -> if (o) 1.0 else 0.0
            is List<*> -> fromString(str(o))
            is String -> fromString(o)
            else -> Double.NaN
        }
    }

    /** ToNumber of a member; undefined (absent) is NaN. */
    fun dblField(m: Any?, k: String): Double = if (def(m, k)) dbl(get(m, k)) else Double.NaN

    private val DEC = Regex("[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
    private val EDGE_WS = Regex("^[\\s\\u00a0\\ufeff\\u2028\\u2029\\u1680\\u2000-\\u200a\\u202f\\u205f\\u3000]+|[\\s\\u00a0\\ufeff\\u2028\\u2029\\u1680\\u2000-\\u200a\\u202f\\u205f\\u3000]+$")

    /** StringToNumber. */
    fun fromString(raw: String): Double {
        val s = raw.replace(EDGE_WS, "")
        if (s.isEmpty()) return 0.0
        if (s == "Infinity" || s == "+Infinity") return Double.POSITIVE_INFINITY
        if (s == "-Infinity") return Double.NEGATIVE_INFINITY
        if (s.length > 2 && s[0] == '0') {
            val c = s[1]
            val radix = when (c) {
                'x', 'X' -> 16
                'o', 'O' -> 8
                'b', 'B' -> 2
                else -> 0
            }
            if (radix != 0) {
                val body = s.substring(2)
                // ASCII digits of the radix only: a sign or a non-ASCII digit is NaN in JavaScript
                if (!body.all { it.code < 128 && Character.digit(it, radix) >= 0 }) return Double.NaN
                return BigInteger(body, radix).toDouble()
            }
        }
        return if (DEC.matches(s)) s.toDouble() else Double.NaN
    }

    /** Object spread (`{...v}`) of a parsed value into a fresh map: maps copy, strings and lists give index keys, anything else is empty. */
    fun spread(v: Any?): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        when (v) {
            is Map<*, *> -> for ((k, x) in v) out[k as String] = x
            is List<*> -> for ((i, x) in v.withIndex()) out[i.toString()] = x
            is String -> for (i in v.indices) out[i.toString()] = v[i].toString()
        }
        return out
    }

    fun lng(o: Any?): Long = Js.num(o)!!.toLong()

    fun num(v: Long): Json.Num = Json.Num(v.toString())

    /** String(v) for a parsed JSON value (template-literal interpolation). */
    fun str(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = Js.num(v)
        if (d != null) return AttestUtil.jsNumString(d)
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

    /** Whole-string regex match (JavaScript "^...$" without the m flag). */
    fun matches(p: Regex, s: Any?): Boolean = s is String && p.matches(s)

    private val B64 = Regex("[A-Za-z0-9+/]+={0,2}")

    fun looksBase64(v: Any?): Boolean = matches(B64, v)

    /** Node Buffer.from(s, "base64") over a string that passed [looksBase64]: unpadded input and dangling bits are tolerated. */
    fun b64decode(s: String): ByteArray {
        var end = s.length
        while (end > 0 && s[end - 1] == '=') end--
        val out = ByteArrayOutputStream()
        var acc = 0
        var bits = 0
        for (i in 0 until end) {
            val c = s[i]
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '+' -> 62
                else -> 63
            }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((acc shr bits) and 0xff)
                acc = acc and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }

    fun b64encode(text: String): String = Base64.toBase64String(Json.utf8(text))

    /** JSON.stringify of a parsed or built value (insertion order). */
    fun stringify(v: Any?): String = Js.stringify(v)

    /** JSON.parse; throws IllegalArgumentException on bad JSON. */
    fun parse(s: String): Any? = Json.parseLenient(s)

    /** The decoded header document: bad base64 and bad JSON are IllegalArgumentExceptions naming [name]. */
    fun decodeHeader(value: Any?, name: String): Any? {
        if (!looksBase64(value)) throw IllegalArgumentException("x402: $name is not base64")
        return try {
            parse(String(b64decode(value as String), Charsets.UTF_8))
        } catch (e: RuntimeException) {
            throw IllegalArgumentException("x402: $name is not JSON")
        }
    }

    fun map(o: Any?): Map<String, Any?> = Js.map(o)
}
