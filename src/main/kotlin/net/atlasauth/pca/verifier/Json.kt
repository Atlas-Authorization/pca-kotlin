package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.BigInteger
import java.nio.charset.StandardCharsets

/**
 * JSON for the PCA wire format v2: a hand-written RFC 8259 parser in two profiles (numbers kept exact as
 * [Num]) plus the canonical serializers (lenient for content addressing, STRICT for the signed PCActn body).
 *
 * This is an idiomatic-Kotlin port of `sdks/java-pca/.../Json.java`, itself a byte-exact mirror of the
 * TypeScript source of truth `packages/pca/src/{strict-json.ts,hash.ts,wire.ts}`. The two implementations
 * must produce identical canonical bytes for cross-language signature convergence.
 *
 * [parse] is the STRICT profile (normative for signed bytes): it rejects comments, trailing commas, BOM,
 * non-JSON whitespace, duplicate keys (after unescaping), lone surrogates (raw or escaped), raw control
 * characters in strings, unknown escapes, nesting deeper than [MAX_DEPTH], input longer than [MAX_CHARS]
 * UTF-8 bytes, and any number not in the canonical wire form (see [numberError]).
 * [parseLenient] accepts any RFC 8259 text and is ONLY for trusted fixtures (conformance files).
 */
object Json {
    const val MAX_DEPTH = 32
    const val MAX_CHARS = 1 shl 20
    const val MAX_DECIMAL_DIGITS = 15
    private val MAX_SAFE: BigInteger = BigInteger.valueOf(9007199254740991L)
    private val MIN_DECIMAL = BigDecimal("0.000001")
    private val LEXEME = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

    /** A JSON number kept as its source text (like Go's json.Number). */
    class Num(val raw: String) {
        override fun toString(): String = raw
        override fun equals(other: Any?): Boolean = other is Num && other.raw == raw
        override fun hashCode(): Int = raw.hashCode()
    }

    // ---- number profile ----
    /**
     * Strict-profile check of a number lexeme. Returns null when canonical, else a reason. Canonical: integers
     * are safe integers (|n| <= 2^53-1, no -0); non-integers are plain decimal (no exponent, no trailing
     * fractional zero), at most 15 significant digits, magnitude >= 1e-6. (Leading +, leading zeros, ".5", "5."
     * fail the lexeme grammar.)
     */
    fun numberError(raw: String?): String? {
        if (raw == null || !LEXEME.matches(raw)) return "malformed number"
        if (raw.indexOf('e') >= 0 || raw.indexOf('E') >= 0) return "exponent form is not allowed"
        if (raw == "-0") return "negative zero is not allowed"
        if (raw.indexOf('.') >= 0) {
            if (raw.endsWith("0")) return "trailing fractional zero is not canonical"
            val digits = raw.replace("-", "").replace(".", "")
            var z = 0
            while (z < digits.length && digits[z] == '0') z++
            if (digits.length - z > MAX_DECIMAL_DIGITS) return "more than 15 significant digits"
            val v = BigDecimal(raw).abs()
            if (v.signum() != 0 && v.compareTo(MIN_DECIMAL) < 0) return "non-integer magnitude below 1e-6"
            return null
        }
        val abs = if (raw.startsWith("-")) raw.substring(1) else raw
        if (abs.length > 16 || BigInteger(abs).compareTo(MAX_SAFE) > 0) return "integer outside the safe range"
        return null
    }

    /** True iff the value is a strict-profile safe integer (a [Num] integer lexeme, Int or Long). */
    fun isSafeInt(o: Any?): Boolean {
        if (o is Num) {
            val r = o.raw
            return numberError(r) == null && r.indexOf('.') < 0
        }
        if (o is Int) return true
        if (o is Long) return Math.abs(o) <= 9007199254740991L
        return false
    }

    /** True iff the value is a strict-profile number (integer or plain decimal). */
    fun isStrictNumber(o: Any?): Boolean {
        if (o is Num) return numberError(o.raw) == null
        return isSafeInt(o)
    }

    /** Value of a safe integer (call only after [isSafeInt]). */
    fun asLong(o: Any?): Long {
        if (o is Num) return o.raw.toLong()
        return (o as Number).toLong()
    }

    /** Exact decimal value of a strict number. */
    fun asDecimal(o: Any?): BigDecimal {
        if (o is Num) return BigDecimal(o.raw)
        return BigDecimal.valueOf((o as Number).toLong())
    }

    fun hasLoneSurrogate(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) i++
                else return true
            } else if (Character.isLowSurrogate(c)) return true
            i++
        }
        return false
    }

    // ---- parser ----
    /** STRICT profile. Throws [IllegalArgumentException] on any deviation. */
    fun parse(s: String?): Any? = Parser(s, true).top()

    /** Lenient RFC 8259 (fixtures only): duplicate keys / lone surrogates / any number allowed. */
    fun parseLenient(s: String?): Any? = Parser(s, false).top()

    private fun dig(c: Char): Boolean = c in '0'..'9'

    private class Parser(val s: String?, val strict: Boolean) {
        var i = 0

        fun top(): Any? {
            if (s == null) throw IllegalArgumentException("input is not a string")
            if (strict && (s.length > MAX_CHARS || s.toByteArray(StandardCharsets.UTF_8).size > MAX_CHARS))
                throw IllegalArgumentException("input too large")
            ws()
            val v = value(1)
            ws()
            if (i != s.length) throw err("trailing data")
            return v
        }

        fun ws() {
            while (i < s!!.length) {
                val c = s[i]
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++ else break
            }
        }

        fun err(m: String) = IllegalArgumentException("$m at $i")

        fun value(depth: Int): Any? {
            if (i >= s!!.length) throw err("unexpected end")
            return when (s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> { lit("true"); true }
                'f' -> { lit("false"); false }
                'n' -> { lit("null"); null }
                else -> number()
            }
        }

        fun lit(w: String) {
            if (!s!!.startsWith(w, i)) throw err("bad literal")
            i += w.length
        }

        fun obj(depth: Int): LinkedHashMap<String, Any?> {
            if (strict && depth > MAX_DEPTH) throw err("nesting too deep")
            val m = LinkedHashMap<String, Any?>()
            i++; ws()
            if (i < s!!.length && s[i] == '}') { i++; return m }
            while (true) {
                ws()
                if (i >= s.length || s[i] != '"') throw err("expected key")
                val k = str()
                if (strict && m.containsKey(k)) throw err("duplicate key")
                ws()
                if (i >= s.length || s[i] != ':') throw err("expected ':'")
                i++; ws()
                m[k] = value(depth + 1)
                ws()
                if (i >= s.length) throw err("unterminated object")
                val c = s[i++]
                if (c == '}') return m
                if (c != ',') throw err("expected ',' or '}'")
            }
        }

        fun arr(depth: Int): ArrayList<Any?> {
            if (strict && depth > MAX_DEPTH) throw err("nesting too deep")
            val l = ArrayList<Any?>()
            i++; ws()
            if (i < s!!.length && s[i] == ']') { i++; return l }
            while (true) {
                ws()
                l.add(value(depth + 1))
                ws()
                if (i >= s.length) throw err("unterminated array")
                val c = s[i++]
                if (c == ']') return l
                if (c != ',') throw err("expected ',' or ']'")
            }
        }

        fun hex4(): Int {
            if (i + 4 > s!!.length) throw err("bad \\u escape")
            var v = 0
            for (k in 0 until 4) {
                val ch = s[i + k]
                val ascii = (ch in '0'..'9') || (ch in 'a'..'f') || (ch in 'A'..'F')
                val d = Character.digit(ch, 16)
                if (!ascii || d < 0) throw err("bad \\u escape")
                v = v * 16 + d
            }
            i += 4
            return v
        }

        fun str(): String {
            val sb = StringBuilder()
            i++
            while (true) {
                if (i >= s!!.length) throw err("unterminated string")
                val c = s[i++]
                if (c == '"') break
                if (c < ' ') throw err("control char in string")
                if (c != '\\') { sb.append(c); continue }
                if (i >= s.length) throw err("bad escape")
                when (val e = s[i++]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    '/' -> sb.append('/')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> sb.append(hex4().toChar())
                    else -> throw err("bad escape")
                }
            }
            val out = sb.toString()
            if (strict && hasLoneSurrogate(out)) throw err("lone surrogate in string")
            return out
        }

        fun number(): Num {
            val st = i
            if (i < s!!.length && s[i] == '-') i++
            if (i >= s.length) throw err("bad number")
            val c = s[i]
            if (c == '0') i++
            else if (c in '1'..'9') { while (i < s.length && dig(s[i])) i++ }
            else throw err("bad number")
            if (i < s.length && s[i] == '.') {
                i++
                val fs = i
                while (i < s.length && dig(s[i])) i++
                if (i == fs) throw err("bad number")
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                val es = i
                while (i < s.length && dig(s[i])) i++
                if (i == es) throw err("bad number")
            }
            val raw = s.substring(st, i)
            if (strict) {
                val e = numberError(raw)
                if (e != null) throw err(e)
            }
            return Num(raw)
        }
    }

    // ---- canonical serializers ----
    /** LENIENT canonical form (content addressing: capabilities, Merkle leaves). Keys in UTF-8 bytewise order. */
    fun canonicalize(v: Any?): String {
        val sb = StringBuilder()
        ser(sb, v, false, 1)
        return sb.toString()
    }

    /**
     * STRICT canonical form of a signed PCActn body (wire v2). Additionally throws [IllegalArgumentException]
     * on non-canonical numbers, lone surrogates in strings or keys, nesting deeper than 32, unsupported types.
     */
    fun canonicalizeStrict(v: Any?): String {
        val sb = StringBuilder()
        ser(sb, v, true, 1)
        return sb.toString()
    }

    /** Bytewise UTF-8 comparison of two strings (== Unicode code point order). */
    fun compareUtf8(a: String, b: String): Int {
        val ba = a.toByteArray(StandardCharsets.UTF_8)
        val bb = b.toByteArray(StandardCharsets.UTF_8)
        val n = minOf(ba.size, bb.size)
        for (k in 0 until n) {
            val d = (ba[k].toInt() and 0xff) - (bb[k].toInt() and 0xff)
            if (d != 0) return d
        }
        return ba.size - bb.size
    }

    private fun jsString(sb: StringBuilder, s: String, strict: Boolean) {
        if (strict && hasLoneSurrogate(s)) throw IllegalArgumentException("canonicalize: lone surrogate in string")
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
                else -> {
                    if (c < ' ') {
                        sb.append("\\u").append(String.format("%04x", c.code))
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                            sb.append(c).append(s[++i])
                        } else sb.append('�')
                    } else if (Character.isLowSurrogate(c)) {
                        sb.append('�') // lenient only (strict rejected above)
                    } else sb.append(c)
                }
            }
            i++
        }
        sb.append('"')
    }

    /** Lenient number formatting: canonical lexemes are already the shortest round-trip form. */
    fun fmtNumber(raw: String): String {
        if (numberError(raw) == null) return raw
        val f: Double = try {
            BigDecimal(raw).toDouble()
        } catch (e: NumberFormatException) {
            throw IllegalArgumentException("canonicalize: non-finite number")
        }
        if (f.isInfinite() || f.isNaN()) throw IllegalArgumentException("canonicalize: non-finite number")
        if (f == 0.0) return "0"
        return BigDecimal(f.toString()).stripTrailingZeros().toPlainString()
    }

    @Suppress("UNCHECKED_CAST")
    private fun ser(sb: StringBuilder, v: Any?, strict: Boolean, depth: Int) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is String -> jsString(sb, v, strict)
            is Num -> {
                val raw = v.raw
                if (strict) {
                    val e = numberError(raw)
                    if (e != null) throw IllegalArgumentException("canonicalize: $e")
                    sb.append(raw)
                } else sb.append(fmtNumber(raw))
            }
            is Int, is Long -> {
                if (strict && !isSafeInt(v)) throw IllegalArgumentException("canonicalize: integer outside the safe range")
                sb.append(v.toString())
            }
            is List<*> -> {
                if (strict && depth > MAX_DEPTH) throw IllegalArgumentException("canonicalize: nesting too deep")
                sb.append('[')
                var first = true
                for (x in v) {
                    if (!first) sb.append(',')
                    first = false
                    ser(sb, x, strict, depth + 1)
                }
                sb.append(']')
            }
            is Map<*, *> -> {
                if (strict && depth > MAX_DEPTH) throw IllegalArgumentException("canonicalize: nesting too deep")
                val m = v as Map<String, Any?>
                val keys = ArrayList(m.keys)
                keys.sortWith(Comparator { a, b -> compareUtf8(a, b) })
                sb.append('{')
                var first = true
                for (k in keys) {
                    if (!first) sb.append(',')
                    first = false
                    jsString(sb, k, strict)
                    sb.append(':')
                    ser(sb, m[k], strict, depth + 1)
                }
                sb.append('}')
            }
            else -> throw IllegalArgumentException("canonicalize: unsupported type ${v.javaClass}")
        }
    }
}
