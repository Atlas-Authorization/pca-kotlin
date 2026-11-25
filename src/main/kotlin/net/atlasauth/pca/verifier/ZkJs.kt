package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.BigInteger

/**
 * The reference's value semantics that the zk checks rest on, for JSON values (Map, List, String, Boolean, null, [Json.Num] and Kotlin
 * numbers): member lookup that tells an absent member from a null one, `===`, truthiness, `String(v)` and `BigInt(v)`. Every helper is
 * total or throws where the reference throws, so a hostile shape is refused the same way.
 */
internal object ZkJs {
    /** An absent member or argument (a JSON null is a value, this is not). */
    val UNDEF: Any = object {
        override fun toString(): String = "undefined"
    }

    /** `o[k]` for an own member of an object; [UNDEF] for anything else. */
    fun get(o: Any?, k: String): Any? = if (o is Map<*, *> && o.containsKey(k)) o[k] else UNDEF

    /** `a === b` (two containers are never the same value). */
    fun strictEq(a: Any?, b: Any?): Boolean {
        if (a === UNDEF || b === UNDEF) return a === b
        if (a == null || b == null) return a == null && b == null
        if (a is String || b is String) return a is String && b is String && a == b
        if (a is Boolean || b is Boolean) return a is Boolean && b is Boolean && a == b
        if (a is BigInteger || b is BigInteger) return a is BigInteger && b is BigInteger && a == b
        val x = IntentJs.num(a)
        val y = IntentJs.num(b)
        return x != null && y != null && x == y
    }

    fun truthy(v: Any?): Boolean {
        if (v == null || v === UNDEF) return false
        if (v is Boolean) return v
        if (v is String) return v.isNotEmpty()
        if (v is BigInteger) return v.signum() != 0
        val d = IntentJs.num(v)
        return d == null || (d != 0.0 && !d.isNaN())
    }

    /** `String(v)`. */
    fun string(v: Any?): String {
        if (v === UNDEF) return "undefined"
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean || v is BigInteger) return v.toString()
        if (v is List<*>) return v.joinToString(",") { if (it == null || it === UNDEF) "" else string(it) }
        if (v is Map<*, *>) return "[object Object]"
        val d = IntentJs.num(v)
        return if (d == null) v.toString() else Json.jsNumberText(d)
    }

    private val DECIMAL = Regex("[+-]?[0-9]+")

    private fun parseBigInt(raw: String): BigInteger {
        val s = raw.trim { it.isWhitespace() || it == '﻿' }
        if (s.isEmpty()) return BigInteger.ZERO
        if (s.length > 2 && s[0] == '0') {
            val radix = when (s[1]) {
                'x', 'X' -> 16
                'o', 'O' -> 8
                'b', 'B' -> 2
                else -> 0
            }
            if (radix != 0) {
                val digits = s.substring(2)
                if (!digits.all { it.code < 128 && Character.digit(it, radix) >= 0 }) throw IllegalArgumentException("not an integer: $raw")
                return BigInteger(digits, radix)
            }
        }
        if (!DECIMAL.matches(s)) throw IllegalArgumentException("not an integer: $raw")
        return BigInteger(if (s[0] == '+') s.substring(1) else s)
    }

    /** `BigInt(v)`: an integral number, an integer string (decimal, or 0x / 0o / 0b), a boolean; anything else throws. */
    fun bigInt(v: Any?): BigInteger {
        if (v is BigInteger) return v
        if (v is Boolean) return if (v) BigInteger.ONE else BigInteger.ZERO
        if (v is String) return parseBigInt(v)
        if (v is List<*>) return parseBigInt(string(v))
        val d = IntentJs.num(v) ?: throw IllegalArgumentException("cannot convert " + string(v) + " to an integer")
        if (d.isNaN() || d.isInfinite() || d != Math.rint(d)) throw IllegalArgumentException("not an integer: " + string(v))
        return BigDecimal(d).toBigIntegerExact()
    }

    /** `Number.isInteger(v)` as a BigInteger, else null. */
    fun integerOf(v: Any?): BigInteger? {
        val d = IntentJs.num(v) ?: return null
        if (d.isNaN() || d.isInfinite() || d != Math.rint(d)) return null
        return BigDecimal(d).toBigIntegerExact()
    }

    /** A finite number, else null (`Number.isFinite`). */
    fun finite(v: Any?): Double? {
        val d = IntentJs.num(v) ?: return null
        return if (d.isNaN() || d.isInfinite()) null else d
    }

    fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xff
            sb.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 15])
        }
        return sb.toString()
    }
}
