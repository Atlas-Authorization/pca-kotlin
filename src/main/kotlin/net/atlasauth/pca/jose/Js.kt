package net.atlasauth.pca.jose

import net.atlasauth.pca.verifier.Json

/**
 * JavaScript value semantics over parsed JSON (Map, List, String, Boolean, [Json.Num], null), shared by the protocol-bridge ports:
 * truthiness, number reads, typeof checks and JSON.stringify (insertion order, unlike the canonical form).
 */
/** The reference's TypeError: a refused argument. */
open class JsTypeError(message: String) : IllegalArgumentException(message)

object Js {
    /** JavaScript truthiness: null, false, "", 0 and NaN are falsy; everything else is truthy. */
    fun truthy(o: Any?): Boolean = when (o) {
        null -> false
        is Boolean -> o
        is String -> o.isNotEmpty()
        else -> num(o)?.let { it != 0.0 && !it.isNaN() } ?: true
    }

    /** The JavaScript number value of a JSON number or a Kotlin number; null when not a number. */
    fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    fun isNumber(o: Any?): Boolean = num(o) != null

    /** typeof o === 'number' && Number.isFinite(o). */
    fun isFinite(o: Any?): Boolean = num(o)?.let { !it.isNaN() && !it.isInfinite() } ?: false

    /** `o[k]` for a read that throws on null, as JavaScript does; a non-object has no members. */
    fun member(o: Any?, k: String): Any? {
        if (o == null) throw JsTypeError("cannot read '$k' of null or undefined")
        return (o as? Map<*, *>)?.get(k)
    }

    /** Number.isInteger: finite and integral. */
    fun isInteger(o: Any?): Boolean = num(o)?.let { !it.isNaN() && !it.isInfinite() && it == Math.floor(it) } ?: false

    fun isNegZero(o: Any?): Boolean = num(o)?.let { it == 0.0 && java.lang.Double.doubleToRawLongBits(it) != 0L } ?: false

    /** typeof x === 'object' && x !== null (an array counts, as in JavaScript). */
    fun isObjectLike(o: Any?): Boolean = o is Map<*, *> || o is List<*>

    /** A member read: null for a non-object or an absent key (undefined and null are not told apart). */
    fun get(o: Any?, k: String): Any? = (o as? Map<*, *>)?.get(k)

    /** The key is present with a value other than null (JavaScript `!== undefined` for JSON-sourced input). */
    fun has(o: Any?, k: String): Boolean = get(o, k) != null

    /** Own-property presence (`k in o` for a plain object), null values included. */
    fun own(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    @Suppress("UNCHECKED_CAST")
    fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: emptyMap()

    @Suppress("UNCHECKED_CAST")
    fun list(o: Any?): List<Any?> = o as List<Any?>

    fun allStrings(o: Any?): Boolean = o is List<*> && o.all { it is String }

    fun allNumbers(o: Any?): Boolean = o is List<*> && o.all { isNumber(it) }

    fun nonEmptyString(o: Any?): Boolean = o is String && o.isNotEmpty()

    /** JSON.stringify of a parsed value (member order as inserted). */
    fun stringify(v: Any?): String = StringBuilder().also { ser(it, v) }.toString()

    private fun ser(sb: StringBuilder, v: Any?) {
        when (v) {
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, x) in v) {
                    if (!first) sb.append(',')
                    first = false
                    sb.append(Json.canonicalize(k.toString())).append(':')
                    ser(sb, x)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                v.forEachIndexed { i, x -> if (i > 0) sb.append(','); ser(sb, x) }
                sb.append(']')
            }
            is Double, is Float -> sb.append(jsNum((v as Number).toDouble()).raw)
            else -> sb.append(Json.canonicalize(v))
        }
    }

    /** An insertion-ordered result map. */
    fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)

    /** A JavaScript template-literal rendering (`${v}`) of a JSON value; arrays join with commas, null elements as "". */
    fun template(v: Any?): String = when {
        v == null -> "null"
        v is String -> v
        v is Boolean -> v.toString()
        num(v) != null -> num(v)!!.let { d ->
            when {
                d.isNaN() -> "NaN"
                d.isInfinite() -> if (d > 0) "Infinity" else "-Infinity"
                else -> jsNum(d).raw
            }
        }
        v is List<*> -> join(v, ",")
        else -> "[object Object]"
    }

    /** Array.prototype.join: null elements print as the empty string. */
    fun join(xs: List<*>, sep: String): String = xs.joinToString(sep) { if (it == null) "" else template(it) }

    /** Math.round: halves round toward +Infinity. */
    fun round(d: Double): Double {
        if (d.isNaN() || d.isInfinite()) return d
        val f = Math.floor(d)
        return if (d - f >= 0.5) f + 1 else f
    }

    fun n(v: Long): Json.Num = Json.Num(v.toString())

    /** A JavaScript number as JSON: integral values print without a fraction. */
    fun jsNum(d: Double): Json.Num {
        require(!d.isNaN() && !d.isInfinite()) { "non-finite number" }
        return if (d == Math.rint(d) && Math.abs(d) < 1e15) n(d.toLong()) else Json.Num(Json.esNumber(d))
    }
}
