package net.atlasauth.pca.gnap

import net.atlasauth.pca.verifier.Json
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHA512Digest

/** Thrown by the issuance paths on a malformed request (the verify paths fail closed instead). */
class GnapError(message: String) : RuntimeException(message)

/** A GNAP interaction failure carrying its stable code (invalid_interaction, unknown_interaction, too_many_attempts, invalid_request, expired, wrong_state, unsupported_hash). */
class InteractionError(val code: String, message: String) : RuntimeException(message)

/** JavaScript value semantics the reference relies on (truthiness, member reads, String(), JSON.stringify). */
internal object GnapJs { // shared by the protocol-bridge ports that need JavaScript value semantics (gnap, ciba)
    /** Marks an argument or member that is absent (JavaScript undefined); a Kotlin null is a JSON null. */
    val ABSENT = Any()

    fun truthy(v: Any?): Boolean = when {
        v == null || v === ABSENT -> false
        v is Boolean -> v
        v is String -> v.isNotEmpty()
        else -> num(v)?.let { it != 0.0 && !it.isNaN() } ?: true
    }

    fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    /** `o[k]` for an object; every other value has no such member (null stands for undefined here). */
    fun member(o: Any?, k: String): Any? = (o as? Map<*, *>)?.get(k)
    fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)
    /** `o[k]`, or [ABSENT] when the member is not there. */
    fun get(o: Any?, k: String): Any? = if (has(o, k)) (o as Map<*, *>)[k] else ABSENT
    fun isObject(o: Any?): Boolean = o is Map<*, *> || o is List<*>

    /** JavaScript `String(v)` for the values a JSON document holds. */
    fun str(v: Any?): String = when {
        v == null -> "null"
        v === ABSENT -> "undefined"
        v is String -> v
        v is Boolean -> v.toString()
        v is Json.Num -> v.raw
        v is Double || v is Float -> jsNumber((v as Number).toDouble())
        v is Number -> v.toString()
        v is List<*> -> v.joinToString(",") { if (it == null) "" else str(it) }
        else -> "[object Object]"
    }

    /** JavaScript `String(n)` of a number. */
    fun jsNumber(d: Double): String = when {
        d.isNaN() -> "NaN"
        d.isInfinite() -> if (d > 0) "Infinity" else "-Infinity"
        d == 0.0 -> "0"
        else -> Json.esNumber(d)
    }

    /** `Number.isSafeInteger`. */
    fun isSafeInteger(o: Any?): Boolean = num(o)?.let { !it.isNaN() && !it.isInfinite() && it == Math.rint(it) && Math.abs(it) <= 9007199254740991.0 } ?: false

    /** The JavaScript whitespace set (`\s`, also what `trim` removes). */
    fun isWs(c: Int): Boolean = (c in 0x09..0x0d) || c == 0x20 || c == 0xa0 || c == 0x1680 || (c in 0x2000..0x200a) || c == 0x2028 || c == 0x2029 ||
        c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff

    /** `String.prototype.trim`. */
    fun trim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isWs(s[a].code)) a++
        while (b > a && isWs(s[b - 1].code)) b--
        return s.substring(a, b)
    }

    /** A deep copy of a JSON tree (what `structuredClone` gives for JSON values). */
    fun deepCopy(v: Any?): Any? = when (v) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = deepCopy(x) }
        is List<*> -> v.mapTo(ArrayList()) { deepCopy(it) }
        else -> v
    }

    /** The digest named by its JCA name, computed with BouncyCastle (SHA-3 is not in every Android provider). */
    fun sha(alg: String, b: ByteArray): ByteArray {
        val d: Digest = when (alg) {
            "SHA-256" -> SHA256Digest()
            "SHA-384" -> SHA384Digest()
            "SHA-512" -> SHA512Digest()
            "SHA3-256" -> SHA3Digest(256)
            "SHA3-512" -> SHA3Digest(512)
            else -> throw IllegalStateException("no digest $alg")
        }
        d.update(b, 0, b.size)
        val out = ByteArray(d.digestSize)
        d.doFinal(out, 0)
        return out
    }

    fun sha256(b: ByteArray): ByteArray = sha("SHA-256", b)

    /** `JSON.stringify` of a JSON value: insertion order of members, numbers as printed, lone surrogates escaped. */
    fun stringify(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(v.toString())
            is Json.Num -> sb.append(if (v.raw == "-0") "0" else v.raw)
            is Number -> sb.append(str(v))
            is String -> string(sb, v)
            is List<*> -> {
                sb.append('[')
                v.forEachIndexed { i, x -> if (i > 0) sb.append(','); write(sb, x) }
                sb.append(']')
            }
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, x) in v) {
                    if (!first) sb.append(',')
                    first = false
                    string(sb, k as String)
                    sb.append(':')
                    write(sb, x)
                }
                sb.append('}')
            }
            else -> throw IllegalArgumentException("not a JSON value: ${v.javaClass.name}")
        }
    }

    private fun string(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000c' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> when {
                    c.code < 0x20 -> sb.append(String.format("\\u%04x", c.code))
                    Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { sb.append(c).append(s[i + 1]); i++ }
                    Character.isSurrogate(c) -> sb.append(String.format("\\u%04x", c.code))
                    else -> sb.append(c)
                }
            }
            i++
        }
        sb.append('"')
    }
}
