package net.atlasauth.pca.actions

import java.util.TreeSet
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/** Small JSON-tree helpers shared by the action-kit ports (values are Map / List / String / Boolean / Json.Num / null). */
@Suppress("UNCHECKED_CAST")
internal object J {
    fun m(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>
    /** Kotlin's read-only lists (emptyList(), listOf()) are not MutableList: those are copied, so a caller never gets a ClassCastException. */
    fun a(o: Any?): MutableList<Any?> = if (o is MutableList<*>) o as MutableList<Any?> else ArrayList(o as List<Any?>)
    fun isMap(o: Any?): Boolean = o is Map<*, *>
    fun isList(o: Any?): Boolean = o is List<*>
    fun isStr(o: Any?): Boolean = o is String
    fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null
    fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    fun num(o: Any?): Double? {
        if (o is Json.Num) return o.raw.toDoubleOrNull()
        if (o is Int || o is Long || o is Double || o is Short) return (o as Number).toDouble()
        return null
    }

    /** `Number.isSafeInteger(v) && !Object.is(v, -0)`. */
    fun isInt(o: Any?): Boolean {
        val d = num(o) ?: return false
        if (d.isNaN() || d.isInfinite() || d != Math.rint(d) || Math.abs(d) > 9007199254740991.0) return false
        return !(d == 0.0 && 1.0 / d < 0)
    }

    fun n(v: Long): Json.Num = Json.Num(v.toString())

    fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i + 1 < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    fun list(vararg xs: Any?): MutableList<Any?> = ArrayList(xs.asList())

    /** Sorted, de-duplicated strings of a list (non-strings are dropped). */
    fun sortUniq(xs: Any?): MutableList<String> {
        val out = TreeSet<String>()
        if (xs is List<*>) for (x in xs) if (x is String) out.add(x)
        return ArrayList(out)
    }

    fun objs(xs: List<String>): MutableList<Any?> = ArrayList<Any?>(xs)

    // ---- JSON.stringify (compact): JavaScript key order and number spelling, for sameJson-style comparisons ----

    /** `JSON.stringify(v)`. */
    fun stringify(v: Any?): String {
        if (v == null) return "null"
        if (v is Boolean) return v.toString()
        if (v is String) return quote(v)
        val d = num(v)
        if (d != null) return if (d.isNaN() || d.isInfinite()) "null" else AttestUtil.jsNumString(d)
        if (v is List<*>) return v.joinToString(",", "[", "]") { stringify(it) }
        val m = v as Map<String, Any?>
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) (if (isIndexKey(k)) idx else rest).add(k)
        idx.sortWith { x, y -> x.toLong().compareTo(y.toLong()) }
        idx.addAll(rest)
        return idx.joinToString(",", "{", "}") { quote(it) + ":" + stringify(m[it]) }
    }

    private fun isIndexKey(k: String): Boolean {
        if (k.isEmpty() || k.length > 10 || (k.length > 1 && k[0] == '0')) return false
        for (c in k) if (c < '0' || c > '9') return false
        return k.toLong() < 4294967295L
    }

    private fun quote(s: String): String {
        val b = StringBuilder("\"")
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when (c) {
                '"' -> b.append("\\\"")
                '\\' -> b.append("\\\\")
                '\b' -> b.append("\\b")
                '\u000c' -> b.append("\\f")
                '\n' -> b.append("\\n")
                '\r' -> b.append("\\r")
                '\t' -> b.append("\\t")
                else -> {
                    var lone = false
                    if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { b.append(c).append(s[i + 1]); i += 2; continue }
                        lone = true
                    } else if (Character.isLowSurrogate(c)) lone = true
                    if (c.code < 0x20 || lone) b.append(String.format("\\u%04x", c.code)) else b.append(c)
                }
            }
            i++
        }
        return b.append('"').toString()
    }

    /** `JSON.stringify(a) === JSON.stringify(b)` where a null on BOTH sides stands for `undefined` (absent). */
    fun sameJson(a: Any?, aPresent: Boolean, b: Any?, bPresent: Boolean): Boolean {
        if (!aPresent || !bPresent) return !aPresent && !bPresent
        return stringify(sortKeys(a)) == stringify(sortKeys(b))
    }

    /** Object keys sorted recursively (UTF-16 order, like the reference's sortKeys); list order is kept. */
    @Suppress("UNCHECKED_CAST")
    fun sortKeys(v: Any?): Any? = when (v) {
        is List<*> -> v.map { sortKeys(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for (k in (v as Map<String, Any?>).keys.sorted()) out[k] = sortKeys(v[k]) }
        else -> v
    }

    fun sameJsonMember(ma: Any?, mb: Any?, key: String): Boolean = sameJson(get(ma, key), has(ma, key), get(mb, key), has(mb, key))

    /** JavaScript String(v) for a JSON value. */
    fun jsStr(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = num(v)
        if (d != null) return AttestUtil.jsNumString(d)
        if (v is List<*>) return v.joinToString(",") { if (it == null) "" else jsStr(it) }
        return "[object Object]"
    }

    /** JavaScript white space (WhiteSpace and LineTerminator). */
    fun jsSpace(c: Char): Boolean {
        val x = c.code
        return (x in 9..13) || x == 32 || x == 0xa0 || x == 0x1680 || (x in 0x2000..0x200a) || x == 0x2028 || x == 0x2029 || x == 0x202f || x == 0x205f || x == 0x3000 || x == 0xfeff
    }

    /** `s.trim()`. */
    fun jsTrim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && jsSpace(s[a])) a++
        while (b > a && jsSpace(s[b - 1])) b--
        return s.substring(a, b)
    }
}
