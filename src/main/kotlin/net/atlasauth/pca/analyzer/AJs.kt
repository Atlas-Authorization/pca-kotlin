package net.atlasauth.pca.analyzer

import net.atlasauth.pca.verifier.Json

/** JavaScript-flavoured helpers over JSON trees (Map / List / String / Boolean / Json.Num / null) for the analyzer. */
internal object AJs {
    /** The binary64 value of a JSON number, else null. */
    fun num(o: Any?): Double? {
        if (o is Json.Num) return o.raw.toDoubleOrNull()
        if (o is Int || o is Long || o is Double || o is Short) return (o as Number).toDouble()
        return null
    }

    fun isNum(o: Any?): Boolean = num(o) != null

    fun isFin(o: Any?): Boolean {
        val d = num(o)
        return d != null && !d.isNaN() && !d.isInfinite()
    }

    /** A number as a JSON value, spelled the way JavaScript prints it. */
    fun n(d: Double): Json.Num {
        if (d.isNaN() || d.isInfinite()) return Json.Num(d.toString())
        return Json.Num(Json.esNumber(if (d == 0.0) 0.0 else d))
    }

    fun n(i: Int): Json.Num = n(i.toDouble())

    fun isMap(o: Any?): Boolean = o is Map<*, *>
    fun isList(o: Any?): Boolean = o is List<*>

    @Suppress("UNCHECKED_CAST")
    fun map(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>

    @Suppress("UNCHECKED_CAST")
    fun list(o: Any?): MutableList<Any?> = if (o is MutableList<*>) o as MutableList<Any?> else ArrayList(o as List<Any?>)

    fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    /** Insertion-ordered object from alternating key / value arguments. */
    fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i + 1 < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    fun arr(vararg xs: Any?): ArrayList<Any?> = ArrayList(xs.asList())

    fun copy(m: Any?): LinkedHashMap<String, Any?> = if (m is Map<*, *>) LinkedHashMap(map(m)) else LinkedHashMap()

    /** A string member, or null when absent or not a string. */
    fun str(o: Any?, k: String): String? = get(o, k) as? String

    /** `a === b`: numbers by value, strings and booleans by value, null with null, anything else by identity. */
    fun strictEq(a: Any?, b: Any?): Boolean {
        if (a == null || b == null) return a == null && b == null
        val x = num(a)
        val y = num(b)
        if (x != null || y != null) return x != null && y != null && x == y
        if (a is String || a is Boolean) return a == b
        return a === b
    }

    /** `arr.includes(x)` (SameValueZero; NaN cannot occur in JSON). */
    fun includes(xs: List<*>, x: Any?): Boolean {
        for (e in xs) if (strictEq(e, x)) return true
        return false
    }

    /** JavaScript's own-key order: array-index keys ascending first, then the rest in insertion order. */
    fun keys(m: Map<String, Any?>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) (if (isIndexKey(k)) idx else rest).add(k)
        idx.sortBy { it.toLong() }
        idx.addAll(rest)
        return idx
    }

    private fun isIndexKey(k: String): Boolean {
        if (k.isEmpty() || k.length > 10 || (k.length > 1 && k[0] == '0')) return false
        for (c in k) if (c < '0' || c > '9') return false
        return k.toLong() < 4294967295L
    }

    /** `JSON.stringify(v)` for a JSON tree. */
    fun stringify(v: Any?): String {
        val sb = StringBuilder()
        ser(sb, v)
        return sb.toString()
    }

    private fun ser(sb: StringBuilder, v: Any?) {
        val d = num(v)
        if (v == null) sb.append("null")
        else if (d != null) sb.append(if (d.isNaN() || d.isInfinite()) "null" else Json.esNumber(if (d == 0.0) 0.0 else d))
        else if (v is Boolean) sb.append(v.toString())
        else if (v is String) sb.append(Json.canonicalize(v))
        else if (v is List<*>) {
            sb.append('[')
            var first = true
            for (x in v) { if (!first) sb.append(','); first = false; ser(sb, x) }
            sb.append(']')
        } else if (v is Map<*, *>) {
            val m = map(v)
            sb.append('{')
            var first = true
            for (k in keys(m)) { if (!first) sb.append(','); first = false; sb.append(Json.canonicalize(k)).append(':'); ser(sb, m[k]) }
            sb.append('}')
        } else sb.append("null")
    }

    /** JavaScript truthiness of a JSON value. */
    fun truthy(o: Any?): Boolean {
        if (o == null) return false
        if (o is Boolean) return o
        if (o is String) return o.isNotEmpty()
        val d = num(o)
        if (d != null) return d != 0.0 && !d.isNaN()
        return true
    }

    private val NUMLIT = Regex("[+-]?(?:\\d+\\.?\\d*|\\.\\d+)(?:[eE][+-]?\\d+)?|[+-]?Infinity")

    /** JavaScript `Number(x)` for a JSON value (NaN when not numeric). */
    fun toNum(o: Any?): Double {
        if (o == null) return 0.0
        if (o is Boolean) return if (o) 1.0 else 0.0
        val d = num(o)
        if (d != null) return d
        if (o is String) {
            val t = o.trim()
            if (t.isEmpty()) return 0.0
            return if (NUMLIT.matches(t)) t.toDouble() else Double.NaN
        }
        if (o is List<*> && o.isEmpty()) return 0.0
        return Double.NaN
    }

    /** `to[k] = from[fk]` only when `from` has the member. */
    fun putIf(to: MutableMap<String, Any?>, k: String, from: Any?, fk: String) {
        if (has(from, fk)) to[k] = get(from, fk)
    }

    /** A property read on null / undefined throws in JavaScript; so does this. */
    fun <T> req(o: T?): T = o ?: throw IllegalArgumentException("cannot read a member of null")

    /** JavaScript `String(d)` of a number. */
    fun fmt(d: Double): String {
        if (d.isNaN()) return "NaN"
        if (d.isInfinite()) return if (d > 0) "Infinity" else "-Infinity"
        return Json.esNumber(if (d == 0.0) 0.0 else d)
    }

    /** `Number(o[k])`, NaN when the member is absent (undefined). */
    fun numOrNaN(o: Any?, k: String): Double = if (has(o, k)) toNum(get(o, k)) else Double.NaN
}
