package net.atlasauth.pca.actions.importers

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.TreeSet
import net.atlasauth.pca.actions.J
import net.atlasauth.pca.verifier.Json

/** Small JSON-tree helpers shared by the importers (values are Map / List / String / Boolean / Json.Num / null). */
@Suppress("UNCHECKED_CAST")
internal object Jx {
    fun m(o: Any?): MutableMap<String, Any?> = J.m(o)
    fun a(o: Any?): MutableList<Any?> = J.a(o)
    fun isMap(o: Any?): Boolean = o is Map<*, *>
    fun isList(o: Any?): Boolean = o is List<*>
    fun isStr(o: Any?): Boolean = o is String
    fun get(o: Any?, k: String): Any? = J.get(o, k)
    fun has(o: Any?, k: String): Boolean = J.has(o, k)
    fun num(o: Any?): Double? = J.num(o)
    fun isInt(o: Any?): Boolean = J.isInt(o)
    fun n(v: Long): Json.Num = J.n(v)
    fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> = J.obj(*kv)
    fun list(vararg xs: Any?): MutableList<Any?> = J.list(*xs)
    fun sortUniq(xs: Any?): MutableList<String> = J.sortUniq(xs)
    fun objs(xs: List<String>): MutableList<Any?> = J.objs(xs)
    fun stringify(v: Any?): String = J.stringify(v)
    fun sameJson(a: Any?, aPresent: Boolean, b: Any?, bPresent: Boolean): Boolean = J.sameJson(a, aPresent, b, bPresent)
    fun sameJsonMember(ma: Any?, mb: Any?, key: String): Boolean = J.sameJsonMember(ma, mb, key)
    fun jsStr(v: Any?): String = J.jsStr(v)
    fun jsSpace(c: Char): Boolean = J.jsSpace(c)
    fun jsTrim(s: String): String = J.jsTrim(s)

    // ---- additions for the importers ----

    /** `Number.isSafeInteger(v)` (so -0 counts). */
    fun isSafe(o: Any?): Boolean {
        val d = num(o)
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0
    }

    /** Marks an absent member (JavaScript `undefined`) where a present JSON null differs. */
    @JvmField val UNDEF: Any = Any()

    fun getU(o: Any?, k: String): Any? = if (o is Map<*, *> && o.containsKey(k)) o[k] else UNDEF

    /** JavaScript truthiness of a JSON value. */
    fun truthy(v: Any?): Boolean {
        if (v == null || v === UNDEF) return false
        if (v is Boolean) return v
        if (v is String) return v.isNotEmpty()
        val d = num(v)
        if (d != null) return !(d == 0.0 || d.isNaN())
        return true
    }

    /** UTF-8 bytes as TextEncoder writes them: a lone surrogate is U+FFFD. */
    fun utf8(s: String): ByteArray {
        val o = ByteArrayOutputStream(s.length + 8)
        var i = 0
        while (i < s.length) {
            var c = s[i].code
            if (Character.isHighSurrogate(c.toChar()) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { i++; c = Character.toCodePoint(c.toChar(), s[i]) }
            else if (c in 0xD800..0xDFFF) c = 0xFFFD
            if (c < 0x80) o.write(c)
            else if (c < 0x800) { o.write(0xC0 or (c shr 6)); o.write(0x80 or (c and 63)) }
            else if (c < 0x10000) { o.write(0xE0 or (c shr 12)); o.write(0x80 or ((c shr 6) and 63)); o.write(0x80 or (c and 63)) }
            else { o.write(0xF0 or (c shr 18)); o.write(0x80 or ((c shr 12) and 63)); o.write(0x80 or ((c shr 6) and 63)); o.write(0x80 or (c and 63)) }
            i++
        }
        return o.toByteArray()
    }

    fun u8(s: String): Int = utf8(s).size

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun isIndexKey(k: String): Boolean {
        if (k.isEmpty() || k.length > 10 || (k.length > 1 && k[0] == '0')) return false
        for (c in k) if (c < '0' || c > '9') return false
        return k.toLong() < 4294967295L
    }

    /** Object.keys order: integer-like keys ascending, then the rest in insertion order. */
    fun keys(m: Map<String, Any?>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) (if (isIndexKey(k)) idx else rest).add(k)
        idx.sortWith { x, y -> x.toLong().compareTo(y.toLong()) }
        idx.addAll(rest)
        return idx
    }

    /** `{...src}` into `dst`: an object copies its members, a string or array its indexed entries, anything else nothing. */
    fun spread(dst: MutableMap<String, Any?>, src: Any?) {
        if (src is Map<*, *>) dst.putAll(src as Map<String, Any?>)
        else if (src is String) { for (i in 0 until src.length) dst[i.toString()] = src[i].toString() }
        else if (src is List<*>) { for (i in 0 until src.size) dst[i.toString()] = src[i] }
    }

    /** `[...x]` of a value that is an array, a string (its code points) or null/absent (caller handles); anything else throws as the engine does. */
    fun spreadList(x: Any?): MutableList<Any?> {
        val out = ArrayList<Any?>()
        if (x is List<*>) out.addAll(x)
        else if (x is String) {
            var i = 0
            while (i < x.length) { val cp = x.codePointAt(i); out.add(String(Character.toChars(cp))); i += Character.charCount(cp) }
        } else throw IllegalArgumentException("not iterable")
        return out
    }

    /** decodeURIComponent; null when the engine would throw URIError. */
    fun decodeUriComponent(s: String): String? {
        val b = StringBuilder()
        val n = s.length
        var i = 0
        while (i < n) {
            val c = s[i]
            if (c != '%') { b.append(c); i++; continue }
            val b0 = hexByte(s, i)
            if (b0 < 0) return null
            i += 2
            if (b0 < 0x80) { b.append(b0.toChar()); i++; continue }
            val need: Int
            var cp: Int
            val min: Int
            if ((b0 and 0xE0) == 0xC0) { need = 1; cp = b0 and 0x1F; min = 0x80 }
            else if ((b0 and 0xF0) == 0xE0) { need = 2; cp = b0 and 0x0F; min = 0x800 }
            else if ((b0 and 0xF8) == 0xF0) { need = 3; cp = b0 and 0x07; min = 0x10000 }
            else return null
            for (k in 0 until need) {
                if (i + 1 >= n || s[i + 1] != '%') return null
                val bx = hexByte(s, i + 1)
                if (bx < 0 || (bx and 0xC0) != 0x80) return null
                cp = (cp shl 6) or (bx and 0x3F)
                i += 3
            }
            if (cp < min || cp > 0x10FFFF || (cp in 0xD800..0xDFFF)) return null
            b.appendCodePoint(cp)
            i++
        }
        return b.toString()
    }

    private fun hexByte(s: String, i: Int): Int {
        if (i + 2 >= s.length) return -1
        val h = Character.digit(s[i + 1], 16)
        val l = Character.digit(s[i + 2], 16)
        return if (h < 0 || l < 0 || s[i + 1].code > 0x7f || s[i + 2].code > 0x7f) -1 else h * 16 + l
    }
}
