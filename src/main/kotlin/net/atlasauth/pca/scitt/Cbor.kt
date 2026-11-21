package net.atlasauth.pca.scitt

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Deterministic CBOR (RFC 8949 section 4.2.1 core deterministic encoding), the minimal profile sufficient for COSE_Sign1: unsigned and
 * negative integers (safe-integer range), byte strings, text strings, arrays, maps (keys sorted by their encoded bytes, no duplicates),
 * tags, and the booleans and null. Floats, other simple values and indefinite lengths are refused on decode, so a forged receipt that
 * uses them fails closed.
 *
 * Value model: [Long] (any Int/Short is accepted on encode), [String], [ByteArray], [Boolean], `null`, [List], [Map] (keys Long or
 * String; decode returns insertion-ordered maps) and [Tag]. Errors are [IllegalArgumentException].
 */
object Cbor {
    /** Largest integer a JavaScript number holds exactly: the profile's integer range is +-(2^53 - 1). */
    const val MAX_SAFE = 9007199254740991L

    /** A CBOR tagged value (major type 6), used for the COSE_Sign1 tag (18). */
    class Tag(@JvmField val tag: Long, @JvmField val value: Any?)

    private fun err(m: String) = IllegalArgumentException(m)

    private fun isWellFormed(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length || !Character.isLowSurrogate(s[i + 1])) return false
                i++
            } else if (Character.isLowSurrogate(c)) return false
            i++
        }
        return true
    }

    private fun head(o: ByteArrayOutputStream, major: Int, arg: Long) {
        val mt = major shl 5
        when {
            arg < 24 -> o.write(mt or arg.toInt())
            arg < 0x100 -> { o.write(mt or 24); o.write(arg.toInt()) }
            arg < 0x10000 -> { o.write(mt or 25); o.write((arg ushr 8).toInt() and 0xff); o.write(arg.toInt() and 0xff) }
            arg < 0x100000000L -> { o.write(mt or 26); var s = 24; while (s >= 0) { o.write((arg ushr s).toInt() and 0xff); s -= 8 } }
            else -> { o.write(mt or 27); var s = 56; while (s >= 0) { o.write((arg ushr s).toInt() and 0xff); s -= 8 } }
        }
    }

    /** An integer value of the model as a long within the safe range, or an error (a non-integral or unsafe number). */
    private fun intOf(v: Any?, what: String): Long {
        val n: Long = when {
            v is Long || v is Int || v is Short -> (v as Number).toLong()
            v is Double && v == Math.rint(v) && !v.isInfinite() && Math.abs(v) <= MAX_SAFE && !(v == 0.0 && 1 / v < 0) -> v.toLong()
            else -> throw err(what)
        }
        if (n > MAX_SAFE || n < -MAX_SAFE) throw err(what)
        return n
    }

    private fun encodeInt(o: ByteArrayOutputStream, n: Long) { if (n >= 0) head(o, 0, n) else head(o, 1, -1 - n) }

    private fun encodeText(o: ByteArrayOutputStream, s: String) {
        if (!isWellFormed(s)) throw err("cbor: text string contains a lone surrogate")
        val b = Json.utf8(s)
        head(o, 3, b.size.toLong())
        o.write(b, 0, b.size)
    }

    private fun encodeKey(k: Any?): ByteArray {
        val o = ByteArrayOutputStream()
        when (k) {
            is Number -> encodeInt(o, intOf(k, "cbor: bad integer map key"))
            is String -> encodeText(o, k)
            else -> throw err("cbor: bad map key")
        }
        return o.toByteArray()
    }

    /** Unsigned lexicographic comparison of two byte arrays. */
    internal fun cmp(a: ByteArray, b: ByteArray): Int {
        val n = Math.min(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    /** Deterministically encode a CBOR value. Throws on anything outside the supported profile. */
    @JvmStatic
    fun encode(v: Any?): ByteArray = ByteArrayOutputStream().also { enc(it, v) }.toByteArray()

    private fun enc(o: ByteArrayOutputStream, v: Any?) {
        when (v) {
            null -> o.write(0xf6)
            is Boolean -> o.write(if (v) 0xf5 else 0xf4)
            is Number -> encodeInt(o, intOf(v, "cbor: only safe-integer numbers are supported"))
            is String -> encodeText(o, v)
            is ByteArray -> { head(o, 2, v.size.toLong()); o.write(v, 0, v.size) }
            is List<*> -> {
                val body = ByteArrayOutputStream()
                for (x in v) enc(body, x)
                head(o, 4, v.size.toLong())
                val bb = body.toByteArray()
                o.write(bb, 0, bb.size)
            }
            is Map<*, *> -> {
                val entries = v.entries.map { arrayOf(encodeKey(it.key), encode(it.value)) }.sortedWith(Comparator { x, y -> cmp(x[0], y[0]) })
                for (i in 1 until entries.size) if (cmp(entries[i - 1][0], entries[i][0]) == 0) throw err("cbor: duplicate map key")
                head(o, 5, v.size.toLong())
                for (e in entries) { o.write(e[0], 0, e[0].size); o.write(e[1], 0, e[1].size) }
            }
            is Tag -> {
                if (v.tag < 0 || v.tag > MAX_SAFE) throw err("cbor: bad tag")
                head(o, 6, v.tag)
                enc(o, v.value)
            }
            else -> throw err("cbor: unsupported value")
        }
    }

    private class Reader(val buf: ByteArray) {
        var pos = 0

        fun octet(): Int {
            if (pos >= buf.size) throw err("cbor: unexpected end of input")
            return buf[pos++].toInt() and 0xff
        }

        fun bytes(n: Long): ByteArray {
            if (n > buf.size - pos) throw err("cbor: unexpected end of input")
            val out = buf.copyOfRange(pos, pos + n.toInt())
            pos += n.toInt()
            return out
        }

        fun readUint(n: Int): Long {
            var v = 0L
            for (i in 0 until n) v = (v shl 8) or octet().toLong()
            if (v < 0 || v > MAX_SAFE) throw err("cbor: integer out of safe range")
            return v
        }

        /** {major, argument}. */
        fun readHead(): LongArray {
            val ib = octet()
            val major = ib shr 5
            val info = ib and 0x1f
            if (major == 7 && info >= 24) throw err("cbor: unsupported simple/float value")
            if (info < 24) return longArrayOf(major.toLong(), info.toLong())
            val arg: Long = when (info) {
                24 -> readUint(1).also { if (it < 24) throw err("cbor: non-minimal integer") }
                25 -> readUint(2).also { if (it < 0x100) throw err("cbor: non-minimal integer") }
                26 -> readUint(4).also { if (it < 0x10000) throw err("cbor: non-minimal integer") }
                27 -> readUint(8).also { if (it < 0x100000000L) throw err("cbor: non-minimal integer") }
                else -> throw err("cbor: unsupported additional information (indefinite/reserved)")
            }
            return longArrayOf(major.toLong(), arg)
        }

        fun value(): Any? {
            val h = readHead()
            val arg = h[1]
            return when (h[0].toInt()) {
                0 -> arg
                1 -> {
                    if (arg >= MAX_SAFE) throw err("cbor: integer out of safe range") // -1 - arg would fall below -(2^53 - 1)
                    -1 - arg
                }
                2 -> bytes(arg)
                3 -> {
                    val b = bytes(arg)
                    try {
                        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString()
                    } catch (e: CharacterCodingException) {
                        throw err("The encoded data was not valid for encoding utf-8")
                    }
                }
                4 -> {
                    val out = ArrayList<Any?>()
                    var i = 0L
                    while (i < arg) { out.add(value()); i++ }
                    out
                }
                5 -> {
                    val map = LinkedHashMap<Any?, Any?>()
                    var prev: ByteArray? = null
                    var i = 0L
                    while (i < arg) {
                        val keyStart = pos
                        val key = value()
                        if (key !is Long && key !is String) throw err("cbor: map key must be int or text")
                        val keyBytes = buf.copyOfRange(keyStart, pos)
                        if (prev != null && cmp(prev, keyBytes) >= 0) throw err("cbor: map keys not canonically ordered / duplicate")
                        prev = keyBytes
                        map[key] = value()
                        i++
                    }
                    map
                }
                6 -> Tag(arg, value())
                7 -> when (arg) {
                    20L -> false
                    21L -> true
                    22L -> null
                    else -> throw err("cbor: unsupported simple/float value")
                }
                else -> throw err("cbor: unsupported major type")
            }
        }
    }

    /** Strictly decode a single canonical CBOR value, requiring the whole buffer to be consumed. */
    @JvmStatic
    fun decode(bytes: ByteArray): Any? {
        val r = Reader(bytes)
        val v = try { r.value() } catch (e: StackOverflowError) { throw err("Maximum call stack size exceeded") }
        if (r.pos != bytes.size) throw err("cbor: trailing bytes")
        return v
    }
}
