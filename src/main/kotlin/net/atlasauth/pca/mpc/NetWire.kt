package net.atlasauth.pca.mpc

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import net.atlasauth.pca.verifier.Json

/**
 * The wire layer of the networked MPC runner: the length-prefixed JSON frame codec with strict envelope validation, the canonical hex
 * field-element encoding, and the structured abort ([NetAbort]) that blames a party only when the evidence names one. Sockets, TLS and
 * the distributed protocol driver are not part of this object.
 */
object NetWire {
    /** Frame envelope version; a peer on another version is rejected as a version mismatch. */
    const val WIRE_VERSION = 2

    /** Largest frame body accepted or produced (4 MiB). */
    const val MAX_FRAME_BYTES = 4 * 1024 * 1024

    @JvmField val ABORT_KINDS: Set<String> = setOf(
        "timeout", "disconnect", "version", "malformed", "oversize", "duplicate", "out-of-order", "wrong-round",
        "wrong-session", "identity", "commitment", "ot-check", "mac-check", "dealer", "equivocation", "flood", "peer-abort", "local",
    )
    private val FRAME_TYPES = setOf("hello", "msg", "abort")

    /** A protocol abort; [blamed] is null when the evidence names no culprit (then [reason] explains why). */
    class NetAbort @JvmOverloads constructor(
        @JvmField val kind: String,
        @JvmField val blamed: Int?,
        @JvmField val reporter: Int,
        detail: String,
        @JvmField val claimedKind: String? = null,
        @JvmField val claimedBlame: Int? = null,
        reason: String? = null,
        @JvmField val evidence: Any? = null,
        @JvmField val deadlineMs: Int? = null,
    ) : RuntimeException("[$kind] blamed=${blamed?.toString() ?: "none"} reporter=$reporter: $detail") {
        @JvmField val reason: String? =
            if (blamed == null) (if (reason != null && reason.isNotEmpty()) reason else "unattributable: the evidence available to this party does not identify a culprit") else null
    }

    // ---- JSON text (JSON.stringify semantics for the value shapes the protocol uses) ----

    /** JSON text of a value with insertion-ordered maps and JavaScript string escaping. */
    @JvmStatic fun stringify(v: Any?): String {
        val sb = StringBuilder()
        write(sb, v)
        return sb.toString()
    }

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(v.toString())
            is String -> quote(sb, v)
            is Json.Num -> sb.append(Json.canonicalize(v))
            is Int, is Long, is Short -> sb.append(v.toString())
            is BigInteger -> sb.append(v.toString())
            is List<*> -> {
                sb.append('[')
                var first = true
                for (x in v) {
                    if (!first) sb.append(',')
                    first = false
                    write(sb, x)
                }
                sb.append(']')
            }
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, value) in v) {
                    if (!first) sb.append(',')
                    first = false
                    quote(sb, k as String)
                    sb.append(':')
                    write(sb, value)
                }
                sb.append('}')
            }
            else -> throw IllegalArgumentException("stringify: unsupported value " + v.javaClass.name)
        }
    }

    private fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c.code < 0x20 -> sb.append("\\u%04x".format(c.code))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                    sb.append(c).append(s[i + 1])
                    i++
                }
                Character.isSurrogate(c) -> sb.append("\\u%04x".format(c.code))
                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }

    /** A frame: {v, ty, sid, seq, rd, d}. Numbers are carried as parsed JSON values so they print as the sender wrote them. */
    class Frame(val v: Any?, val ty: String?, val sid: String?, val seq: Any?, val rd: String?, val d: Any?)

    /** Length-prefixed (4-byte big-endian) JSON frame; throws when the body exceeds MAX_FRAME_BYTES. */
    @JvmStatic fun encodeFrame(f: Frame): ByteArray {
        val m = LinkedHashMap<String, Any?>()
        m["v"] = f.v
        m["ty"] = f.ty
        m["sid"] = f.sid
        m["seq"] = f.seq
        m["rd"] = f.rd
        m["d"] = f.d
        val body = Json.utf8(stringify(m))
        require(body.size <= MAX_FRAME_BYTES) { "frame too large" }
        val out = ByteArray(4 + body.size)
        out[0] = (body.size ushr 24).toByte()
        out[1] = (body.size ushr 16).toByte()
        out[2] = (body.size ushr 8).toByte()
        out[3] = body.size.toByte()
        System.arraycopy(body, 0, out, 4, body.size)
        return out
    }

    /** Reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix throws. */
    class FrameSplitter {
        private val buf = ByteArrayOutputStream()
        private var data = ByteArray(0)

        fun push(chunk: ByteArray): List<ByteArray> {
            if (chunk.isNotEmpty()) {
                buf.write(chunk, 0, chunk.size)
                data = buf.toByteArray()
            }
            val out = ArrayList<ByteArray>()
            var off = 0
            while (true) {
                if (data.size - off < 4) break
                val len = ((data[off].toLong() and 0xffL) shl 24) or ((data[off + 1].toLong() and 0xffL) shl 16) or
                    ((data[off + 2].toLong() and 0xffL) shl 8) or (data[off + 3].toLong() and 0xffL)
                check(len <= MAX_FRAME_BYTES) { "oversize" }
                if ((data.size - off).toLong() < 4 + len) break
                val body = ByteArray(len.toInt())
                System.arraycopy(data, off + 4, body, 0, len.toInt())
                out.add(body)
                off += 4 + len.toInt()
            }
            if (off > 0) {
                val rest = ByteArray(data.size - off)
                System.arraycopy(data, off, rest, 0, rest.size)
                data = rest
                buf.reset()
                buf.write(rest, 0, rest.size)
            }
            return out
        }
    }

    // ---- envelope validation ----

    /** The JavaScript number value of a parsed JSON number (null for anything else). */
    private fun num(o: Any?): Double? {
        if (o is Json.Num) {
            return try {
                o.toString().toDouble()
            } catch (e: NumberFormatException) {
                null
            }
        }
        return null
    }

    private fun safeInt(d0: Double?): Boolean {
        val d: Double = d0 ?: return false
        return !d.isInfinite() && !d.isNaN() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0
    }

    private fun negZero(d: Double): Boolean = d == 0.0 && 1 / d < 0

    @Suppress("UNCHECKED_CAST")
    private fun parseObject(body: ByteArray): Map<String, Any?>? {
        val j: Any? = try {
            Json.parseLenient(String(body, Charsets.UTF_8))
        } catch (e: RuntimeException) {
            return null
        }
        return if (j is Map<*, *>) j as Map<String, Any?> else null
    }

    /** The envelope version of a body, or null when it is not a JSON object with a safe-integer v. */
    @JvmStatic fun peekVersion(body: ByteArray): Long? {
        val o = parseObject(body) ?: return null
        val v = num(o["v"])
        return if (v != null && safeInt(v) && !negZero(v)) v.toLong() else null
    }

    private fun envelopeShapeOk(o: Map<String, Any?>): Boolean {
        if (o.size != 6 || !o.containsKey("v")) return false
        val ty = o["ty"]
        if (ty !is String || !FRAME_TYPES.contains(ty)) return false
        if (o["sid"] !is String || o["rd"] !is String) return false
        val seq = num(o["seq"])
        if (seq == null || !safeInt(seq) || seq < 0 || negZero(seq)) return false
        return o.containsKey("d")
    }

    /** The frame as a map when it is a well-formed envelope of the current version, else null. */
    @JvmStatic fun parseFrame(body: ByteArray): Map<String, Any?>? {
        val o = parseObject(body) ?: return null
        val v = num(o["v"])
        if (v == null || v != WIRE_VERSION.toDouble() || !envelopeShapeOk(o)) return null
        return o
    }

    /** The peer's version when the body is a well-formed envelope of a DIFFERENT version, else null. */
    @JvmStatic fun versionMismatch(body: ByteArray): Long? {
        val o = parseObject(body) ?: return null
        val v = num(o["v"])
        if (v == null || !safeInt(v) || negZero(v) || v == WIRE_VERSION.toDouble()) return null
        return if (envelopeShapeOk(o)) v.toLong() else null
    }

    // ---- canonical field-element hex ----

    @JvmStatic fun hx(x: BigInteger): String = x.toString(16)

    private val HEX61 = Regex("^(0|[1-9a-f][0-9a-f]{0,15})$")

    /** Canonical lowercase hex without leading zeros of an element below the field prime; null otherwise. */
    @JvmStatic fun unhx(s: Any?): BigInteger? {
        if (s !is String || !HEX61.matches(s)) return null
        val v = BigInteger(s, 16)
        return if (v < Field.PRIME) v else null
    }

    @JvmStatic fun unhxArray(a: Any?, len: Int): Array<BigInteger>? {
        if (a !is List<*> || a.size != len) return null
        val out = ArrayList<BigInteger>()
        for (i in 0 until len) {
            val v = unhx(a[i]) ?: return null
            out.add(v)
        }
        return out.toTypedArray()
    }
}
