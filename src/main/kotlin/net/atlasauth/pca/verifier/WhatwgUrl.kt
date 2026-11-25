package net.atlasauth.pca.verifier

import java.util.Locale

/**
 * The slice of the WHATWG URL parser and serializer the QRNG HTTP source needs: special-scheme URLs (http, https, ftp, ws, wss) with
 * userinfo, host, port, dot-segment resolution, percent-encoding sets, a form-urlencoded query (`searchParams.set`) and a fragment.
 * Any other scheme parses as an opaque URL with an empty host (so the transport check refuses it).
 * shortcut: IPv6 literals are lower-cased but not compressed and numeric IPv4 shorthand is not normalised (127.1 stays 127.1, which the
 * loopback check then refuses: fail closed); upgrade when a caller needs those spellings.
 */
internal class WhatwgUrl private constructor(private val scheme: String, private val special: Boolean) {
    private var username = ""
    private var password = ""
    private var host = ""
    private var port = -1
    private var path = ""
    private var query: String? = null // raw, without '?'
    private var fragment: String? = null // without '#'

    fun protocol(): String = "$scheme:"

    /** True when the URL carries a username or a password. */
    fun hasCredentials(): Boolean = username.isNotEmpty() || password.isNotEmpty()
    fun isOpaque(): Boolean = !special

    /** The host without a port (IPv6 keeps its brackets). */
    fun hostname(): String = host

    /** The host plus a non-default port. */
    fun hostWithPort(): String = if (port < 0) host else "$host:$port"

    /** `searchParams.set(name, value)`: replaces the first pair with that name in place, drops later ones, else appends. */
    fun setParam(name: String, value: String) {
        val pairs = ArrayList<Array<String>>()
        query?.let { q ->
            for (part in q.split("&")) {
                if (part.isEmpty()) continue
                val eq = part.indexOf('=')
                val n = if (eq < 0) part else part.substring(0, eq)
                val v = if (eq < 0) "" else part.substring(eq + 1)
                pairs.add(arrayOf(formDecode(n), formDecode(v)))
            }
        }
        var found = false
        val next = ArrayList<Array<String>>()
        for (p in pairs) {
            if (p[0] == name) {
                if (!found) { found = true; next.add(arrayOf(name, value)) }
            } else next.add(p)
        }
        if (!found) next.add(arrayOf(name, value))
        query = next.joinToString("&") { formEncode(it[0]) + "=" + formEncode(it[1]) }
    }

    /** The serialized URL (`URL.href`). */
    fun href(): String {
        if (!special) return "$scheme:$path"
        val sb = StringBuilder(scheme).append("://")
        if (username.isNotEmpty() || password.isNotEmpty()) {
            sb.append(username)
            if (password.isNotEmpty()) sb.append(':').append(password)
            sb.append('@')
        }
        sb.append(hostWithPort()).append(path)
        query?.let { sb.append('?').append(it) }
        fragment?.let { sb.append('#').append(it) }
        return sb.toString()
    }

    companion object {
        private const val HEX = "0123456789ABCDEF"

        private fun defaultPort(s: String): Int = when (s) { "http", "ws" -> 80; "https", "wss" -> 443; "ftp" -> 21; else -> -1 }
        private fun bad() = IllegalArgumentException("Invalid URL")
        private fun isAlpha(c: Char) = (c in 'a'..'z') || (c in 'A'..'Z')

        /** Parses an absolute URL; throws IllegalArgumentException("Invalid URL") when it is not one. */
        fun parse(input: String): WhatwgUrl {
            var b = 0
            var e = input.length
            while (b < e && input[b].code <= 0x20) b++
            while (e > b && input[e - 1].code <= 0x20) e--
            val s = input.substring(b, e).replace("\t", "").replace("\n", "").replace("\r", "")
            val colon = s.indexOf(':')
            if (colon < 1 || !isAlpha(s[0])) throw bad()
            for (i in 1 until colon) {
                val c = s[i]
                if (!(isAlpha(c) || c in '0'..'9' || c == '+' || c == '-' || c == '.')) throw bad()
            }
            val scheme = s.substring(0, colon).lowercase(Locale.ROOT)
            var rest = s.substring(colon + 1)
            val special = defaultPort(scheme) >= 0
            val u = WhatwgUrl(scheme, special)
            if (!special) { u.path = rest; return u }

            val h = rest.indexOf('#')
            if (h >= 0) { u.fragment = encode(rest.substring(h + 1), FRAGMENT); rest = rest.substring(0, h) }
            val q = rest.indexOf('?')
            if (q >= 0) { u.query = encode(rest.substring(q + 1), QUERY_SPECIAL); rest = rest.substring(0, q) }
            var i = 0
            while (i < rest.length && (rest[i] == '/' || rest[i] == '\\')) i++
            rest = rest.substring(i)
            var slash = 0
            while (slash < rest.length && rest[slash] != '/' && rest[slash] != '\\') slash++
            var authority = rest.substring(0, slash)
            val rawPath = rest.substring(slash)

            val at = authority.lastIndexOf('@')
            if (at >= 0) {
                val ui = authority.substring(0, at)
                authority = authority.substring(at + 1)
                val pc = ui.indexOf(':')
                u.username = encode(if (pc < 0) ui else ui.substring(0, pc), USERINFO)
                u.password = if (pc < 0) "" else encode(ui.substring(pc + 1), USERINFO)
            }
            var hostText = authority
            var portText: String? = null
            val pcol = authority.lastIndexOf(':')
            if (pcol >= 0 && authority.indexOf(']', pcol) < 0) { hostText = authority.substring(0, pcol); portText = authority.substring(pcol + 1) }
            u.host = parseHost(hostText)
            if (!portText.isNullOrEmpty()) {
                if (portText.any { it !in '0'..'9' } || portText.length > 5) throw bad()
                val p = portText.toInt()
                if (p > 65535) throw bad()
                u.port = if (p == defaultPort(scheme)) -1 else p
            }
            u.path = normalizePath(rawPath)
            return u
        }

        private fun parseHost(text: String): String {
            if (text.startsWith("[")) {
                if (!text.endsWith("]") || text.length < 4) throw bad()
                val inner = text.substring(1, text.length - 1).lowercase(Locale.ROOT)
                if (inner.any { !(it in '0'..'9' || it in 'a'..'f' || it == ':' || it == '.') }) throw bad()
                return "[$inner]"
            }
            var h = String(percentDecode(text), Charsets.UTF_8)
            if (h.any { it.code > 0x7f }) {
                h = try { java.net.IDN.toASCII(h, java.net.IDN.ALLOW_UNASSIGNED) } catch (ex: IllegalArgumentException) { throw bad() }
            }
            h = h.lowercase(Locale.ROOT)
            if (h.isEmpty()) throw bad()
            if (h.any { it.code <= 0x20 || it.code == 0x7f || "#%/:<>?@[\\]^|".indexOf(it) >= 0 }) throw bad()
            return h
        }

        private fun normalizePath(raw: String): String {
            val p = raw.replace('\\', '/')
            val out = ArrayList<String>()
            val segs = if (p.isEmpty()) emptyList<String>() else p.substring(1).split("/")
            for ((i, seg) in segs.withIndex()) {
                val last = i == segs.size - 1
                val l = seg.lowercase(Locale.ROOT)
                val dot2 = l == ".." || l == ".%2e" || l == "%2e." || l == "%2e%2e"
                val dot1 = l == "." || l == "%2e"
                if (dot2) { if (out.isNotEmpty()) out.removeAt(out.size - 1); if (last) out.add("") }
                else if (dot1) { if (last) out.add("") }
                else out.add(encode(seg, PATH))
            }
            return "/" + out.joinToString("/")
        }

        // ---- percent-encode sets (a predicate over the byte value) ----
        private val FRAGMENT: (Int) -> Boolean = { b -> b <= 0x20 || b > 0x7e || b == '"'.code || b == '<'.code || b == '>'.code || b == '`'.code }
        private val QUERY_SPECIAL: (Int) -> Boolean = { b -> b <= 0x20 || b > 0x7e || b == '"'.code || b == '#'.code || b == '<'.code || b == '>'.code || b == '\''.code }
        private val PATH: (Int) -> Boolean = { b -> b <= 0x20 || b > 0x7e || b == '"'.code || b == '#'.code || b == '<'.code || b == '>'.code || b == '?'.code || b == '`'.code || b == '{'.code || b == '}'.code }
        private val USERINFO: (Int) -> Boolean = { b -> PATH(b) || b == '/'.code || b == ':'.code || b == ';'.code || b == '='.code || b == '@'.code || (b >= '['.code && b <= '^'.code) || b == '|'.code }

        private fun encode(s: String, set: (Int) -> Boolean): String {
            val sb = StringBuilder()
            for (x in s.toByteArray(Charsets.UTF_8)) {
                val b = x.toInt() and 0xff
                if (set(b)) sb.append('%').append(HEX[b shr 4]).append(HEX[b and 15]) else sb.append(b.toChar())
            }
            return sb.toString()
        }

        private fun hexv(c: Int): Int = when (c) {
            in '0'.code..'9'.code -> c - '0'.code
            in 'a'.code..'f'.code -> c - 'a'.code + 10
            in 'A'.code..'F'.code -> c - 'A'.code + 10
            else -> -1
        }

        private fun percentDecode(s: String): ByteArray {
            val inp = s.toByteArray(Charsets.UTF_8)
            val out = java.io.ByteArrayOutputStream()
            var i = 0
            while (i < inp.size) {
                val c = inp[i].toInt() and 0xff
                if (c == '%'.code && i + 2 < inp.size && hexv(inp[i + 1].toInt()) >= 0 && hexv(inp[i + 2].toInt()) >= 0) {
                    out.write(hexv(inp[i + 1].toInt()) * 16 + hexv(inp[i + 2].toInt()))
                    i += 2
                } else out.write(c)
                i++
            }
            return out.toByteArray()
        }

        private fun formDecode(s: String): String = String(percentDecode(s.replace('+', ' ')), Charsets.UTF_8)

        private fun formEncode(s: String): String {
            val sb = StringBuilder()
            for (x in s.toByteArray(Charsets.UTF_8)) {
                val b = x.toInt() and 0xff
                if ((b >= 'a'.code && b <= 'z'.code) || (b >= 'A'.code && b <= 'Z'.code) || (b >= '0'.code && b <= '9'.code) ||
                    b == '*'.code || b == '-'.code || b == '.'.code || b == '_'.code) sb.append(b.toChar())
                else if (b == ' '.code) sb.append('+')
                else sb.append('%').append(HEX[b shr 4]).append(HEX[b and 15])
            }
            return sb.toString()
        }
    }
}
