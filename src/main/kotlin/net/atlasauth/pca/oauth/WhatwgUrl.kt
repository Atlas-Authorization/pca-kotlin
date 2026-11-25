package net.atlasauth.pca.oauth

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.Locale
import net.atlasauth.pca.jose.Uts46

/**
 * The part of the WHATWG URL parser the protocol bridges read (`new URL(s)`: protocol, origin, pathname, search) for absolute URLs
 * without a base. Special schemes (http, https, ftp, ws, wss) get the full authority, host (domain, IPv4, IPv6), port and path
 * handling; file and non-special schemes only validate the scheme (and a non-special authority's host characters).
 * Non-ASCII hosts go through UTS 46 (ICU4J), as the standard's domain to ASCII does.
 */
class WhatwgUrl private constructor(
    /** e.g. "https:". */
    val protocol: String,
    /** Serialized host ("" for file and non-special schemes). */
    val host: String,
    /** Port digits, "" when absent or the scheme default. */
    val port: String,
    val pathname: String,
    /** "" or "?" + query. */
    val search: String,
    private val special: Boolean,
) {
    /** scheme://host[:port] for a special scheme (not file); "null" otherwise. */
    fun origin(): String = if (special) protocol + "//" + host + (if (port.isEmpty()) "" else ":$port") else "null"

    companion object {
        private fun defaultPort(scheme: String): Int = when (scheme) {
            "http", "ws" -> 80
            "https", "wss" -> 443
            "ftp" -> 21
            else -> -1
        }

        private fun isAlpha(c: Char) = c in 'a'..'z' || c in 'A'..'Z'
        private fun isDigit(c: Char) = c in '0'..'9'

        /** The parsed URL, or null where `new URL()` would throw. */
        fun parse(input: String): WhatwgUrl? {
            var a = 0
            var b = input.length
            while (a < b && input[a] <= ' ') a++
            while (b > a && input[b - 1] <= ' ') b--
            val s = input.substring(a, b).filter { it != '\t' && it != '\n' && it != '\r' }
            if (s.isEmpty() || !isAlpha(s[0])) return null
            var i = 1
            while (i < s.length && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '+' || s[i] == '-' || s[i] == '.')) i++
            if (i >= s.length || s[i] != ':') return null
            val scheme = s.substring(0, i).lowercase(Locale.ROOT)
            val rest = s.substring(i + 1)
            val proto = "$scheme:"
            if (scheme == "file") return WhatwgUrl(proto, "", "", "", "", false)
            val dport = defaultPort(scheme)
            if (dport < 0) { // non-special: only an authority's host characters can fail
                if (rest.startsWith("//")) {
                    var e = rest.length
                    for (k in 2 until rest.length) if (rest[k] == '/' || rest[k] == '?' || rest[k] == '#') { e = k; break }
                    val auth = rest.substring(2, e)
                    val hp = auth.substring(auth.lastIndexOf('@') + 1)
                    val h = if (hp.startsWith("[")) hp else if (hp.contains(':')) hp.substring(0, hp.indexOf(':')) else hp
                    if (!h.startsWith("[") && h.any { forbiddenHost(it) }) return null
                }
                return WhatwgUrl(proto, "", "", "", "", false)
            }
            var p = 0
            while (p < rest.length && (rest[p] == '/' || rest[p] == '\\')) p++
            var e = rest.length
            for (k in p until rest.length) { val c = rest[k]; if (c == '/' || c == '\\' || c == '?' || c == '#') { e = k; break } }
            val authority = rest.substring(p, e)
            val at = authority.lastIndexOf('@')
            var hostport = authority
            if (at >= 0) {
                hostport = authority.substring(at + 1)
                if (hostport.isEmpty()) return null
            }
            val hostStr: String
            var portStr = ""
            if (hostport.startsWith("[")) {
                val close = hostport.indexOf(']')
                if (close < 0) return null
                hostStr = hostport.substring(0, close + 1)
                val after = hostport.substring(close + 1)
                if (after.isNotEmpty()) {
                    if (after[0] != ':') return null
                    portStr = after.substring(1)
                }
            } else {
                val colon = hostport.indexOf(':')
                hostStr = if (colon < 0) hostport else hostport.substring(0, colon)
                if (colon >= 0) portStr = hostport.substring(colon + 1)
            }
            var port = ""
            if (portStr.isNotEmpty()) {
                if (!portStr.all { isDigit(it) }) return null
                val pv = BigInteger(portStr)
                if (pv > BigInteger.valueOf(65535)) return null
                port = if (pv.toInt() == dport) "" else pv.toString()
            }
            if (hostStr.isEmpty()) return null
            val host = parseHost(hostStr) ?: return null

            var tail = rest.substring(e)
            val hash = tail.indexOf('#')
            if (hash >= 0) tail = tail.substring(0, hash)
            var pathStr = tail
            var query: String? = null
            val q = tail.indexOf('?')
            if (q >= 0) { pathStr = tail.substring(0, q); query = tail.substring(q + 1) }
            val search = if (query.isNullOrEmpty()) "" else "?" + encode(query, true)
            return WhatwgUrl(proto, host, port, parsePath(pathStr), search, true)
        }

        private fun isDoubleDot(s: String) = s.lowercase(Locale.ROOT) in setOf("..", ".%2e", "%2e.", "%2e%2e")
        private fun isSingleDot(s: String) = s.lowercase(Locale.ROOT) in setOf(".", "%2e")

        private fun parsePath(pathStr: String): String {
            val t = if (pathStr.isNotEmpty() && (pathStr[0] == '/' || pathStr[0] == '\\')) pathStr.substring(1) else pathStr
            val segs = ArrayList<String>()
            var start = 0
            while (true) {
                var end = t.length
                var more = false
                for (k in start until t.length) if (t[k] == '/' || t[k] == '\\') { end = k; more = true; break }
                val seg = t.substring(start, end)
                when {
                    isDoubleDot(seg) -> { if (segs.isNotEmpty()) segs.removeAt(segs.size - 1); if (!more) segs.add("") }
                    isSingleDot(seg) -> if (!more) segs.add("")
                    else -> segs.add(encode(seg, false))
                }
                if (!more) break
                start = end + 1
            }
            return "/" + segs.joinToString("/")
        }

        /** Percent-encode with the path (query=false) or special-query (query=true) set; a lone surrogate becomes U+FFFD. */
        private fun encode(s: String, query: Boolean): String {
            val sb = StringBuilder()
            var i = 0
            while (i < s.length) {
                var cp = s.codePointAt(i)
                i += Character.charCount(cp)
                if (cp in 0xD800..0xDFFF) cp = 0xFFFD
                val enc = when {
                    cp > 0x7e -> true
                    cp <= 0x20 || cp == 0x7f || cp == '"'.code || cp == '#'.code || cp == '<'.code || cp == '>'.code -> true
                    query -> cp == '\''.code
                    else -> cp == '?'.code || cp == '`'.code || cp == '{'.code || cp == '}'.code
                }
                if (!enc) { sb.append(cp.toChar()); continue }
                for (by in Json.utf8(String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", by.toInt() and 0xff))
            }
            return sb.toString()
        }

        private fun forbiddenHost(c: Char): Boolean =
            c <= ' ' || c == '\u007f' || c == '#' || c == '/' || c == ':' || c == '<' || c == '>' || c == '?' || c == '@' || c == '[' ||
                c == '\\' || c == ']' || c == '^' || c == '|'

        private fun forbiddenDomain(c: Char) = forbiddenHost(c) || c == '%'

        private fun parseHost(h: String): String? {
            if (h.startsWith("[")) {
                if (!h.endsWith("]")) return null
                return parseIpv6(h.substring(1, h.length - 1))?.let { "[" + serializeIpv6(it) + "]" }
            }
            val domain = percentDecode(h)
            val ad = if (!Uts46.needed(domain)) domain.lowercase(Locale.ROOT) else (Uts46.toAscii(domain) ?: return null).lowercase(Locale.ROOT)
            if (ad.isEmpty() || ad.any { forbiddenDomain(it) }) return null
            return if (endsInNumber(ad)) parseIpv4(ad) else ad
        }

        private fun percentDecode(s: String): String {
            val inp = Json.utf8(s)
            val out = ByteArrayOutputStream()
            var i = 0
            while (i < inp.size) {
                if (inp[i] == '%'.code.toByte() && i + 2 < inp.size && hex(inp[i + 1].toInt()) >= 0 && hex(inp[i + 2].toInt()) >= 0) {
                    out.write(hex(inp[i + 1].toInt()) * 16 + hex(inp[i + 2].toInt()))
                    i += 3
                } else {
                    out.write(inp[i].toInt())
                    i++
                }
            }
            return String(out.toByteArray(), StandardCharsets.UTF_8)
        }

        private fun hex(c: Int): Int = when (c) {
            in '0'.code..'9'.code -> c - '0'.code
            in 'a'.code..'f'.code -> c - 'a'.code + 10
            in 'A'.code..'F'.code -> c - 'A'.code + 10
            else -> -1
        }

        // ---- IPv4 ----

        private fun parseIpv4Number(inp: String): BigInteger? {
            if (inp.isEmpty()) return null
            var radix = 10
            var t = inp
            if (t.length >= 2 && (t.startsWith("0x") || t.startsWith("0X"))) { t = t.substring(2); radix = 16 }
            else if (t.length >= 2 && t[0] == '0') { t = t.substring(1); radix = 8 }
            if (t.isEmpty()) return BigInteger.ZERO
            if (t.any { val d = hex(it.code); d < 0 || d >= radix }) return null
            return BigInteger(t, radix)
        }

        private fun endsInNumber(s: String): Boolean {
            val parts = s.split('.').toMutableList()
            if (parts.last().isEmpty()) {
                if (parts.size == 1) return false
                parts.removeAt(parts.size - 1)
            }
            val last = parts.last()
            if (last.isNotEmpty() && last.all { isDigit(it) }) return true
            return parseIpv4Number(last) != null
        }

        private fun parseIpv4(s: String): String? {
            val parts = s.split('.').toMutableList()
            if (parts.last().isEmpty() && parts.size > 1) parts.removeAt(parts.size - 1)
            if (parts.size > 4) return null
            val nums = parts.map { parseIpv4Number(it) ?: return null }
            val b255 = BigInteger.valueOf(255)
            for (k in 0 until nums.size - 1) if (nums[k] > b255) return null
            val b256 = BigInteger.valueOf(256)
            if (nums.last() >= b256.pow(5 - nums.size)) return null
            var ip = nums.last()
            for (k in 0 until nums.size - 1) ip = ip.add(nums[k].multiply(b256.pow(3 - k)))
            val v = ip.toLong()
            return "${(v shr 24) and 0xff}.${(v shr 16) and 0xff}.${(v shr 8) and 0xff}.${v and 0xff}"
        }

        // ---- IPv6 ----

        private fun parseIpv6(inp: String): IntArray? {
            val pieces = IntArray(8)
            var idx = 0
            var compress = -1
            var p = 0
            val n = inp.length
            if (p < n && inp[p] == ':') {
                if (!(p + 1 < n && inp[p + 1] == ':')) return null
                p += 2
                idx++
                compress = idx
            }
            while (p < n) {
                if (idx == 8) return null
                if (inp[p] == ':') {
                    if (compress != -1) return null
                    p++
                    idx++
                    compress = idx
                    continue
                }
                var value = 0
                var len = 0
                while (len < 4 && p < n && hex(inp[p].code) >= 0) { value = value * 16 + hex(inp[p].code); p++; len++ }
                if (p < n && inp[p] == '.') {
                    if (len == 0) return null
                    p -= len
                    if (idx > 6) return null
                    var seen = 0
                    while (p < n) {
                        var v4 = -1
                        if (seen > 0) {
                            if (inp[p] == '.' && seen < 4) p++ else return null
                        }
                        if (p >= n || !isDigit(inp[p])) return null
                        while (p < n && isDigit(inp[p])) {
                            val num = inp[p] - '0'
                            v4 = when (v4) { -1 -> num; 0 -> return null; else -> v4 * 10 + num }
                            if (v4 > 255) return null
                            p++
                        }
                        pieces[idx] = pieces[idx] * 0x100 + v4
                        seen++
                        if (seen == 2 || seen == 4) idx++
                    }
                    if (seen != 4) return null
                    break
                } else if (p < n && inp[p] == ':') {
                    p++
                    if (p >= n) return null
                } else if (p < n) return null
                pieces[idx] = value
                idx++
            }
            if (compress != -1) {
                var swaps = idx - compress
                idx = 7
                while (idx != 0 && swaps > 0) {
                    val t = pieces[compress + swaps - 1]
                    pieces[compress + swaps - 1] = pieces[idx]
                    pieces[idx] = t
                    idx--
                    swaps--
                }
            } else if (idx != 8) return null
            return pieces
        }

        private fun serializeIpv6(a: IntArray): String {
            var best = -1
            var bestLen = 0
            var i = 0
            while (i < 8) {
                if (a[i] != 0) { i++; continue }
                var j = i
                while (j < 8 && a[j] == 0) j++
                if (j - i > bestLen) { best = i; bestLen = j - i }
                i = j
            }
            if (bestLen < 2) best = -1
            val sb = StringBuilder()
            var ignore0 = false
            for (k in 0 until 8) {
                if (ignore0 && a[k] == 0) continue
                ignore0 = false
                if (best == k) {
                    sb.append(if (k == 0) "::" else ":")
                    ignore0 = true
                    continue
                }
                sb.append(Integer.toHexString(a[k]))
                if (k != 7) sb.append(':')
            }
            return sb.toString()
        }
    }
}
