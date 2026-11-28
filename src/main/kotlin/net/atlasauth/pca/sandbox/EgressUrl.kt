package net.atlasauth.pca.sandbox

import net.atlasauth.pca.verifier.Json

import java.math.BigInteger
import java.util.Locale

/**
 * The part of the WHATWG URL parser the egress target check needs: scheme, credentials, host, port, path and query of an absolute
 * URL. Hosts must be ASCII (a non-ASCII host is refused: fail closed). Returns null for a URL the parser rejects.
 */
internal object EgressUrl {
    class Parsed {
        var scheme: String = ""
        var credentials = false
        var hash = false
        var host = ""
        var port = -1
        var path = "/"
        var query = ""
    }

    private fun defaultPort(scheme: String): Int = when (scheme) {
        "http", "ws" -> 80
        "https", "wss" -> 443
        "ftp" -> 21
        else -> -1
    }

    private fun isAlpha(c: Char): Boolean = (c in 'a'..'z') || (c in 'A'..'Z')

    fun parse(input: String): Parsed? {
        var b = 0
        var e = input.length
        while (b < e && input[b].code <= 0x20) b++
        while (e > b && input[e - 1].code <= 0x20) e--
        val sb = StringBuilder()
        for (i in b until e) {
            val c = input[i]
            if (c != '\t' && c != '\n' && c != '\r') sb.append(c)
        }
        val s = sb.toString()
        var colon = -1
        if (s.isNotEmpty() && isAlpha(s[0])) {
            for (i in 1 until s.length) {
                val c = s[i]
                if (c == ':') { colon = i; break }
                if (!(isAlpha(c) || (c in '0'..'9') || c == '+' || c == '-' || c == '.')) return null
            }
        }
        if (colon < 0) return null
        val p = Parsed()
        p.scheme = s.substring(0, colon).lowercase(Locale.ROOT)
        val rest = s.substring(colon + 1)
        val special = defaultPort(p.scheme) >= 0 || p.scheme == "file"
        if (!special) {
            val h = rest.indexOf('#')
            p.hash = h >= 0 && h + 1 < rest.length
            return p // an opaque or hierarchical non-special URL: the caller refuses its scheme
        }
        if (p.scheme == "file") return p
        var i = 0
        while (i < rest.length && (rest[i] == '/' || rest[i] == '\\')) i++
        var end = i
        while (end < rest.length && "/\\?#".indexOf(rest[end]) < 0) end++
        val authority = rest.substring(i, end)
        val tail = rest.substring(end)
        var hostport = authority
        val at = authority.lastIndexOf('@')
        if (at >= 0) {
            val userinfo = authority.substring(0, at)
            val c = userinfo.indexOf(':')
            val user = if (c < 0) userinfo else userinfo.substring(0, c)
            val pass = if (c < 0) "" else userinfo.substring(c + 1)
            p.credentials = user.isNotEmpty() || pass.isNotEmpty()
            hostport = authority.substring(at + 1)
            if (hostport.isEmpty()) return null
        }
        val hostText: String
        var portText = ""
        if (hostport.startsWith("[")) {
            val close = hostport.indexOf(']')
            if (close < 0) return null
            hostText = hostport.substring(0, close + 1)
            val after = hostport.substring(close + 1)
            if (after.isNotEmpty()) {
                if (after[0] != ':') return null
                portText = after.substring(1)
            }
        } else {
            val c = hostport.indexOf(':')
            hostText = if (c < 0) hostport else hostport.substring(0, c)
            if (c >= 0) portText = hostport.substring(c + 1)
        }
        if (hostText.isEmpty()) return null
        if (portText.isNotEmpty()) {
            for (k in portText.indices) if (portText[k] < '0' || portText[k] > '9') return null
            val n = BigInteger(portText)
            if (n > BigInteger.valueOf(65535)) return null
            val v = n.toInt()
            p.port = if (v == defaultPort(p.scheme)) -1 else v
        }
        val host = (if (hostText.startsWith("[")) ipv6Host(hostText.substring(1, hostText.length - 1)) else domainHost(hostText)) ?: return null
        p.host = host

        val hashAt = tail.indexOf('#')
        val beforeHash = if (hashAt < 0) tail else tail.substring(0, hashAt)
        p.hash = hashAt >= 0 && hashAt + 1 < tail.length
        val q = beforeHash.indexOf('?')
        val pathPart = if (q < 0) beforeHash else beforeHash.substring(0, q)
        p.query = if (q < 0) "" else encode(beforeHash.substring(q + 1), true)
        p.path = path(pathPart)
        return p
    }

    // ---- path and query ----

    private fun path(raw: String): String {
        if (raw.isEmpty()) return "/"
        val parts = raw.replace('\\', '/').substring(1).split("/")
        val stack = ArrayList<String>()
        for (i in parts.indices) {
            val seg = parts[i]
            val l = seg.lowercase(Locale.ROOT)
            val last = i == parts.size - 1
            if (l == ".." || l == ".%2e" || l == "%2e." || l == "%2e%2e") {
                if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
                if (last) stack.add("")
            } else if (l == "." || l == "%2e") {
                if (last) stack.add("")
            } else stack.add(encode(seg, false))
        }
        return "/" + stack.joinToString("/")
    }

    /** Percent-encode with the path (or special-query) encode set: C0 controls, space, ", #, <, >, DEL and non-ASCII (UTF-8); path adds ? ^ ` { }; query adds '. */
    private fun encode(s: String, query: Boolean): String {
        val out = StringBuilder()
        for (raw in Json.utf8(s)) {
            val c = raw.toInt() and 0xff
            val enc = c <= 0x20 || c >= 0x7f || c == '"'.code || c == '#'.code || c == '<'.code || c == '>'.code ||
                (if (query) c == '\''.code else (c == '?'.code || c == '^'.code || c == '`'.code || c == '{'.code || c == '}'.code))
            if (enc) out.append('%').append(Character.toUpperCase(Character.forDigit(c shr 4, 16))).append(Character.toUpperCase(Character.forDigit(c and 15, 16)))
            else out.append(c.toChar())
        }
        return out.toString()
    }

    // ---- hosts ----

    private fun hex(c: Int): Int = when (c) {
        in '0'.code..'9'.code -> c - '0'.code
        in 'a'.code..'f'.code -> c - 'a'.code + 10
        in 'A'.code..'F'.code -> c - 'A'.code + 10
        else -> -1
    }

    private fun domainHost(text: String): String? {
        val src = Json.utf8(text)
        val d = StringBuilder()
        var i = 0
        while (i < src.size) {
            var c = src[i].toInt() and 0xff
            if (c == '%'.code && i + 2 < src.size && hex(src[i + 1].toInt() and 0xff) >= 0 && hex(src[i + 2].toInt() and 0xff) >= 0) {
                c = hex(src[i + 1].toInt() and 0xff) * 16 + hex(src[i + 2].toInt() and 0xff)
                i += 2
            }
            if (c >= 0x80) return null // non-ASCII host: not ported, refused
            d.append(c.toChar())
            i++
        }
        val domain = d.toString().lowercase(Locale.ROOT)
        if (domain.isEmpty()) return null
        for (ch in domain) if (ch.code <= 0x1f || ch.code == 0x7f || " #%/:<>?@[\\]^|".indexOf(ch) >= 0) return null
        if (endsInNumber(domain)) return ipv4Host(domain)
        return domain
    }

    private fun endsInNumber(domain: String): Boolean {
        val parts = ArrayList(domain.split("."))
        if (parts[parts.size - 1].isEmpty()) {
            if (parts.size == 1) return false
            parts.removeAt(parts.size - 1)
        }
        val last = parts[parts.size - 1]
        if (last.isNotEmpty() && last.all { it in '0'..'9' }) return true
        if (last.length >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X')) {
            for (i in 2 until last.length) if (hex(last[i].code) < 0) return false
            return true
        }
        return false
    }

    private fun ipv4Number(inp: String): BigInteger? {
        if (inp.isEmpty()) return null
        var radix = 10
        var s = inp
        if (s.length >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { s = s.substring(2); radix = 16 }
        else if (s.length >= 2 && s[0] == '0') { s = s.substring(1); radix = 8 }
        if (s.isEmpty()) return BigInteger.ZERO
        for (ch in s) {
            val h = hex(ch.code)
            if (h < 0 || h >= radix) return null
        }
        return BigInteger(s, radix)
    }

    private fun ipv4Host(domain: String): String? {
        val parts = ArrayList(domain.split("."))
        if (parts[parts.size - 1].isEmpty() && parts.size > 1) parts.removeAt(parts.size - 1)
        if (parts.size > 4) return null
        val nums = ArrayList<BigInteger>()
        for (p in parts) nums.add(ipv4Number(p) ?: return null)
        for (i in 0 until nums.size - 1) if (nums[i] > BigInteger.valueOf(255)) return null
        val last = nums[nums.size - 1]
        if (last >= BigInteger.valueOf(256).pow(5 - nums.size)) return null
        var ip = last
        for (i in 0 until nums.size - 1) ip = ip.add(nums[i].multiply(BigInteger.valueOf(256).pow(3 - i)))
        val v = ip.toLong()
        return "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"
    }

    /** Parse the text between the brackets and serialize it in the compressed lowercase form; null when invalid. */
    private fun ipv6Host(inp: String): String? {
        val a = IntArray(8)
        var piece = 0
        var compress = -1
        var p = 0
        val n = inp.length
        if (n > 0 && inp[0] == ':') {
            if (n < 2 || inp[1] != ':') return null
            p += 2
            piece++
            compress = piece
        }
        while (p < n) {
            if (piece == 8) return null
            if (inp[p] == ':') {
                if (compress != -1) return null
                p++
                piece++
                compress = piece
                continue
            }
            var value = 0
            var length = 0
            while (length < 4 && p < n && hex(inp[p].code) >= 0) {
                value = value * 16 + hex(inp[p].code)
                p++
                length++
            }
            if (p < n && inp[p] == '.') {
                if (length == 0) return null
                p -= length
                if (piece > 6) return null
                var seen = 0
                while (p < n) {
                    var v4 = -1
                    if (seen > 0) {
                        if (inp[p] == '.' && seen < 4) p++ else return null
                    }
                    if (p >= n || inp[p] < '0' || inp[p] > '9') return null
                    while (p < n && inp[p] >= '0' && inp[p] <= '9') {
                        val d = inp[p] - '0'
                        if (v4 == -1) v4 = d
                        else if (v4 == 0) return null
                        else v4 = v4 * 10 + d
                        if (v4 > 255) return null
                        p++
                    }
                    a[piece] = a[piece] * 0x100 + v4
                    seen++
                    if (seen == 2 || seen == 4) piece++
                }
                if (seen != 4) return null
                break
            } else if (p < n && inp[p] == ':') {
                p++
                if (p >= n) return null
            } else if (p < n) return null
            a[piece] = value
            piece++
        }
        if (compress != -1) {
            var swaps = piece - compress
            piece = 7
            while (piece != 0 && swaps > 0) {
                val t = a[compress + swaps - 1]
                a[compress + swaps - 1] = a[piece]
                a[piece] = t
                piece--
                swaps--
            }
        } else if (piece != 8) return null
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (a[i] != 0) { i++; continue }
            var j = i
            while (j < 8 && a[j] == 0) j++
            if (j - i > bestLen) { bestStart = i; bestLen = j - i }
            i = j
        }
        if (bestLen < 2) bestStart = -1
        val out = StringBuilder()
        var ignore0 = false
        for (k in 0 until 8) {
            if (ignore0 && a[k] == 0) continue
            ignore0 = false
            if (bestStart == k) {
                out.append(if (k == 0) "::" else ":")
                ignore0 = true
                continue
            }
            out.append(Integer.toHexString(a[k]))
            if (k != 7) out.append(':')
        }
        return out.toString()
    }
}
