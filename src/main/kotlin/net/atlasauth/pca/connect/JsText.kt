package net.atlasauth.pca.connect

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import net.atlasauth.pca.signals.JsV

/** JavaScript string helpers shared by the connection vault and the connector catalog (URI encoding, trim, regex-style splits, redaction). */
object JsText {
    /** encodeURIComponent: everything but A-Za-z0-9 and -_.!~*'() is percent-encoded as UTF-8; a lone surrogate throws (URIError). */
    fun encodeURIComponent(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            if (cp in 0xD800..0xDFFF) throw IllegalArgumentException("URI malformed")
            if ((cp >= 'A'.code && cp <= 'Z'.code) || (cp >= 'a'.code && cp <= 'z'.code) || (cp >= '0'.code && cp <= '9'.code) || (cp < 128 && "-_.!~*'()".indexOf(cp.toChar()) >= 0)) {
                sb.append(cp.toChar())
            } else {
                for (b in Json.utf8(String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", b.toInt() and 0xff))
            }
        }
        return sb.toString()
    }

    /** decodeURIComponent: throws IllegalArgumentException (URIError) on a malformed escape or a non-UTF-8 sequence. */
    fun decodeURIComponent(s: String): String {
        if (s.indexOf('%') < 0) return s
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 2 >= s.length) throw IllegalArgumentException("URI malformed")
                val h = hex(s[i + 1])
                val l = hex(s[i + 2])
                if (h < 0 || l < 0) throw IllegalArgumentException("URI malformed")
                out.write(h * 16 + l)
                i += 3
            } else {
                val cp = s.codePointAt(i)
                i += Character.charCount(cp)
                val b = Json.utf8(String(Character.toChars(cp)))
                out.write(b, 0, b.size)
            }
        }
        try {
            return Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(out.toByteArray())).toString()
        } catch (e: CharacterCodingException) {
            throw IllegalArgumentException("URI malformed")
        }
    }

    private fun hex(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /** key=value pairs joined with '&', each side through encodeURIComponent, in the map's order. */
    fun formEncode(params: Map<String, String>): String {
        val sb = StringBuilder()
        for ((k, v) in params) {
            if (sb.isNotEmpty()) sb.append('&')
            sb.append(encodeURIComponent(k)).append('=').append(encodeURIComponent(v))
        }
        return sb.toString()
    }

    /** String.prototype.trim (JavaScript whitespace and line terminators). */
    fun trim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && JsV.isSpace(s[a])) a++
        while (b > a && JsV.isSpace(s[b - 1])) b--
        return s.substring(a, b)
    }

    /** `s.split(/[\s]+/)` or `s.split(/[\s,]+/)` (JavaScript semantics: leading and trailing empty pieces are kept). */
    fun splitRuns(s: String, commaToo: Boolean): List<String> {
        val out = ArrayList<String>()
        var start = 0
        var i = 0
        val n = s.length
        while (i < n) {
            if (isSep(s[i], commaToo)) {
                var j = i
                while (j < n && isSep(s[j], commaToo)) j++
                out.add(s.substring(start, i))
                start = j
                i = j
            } else i++
        }
        out.add(s.substring(start))
        return out
    }

    private fun isSep(c: Char, commaToo: Boolean): Boolean = JsV.isSpace(c) || (commaToo && c == ',')

    /** True when [s] contains a JavaScript whitespace character or a comma (the regex /[\s,]/). */
    fun hasSpaceOrComma(s: String): Boolean = s.any { JsV.isSpace(it) || it == ',' }

    /** Replace every secret in [text] (split/join semantics) so an error message can never carry one. Null and empty secrets are skipped. */
    fun redact(text: String, secrets: List<String?>): String {
        var out = text
        for (s in secrets) if (s != null && s.isNotEmpty()) out = out.replace(s, "[redacted]")
        return out
    }

    /** `e.message` for an Error; the class name stands in when there is none. */
    fun errText(e: Throwable): String = e.message ?: e.toString()

    /** Base64url decode with the leniency of the JDK URL decoder (padding optional, trailing bits ignored); throws IllegalArgumentException on anything else. */
    fun b64uDecode(input: String): ByteArray {
        var s = input
        var pad = 0
        while (s.endsWith("=") && pad < 2) { s = s.substring(0, s.length - 1); pad++ }
        if (s.length % 4 == 1 || (pad > 0 && (s.length + pad) % 4 != 0)) throw IllegalArgumentException("bad base64url")
        val out = ByteArrayOutputStream()
        var acc = 0
        var bits = 0
        for (c in s) {
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '-' -> 62
                '_' -> 63
                else -> throw IllegalArgumentException("bad base64url")
            }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((acc shr bits) and 0xff)
                acc = acc and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }
}

/**
 * The URL members the WHATWG parser port does not expose (credentials and fragment), read from the raw text with the same
 * pre-processing (trim C0/space, drop tab and newlines). Only emptiness matters to the callers.
 */
object UrlBits {
    private fun clean(input: String): String {
        var a = 0
        var b = input.length
        while (a < b && input[a].code <= 0x20) a++
        while (b > a && input[b - 1].code <= 0x20) b--
        val sb = StringBuilder()
        for (i in a until b) {
            val c = input[i]
            if (c != '\t' && c != '\n' && c != '\r') sb.append(c)
        }
        return sb.toString()
    }

    /** True when `new URL(input).hash` is not the empty string (a '#' followed by at least one character). */
    fun hasFragment(input: String): Boolean {
        val s = clean(input)
        val h = s.indexOf('#')
        return h >= 0 && h + 1 < s.length
    }

    private fun special(s: String): Boolean {
        val c = s.indexOf(':')
        if (c < 0) return false
        return when (s.substring(0, c).lowercase(java.util.Locale.ROOT)) {
            "http", "https", "ftp", "ws", "wss" -> true
            else -> false
        }
    }

    /** True when the URL carries a non-empty username or password. */
    fun hasCredentials(input: String): Boolean {
        val s = clean(input)
        val c = s.indexOf(':')
        if (c < 0) return false
        val rest = s.substring(c + 1)
        val sp = special(s)
        var p = 0
        if (sp) { while (p < rest.length && (rest[p] == '/' || rest[p] == '\\')) p++ }
        else if (rest.startsWith("//")) p = 2
        else return false
        var e = rest.length
        for (k in p until rest.length) {
            val ch = rest[k]
            if (ch == '/' || ch == '?' || ch == '#' || (sp && ch == '\\')) { e = k; break }
        }
        val authority = rest.substring(p, e)
        val at = authority.lastIndexOf('@')
        if (at < 0) return false
        val userinfo = authority.substring(0, at)
        return !(userinfo.isEmpty() || userinfo == ":")
    }
}
