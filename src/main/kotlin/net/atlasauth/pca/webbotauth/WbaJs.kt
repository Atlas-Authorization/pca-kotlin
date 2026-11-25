package net.atlasauth.pca.webbotauth

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.Locale
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import org.bouncycastle.util.encoders.Base64

/** JavaScript string / number / Buffer semantics the Web Bot Auth port needs. */
internal object WbaJs {
    /** A parse failure the reference raises as WebBotAuthParseError (its message is part of the verify reason). */
    class ParseError(message: String) : RuntimeException(message)

    /** JavaScript's whitespace + line terminator set (String.prototype.trim). */
    fun isWs(c: Char): Boolean =
        c == ' ' || c in '\u0009'..'\u000d' || c == ' ' || c == ' ' || c in ' '..' ' || c == ' ' || c == ' ' ||
            c == ' ' || c == ' ' || c == '　' || c == '﻿'

    fun trim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isWs(s[a])) a++
        while (b > a && isWs(s[b - 1])) b--
        return s.substring(a, b)
    }

    /** The number value of a parsed JSON number (NaN when it is not one). */
    fun number(o: Any?): Double = Js.num(o) ?: Double.NaN

    fun lower(s: String): String = s.lowercase(Locale.ROOT)

    fun def(m: Any?, k: String): Boolean = m is Map<*, *> && m.containsKey(k)

    fun get(m: Any?, k: String): Any? = if (m is Map<*, *>) m[k] else null

    /** Buffer.from(s, "base64"): standard and URL-safe alphabets, other characters skipped, decoding stops at the first "=", dangling bits dropped. */
    fun nodeBase64(s: String): ByteArray {
        val out = ByteArrayOutputStream()
        var acc = 0
        var bits = 0
        for (c in s) {
            if (c == '=') break
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '+', '-' -> 62
                '/', '_' -> 63
                else -> -1
            }
            if (v < 0) continue
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

    /** base64 (standard alphabet, padded). */
    fun b64(b: ByteArray): String = Base64.toBase64String(b)

    fun numStr(d: Double): String = AttestUtil.jsNumString(d)

    /** String(v) of a parameter value (String, Double or Boolean) or of undefined. */
    fun str(v: Any?): String = when (v) {
        null -> "undefined"
        is Double -> numStr(v)
        else -> v.toString()
    }

    /** String(v) of any parsed JSON value. */
    fun anyStr(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = Js.num(v)
        if (d != null) return numStr(d)
        if (v is List<*>) {
            val sb = StringBuilder()
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                if (x != null) sb.append(anyStr(x))
            }
            return sb.toString()
        }
        return "[object Object]"
    }

    /** An RFC 8941 sf-string: quoted, with backslash and double quote escaped. */
    fun sfString(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    fun sha(alg: String, b: ByteArray): ByteArray = MessageDigest.getInstance(alg).digest(b)

    /** RFC 7638 thumbprint of an Ed25519 public key given as its b64u `x`. */
    fun thumbprintOfX(x: String): String = Keys.b64u(sha("SHA-256", Json.utf8("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"$x\"}")))

    /** The PCA header value to its UTF-8 text: strict unpadded base64url of well-formed UTF-8, else null. */
    fun decodePcaHeader(value: String?): String? {
        if (value == null || value.isEmpty()) return null
        val raw = Pca.decodeB64uStrict(value, -1) ?: return null
        return try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
        } catch (e: CharacterCodingException) {
            null
        }
    }

    /** The authority end and credential check of a raw URL string, as WHATWG parsing sees it: true when the authority carries userinfo. */
    fun hasCredentials(noFrag: String): Boolean {
        val slashes = noFrag.indexOf("//")
        if (slashes < 0) return false
        var authEnd = noFrag.length
        for (k in slashes + 2 until noFrag.length) {
            val ch = noFrag[k]
            if (ch == '/' || ch == '\\' || ch == '?') { authEnd = k; break }
        }
        return noFrag.substring(slashes + 2, authEnd).indexOf('@') >= 0
    }
}
