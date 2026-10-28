package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

/**
 * Compact-JWS plumbing shared by the Azure MAA and Google Confidential Space verifiers: the canonical base64url gate, the parsed
 * token and the signature checks (ES256 and RS256) under a certificate or JWK key; and the wording of the reference's
 * `JSON.parse` failures (the token verifiers embed the engine's message for a malformed segment into their reason).
 */
internal object AttestJws {
    private val B64U = Regex("[A-Za-z0-9_-]*")

    /** Decodes one strictly canonical unpadded base64url segment (one spelling per value). */
    fun decodeCanonicalBase64url(seg: String): ByteArray {
        if (!B64U.matches(seg)) throw AttErr("non-canonical compact JWS: bad-character")
        if (seg.length % 4 == 1) throw AttErr("non-canonical compact JWS: non-canonical-base64url (impossible length)")
        val b = try {
            Base64.getUrlDecoder().decode(seg)
        } catch (e: IllegalArgumentException) {
            throw AttErr("non-canonical compact JWS: non-canonical-base64url")
        }
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(b) != seg) throw AttErr("non-canonical compact JWS: non-canonical-base64url")
        return b
    }

    class Parsed(
        val alg: String, val kid: String, val hasKid: Boolean, val x5c: List<String>, val hasX5c: Boolean,
        val payload: Map<String, Any?>, val signingInput: ByteArray, val signature: ByteArray,
    )

    /** Parses a compact JWS into header fields, payload and signing input; it verifies nothing. `prefix` is the reference parser's name. */
    fun parseJwt(token: String, prefix: String): Parsed {
        if (token.isEmpty()) throw AttErr("$prefix: empty token")
        val parts = token.split(".")
        if (parts.size != 3) throw AttErr("$prefix: a compact JWS has exactly three dot-separated parts")
        val h = parts[0]
        val p = parts[1]
        val s = parts[2]
        if (h.isEmpty() || p.isEmpty() || s.isEmpty()) throw AttErr("$prefix: empty JWS segment")
        var headerObj: Any? = null
        var payloadObj: Any? = null
        var err: Exception? = null
        try {
            headerObj = AttestUtil.jsonLenient(decodeCanonicalBase64url(h))
            payloadObj = AttestUtil.jsonLenient(decodeCanonicalBase64url(p))
        } catch (e: AttErr) {
            err = e
        } catch (e: IllegalArgumentException) {
            err = e
        }
        if (err != null) throw AttErr("$prefix: malformed JSON segment: ${jsonSegmentError(h, p, err)}")
        val hdr = AttestUtil.rec(headerObj) ?: throw AttErr("$prefix: header is not a JSON object")
        val payload = AttestUtil.rec(payloadObj) ?: throw AttErr("$prefix: payload is not a JSON object")
        val alg = hdr["alg"] as? String ?: ""
        if (alg.isEmpty()) throw AttErr("$prefix: header has no alg")
        val kid = hdr["kid"] as? String
        val x5c = AttestUtil.asStrList(hdr["x5c"])
        val sig = try {
            decodeCanonicalBase64url(s)
        } catch (e: AttErr) {
            throw AttErr("$prefix: malformed signature segment: ${e.message}")
        }
        return Parsed(alg, kid ?: "", kid != null, x5c ?: emptyList(), x5c != null, payload, (h + "." + p).toByteArray(Charsets.UTF_8), sig)
    }

    /** The kty / crv of a key's JWK export (`undefined` for a key type without a curve). */
    fun jwkKtyCrv(k: AttestCert.CertKey): Pair<String, String> {
        val pub = k.pub
        if (pub is ECPublicKey) return Pair("EC", AttestCert.goCurveName(k))
        if (pub is RSAPublicKey) return Pair("RSA", "undefined")
        if (k.typ == "ed25519") return Pair("OKP", "Ed25519")
        return Pair(k.typ, "undefined")
    }

    /** A raw `r || s` ES256 signature over the signing input under a P-256 key. */
    fun es256Ok(sig: ByteArray, input: ByteArray, k: AttestCert.CertKey): Boolean {
        val pk = k.pub as? ECPublicKey ?: return false
        if (AttestCert.goCurveName(k) != "P-256" || sig.size != 64) return false
        return AttestUtil.verifyRawEcdsa(pk, AttestUtil.sha256(input), sig)
    }

    /** An RSASSA-PKCS1-v1_5 / SHA-256 signature under an RSA key. */
    fun rs256Ok(sig: ByteArray, input: ByteArray, k: AttestCert.CertKey): Boolean {
        val pk = k.pub as? RSAPublicKey ?: return false
        return try {
            val s = java.security.Signature.getInstance("SHA256withRSA")
            s.initVerify(pk)
            s.update(input)
            s.verify(sig)
        } catch (e: java.security.GeneralSecurityException) {
            false
        }
    }

    /** A public RSA key from base64url `n` / `e`. */
    fun jwkRsaKey(n: String, e: String): AttestCert.CertKey {
        val nb = AttestUtil.nodeB64(n)
        val eb = AttestUtil.nodeB64(e)
        if (nb.isEmpty() || eb.isEmpty()) throw AttErr(AttestCert.OSSL_UNSUPPORTED)
        val ev = BigInteger(1, eb)
        if (ev.bitLength() > 31 || ev.toLong() < 3) throw AttErr(AttestCert.OSSL_UNSUPPORTED)
        val pub = try {
            KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(BigInteger(1, nb), ev)) as RSAPublicKey
        } catch (x: java.security.GeneralSecurityException) {
            throw AttErr(AttestCert.OSSL_UNSUPPORTED)
        }
        return AttestCert.keyInfoOf(pub, pub.encoded)
    }

    /** A public EC key from crv / x / y (on-curve points only). */
    fun jwkEcKey(crv: String, x: String, y: String): AttestCert.CertKey {
        val name = when (crv) {
            "P-256" -> "secp256r1"
            "P-384" -> "secp384r1"
            "P-521" -> "secp521r1"
            else -> throw AttErr(AttestCert.OSSL_UNSUPPORTED)
        }
        val params = AttestUtil.curveParams(name) ?: throw AttErr(AttestCert.OSSL_UNSUPPORTED)
        val xv = BigInteger(1, AttestUtil.nodeB64(x))
        val yv = BigInteger(1, AttestUtil.nodeB64(y))
        if (!AttestUtil.onCurve(params, xv, yv)) throw AttErr(AttestCert.OSSL_UNSUPPORTED)
        val pub = try {
            AttestUtil.ecKeyOf(ECPublicKeySpec(ECPoint(xv, yv), params)) as ECPublicKey
        } catch (e: java.security.GeneralSecurityException) {
            throw AttErr(AttestCert.OSSL_UNSUPPORTED)
        }
        return AttestCert.keyInfoOf(pub, pub.encoded)
    }

    /**
     * The message to report for a header or payload segment that did not decode or parse: the canonical-form message of the
     * base64url gate, else the engine's `JSON.parse` wording of the segment that failed.
     */
    private fun jsonSegmentError(h: String, p: String, err: Exception): String {
        val m = err.message ?: ""
        if (m.startsWith("non-canonical compact JWS")) return m
        for (seg in listOf(h, p)) {
            val b = try {
                decodeCanonicalBase64url(seg)
            } catch (e: AttErr) {
                return e.message ?: ""
            }
            try {
                AttestUtil.jsonLenient(b)
            } catch (e: RuntimeException) {
                val msg = V8Json.error(String(b, Charsets.UTF_8))
                if (msg != "") return msg
                return e.message ?: ""
            }
        }
        return m
    }
}

/**
 * The wording of the reference's `JSON.parse` failures: [error] validates a document with the grammar of `JSON.parse` and, when it
 * is not valid, returns the message V8 reports for it ("" for a valid document). Only the reason text depends on this; whether a
 * segment parses never does.
 */
internal object V8Json {
    fun error(text: String): String {
        val p = Parser(text.toCharArray())
        p.value()
        if (p.err != "") return p.err
        p.ws()
        if (p.pos < p.src.size) p.fail("Unexpected non-whitespace character after JSON at position %d (line %d column %d)", p.pos)
        return p.err
    }

    private class Parser(val src: CharArray) {
        var pos = 0
        var err = ""

        private fun location(pos: Int): Pair<Int, Int> {
            var line = 1
            var last = -1
            var i = 0
            while (i < pos && i < src.size) {
                val c = src[i]
                if (c == '\n' || (c == '\r' && !(i + 1 < src.size && src[i + 1] == '\n'))) {
                    line++
                    last = i
                }
                i++
            }
            return Pair(line, pos - last)
        }

        /** Records the message; its format takes position, line and column. */
        fun fail(format: String, pos: Int) {
            if (err != "") return
            val (line, col) = location(pos)
            err = String.format(format, pos, line, col)
        }

        private fun failExpected(what: String, pos: Int) = fail("$what in JSON at position %d (line %d column %d)", pos)

        private fun unexpectedEnd() {
            if (err == "") err = "Unexpected end of JSON input"
        }

        private fun sub(a: Int, b: Int): String = String(src, a, b - a)

        private fun unexpectedToken(pos: Int) {
            if (err != "") return
            val whole = String(src)
            when (whole) {
                "NaN", "Infinity", "undefined", "[object Object]" -> {
                    err = "\"$whole\" is not valid JSON"
                    return
                }
            }
            val ctx = 10
            val tok = sub(pos, pos + 1)
            val n = src.size
            err = when {
                n < ctx * 2 + 1 -> "Unexpected token '$tok', \"$whole\" is not valid JSON"
                pos < ctx -> "Unexpected token '$tok', \"${sub(0, pos + ctx)}\"... is not valid JSON"
                pos < n - ctx -> "Unexpected token '$tok', ...\"${sub(pos - ctx, pos + ctx)}\"... is not valid JSON"
                else -> "Unexpected token '$tok', ...\"${sub(pos - ctx, n)}\" is not valid JSON"
            }
        }

        fun ws() {
            while (pos < src.size) {
                when (src[pos]) {
                    ' ', '\t', '\n', '\r' -> pos++
                    else -> return
                }
            }
        }

        private fun peek(): Int = if (pos >= src.size) -1 else src[pos].code

        fun value() {
            ws()
            if (err != "") return
            val c = peek()
            when {
                c < 0 -> unexpectedEnd()
                c == '"'.code -> str()
                c == '{'.code -> obj()
                c == '['.code -> arr()
                c == '-'.code || (c >= '0'.code && c <= '9'.code) -> number()
                c == 't'.code -> literal("true")
                c == 'f'.code -> literal("false")
                c == 'n'.code -> literal("null")
                else -> unexpectedToken(pos)
            }
        }

        private fun literal(word: String) {
            for (i in word.indices) {
                if (pos >= src.size) {
                    unexpectedEnd()
                    return
                }
                if (src[pos] != word[i]) {
                    unexpectedToken(pos)
                    return
                }
                pos++
            }
        }

        private fun isDigit(c: Int): Boolean = c >= '0'.code && c <= '9'.code

        private fun number() {
            if (peek() == '-'.code) {
                pos++
                if (!isDigit(peek())) {
                    failExpected("No number after minus sign", pos)
                    return
                }
            }
            if (peek() == '0'.code) {
                pos++
                if (isDigit(peek())) {
                    fail("Unexpected number in JSON at position %d (line %d column %d)", pos)
                    return
                }
            } else {
                while (isDigit(peek())) pos++
            }
            if (peek() == '.'.code) {
                pos++
                if (!isDigit(peek())) {
                    failExpected("Unterminated fractional number", pos)
                    return
                }
                while (isDigit(peek())) pos++
            }
            val c = peek()
            if (c == 'e'.code || c == 'E'.code) {
                pos++
                val s = peek()
                if (s == '+'.code || s == '-'.code) pos++
                if (!isDigit(peek())) {
                    failExpected("Exponent part is missing a number", pos)
                    return
                }
                while (isDigit(peek())) pos++
            }
        }

        private fun str() {
            pos++ // opening quote
            while (true) {
                val c = peek()
                when {
                    c < 0 -> {
                        failExpected("Unterminated string", pos)
                        return
                    }
                    c == '"'.code -> {
                        pos++
                        return
                    }
                    c < 0x20 -> {
                        failExpected("Bad control character in string literal", pos)
                        return
                    }
                    c == '\\'.code -> {
                        pos++
                        val e = peek()
                        when {
                            e == '"'.code || e == '\\'.code || e == '/'.code || e == 'b'.code || e == 'f'.code || e == 'n'.code || e == 'r'.code || e == 't'.code -> pos++
                            e == 'u'.code -> {
                                pos++
                                for (i in 0 until 4) {
                                    val h = peek()
                                    if (!(isDigit(h) || (h >= 'a'.code && h <= 'f'.code) || (h >= 'A'.code && h <= 'F'.code))) {
                                        failExpected("Bad Unicode escape", pos)
                                        return
                                    }
                                    pos++
                                }
                            }
                            e == -1 -> {
                                failExpected("Unterminated string", pos)
                                return
                            }
                            else -> {
                                failExpected("Bad escaped character", pos)
                                return
                            }
                        }
                    }
                    else -> pos++
                }
            }
        }

        private fun obj() {
            pos++ // {
            ws()
            if (peek() == '}'.code) {
                pos++
                return
            }
            if (peek() != '"'.code) {
                failExpected("Expected property name or '}'", pos)
                return
            }
            while (true) {
                str()
                if (err != "") return
                ws()
                if (peek() != ':'.code) {
                    failExpected("Expected ':' after property name", pos)
                    return
                }
                pos++
                value()
                if (err != "") return
                ws()
                when (peek()) {
                    ','.code -> {
                        pos++
                        ws()
                        if (peek() != '"'.code) {
                            failExpected("Expected double-quoted property name", pos)
                            return
                        }
                    }
                    '}'.code -> {
                        pos++
                        return
                    }
                    else -> {
                        failExpected("Expected ',' or '}' after property value", pos)
                        return
                    }
                }
            }
        }

        private fun arr() {
            pos++ // [
            ws()
            if (peek() == ']'.code) {
                pos++
                return
            }
            while (true) {
                value()
                if (err != "") return
                ws()
                when (peek()) {
                    ','.code -> pos++
                    ']'.code -> {
                        pos++
                        return
                    }
                    else -> {
                        failExpected("Expected ',' or ']' after array element", pos)
                        return
                    }
                }
            }
        }
    }
}
