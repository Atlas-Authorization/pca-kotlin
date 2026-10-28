package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

/** A failure the attestation readers report with the reference's text (the Go `error` values). */
internal class AttErr(message: String) : RuntimeException(message)

/** Shared helpers of the attestation verifiers: byte / text decoding with JavaScript semantics, hashes, raw ECDSA, JSON access. */
internal object AttestUtil {
    const val BIND_DOMAIN = "atlas-pca/attest-bind/v1\u0000"
    const val MAX_SAFE = 9007199254740991.0

    // ---- hashes ----
    private fun digest(alg: String, b: ByteArray): ByteArray = MessageDigest.getInstance(alg).digest(b)
    fun sha1(b: ByteArray): ByteArray = digest("SHA-1", b)
    fun sha256(b: ByteArray): ByteArray = digest("SHA-256", b)
    fun sha384(b: ByteArray): ByteArray = digest("SHA-384", b)
    fun sha512(b: ByteArray): ByteArray = digest("SHA-512", b)

    // ---- hex ----
    private val HEXCHARS = "0123456789abcdef".toCharArray()

    fun hex(b: ByteArray): String {
        val c = CharArray(b.size * 2)
        for (i in b.indices) {
            val v = b[i].toInt() and 0xff
            c[2 * i] = HEXCHARS[v ushr 4]
            c[2 * i + 1] = HEXCHARS[v and 15]
        }
        return String(c)
    }

    private fun nibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /** Hex text to bytes; null on any non-hex character (a trailing odd nibble is dropped, as the reference's loose reader does). */
    fun hexDecodeLoose(s: String): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i + 1 < s.length) {
            val hi = nibble(s[i])
            val lo = nibble(s[i + 1])
            if (hi < 0 || lo < 0) return null
            out.write(hi * 16 + lo)
            i += 2
        }
        return out.toByteArray()
    }

    private val HEX_RE = Regex("[0-9a-fA-F]+")
    fun isHexString(s: String): Boolean = s.isNotEmpty() && s.length % 2 == 0 && HEX_RE.matches(s)
    fun isHexText(s: String): Boolean = HEX_RE.matches(s)

    // ---- JavaScript-flavoured text ----
    fun isJsSpace(r: Int): Boolean = when (r) {
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff -> true
        else -> r in 0x2000..0x200a
    }

    fun jsTrim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isJsSpace(s[a].code)) a++
        while (b > a && isJsSpace(s[b - 1].code)) b--
        return s.substring(a, b)
    }

    fun stripJsSpace(s: String): String {
        val sb = StringBuilder()
        for (ch in s) if (!isJsSpace(ch.code)) sb.append(ch)
        return sb.toString()
    }

    /** `Buffer.from(s, "base64")`: either alphabet, characters outside it are skipped, `=` ends the data. */
    fun nodeB64(s: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var acc = 0
        var bits = 0
        for (ch in s) {
            val c = ch.code
            val v: Int = when {
                c >= 'A'.code && c <= 'Z'.code -> c - 'A'.code
                c >= 'a'.code && c <= 'z'.code -> c - 'a'.code + 26
                c >= '0'.code && c <= '9'.code -> c - '0'.code + 52
                c == '+'.code || c == '-'.code -> 62
                c == '/'.code || c == '_'.code -> 63
                c == '='.code -> break
                else -> continue
            }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((acc ushr bits) and 0xff)
                acc = acc and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }

    /** Standard padded base64 (strict, like Go's `StdEncoding.DecodeString`); null when malformed. */
    fun base64Std(s: String): ByteArray? = try {
        if (s.length % 4 != 0) null else java.util.Base64.getDecoder().decode(s)
    } catch (e: IllegalArgumentException) {
        null
    }

    /** A byte-carrying claim: hex (optionally 0x-prefixed), else base64url / base64; null when empty or undecodable. */
    fun decodeClaimBytes(value: String): ByteArray? {
        val t = jsTrim(value)
        val hx = if (t.startsWith("0x") || t.startsWith("0X")) t.substring(2) else t
        if (isHexString(hx)) return hexDecodeLoose(hx)
        val b = nodeB64(t)
        return if (b.isNotEmpty()) b else null
    }

    fun timingSafeEq(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun lowerAll(l: List<String>): List<String> = l.map { it.lowercase() }

    // ---- JSON access (values are Json.parseLenient trees) ----
    fun jsonLenient(b: ByteArray): Any? = Json.parseLenient(String(b, StandardCharsets.UTF_8))

    @Suppress("UNCHECKED_CAST")
    fun rec(v: Any?): Map<String, Any?>? = v as? Map<String, Any?>

    fun asStr(v: Any?): String? = v as? String

    /** A finite JSON number (the reference `asNumber`). */
    fun asFinite(v: Any?): Double? {
        val f: Double = when (v) {
            is Json.Num -> v.raw.toDoubleOrNull() ?: return null
            is Double -> v
            is Float -> v.toDouble()
            is Int -> v.toDouble()
            is Long -> v.toDouble()
            else -> return null
        }
        return if (f.isNaN() || f.isInfinite()) null else f
    }

    fun asStrList(v: Any?): List<String>? {
        val arr = v as? List<*> ?: return null
        val out = ArrayList<String>(arr.size)
        for (x in arr) out.add(x as? String ?: return null)
        return out
    }

    /** The string members of a JSON array (empty when `v` is not an array). */
    fun anyStrings(v: Any?): List<String> = (v as? List<*>)?.filterIsInstance<String>() ?: emptyList()

    fun listLen(v: Any?): Int = when (v) {
        is List<*> -> v.size
        is String -> v.length
        else -> 0
    }

    /** `String(n)` for the integers (and doubles) these verifiers report. */
    fun jsNumString(f: Double): String {
        if (f == Math.floor(f) && Math.abs(f) < 1e21) return java.math.BigDecimal(f).toBigInteger().toString()
        return IntentJs.shortest(f)
    }

    fun jsAnyString(v: Any?): String {
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val f = asFinite(v)
        if (f != null) return jsNumString(f)
        return v.toString()
    }

    fun skewOf(cfg: Map<String, Any?>): Double {
        val f = asFinite(cfg["clockSkewMs"]) ?: return 0.0
        return Math.max(0.0, f)
    }

    /** Evidence member as bytes (`Buffer.from(x, "base64")`); null when absent or not a string. */
    fun evBytes(ev: Map<String, Any?>?, key: String): ByteArray? {
        val s = ev?.get(key) as? String ?: return null
        return nodeB64(s)
    }

    fun evString(ev: Map<String, Any?>?, key: String): String? = ev?.get(key) as? String

    fun newMeasured(runtimeMeasurement: String, operator: String): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["model_id"] = ""
        m["weights_digest"] = ""
        m["weights_measured"] = false
        m["runtime_measurement"] = runtimeMeasurement
        m["operator"] = operator
        return m
    }

    // ---- raw ECDSA over a digest ----
    private fun derInt(v: BigInteger): ByteArray {
        val b = v.toByteArray() // minimal two's complement; a positive value gets a leading 0 when its top bit is set
        return byteArrayOf(0x02, b.size.toByte()) + b
    }

    /** DER `ECDSA-Sig-Value { r, s }` (lengths stay below 128 for P-256 / P-384 / P-521 halves, so one length byte suffices). */
    fun derSig(r: BigInteger, s: BigInteger): ByteArray {
        val body = derInt(r) + derInt(s)
        return if (body.size < 128) byteArrayOf(0x30, body.size.toByte()) + body else byteArrayOf(0x30, 0x81.toByte(), body.size.toByte()) + body
    }

    fun bigFromBytes(b: ByteArray): BigInteger = BigInteger(1, b)

    /** BouncyCastle (already a dependency) covers the curves SunEC dropped (secp224r1 since JDK 16) or never had. */
    private val bc: java.security.Provider by lazy { org.bouncycastle.jce.provider.BouncyCastleProvider() }

    /** An EC `KeyFactory`: SunEC first for the curves it has, BouncyCastle for any other (P-224, Brainpool, secp256k1). */
    fun ecKeyOf(spec: java.security.spec.KeySpec): java.security.PublicKey = try {
        java.security.KeyFactory.getInstance("EC").generatePublic(spec)
    } catch (e: java.security.GeneralSecurityException) {
        java.security.KeyFactory.getInstance("EC", bc).generatePublic(spec)
    }

    /** Verify `(r, s)` over `digest` under `pub` (standard ECDSA, the digest truncated to the group order length as usual). */
    fun ecdsaVerify(pub: java.security.interfaces.ECPublicKey, digest: ByteArray, r: BigInteger, s: BigInteger): Boolean {
        val n = pub.params.order
        if (r.signum() <= 0 || s.signum() <= 0 || r >= n || s >= n) return false
        val der = derSig(r, s)
        fun run(key: java.security.PublicKey, p: java.security.Provider?): Boolean? = try {
            val sig = if (p == null) java.security.Signature.getInstance("NONEwithECDSA") else java.security.Signature.getInstance("NONEwithECDSA", p)
            sig.initVerify(key)
            sig.update(digest)
            sig.verify(der)
        } catch (e: java.security.GeneralSecurityException) {
            null
        }
        if (pub.javaClass.name.startsWith("org.bouncycastle")) return run(pub, bc) ?: false
        // SunEC decodes the keys of the curves it dropped (secp224r1 since JDK 16, secp256k1, Brainpool) but cannot verify with them
        // (InvalidKeyException: curve not supported): a refusal to run is not a verdict, so BouncyCastle gets the same key
        run(pub, null)?.let { return it }
        return try {
            run(java.security.KeyFactory.getInstance("EC", bc).generatePublic(java.security.spec.X509EncodedKeySpec(pub.encoded)), bc) ?: false
        } catch (e: java.security.GeneralSecurityException) {
            false
        }
    }

    /** A raw `r || s` signature (equal halves) over `digest`. */
    fun verifyRawEcdsa(pub: java.security.interfaces.ECPublicKey, digest: ByteArray, sig: ByteArray): Boolean {
        if (sig.isEmpty() || sig.size % 2 != 0) return false
        val h = sig.size / 2
        return ecdsaVerify(pub, digest, bigFromBytes(sig.copyOfRange(0, h)), bigFromBytes(sig.copyOfRange(h, sig.size)))
    }

    /** A DER `ECDSA-Sig-Value` under the strict rules of Go's `VerifyASN1` (minimal positive INTEGERs, nothing after the SEQUENCE). */
    fun verifyDerEcdsa(pub: java.security.interfaces.ECPublicKey, digest: ByteArray, sig: ByteArray): Boolean {
        val rs = parseDerSig(sig) ?: return false
        return ecdsaVerify(pub, digest, rs.first, rs.second)
    }

    private fun parseDerSig(b: ByteArray): Pair<BigInteger, BigInteger>? {
        var p = 0
        fun len(): Int {
            if (p >= b.size) return -1
            val l = b[p++].toInt() and 0xff
            if (l < 0x80) return l
            val n = l and 0x7f
            if (n == 0 || n > 3 || p + n > b.size) return -1
            var v = 0
            if (n > 1 && b[p].toInt() == 0) return -1
            for (i in 0 until n) v = (v shl 8) or (b[p + i].toInt() and 0xff)
            p += n
            return if (v < 0x80) -1 else v
        }
        if (b.isEmpty() || (b[p++].toInt() and 0xff) != 0x30) return null
        val total = len()
        if (total < 0 || p + total != b.size) return null
        fun int(): BigInteger? {
            if (p >= b.size || (b[p++].toInt() and 0xff) != 0x02) return null
            val l = len()
            if (l < 1 || p + l > b.size) return null
            val c = b.copyOfRange(p, p + l)
            p += l
            if (c.size > 1 && ((c[0].toInt() == 0 && (c[1].toInt() and 0x80) == 0) || (c[0].toInt() == -1 && (c[1].toInt() and 0x80) != 0))) return null
            if ((c[0].toInt() and 0x80) != 0) return null
            return BigInteger(c)
        }
        val r = int() ?: return null
        val s = int() ?: return null
        return if (p == b.size) Pair(r, s) else null
    }

    /** Whether `(x, y)` lies on the curve `y^2 = x^3 + ax + b (mod p)` with both coordinates in `[0, p)`. */
    fun onCurve(params: ECParameterSpec, x: BigInteger, y: BigInteger): Boolean {
        val c = params.curve
        val p = (c.field as java.security.spec.ECFieldFp).p
        if (x.signum() < 0 || y.signum() < 0 || x >= p || y >= p) return false
        val lhs = y.multiply(y).mod(p)
        val rhs = x.multiply(x).multiply(x).add(c.a.multiply(x)).add(c.b).mod(p)
        return lhs == rhs
    }

    /** The standard parameters of a named curve (`secp256r1`, `secp224r1`, ...); null for another curve name. */
    fun curveParams(name: String): ECParameterSpec? = try {
        val ap = java.security.AlgorithmParameters.getInstance("EC")
        ap.init(java.security.spec.ECGenParameterSpec(name))
        ap.getParameterSpec(ECParameterSpec::class.java)
    } catch (e: java.security.GeneralSecurityException) {
        try {
            val ap = java.security.AlgorithmParameters.getInstance("EC", bc)
            ap.init(java.security.spec.ECGenParameterSpec(name))
            ap.getParameterSpec(ECParameterSpec::class.java)
        } catch (e2: java.security.GeneralSecurityException) {
            null
        }
    }

    /** An on-curve public key from an uncompressed SEC1 point; null for anything else. */
    fun pointToKey(curveName: String, point: ByteArray): java.security.interfaces.ECPublicKey? {
        val params = curveParams(curveName) ?: return null
        val size = (params.order.bitLength() + 7) / 8
        if (point.size != 1 + 2 * size || point[0].toInt() != 4) return null
        val x = bigFromBytes(point.copyOfRange(1, 1 + size))
        val y = bigFromBytes(point.copyOfRange(1 + size, point.size))
        if (!onCurve(params, x, y)) return null
        return try {
            ecKeyOf(java.security.spec.ECPublicKeySpec(ECPoint(x, y), params)) as java.security.interfaces.ECPublicKey
        } catch (e: java.security.GeneralSecurityException) {
            null
        }
    }

    /** `leToBig`: a little-endian byte string as a non-negative integer. */
    fun leToBig(le: ByteArray): BigInteger {
        val be = ByteArray(le.size)
        for (i in le.indices) be[le.size - 1 - i] = le[i]
        return BigInteger(1, be)
    }

    // ---- the Azure runtime-data binding ----
    /** The failure reason, or "" when the quote binds. */
    fun checkAzureRuntimeDataBinding(reportData: ByteArray, runtimeData: ByteArray, expected: Attest.Binding): String {
        if (reportData.size != 64) return "report_data is not 64 bytes"
        for (i in 32 until 64) if (reportData[i].toInt() != 0) return "report_data[32:64] is not zero (not an Azure runtime-data hash)"
        if (!sha256(runtimeData).contentEquals(reportData.copyOfRange(0, 32))) return "sha256(runtime data) does not equal the quote report_data"
        val parsed = try { jsonLenient(runtimeData) } catch (e: RuntimeException) { return "runtime data is not valid JSON" }
        val obj = parsed as? Map<*, *> ?: return "runtime data is not a JSON object"
        val userData = obj["user-data"] as? String
        if (userData == null || userData.length != 128 || !isHexText(userData)) return "runtime data carries no 64-byte hex user-data"
        val want = try { Attest.bindingBytes(expected) } catch (e: IllegalArgumentException) { return "binding not constructible: " + e.message }
        val got = hexDecodeLoose(userData) ?: return "runtime data carries no 64-byte hex user-data"
        if (!got.contentEquals(want)) return "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)"
        return ""
    }

    fun errMsg(e: Throwable?): String = e?.message ?: "invalid"
}
