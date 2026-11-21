package net.atlasauth.pca.jose

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.engines.RSABlindedEngine
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.DSADigestSigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.crypto.signers.PSSSigner
import org.bouncycastle.crypto.signers.PlainDSAEncoding
import org.bouncycastle.crypto.signers.RSADigestSigner

/**
 * The JOSE plumbing the identity-credential packages share (DPoP, SD-JWT, VC, WebAuthn, the agent-card / commerce bridges): the
 * canonical compact-JWS gate (JWS and JWE shapes), JWK handling, compact JWS verify / sign for the asymmetric algorithms (EdDSA,
 * ES256/384/512, RS256/384/512, PS256/384/512), JWT claim checks with the reference library's semantics and wording, RFC 7638
 * thumbprints and an insertion-order JSON writer. Keys are JWK maps. Symmetric (HS*) and `none` are not supported: a key or an
 * algorithm outside the asymmetric set is refused. Ed25519 verification is strict RFC 8032 (canonical S, no small-order or
 * mixed-order key or R). All signature math is the BouncyCastle lightweight API, so the same code runs on Android and the JVM; ECDSA
 * signs with deterministic nonces (RFC 6979).
 */
object Jose {
    /** A JOSE failure (invalid token, key or claim). The message is the reference library's wording where it has one. */
    open class JoseException(message: String) : RuntimeException(message)

    /** A token that is not the one canonical spelling of a compact JWS ([reason] is the gate's reason token). */
    class CanonicalJwsError(val reason: String, detail: String? = null) :
        RuntimeException("non-canonical compact JWS: $reason" + if (detail.isNullOrEmpty()) "" else " ($detail)")

    const val DEFAULT_MAX_JWS_BYTES = 64 * 1024

    /** Marks "verify under the `jwk` member of the protected header" (RFC 7515 s4.1.3, EmbeddedJWK). */
    val EMBEDDED = Any()

    // ---- bytes ----

    fun sha256(b: ByteArray): ByteArray = digest("SHA-256", b)

    internal fun digest(alg: String, b: ByteArray): ByteArray = MessageDigest.getInstance(alg).digest(b)

    fun b64u(b: ByteArray): String = Pca.b64(b)

    /** UTF-8 bytes of a string as TextEncoder writes them: a lone surrogate becomes U+FFFD. */
    fun utf8(s: String): ByteArray {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { sb.append(c).append(s[i + 1]); i += 2; continue }
            sb.append(if (Character.isSurrogate(c)) '�' else c)
            i++
        }
        return Json.utf8(sb.toString())
    }

    private val B64_LENIENT = Regex("[A-Za-z0-9_-]*")

    /** Lenient base64url (either alphabet, optional padding) as a JOSE library reads a key member; JoseException when undecodable. */
    fun decodeB64Lenient(s: String): ByteArray {
        val t = s.trimEnd('=').replace('+', '-').replace('/', '_')
        if (!B64_LENIENT.matches(t) || t.length % 4 == 1) throw JoseException("invalid base64url")
        return Base64.getUrlDecoder().decode(t)
    }

    /** A JWK member as Node's base64url decoder reads it: characters outside the alphabet (spaces, replacement bytes of a lone surrogate) are skipped. */
    private fun decodeJwkMember(s: String): ByteArray = decodeB64Lenient(s.filter { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' || it == '+' || it == '/' || it == '=' })

    // ---- canonical compact JWS gate ----

    /** A token that passed the canonical gate: its segments and the strict-JSON header (and payload, when JSON). */
    class CanonicalJws internal constructor(val segments: List<String>, val header: Map<String, Any?>, val payload: Map<String, Any?>?)

    private fun b64uAlphabet(s: String) = s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }

    /** One strictly canonical unpadded base64url segment (CanonicalJwsError otherwise). */
    fun decodeCanonicalBase64url(seg: String): ByteArray {
        if (!b64uAlphabet(seg)) throw CanonicalJwsError("bad-character")
        if (seg.length % 4 == 1) throw CanonicalJwsError("non-canonical-base64url", "impossible length")
        val b = Base64.getUrlDecoder().decode(seg)
        if (b64u(b) != seg) throw CanonicalJwsError("non-canonical-base64url")
        return b
    }

    /** A canonical base64url segment holding a strict-JSON document of any type (an SD-JWT Disclosure). */
    fun decodeCanonicalJsonSegment(seg: String): Any? = parseJsonBytes(decodeCanonicalBase64url(seg))

    private fun parseJsonBytes(bytes: ByteArray): Any? {
        if (bytes.size >= 3 && (bytes[0].toInt() and 0xff) == 0xef && (bytes[1].toInt() and 0xff) == 0xbb && (bytes[2].toInt() and 0xff) == 0xbf) {
            throw CanonicalJwsError("bom")
        }
        val text = Jws.utf8Strict(bytes) ?: throw CanonicalJwsError("bad-utf8")
        return try {
            Json.parse(text)
        } catch (e: RuntimeException) {
            throw CanonicalJwsError("bad-json", e.message)
        } catch (e: StackOverflowError) {
            throw CanonicalJwsError("bad-json", "nesting too deep")
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun asObject(v: Any?): Map<String, Any?> = v as? Map<String, Any?> ?: throw CanonicalJwsError("not-an-object")

    /**
     * Throws CanonicalJwsError unless [token] is the one canonical spelling of a compact JWS ([parts] 3) or JWE (5): non-empty unpadded
     * base64url segments that re-encode exactly (a JWE's encrypted key may be empty), a strict-JSON header (and payload when [payloadJson]).
     */
    fun assertCanonicalCompactJws(token: Any?, parts: Int = 3, maxBytes: Int = DEFAULT_MAX_JWS_BYTES, payloadJson: Boolean = true): CanonicalJws {
        if (token !is String) throw CanonicalJwsError("not-a-string")
        if (token.length > maxBytes) throw CanonicalJwsError("too-long")
        val segs = token.split('.')
        if (segs.size != parts) throw CanonicalJwsError("bad-segment-count", "${segs.size} != $parts")
        val bytes = segs.mapIndexed { i, seg ->
            if (seg.isEmpty()) {
                if (parts == 5 && i == 1) ByteArray(0) else throw CanonicalJwsError("empty-segment", "segment $i")
            } else decodeCanonicalBase64url(seg)
        }
        val header = asObject(parseJsonBytes(bytes[0]))
        val payload = if (parts == 3 && payloadJson) asObject(parseJsonBytes(bytes[1])) else null
        return CanonicalJws(segs, header, payload)
    }

    // ---- JSON writer / members ----

    /** JSON text of a value with object members in insertion order, strings escaped like JSON.stringify. */
    fun stringify(v: Any?): String = Js.stringify(v)

    /** The JavaScript number value of a JSON number, else null. */
    fun num(o: Any?): Double? = Js.num(o)

    @Suppress("UNCHECKED_CAST")
    internal fun obj(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    internal fun str(o: Any?): String? = o as? String

    // ---- key import ----

    /** A public verification key resolved from a JWK. [kind]: ed25519 | ed448 | ec | rsa. */
    internal class PubKey(val kind: String, val crv: String?, val raw: ByteArray?, val ec: ECPublicKeyParameters?, val rsa: RSAKeyParameters?, val rsaBits: Int)

    private fun domain(crv: String): ECDomainParameters {
        val name = when (crv) {
            "P-256" -> "secp256r1"
            "P-384" -> "secp384r1"
            "P-521" -> "secp521r1"
            else -> throw JoseException("Unsupported key curve for this operation")
        }
        val x9 = CustomNamedCurves.getByName(name)
        return ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
    }

    private fun need(jwk: Map<String, Any?>, name: String): String = str(jwk[name]) ?: throw JoseException("Invalid JWK: missing \"$name\"")

    private fun big(jwk: Map<String, Any?>, name: String) = BigInteger(1, decodeJwkMember(need(jwk, name)))

    /** A public JWK (OKP Ed25519 / Ed448, EC P-256/384/521 on-curve, RSA) as a verification key; JoseException otherwise. */
    internal fun importPublic(jwk: Map<String, Any?>): PubKey {
        val kty = str(jwk["kty"]) ?: throw JoseException("JWK must have a kty")
        try {
            return when (kty) {
                "OKP" -> {
                    val crv = need(jwk, "crv")
                    val x = decodeJwkMember(need(jwk, "x"))
                    when {
                        crv == "Ed25519" && x.size == 32 -> PubKey("ed25519", crv, x, null, null, 0)
                        crv == "Ed448" && x.size == 57 -> PubKey("ed448", crv, x, null, null, 0)
                        else -> throw JoseException("Invalid OKP JWK")
                    }
                }
                "EC" -> {
                    val crv = need(jwk, "crv")
                    val dom = domain(crv)
                    val x = big(jwk, "x")
                    val y = big(jwk, "y")
                    val p = dom.curve.field.characteristic
                    if (x.signum() < 0 || y.signum() < 0 || x >= p || y >= p) throw JoseException("Invalid EC JWK: point is not on the curve")
                    val q = try { dom.curve.validatePoint(x, y) } catch (e: IllegalArgumentException) { throw JoseException("Invalid EC JWK: point is not on the curve") }
                    PubKey("ec", crv, null, ECPublicKeyParameters(q, dom), null, 0)
                }
                "RSA" -> {
                    if (jwk.containsKey("oth")) throw JoseException("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported")
                    val n = big(jwk, "n")
                    val e = big(jwk, "e")
                    if (n.signum() == 0 || !e.testBit(0) || e < BigInteger.valueOf(3) || e >= n) throw JoseException("Invalid RSA JWK")
                    PubKey("rsa", null, null, null, RSAKeyParameters(false, n, e), n.bitLength())
                }
                else -> throw JoseException("Unsupported \"kty\" (Key Type) Parameter value")
            }
        } catch (x: JoseException) {
            throw x
        } catch (x: RuntimeException) {
            throw JoseException("Invalid JWK: ${x.message}")
        }
    }

    // ---- algorithm / key agreement (the reference's keyForCrypto) ----

    private val ALGS = listOf("EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512")

    private fun checkKeyForAlg(alg: String, kind: String, crv: String?, rsaBits: Int) {
        when (alg) {
            "EdDSA" -> if (kind != "ed25519" && kind != "ed448") throw JoseException("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448")
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> {
                if (kind != "rsa") throw JoseException("Invalid key for this operation, its asymmetricKeyType must be rsa")
                if (rsaBits < 2048) throw JoseException("$alg requires key modulusLength to be 2048 bits or larger")
            }
            "ES256", "ES384", "ES512" -> {
                if (kind != "ec") throw JoseException("Invalid key for this operation, its asymmetricKeyType must be ec")
                val want = when (alg) { "ES256" -> "P-256"; "ES384" -> "P-384"; else -> "P-521" }
                if (want != crv) throw JoseException("Invalid key curve for the algorithm, its curve must be $want, got $crv")
            }
            else -> throw JoseException("alg $alg is not supported either by JOSE or your javascript runtime")
        }
    }

    private fun hash(alg: String): Digest = when {
        alg.endsWith("256") -> SHA256Digest()
        alg.endsWith("384") -> SHA384Digest()
        else -> SHA512Digest()
    }

    // ---- strict Ed25519 ----

    /** Strict RFC 8032 Ed25519 verify: canonical S, no non-canonical / small-order / mixed-order key or R. */
    fun verifyEd25519Strict(pk: ByteArray?, msg: ByteArray, sig: ByteArray?): Boolean = Pca.ed25519Strict(pk, msg, sig)

    // ---- verify / sign primitives ----

    private fun verifyRaw(alg: String, k: PubKey, sig: ByteArray, data: ByteArray): Boolean = try {
        when {
            alg == "EdDSA" && k.kind == "ed25519" -> verifyEd25519Strict(k.raw, data, sig)
            alg == "EdDSA" -> Ed448Signer(ByteArray(0)).run { init(false, Ed448PublicKeyParameters(k.raw, 0)); update(data, 0, data.size); verifySignature(sig) }
            alg.startsWith("ES") -> DSADigestSigner(ECDSASigner(), hash(alg), PlainDSAEncoding.INSTANCE).run { init(false, k.ec); update(data, 0, data.size); verifySignature(sig) }
            alg.startsWith("RS") -> RSADigestSigner(hash(alg)).run { init(false, k.rsa); update(data, 0, data.size); verifySignature(sig) }
            else -> { val d = hash(alg); PSSSigner(RSAEngine(), d, hash(alg), d.digestSize).run { init(false, k.rsa); update(data, 0, data.size); verifySignature(sig) } }
        }
    } catch (e: RuntimeException) {
        false
    }

    /** Verifies a JWS signature over [data] under a public JWK; false for any failure. JoseException when alg and key do not agree. */
    fun verifySignature(alg: String, publicJwk: Map<String, Any?>, sig: ByteArray, data: ByteArray): Boolean {
        val k = importPublic(publicJwk)
        checkKeyForAlg(alg, k.kind, k.crv, k.rsaBits)
        return verifyRaw(alg, k, sig, data)
    }

    private val rng by lazy { SecureRandom() }

    /** Signs [data] under a private JWK (OKP Ed25519 / Ed448, EC, RSA); JoseException when the key cannot sign under [alg]. */
    fun signRaw(alg: String, jwk: Map<String, Any?>, data: ByteArray): ByteArray {
        val kty = str(jwk["kty"])
        if (kty == null || str(jwk["d"]) == null) throw JoseException("JSON Web Key for this operation be a private JWK")
        str(jwk["alg"])?.let { if (it != alg) throw JoseException("Invalid key for this operation, when present its alg must be $alg") }
        try {
            return when (kty) {
                "OKP" -> {
                    val crv = need(jwk, "crv")
                    val d = decodeJwkMember(need(jwk, "d"))
                    checkKeyForAlg(alg, when (crv) { "Ed25519" -> "ed25519"; "Ed448" -> "ed448"; else -> "okp" }, null, 0)
                    when {
                        crv == "Ed25519" && d.size == 32 -> Ed25519Signer().run { init(true, Ed25519PrivateKeyParameters(d, 0)); update(data, 0, data.size); generateSignature() }
                        crv == "Ed448" && d.size == 57 -> Ed448Signer(ByteArray(0)).run { init(true, Ed448PrivateKeyParameters(d, 0)); update(data, 0, data.size); generateSignature() }
                        else -> throw JoseException("Invalid OKP JWK")
                    }
                }
                "EC" -> {
                    val crv = need(jwk, "crv")
                    checkKeyForAlg(alg, "ec", crv, 0)
                    val dom = domain(crv)
                    val s = DSADigestSigner(ECDSASigner(HMacDSAKCalculator(hash(alg))), hash(alg), PlainDSAEncoding.INSTANCE)
                    s.init(true, ECPrivateKeyParameters(big(jwk, "d"), dom))
                    s.update(data, 0, data.size)
                    s.generateSignature()
                }
                "RSA" -> {
                    val n = big(jwk, "n")
                    checkKeyForAlg(alg, "rsa", null, n.bitLength())
                    val priv = RSAPrivateCrtKeyParameters(n, big(jwk, "e"), big(jwk, "d"), big(jwk, "p"), big(jwk, "q"), big(jwk, "dp"), big(jwk, "dq"), big(jwk, "qi"))
                    if (alg.startsWith("PS")) {
                        val d = hash(alg)
                        PSSSigner(RSABlindedEngine(), d, hash(alg), d.digestSize).run { init(true, ParametersWithRandom(priv, rng)); update(data, 0, data.size); generateSignature() }
                    } else RSADigestSigner(hash(alg)).run { init(true, ParametersWithRandom(priv, rng)); update(data, 0, data.size); generateSignature() }
                }
                else -> throw JoseException("Invalid key for this operation, its kty must be RSA, OKP, or EC")
            }
        } catch (e: JoseException) {
            throw e
        } catch (e: Exception) {
            throw JoseException("signing failed: ${e.message}")
        }
    }

    // ---- compact JWS verify ----

    /** A verified compact JWS: the parsed protected header and the payload bytes. */
    class Verified internal constructor(val protectedHeader: Map<String, Any?>, val payload: ByteArray)

    private const val CRIT_MSG = "\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present"

    /** The reference's crit-header check (only `b64` is understood); throws [JoseException]. */
    internal fun checkCritHeader(prot: Map<String, Any?>) = validateCrit(prot)

    private fun validateCrit(prot: Map<String, Any?>) {
        if (!prot.containsKey("crit")) return
        val crit = prot["crit"] as? List<*>
        if (crit == null || crit.isEmpty() || crit.any { it !is String || it.isEmpty() }) throw JoseException(CRIT_MSG)
        for (c in crit) {
            if (c != "b64") throw JoseException("Extension Header Parameter \"$c\" is not recognized")
            if (!prot.containsKey("b64")) throw JoseException("Extension Header Parameter \"b64\" is missing")
        }
    }

    /**
     * Verifies a compact JWS under [key] ([EMBEDDED] or a public JWK map), allowing only [algorithms] (null = any supported). Mirrors
     * the reference compactVerify: header checks, crit, alg allow-list, key / alg agreement, signature.
     */
    fun compactVerify(jws: String, key: Any?, algorithms: Collection<String>?): Verified {
        val parts = jws.split('.')
        if (parts.size != 3) throw JoseException("Invalid Compact JWS")
        val (protectedB64, payloadSeg, sigSeg) = parts
        var prot: Map<String, Any?> = LinkedHashMap()
        if (protectedB64.isNotEmpty()) {
            prot = try {
                obj(Json.parseLenient(String(decodeB64Lenient(protectedB64), StandardCharsets.UTF_8))) ?: throw JoseException("JWS Protected Header is invalid")
            } catch (e: RuntimeException) {
                throw JoseException("JWS Protected Header is invalid")
            }
        }
        validateCrit(prot)
        var b64 = true
        if ((prot["crit"] as? List<*>)?.contains("b64") == true) {
            b64 = prot["b64"] as? Boolean ?: throw JoseException("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean")
        }
        val alg = str(prot["alg"])
        if (alg.isNullOrEmpty()) throw JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")
        if (algorithms != null && alg !in algorithms) throw JoseException("\"alg\" (Algorithm) Header Parameter value not allowed")
        val jwk: Map<String, Any?> = if (key === EMBEDDED) {
            val h = obj(prot["jwk"]) ?: throw JoseException("\"jwk\" (JSON Web Key) Header Parameter must be a JSON object")
            if (h["kty"] == "oct" || h["d"] is String) throw JoseException("\"jwk\" (JSON Web Key) Header Parameter must be a public key")
            h
        } else {
            val j = obj(key) ?: throw JoseException("Invalid key input")
            if (str(j["kty"]) == null || j["kty"] == "oct" || j["d"] != null) throw JoseException("JSON Web Key for this operation be a public JWK")
            j
        }
        val k = importPublic(jwk)
        checkKeyForAlg(alg, k.kind, k.crv, k.rsaBits)
        val sig = try { decodeB64Lenient(sigSeg) } catch (e: JoseException) { throw JoseException("Failed to base64url decode the signature") }
        if (!verifyRaw(alg, k, sig, utf8("$protectedB64.$payloadSeg"))) throw JoseException("signature verification failed")
        val payload = if (b64) {
            try { decodeB64Lenient(payloadSeg) } catch (e: JoseException) { throw JoseException("Failed to base64url decode the payload") }
        } else utf8(payloadSeg)
        return Verified(prot, payload)
    }

    // ---- JWT ----

    /**
     * Claim checks of a JWT verification (null members are not checked). [currentDateMs]: null = now; NaN or beyond +-8.64e15 is an
     * invalid Date (every time check passes, as in the reference). [audience]: null = no audience check.
     */
    data class JwtOptions(
        val typ: String? = null,
        val issuer: String? = null,
        val subject: String? = null,
        val audience: List<String>? = null,
        val clockTolerance: Double? = null,
        val currentDateMs: Double? = null,
        val algorithms: Collection<String>? = null,
    )

    /** A verified JWT. */
    class VerifiedJwt internal constructor(val payload: Map<String, Any?>, val protectedHeader: Map<String, Any?>)

    private fun normalizeTyp(v: String): String = v.lowercase(Locale.ROOT).removePrefix("application/")

    /** compactVerify, then the reference JWT claim checks (typ, aud, nbf, exp, iat shape). Everything that fails throws JoseException. */
    fun jwtVerify(jwt: String, key: Any?, opts: JwtOptions): VerifiedJwt {
        val v = compactVerify(jwt, key, opts.algorithms)
        if ((v.protectedHeader["crit"] as? List<*>)?.contains("b64") == true && v.protectedHeader["b64"] == false) throw JoseException("JWTs MUST NOT use unencoded payload")
        val parsed = try { Json.parseLenient(String(v.payload, StandardCharsets.UTF_8)) } catch (e: RuntimeException) { null }
        val payload = obj(parsed) ?: throw JoseException("JWT Claims Set must be a top-level JSON object")
        if (!opts.typ.isNullOrEmpty()) {
            val t = v.protectedHeader["typ"] as? String
            if (t == null || normalizeTyp(t) != normalizeTyp(opts.typ)) throw JoseException("unexpected \"typ\" JWT header value")
        }
        if (opts.audience != null && !payload.containsKey("aud")) throw JoseException("missing required \"aud\" claim")
        if (opts.subject != null && !payload.containsKey("sub")) throw JoseException("missing required \"sub\" claim")
        if (opts.issuer != null && !payload.containsKey("iss")) throw JoseException("missing required \"iss\" claim")
        if (!opts.issuer.isNullOrEmpty() && opts.issuer != payload["iss"]) throw JoseException("unexpected \"iss\" claim value")
        if (!opts.subject.isNullOrEmpty() && opts.subject != payload["sub"]) throw JoseException("unexpected \"sub\" claim value")
        // an empty-string audience option is required to be present but, being falsy in the reference, is not compared
        if (opts.audience != null && !(opts.audience.size == 1 && opts.audience[0].isEmpty())) {
            val ok = when (val aud = payload["aud"]) {
                is String -> aud in opts.audience
                is List<*> -> opts.audience.any { it in aud }
                else -> false
            }
            if (!ok) throw JoseException("unexpected \"aud\" claim value")
        }
        val tol = opts.clockTolerance ?: 0.0
        val now = when (val ms = opts.currentDateMs) {
            null -> Math.floor(System.currentTimeMillis() / 1000.0)
            else -> if (ms.isNaN() || Math.abs(ms) > 8.64e15) Double.NaN else Math.floor((if (ms < 0) Math.ceil(ms) else Math.floor(ms)) / 1000.0)
        }
        if (payload.containsKey("iat") && num(payload["iat"]) == null) throw JoseException("\"iat\" claim must be a number")
        if (payload.containsKey("nbf")) {
            val nbf = num(payload["nbf"]) ?: throw JoseException("\"nbf\" claim must be a number")
            if (nbf > now + tol) throw JoseException("\"nbf\" claim timestamp check failed")
        }
        if (payload.containsKey("exp")) {
            val exp = num(payload["exp"]) ?: throw JoseException("\"exp\" claim must be a number")
            if (exp <= now - tol) throw JoseException("\"exp\" claim timestamp check failed")
        }
        return VerifiedJwt(payload, v.protectedHeader)
    }

    /** SignJWT: compact JWS of [header] + [payload] (JSON.stringify member order) under a private JWK. */
    fun signJwt(header: Map<String, Any?>, payload: Map<String, Any?>, privateJwk: Map<String, Any?>): String {
        val alg = str(header["alg"])
        if (alg.isNullOrEmpty()) throw JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")
        if (header.containsKey("crit")) throw JoseException("crit is not supported when signing")
        val h = b64u(utf8(stringify(header)))
        val p = b64u(utf8(stringify(payload)))
        return "$h.$p." + b64u(signRaw(alg, privateJwk, utf8("$h.$p")))
    }

    // ---- thumbprint ----

    private fun check(v: Any?, description: String) {
        if (v !is String || v.isEmpty()) throw JoseException("$description missing or invalid")
    }

    /** RFC 7638 JWK thumbprint (base64url of the hash of the required members, keys sorted). [digest]: sha256 (default), sha384, sha512. */
    fun jwkThumbprint(jwk: Map<String, Any?>?, digest: String? = null): String {
        if (jwk == null) throw JoseException("JWK must be an object")
        val d = digest ?: "sha256"
        if (d != "sha256" && d != "sha384" && d != "sha512") throw JoseException("digestAlgorithm must one of \"sha256\", \"sha384\", or \"sha512\"")
        val kty = jwk["kty"]
        val c: Map<String, Any?> = when (kty) {
            "EC" -> {
                check(jwk["crv"], "\"crv\" (Curve) Parameter"); check(jwk["x"], "\"x\" (X Coordinate) Parameter"); check(jwk["y"], "\"y\" (Y Coordinate) Parameter")
                Js.obj("crv" to jwk["crv"], "kty" to kty, "x" to jwk["x"], "y" to jwk["y"])
            }
            "OKP" -> {
                check(jwk["crv"], "\"crv\" (Subtype of Key Pair) Parameter"); check(jwk["x"], "\"x\" (Public Key) Parameter")
                Js.obj("crv" to jwk["crv"], "kty" to kty, "x" to jwk["x"])
            }
            "RSA" -> {
                check(jwk["e"], "\"e\" (Exponent) Parameter"); check(jwk["n"], "\"n\" (Modulus) Parameter")
                Js.obj("e" to jwk["e"], "kty" to kty, "n" to jwk["n"])
            }
            "oct" -> {
                check(jwk["k"], "\"k\" (Key Value) Parameter")
                Js.obj("k" to jwk["k"], "kty" to kty)
            }
            else -> throw JoseException("\"kty\" (Key Type) Parameter missing or unsupported")
        }
        return b64u(digest(when (d) { "sha256" -> "SHA-256"; "sha384" -> "SHA-384"; else -> "SHA-512" }, utf8(stringify(c))))
    }

    /** True when [alg] is one this object can verify or sign. */
    fun supportsAlg(alg: String?): Boolean = alg in ALGS
}
