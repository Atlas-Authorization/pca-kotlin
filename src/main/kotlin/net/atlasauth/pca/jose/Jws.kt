package net.atlasauth.pca.jose

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Locale
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.DSADigestSigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.PSSSigner
import org.bouncycastle.crypto.signers.PlainDSAEncoding
import org.bouncycastle.crypto.signers.RSADigestSigner

/**
 * The slice of a JOSE library (jose 5.x semantics) the protocol bridges share: the canonical compact-JWS gate, compact JWS
 * verification with a static key or a key resolver (a local JWK Set), and JWT claim validation (issuer, audience, exp, nbf, iat,
 * max token age, required claims, typ). Verification keys: a public JWK map, a [PublicKey] (Ed25519, EC P-256/384/521, RSA), a
 * [VerifyKey], or a [KeyResolver]. All signature math runs on the BouncyCastle lightweight API (no JCA provider needed, so the same
 * code runs on Android and the JVM). EdDSA verification is the strict Ed25519 check of the core verifier.
 * shortcut: no HMAC (the OIDC default algorithm set excludes it), no Ed448 / ES256K keys; a token needing them is refused (invalid)
 * rather than verified. Upgrade when a deployment signs with them.
 */
object Jws {
    const val DEFAULT_MAX_JWS_BYTES = 64 * 1024

    /** A JOSE failure. [kind]: signature, expired, claim, other. [claim] names the JWT claim of an expired / claim failure. */
    class JoseException(val kind: String, val claim: String?, message: String) : RuntimeException(message) {
        constructor(message: String) : this("other", null, message)
    }

    /** Resolves the verification key of a token from its protected header. */
    fun interface KeyResolver {
        fun getKey(protectedHeader: Map<String, Any?>): Any?
    }

    /** An imported public verification key. */
    sealed class VerifyKey {
        class Ed25519(val x: ByteArray) : VerifyKey()
        class Ec(val crv: String, val params: ECPublicKeyParameters, val bits: Int) : VerifyKey()
        class Rsa(val n: BigInteger, val e: BigInteger) : VerifyKey()
    }

    // ---- canonical compact JWS ----

    class CanonicalJwsError(val reason: String) : RuntimeException("non-canonical compact JWS: $reason")

    class Canonical internal constructor(val segments: List<String>, val header: Map<String, Any?>, val payload: Map<String, Any?>)

    private fun b64uAlphabet(s: String): Boolean = s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }

    fun b64u(b: ByteArray): String = Pca.b64(b)

    /** One strictly canonical unpadded base64url segment. */
    fun decodeCanonicalBase64url(seg: String): ByteArray {
        if (!b64uAlphabet(seg)) throw CanonicalJwsError("bad-character")
        if (seg.length % 4 == 1) throw CanonicalJwsError("non-canonical-base64url")
        val b = Base64.getUrlDecoder().decode(seg)
        if (b64u(b) != seg) throw CanonicalJwsError("non-canonical-base64url")
        return b
    }

    /** Strict UTF-8 decode (malformed input is refused, never replaced). */
    fun utf8Strict(bytes: ByteArray): String? = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (e: CharacterCodingException) {
        null
    }

    private fun parseJsonBytes(bytes: ByteArray): Any? {
        if (bytes.size >= 3 && (bytes[0].toInt() and 0xff) == 0xef && (bytes[1].toInt() and 0xff) == 0xbb && (bytes[2].toInt() and 0xff) == 0xbf) {
            throw CanonicalJwsError("bom")
        }
        val text = utf8Strict(bytes) ?: throw CanonicalJwsError("bad-utf8")
        return try {
            Json.parse(text)
        } catch (e: RuntimeException) {
            throw CanonicalJwsError("bad-json")
        } catch (e: StackOverflowError) {
            throw CanonicalJwsError("bad-json")
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun asObject(v: Any?): Map<String, Any?> = v as? Map<String, Any?> ?: throw CanonicalJwsError("not-an-object")

    /** Throws unless [token] is the one canonical spelling of a compact JWS: 3 unpadded canonical base64url segments, strict-JSON object header and payload. */
    fun assertCanonicalCompactJws(token: Any?): Canonical {
        if (token !is String) throw CanonicalJwsError("not-a-string")
        if (token.length > DEFAULT_MAX_JWS_BYTES) throw CanonicalJwsError("too-long")
        val segs = token.split('.')
        if (segs.size != 3) throw CanonicalJwsError("bad-segment-count")
        val bytes = segs.map { if (it.isEmpty()) throw CanonicalJwsError("empty-segment"); decodeCanonicalBase64url(it) }
        return Canonical(segs, asObject(parseJsonBytes(bytes[0])), asObject(parseJsonBytes(bytes[1])))
    }

    // ---- key import ----

    private fun curveFor(crv: String): Pair<ECDomainParameters, Int> {
        val (name, bits) = when (crv) {
            "P-256" -> "secp256r1" to 256
            "P-384" -> "secp384r1" to 384
            "P-521" -> "secp521r1" to 521
            else -> throw JoseException("unsupported curve")
        }
        val x9 = CustomNamedCurves.getByName(name)
        return ECDomainParameters(x9.curve, x9.g, x9.n, x9.h) to bits
    }

    private fun ecKey(crv: String, x: BigInteger, y: BigInteger): VerifyKey.Ec {
        val (dom, bits) = curveFor(crv)
        val p = dom.curve.field.characteristic
        if (x.signum() < 0 || y.signum() < 0 || x >= p || y >= p) throw JoseException("invalid EC JWK: not on the curve")
        val q = try { dom.curve.validatePoint(x, y) } catch (e: IllegalArgumentException) { throw JoseException("invalid EC JWK: not on the curve") }
        return VerifyKey.Ec(crv, ECPublicKeyParameters(q, dom), bits)
    }

    private fun jwkBytes(jwk: Map<String, Any?>, name: String): ByteArray {
        val s = jwk[name] as? String ?: throw JoseException("invalid JWK: missing $name")
        return try { Base64.getUrlDecoder().decode(s) } catch (e: IllegalArgumentException) { throw JoseException("invalid JWK: $name") }
    }

    /** A public JWK (OKP Ed25519, EC P-256/384/521 on-curve, RSA) as a verification key; JoseException for anything else, a private JWK included. */
    fun importPublicJwk(jwk: Map<String, Any?>): VerifyKey {
        if (jwk["d"] != null) throw JoseException("JSON Web Key Set members must be public keys")
        val kty = jwk["kty"] as? String ?: throw JoseException("JWK must have a kty")
        return when (kty) {
            "OKP" -> {
                if (jwk["crv"] != "Ed25519") throw JoseException("unsupported OKP curve")
                val x = jwkBytes(jwk, "x")
                if (x.size != 32) throw JoseException("invalid OKP JWK")
                VerifyKey.Ed25519(x)
            }
            "EC" -> ecKey(jwk["crv"] as? String ?: "", BigInteger(1, jwkBytes(jwk, "x")), BigInteger(1, jwkBytes(jwk, "y")))
            "RSA" -> {
                val n = BigInteger(1, jwkBytes(jwk, "n"))
                val e = BigInteger(1, jwkBytes(jwk, "e"))
                if (n.signum() == 0 || !e.testBit(0) || e < BigInteger.valueOf(3) || e >= n) throw JoseException("invalid RSA JWK")
                VerifyKey.Rsa(n, e)
            }
            else -> throw JoseException("unsupported kty")
        }
    }

    private const val ED25519_SPKI_LEN = 44

    /** A JCA public key as a verification key (Ed25519 by its X.509 encoding, EC by curve size, RSA). */
    fun importPublicKey(k: PublicKey): VerifyKey = when {
        k is RSAPublicKey -> VerifyKey.Rsa(k.modulus, k.publicExponent)
        k is ECPublicKey -> {
            val crv = when (k.params.curve.field.fieldSize) { 256 -> "P-256"; 384 -> "P-384"; 521 -> "P-521"; else -> throw JoseException("unsupported curve") }
            ecKey(crv, k.w.affineX, k.w.affineY)
        }
        (k.algorithm == "Ed25519" || k.algorithm == "EdDSA") && k.encoded?.size == ED25519_SPKI_LEN -> VerifyKey.Ed25519(k.encoded.copyOfRange(12, 44))
        else -> throw JoseException("invalid key input")
    }

    /** The raw 32-byte Ed25519 public key as a verification key. */
    fun ed25519(pub: ByteArray): VerifyKey {
        require(pub.size == 32) { "an Ed25519 public key is 32 bytes" }
        return VerifyKey.Ed25519(pub.copyOf())
    }

    private fun digest(alg: String): Digest = when (alg.takeLast(3)) {
        "256" -> SHA256Digest()
        "384" -> SHA384Digest()
        else -> SHA512Digest()
    }

    private fun verifyRaw(alg: String, key: VerifyKey, sig: ByteArray, data: ByteArray): Boolean = try {
        when (key) {
            is VerifyKey.Ed25519 -> Pca.ed25519Strict(key.x, data, sig)
            is VerifyKey.Ec -> {
                val s = DSADigestSigner(ECDSASigner(), digest(alg), PlainDSAEncoding.INSTANCE)
                s.init(false, key.params)
                s.update(data, 0, data.size)
                s.verifySignature(sig)
            }
            is VerifyKey.Rsa -> {
                val pub = RSAKeyParameters(false, key.n, key.e)
                if (alg.startsWith("PS")) {
                    val d = digest(alg)
                    val s = PSSSigner(RSAEngine(), d, digest(alg), d.digestSize)
                    s.init(false, pub)
                    s.update(data, 0, data.size)
                    s.verifySignature(sig)
                } else {
                    val s = RSADigestSigner(digest(alg))
                    s.init(false, pub)
                    s.update(data, 0, data.size)
                    s.verifySignature(sig)
                }
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    /** jose's key / algorithm agreement: the key's type (and curve, RSA size) must fit [alg]; a mismatch is not a signature failure. */
    private fun checkKeyForAlg(alg: String, key: VerifyKey) {
        when (alg) {
            "EdDSA" -> if (key !is VerifyKey.Ed25519) throw JoseException("key type does not fit EdDSA")
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> {
                if (key !is VerifyKey.Rsa) throw JoseException("key type does not fit $alg")
                if (key.n.bitLength() < 2048) throw JoseException("$alg requires a key of 2048 bits or larger")
            }
            "ES256", "ES384", "ES512" -> {
                if (key !is VerifyKey.Ec) throw JoseException("key type does not fit $alg")
                val want = when (alg) { "ES256" -> 256; "ES384" -> 384; else -> 521 }
                if (key.bits != want) throw JoseException("key curve does not fit $alg")
            }
            else -> throw JoseException("alg $alg is not supported")
        }
    }

    // ---- local JWK Set ----

    private fun isJwksLike(jwks: Any?): Boolean {
        val keys = (jwks as? Map<*, *>)?.get("keys") as? List<*> ?: return false
        return keys.all { it is Map<*, *> }
    }

    /** jose's createLocalJWKSet: a resolver that picks the one key matching the header's alg / kid (and the key's use, key_ops, curve). */
    @Suppress("UNCHECKED_CAST")
    fun localJwks(jwks: Any?): KeyResolver {
        if (!isJwksLike(jwks)) throw JoseException("JSON Web Key Set malformed")
        val keys = ArrayList((jwks as Map<String, Any?>)["keys"] as List<Map<String, Any?>>)
        return KeyResolver { header ->
            val a = header["alg"] as? String
            val kid = header["kid"]
            val kty = when {
                a != null && (a.startsWith("RS") || a.startsWith("PS")) -> "RSA"
                a != null && a.startsWith("ES") -> "EC"
                a != null && a.startsWith("Ed") -> "OKP"
                else -> throw JoseException("Unsupported \"alg\" value for a JSON Web Key Set")
            }
            val cands = keys.filter { jwk ->
                var c = kty == jwk["kty"]
                if (c && kid is String) c = kid == jwk["kid"]
                if (c && jwk["alg"] is String) c = a == jwk["alg"]
                if (c && jwk["use"] is String) c = "sig" == jwk["use"]
                if (c && jwk["key_ops"] is List<*>) c = (jwk["key_ops"] as List<*>).contains("verify")
                if (c && a == "EdDSA") c = jwk["crv"] == "Ed25519" || jwk["crv"] == "Ed448"
                if (c) c = when (a) {
                    "ES256" -> jwk["crv"] == "P-256"
                    "ES256K" -> jwk["crv"] == "secp256k1"
                    "ES384" -> jwk["crv"] == "P-384"
                    "ES512" -> jwk["crv"] == "P-521"
                    else -> true
                }
                c
            }
            if (cands.isEmpty()) throw JoseException("no applicable key found in the JSON Web Key Set")
            if (cands.size != 1) throw JoseException("multiple matching keys found in the JSON Web Key Set")
            importPublicJwk(cands[0])
        }
    }

    // ---- compact verification ----

    class Verified internal constructor(val protectedHeader: Map<String, Any?>, val payload: Map<String, Any?>)

    @Suppress("UNCHECKED_CAST")
    private fun toVerifyKey(k: Any?): VerifyKey = when (k) {
        is VerifyKey -> k
        is Map<*, *> -> importPublicJwk(k as Map<String, Any?>)
        is PublicKey -> importPublicKey(k)
        else -> throw JoseException("invalid key input")
    }

    /**
     * jose's compactVerify over a token that already passed [assertCanonicalCompactJws]. [key]: a [VerifyKey], a public JWK map, a
     * [PublicKey] or a [KeyResolver]; [algorithms] the allowed JWS algorithms (null: any).
     */
    fun compactVerify(jws: String, canon: Canonical, key: Any?, algorithms: Collection<String>?): Verified {
        val hdr = canon.header
        var b64False = false
        if (hdr.containsKey("crit")) {
            val crit = hdr["crit"] as? List<*>
            if (crit == null || crit.isEmpty() || crit.any { it !is String || it.isEmpty() }) throw JoseException("\"crit\" must be a non-empty array of strings")
            for (c in crit) {
                if (c != "b64") throw JoseException("Extension Header Parameter is not recognized")
                val b64 = hdr["b64"] ?: throw JoseException("Extension Header Parameter \"b64\" is missing")
                if (b64 !is Boolean) throw JoseException("\"b64\" must be a boolean")
                b64False = !b64
            }
        }
        val alg = hdr["alg"] as? String
        if (alg.isNullOrEmpty()) throw JoseException("JWS \"alg\" missing or invalid")
        if (algorithms != null && alg !in algorithms) throw JoseException("\"alg\" not allowed")
        val pk = toVerifyKey(if (key is KeyResolver) key.getKey(hdr) else key)
        checkKeyForAlg(alg, pk)
        val d2 = jws.lastIndexOf('.')
        val data = Json.utf8(jws.substring(0, d2))
        val sig = Base64.getUrlDecoder().decode(jws.substring(d2 + 1))
        if (!verifyRaw(alg, pk, sig, data)) throw JoseException("signature", null, "signature verification failed")
        if (b64False) throw JoseException("JWTs MUST NOT use unencoded payload")
        return Verified(hdr, canon.payload)
    }

    // ---- JWT claims ----

    /**
     * jose's JWT claim options. [audience] / [issuer]: a String or a List; [clockTolerance] / [maxTokenAge]: a number (any other
     * value is refused as jose refuses it); [algorithms]: the allowed JWS algorithms (null: any).
     */
    data class JwtOptions(
        val typ: String? = null,
        val requiredClaims: List<String> = emptyList(),
        val issuer: Any? = null,
        val audience: Any? = null,
        val maxTokenAge: Any? = null,
        val clockTolerance: Any? = null,
        val algorithms: List<String>? = null,
    )

    /** jose's JWT claim validation at [nowMs]. Throws a [JoseException] (kind claim / expired). */
    fun validateClaims(header: Map<String, Any?>, payload: Map<String, Any?>, o: JwtOptions, nowMs: Long) {
        if (Js.truthy(o.typ)) {
            val t = header["typ"] as? String
            if (t == null || normalizeTyp(t) != normalizeTyp(o.typ!!)) throw JoseException("claim", "typ", "unexpected \"typ\" JWT header value")
        }
        val presence = ArrayList(o.requiredClaims)
        if (o.maxTokenAge != null) presence.add("iat")
        if (o.audience != null) presence.add("aud")
        if (o.issuer != null) presence.add("iss")
        for (c in LinkedHashSet(presence.reversed())) {
            if (!payload.containsKey(c)) throw JoseException("claim", c, "missing required \"$c\" claim")
        }
        if (Js.truthy(o.issuer)) {
            val issuers = o.issuer as? List<*> ?: listOf(o.issuer)
            if (payload["iss"] !in issuers) throw JoseException("claim", "iss", "unexpected \"iss\" claim value")
        }
        if (Js.truthy(o.audience)) {
            val opts = o.audience as? List<*> ?: listOf(o.audience)
            val ok = when (val pa = payload["aud"]) {
                is String -> pa in opts
                is List<*> -> opts.any { it in pa }
                else -> false
            }
            if (!ok) throw JoseException("claim", "aud", "unexpected \"aud\" claim value")
        }
        val tol = if (o.clockTolerance == null) 0.0 else Js.num(o.clockTolerance) ?: throw IllegalArgumentException("Invalid clockTolerance option type")
        val now = Math.floorDiv(nowMs, 1000L)
        val iat = Js.num(payload["iat"])
        if ((payload.containsKey("iat") || Js.truthy(o.maxTokenAge)) && iat == null) throw JoseException("claim", "iat", "\"iat\" claim must be a number")
        if (payload.containsKey("nbf")) {
            val nbf = Js.num(payload["nbf"]) ?: throw JoseException("claim", "nbf", "\"nbf\" claim must be a number")
            if (nbf > now + tol) throw JoseException("claim", "nbf", "\"nbf\" claim timestamp check failed")
        }
        if (payload.containsKey("exp")) {
            val exp = Js.num(payload["exp"]) ?: throw JoseException("claim", "exp", "\"exp\" claim must be a number")
            if (exp <= now - tol) throw JoseException("expired", "exp", "\"exp\" claim timestamp check failed")
        }
        if (Js.truthy(o.maxTokenAge)) {
            val max = Js.num(o.maxTokenAge) ?: throw IllegalArgumentException("Invalid maxTokenAge option type")
            val age = now - iat!!
            if (age - tol > max) throw JoseException("expired", "iat", "\"iat\" claim timestamp check failed (too far in the past)")
            if (age < 0 - tol) throw JoseException("claim", "iat", "\"iat\" claim timestamp check failed (it should be in the past)")
        }
    }

    private fun normalizeTyp(v: String): String = v.lowercase(Locale.ROOT).removePrefix("application/")

    /** compactVerify, the b64 rule and claim validation in one call (jose's jwtVerify) over a canonical token. */
    fun jwtVerify(jwt: String, canon: Canonical, key: Any?, opts: JwtOptions, nowMs: Long): Verified {
        val v = compactVerify(jwt, canon, key, opts.algorithms)
        validateClaims(v.protectedHeader, v.payload, opts, nowMs)
        return v
    }

    /** Signs a compact JWS with an Ed25519 key; header and payload are written in insertion order (JSON.stringify), as the reference does. */
    fun signEd25519(header: Map<String, Any?>, payload: Map<String, Any?>, key: Keys.EdKey): String {
        val data = b64u(Json.utf8(Js.stringify(header))) + "." + b64u(Json.utf8(Js.stringify(payload)))
        return data + "." + b64u(key.sign(Json.utf8(data)))
    }
}
