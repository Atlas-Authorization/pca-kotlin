package net.atlasauth.pca.ap2

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.verifier.Json
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator

/**
 * SD-JWT primitives for AP2 mandates (RFC 9901): strict compact parsing, disclosure processing, the `sd_hash` /
 * `issuer_jwt_hash` binding digests, and ES256 (P-256) signing and verification.
 *
 * No primitive is implemented here: SHA-2 comes from the platform and ECDSA from the BouncyCastle lightweight API (RFC 6979
 * deterministic nonces; the JWS `r || s` form is assembled by hand, so no DER is involved). The code is the SD-JWT format and it
 * fails closed on every ambiguity (duplicate digests, unreferenced disclosures, malformed base64url, duplicate JSON keys, unknown
 * `_sd_alg`, non-ES256 algorithms). JSON values are the core [Json] tree: Map, List, String, Boolean, [Json.Num], null.
 */
@Suppress("UNCHECKED_CAST")
object Sdjwt {
    // ---------------------------------------------------------------------------------------------
    // base64url + JSON helpers
    // ---------------------------------------------------------------------------------------------

    @JvmStatic fun b64uEncode(data: ByteArray): String = Ap2Js.b64u(data)

    @JvmStatic fun b64uEncode(s: String): String = b64uEncode(Ap2Js.utf8(s))

    private fun isB64uChar(c: Char): Boolean = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '_' || c == '-'

    /** Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip. */
    @JvmStatic
    fun b64uDecode(s: String, what: String): ByteArray {
        for (c in s) if (!isB64uChar(c)) throw Ap2Error("$what: not base64url")
        val buf = try {
            Ap2Js.unb64uLenient(s)
        } catch (e: IllegalArgumentException) {
            throw Ap2Error("$what: non-canonical base64url")
        }
        if (b64uEncode(buf) != s) throw Ap2Error("$what: non-canonical base64url")
        return buf
    }

    @JvmStatic fun isObject(v: Any?): Boolean = v is Map<*, *>

    /**
     * Reject an object that repeats a key: a plain parse keeps the last duplicate, which would let two parties read different
     * claims out of the same signed bytes. Run on text that already parsed, so only string/brace structure needs tracking.
     */
    internal fun assertNoDuplicateKeys(text: String, what: String) {
        val stack = ArrayList<HashSet<String>?>() // a null entry is an array
        var expectKey = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c == '"') {
                var j = i + 1
                while (text[j] != '"') j += if (text[j] == '\\') 2 else 1
                val top = if (stack.isEmpty()) null else stack[stack.size - 1]
                if (expectKey && top != null) {
                    val key = Json.parseLenient(text.substring(i, j + 1)) as String
                    if (!top.add(key)) throw Ap2Error("$what: duplicate key " + Ap2Js.stringify(key))
                    expectKey = false
                }
                i = j
            } else if (c == '{') {
                stack.add(HashSet())
                expectKey = true
            } else if (c == '[') {
                stack.add(null)
                expectKey = false
            } else if (c == '}' || c == ']') {
                if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
                expectKey = false
            } else if (c == ',') {
                expectKey = stack.isNotEmpty() && stack[stack.size - 1] != null
            }
            i++
        }
    }

    /**
     * JSON parse that rejects duplicate keys. Numbers are parsed as written (`1000.0` is accepted: the official Python SDK
     * serialises float fields that way). Objects enumerate their keys in ECMAScript order.
     */
    @JvmStatic
    fun parseJson(text: String, what: String): Any? {
        val v = try {
            Ap2Js.jsOrder(Json.parseLenient(text))
        } catch (e: IllegalArgumentException) {
            throw Ap2Error("$what: invalid JSON (${e.message})")
        }
        assertNoDuplicateKeys(text, what)
        return v
    }

    /** UTF-8 text of decoded bytes, FATAL on any invalid sequence. The BOM is kept, so the JSON parse refuses it. */
    internal fun utf8Text(bytes: ByteArray, what: String): String = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (e: CharacterCodingException) {
        throw Ap2Error("$what: not valid UTF-8")
    }

    internal fun decodeJsonSegment(segment: String, what: String): MutableMap<String, Any?> {
        val v = parseJson(utf8Text(b64uDecode(segment, what), what), what)
        if (v !is Map<*, *>) throw Ap2Error("$what: must be a JSON object")
        return Ap2Js.obj(v)
    }

    // ---------------------------------------------------------------------------------------------
    // hashing
    // ---------------------------------------------------------------------------------------------

    /** The `_sd_alg` values the AP2 reference SDK accepts: "sha-256", "sha-384", "sha-512". */
    @JvmStatic fun isSdAlg(v: Any?): Boolean = v == "sha-256" || v == "sha-384" || v == "sha-512"

    /** base64url(hash(ascii(value))): the digest used for disclosures, `sd_hash` and `checkout_hash`. */
    @JvmStatic
    @JvmOverloads
    fun sdDigest(value: String, alg: String = "sha-256"): String {
        for (c in value) if (c.code < 0x20 || c.code > 0x7e) throw Ap2Error("digest input must be ASCII")
        val name = when (alg) {
            "sha-256" -> "SHA-256"
            "sha-384" -> "SHA-384"
            "sha-512" -> "SHA-512"
            else -> throw IllegalArgumentException("unsupported hash $alg")
        }
        return b64uEncode(MessageDigest.getInstance(name).digest(value.toByteArray(StandardCharsets.US_ASCII)))
    }

    // ---------------------------------------------------------------------------------------------
    // ES256 keys (P-256)
    // ---------------------------------------------------------------------------------------------

    private val P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    private val X9 = CustomNamedCurves.getByName("secp256r1")
    private val DOMAIN = ECDomainParameters(X9.curve, X9.g, X9.n, X9.h)
    private val N: BigInteger = X9.n

    private fun b64u43(o: Any?): Boolean {
        if (o !is String || o.length != 43) return false
        for (c in o) if (!isB64uChar(c)) return false
        return true
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = Math.min(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }

    /** The public point of a (shape-checked) JWK; throws when the point is not on P-256. */
    private fun publicKey(jwk: Map<String, Any?>): ECPublicKeyParameters {
        try {
            val x = BigInteger(1, Ap2Js.unb64uLenient(jwk["x"] as String))
            val y = BigInteger(1, Ap2Js.unb64uLenient(jwk["y"] as String))
            if (x >= P || y >= P) throw Ap2Error("point out of range")
            val rhs = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(B).mod(P)
            if (y.multiply(y).mod(P) != rhs) throw Ap2Error("point not on the curve")
            return ECPublicKeyParameters(X9.curve.validatePoint(x, y), DOMAIN)
        } catch (e: RuntimeException) {
            throw Ap2Error("not a valid P-256 point")
        }
    }

    /** Validate a public JWK against `types/jwk.json` and prove the point is on the curve. */
    @JvmStatic
    fun assertP256Jwk(jwk: Any?, what: String): MutableMap<String, Any?> {
        if (jwk !is Map<*, *>) throw Ap2Error("$what: JWK must be an object")
        val j = Ap2Js.obj(jwk)
        if (j["kty"] != "EC" || j["crv"] != "P-256") throw Ap2Error("$what: JWK must be EC P-256")
        if (!b64u43(j["x"])) throw Ap2Error("$what: bad JWK x")
        if (!b64u43(j["y"])) throw Ap2Error("$what: bad JWK y")
        if (j.containsKey("d")) throw Ap2Error("$what: JWK carries private material")
        if (j.containsKey("alg") && j["alg"] != "ES256") throw Ap2Error("$what: JWK alg must be ES256")
        try {
            publicKey(j)
        } catch (e: Ap2Error) {
            throw Ap2Error("$what: JWK is not a valid P-256 point")
        }
        return j
    }

    /** A P-256 private key (the scalar never leaves this package). */
    class Ap2PrivateKey internal constructor(internal val d: BigInteger) {
        override fun toString(): String = "Ap2PrivateKey(P-256)"
    }

    /** A P-256 key pair: the public JWK (never carries `d`) and the private key. */
    class Ap2KeyPair(val publicJwk: MutableMap<String, Any?>, val privateKey: Ap2PrivateKey)

    private fun jwkOf(x: BigInteger, y: BigInteger, kid: String?): MutableMap<String, Any?> {
        val out = Ap2Js.m("kty" to "EC", "crv" to "P-256", "x" to b64uEncode(fixed32(x)), "y" to b64uEncode(fixed32(y)))
        if (kid != null) out["kid"] = kid
        return out
    }

    private val RANDOM = SecureRandom()

    @JvmStatic
    @JvmOverloads
    fun generateAp2KeyPair(kid: String? = null): Ap2KeyPair {
        var d: BigInteger
        do {
            d = BigInteger(256, RANDOM)
        } while (d.signum() <= 0 || d >= N)
        val q = X9.g.multiply(d).normalize()
        return Ap2KeyPair(jwkOf(q.affineXCoord.toBigInteger(), q.affineYCoord.toBigInteger(), kid), Ap2PrivateKey(d))
    }

    /**
     * Rebuild a key pair from a private JWK (`d` present, with `x` and `y`), e.g. for fixtures. The public point is derived from
     * `d`; a JWK whose `x`/`y` disagree with it is refused.
     */
    @JvmStatic
    fun ap2KeyPairFromPrivateJwk(jwk: Map<String, Any?>): Ap2KeyPair {
        if (jwk["kty"] != "EC" || jwk["crv"] != "P-256" || !b64u43(jwk["d"]) || !b64u43(jwk["x"]) || !b64u43(jwk["y"])) {
            throw Ap2Error("private JWK must be EC P-256 with d, x and y")
        }
        val d = BigInteger(1, Ap2Js.unb64uLenient(jwk["d"] as String))
        if (d.signum() <= 0 || d >= N) throw Ap2Error("private JWK: d is out of range")
        val q = X9.g.multiply(d).normalize()
        val x = q.affineXCoord.toBigInteger()
        val y = q.affineYCoord.toBigInteger()
        if (b64uEncode(fixed32(x)) != jwk["x"] || b64uEncode(fixed32(y)) != jwk["y"]) throw Ap2Error("private JWK: x/y do not match d")
        return Ap2KeyPair(jwkOf(x, y, jwk["kid"] as? String), Ap2PrivateKey(d))
    }

    /** RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key. */
    @JvmStatic
    fun jwkThumbprint(jwk: Any?): String {
        val canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + Ap2Js.str(Ap2Js.getU(jwk, "x")) + "\",\"y\":\"" + Ap2Js.str(Ap2Js.getU(jwk, "y")) + "\"}"
        return b64uEncode(MessageDigest.getInstance("SHA-256").digest(Ap2Js.utf8(canonical)))
    }

    private fun sha256(s: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(StandardCharsets.US_ASCII))

    /** ES256 over [signingInput]; returns the 64-byte `r || s` JWS signature as base64url. */
    internal fun es256Sign(privateKey: Ap2PrivateKey, signingInput: String): String {
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(privateKey.d, DOMAIN))
        val rs = signer.generateSignature(sha256(signingInput))
        val out = ByteArray(64)
        System.arraycopy(fixed32(rs[0]), 0, out, 0, 32)
        System.arraycopy(fixed32(rs[1]), 0, out, 32, 32)
        return b64uEncode(out)
    }

    internal fun es256Verify(jwk: Map<String, Any?>, signingInput: String, signature: ByteArray): Boolean {
        if (signature.size != 64) return false
        val pk = publicKey(jwk)
        return try {
            val r = BigInteger(1, signature.copyOfRange(0, 32))
            val s = BigInteger(1, signature.copyOfRange(32, 64))
            if (r.signum() <= 0 || s.signum() <= 0 || r >= N || s >= N) return false
            val v = ECDSASigner()
            v.init(false, pk)
            v.verifySignature(sha256(signingInput), r, s)
        } catch (e: RuntimeException) {
            false
        }
    }

    // ---------------------------------------------------------------------------------------------
    // compact JWT / SD-JWT parsing
    // ---------------------------------------------------------------------------------------------

    /** One SD-JWT: an issuer-signed JWT plus its disclosures (no trailing KB-JWT; AP2 binds with chain hops). */
    class SdJwtHop internal constructor(
        /** Canonical serialisation `<jwt>~<d1>~...~<dn>~`. */
        val raw: String,
        val jwt: String,
        val header: MutableMap<String, Any?>,
        /** The signed payload exactly as issued (digest placeholders still in place). */
        val payload: MutableMap<String, Any?>,
        val disclosures: List<String>,
        val sdAlg: String,
        val signingInput: String,
        val signature: ByteArray,
    )

    /** The hop's `~`-joined serialisation: what `sd_hash` is computed over. */
    @JvmStatic
    fun hopSdJwt(jwt: String, disclosures: List<String>): String {
        val sb = StringBuilder(jwt).append('~')
        for (d in disclosures) sb.append(d).append('~')
        return sb.toString()
    }

    @JvmStatic fun hopSdJwt(hop: SdJwtHop): String = hopSdJwt(hop.jwt, hop.disclosures)

    /** Parse one SD-JWT (`jwt~d1~...~dn~`). The serialisation must end with `~`. */
    @JvmStatic
    fun parseSdJwtHop(tokenObj: Any?): SdJwtHop {
        if (tokenObj !is String || tokenObj.isEmpty()) throw Ap2Error("SD-JWT: empty")
        val token: String = tokenObj
        if (token.startsWith("~")) throw Ap2Error("SD-JWT: empty issuer JWT")
        if (!token.endsWith("~")) throw Ap2Error("SD-JWT: must end with \"~\" (a trailing KB-JWT is not an AP2 form)")
        val parts = token.substring(0, token.length - 1).split("~")
        val jwt = parts[0]
        val disclosures = ArrayList(parts.subList(1, parts.size))
        for (d in disclosures) if (d.isEmpty()) throw Ap2Error("SD-JWT: empty disclosure segment")
        val seg = jwt.split(".")
        if (seg.size != 3 || seg[0].isEmpty() || seg[1].isEmpty() || seg[2].isEmpty()) throw Ap2Error("SD-JWT: issuer JWT must be header.payload.signature")
        val header = decodeJsonSegment(seg[0], "JWT header")
        val payload = decodeJsonSegment(seg[1], "JWT payload")
        val signature = b64uDecode(seg[2], "JWT signature")
        val rawAlg = payload["_sd_alg"]
        if (payload.containsKey("_sd_alg") && !isSdAlg(rawAlg)) throw Ap2Error("SD-JWT: unsupported _sd_alg " + Ap2Js.stringify(rawAlg))
        return SdJwtHop(token, jwt, header, payload, disclosures, if (isSdAlg(rawAlg)) rawAlg as String else "sha-256", seg[0] + "." + seg[1], signature)
    }

    /** `sd_hash` of a hop: the digest of `<jwt>~<d1>~...~` (the on-wire form of the preceding hop). */
    @JvmStatic @JvmOverloads fun sdHashOf(hop: SdJwtHop, alg: String = hop.sdAlg): String = sdDigest(hopSdJwt(hop), alg)

    /** `issuer_jwt_hash` of a hop: the digest of the issuer-signed JWT alone. */
    @JvmStatic @JvmOverloads fun issuerJwtHashOf(hop: SdJwtHop, alg: String = hop.sdAlg): String = sdDigest(hop.jwt, alg)

    /** Verify the issuer JWT's ES256 signature. Anything other than `alg: ES256` is rejected. */
    @JvmStatic
    fun verifyHopSignature(hop: SdJwtHop, key: Map<String, Any?>?): Boolean {
        if (hop.header["alg"] != "ES256") return false
        return es256Verify(assertP256Jwk(key, "verification key"), hop.signingInput, hop.signature)
    }

    // ---------------------------------------------------------------------------------------------
    // disclosure processing (RFC 9901 section 7)
    // ---------------------------------------------------------------------------------------------

    private class Disclosure(val property: Boolean, val name: String?, val value: Any?)

    private fun decodeDisclosure(raw: String): Disclosure {
        val arr = parseJson(utf8Text(b64uDecode(raw, "disclosure"), "disclosure"), "disclosure")
        if (arr !is List<*>) throw Ap2Error("disclosure: must be a JSON array")
        val a = arr
        if (a.isEmpty() || a[0] !is String || (a[0] as String).isEmpty()) throw Ap2Error("disclosure: salt must be a non-empty string")
        if (a.size == 3) {
            val name = a[1] as? String ?: throw Ap2Error("disclosure: claim name must be a string")
            if (name == "_sd" || name == "...") throw Ap2Error("disclosure: claim name $name is reserved")
            return Disclosure(true, name, a[2])
        }
        if (a.size == 2) return Disclosure(false, null, a[1])
        throw Ap2Error("disclosure: array must have 2 or 3 elements")
    }

    /**
     * Resolve every selectively-disclosable claim in [payload] using [disclosures]. Returns the processed claims (`_sd`, `...`
     * markers and `_sd_alg` removed). Throws if a disclosure is duplicated, is not referenced from the payload, collides with an
     * existing claim, or is used in the wrong position.
     */
    @JvmStatic
    fun processDisclosures(payload: Map<String, Any?>, disclosures: List<String>, alg: String): MutableMap<String, Any?> {
        val byDigest = HashMap<String, Disclosure>()
        for (raw in disclosures) {
            val d = decodeDisclosure(raw)
            val digest = sdDigest(raw, alg)
            if (byDigest.containsKey(digest)) throw Ap2Error("SD-JWT: duplicate disclosure")
            byDigest[digest] = d
        }
        val used = HashSet<String>()
        val result = Ap2Js.obj(walk(payload, 0, byDigest, used))
        if (used.size != byDigest.size) throw Ap2Error("SD-JWT: a disclosure is not referenced by the signed payload")
        return result
    }

    private fun take(digest: String, wantProperty: Boolean, byDigest: Map<String, Disclosure>, used: MutableSet<String>): Disclosure? {
        val d = byDigest[digest] ?: return null // decoy digest, or a disclosure the holder chose not to reveal
        if (used.contains(digest)) throw Ap2Error("SD-JWT: a digest is referenced more than once")
        if (d.property != wantProperty) {
            throw Ap2Error("SD-JWT: a " + (if (d.property) "property" else "element") + " disclosure is referenced from a " + (if (wantProperty) "property" else "element") + " position")
        }
        used.add(digest)
        return d
    }

    private fun walk(node: Any?, depth: Int, byDigest: Map<String, Disclosure>, used: MutableSet<String>): Any? {
        if (depth > 32) throw Ap2Error("SD-JWT: nesting too deep")
        if (node is List<*>) {
            val out = ArrayList<Any?>()
            for (el in node) {
                if (el is Map<*, *> && el.containsKey("...")) {
                    val dig = el["..."]
                    if (el.size != 1 || dig !is String) throw Ap2Error("SD-JWT: malformed array digest placeholder")
                    val d = take(dig, false, byDigest, used)
                    if (d != null) out.add(walk(d.value, depth + 1, byDigest, used))
                } else out.add(walk(el, depth + 1, byDigest, used))
            }
            return out
        }
        if (node is Map<*, *>) {
            val src = node as Map<String, Any?>
            val out = LinkedHashMap<String, Any?>()
            for ((k, v) in src) {
                if (k == "_sd" || k == "_sd_alg") continue
                if (k == "...") throw Ap2Error("SD-JWT: \"...\" is only valid as the sole key of an array element")
                out[k] = walk(v, depth + 1, byDigest, used)
            }
            if (src.containsKey("_sd")) {
                val sd = src["_sd"] as? List<*> ?: throw Ap2Error("SD-JWT: _sd must be an array of strings")
                for (x in sd) if (x !is String) throw Ap2Error("SD-JWT: _sd must be an array of strings")
                for (digest in sd) {
                    val d = take(digest as String, true, byDigest, used)
                    if (d == null || !d.property) continue
                    val name = d.name!!
                    if (out.containsKey(name)) throw Ap2Error("SD-JWT: disclosed claim $name collides with an existing claim")
                    out[name] = walk(d.value, depth + 1, byDigest, used)
                }
            }
            return out
        }
        return node
    }

    // ---------------------------------------------------------------------------------------------
    // issuing
    // ---------------------------------------------------------------------------------------------

    @JvmStatic
    fun newSalt(): String {
        val b = ByteArray(16)
        RANDOM.nextBytes(b)
        return b64uEncode(b)
    }

    /** Builds disclosures: each call appends one and returns the digest (or the `{"...": digest}` placeholder). */
    class DisclosureBuilder internal constructor(private val alg: String, private val salt: () -> String) {
        val disclosures: MutableList<String> = ArrayList()

        /** Array-element disclosure for [value]; returns the `{"...": digest}` placeholder. */
        fun element(value: Any?): MutableMap<String, Any?> {
            val raw = b64uEncode(Ap2Js.json(Ap2Js.l(salt(), value)))
            disclosures.add(raw)
            return Ap2Js.m("..." to sdDigest(raw, alg))
        }

        /** Property disclosure; returns the digest to put into the parent's `_sd`. */
        fun property(name: String, value: Any?): String {
            val raw = b64uEncode(Ap2Js.json(Ap2Js.l(salt(), name, value)))
            disclosures.add(raw)
            return sdDigest(raw, alg)
        }
    }

    /** [alg] defaults to sha-256 and [salt] to [newSalt] when null (tests inject a deterministic one). */
    @JvmStatic
    @JvmOverloads
    fun disclosureBuilder(alg: String? = null, salt: (() -> String)? = null): DisclosureBuilder =
        DisclosureBuilder(alg ?: "sha-256", salt ?: { newSalt() })

    private fun merged(head: Map<String, Any?>, over: Map<String, Any?>): MutableMap<String, Any?> {
        val out = LinkedHashMap(head)
        out.putAll(over)
        return out
    }

    /** Sign [payload] as an ES256 JWT and append [disclosures]: `<jwt>~<d1>~...~<dn>~`. */
    @JvmStatic
    fun signSdJwt(header: Map<String, Any?>, payload: Map<String, Any?>, disclosures: List<String>, privateKey: Ap2PrivateKey): String {
        val h = b64uEncode(Ap2Js.json(merged(Ap2Js.m("alg" to "ES256"), header)))
        val p = b64uEncode(Ap2Js.json(payload))
        val jwt = h + "." + p + "." + es256Sign(privateKey, "$h.$p")
        return hopSdJwt(jwt, disclosures)
    }

    /** Sign an arbitrary compact JWT (used for merchant-signed `checkout_jwt`). */
    @JvmStatic
    fun signJwtEs256(header: Map<String, Any?>, payload: Map<String, Any?>, privateKey: Ap2PrivateKey): String {
        val h = b64uEncode(Ap2Js.json(merged(Ap2Js.m("alg" to "ES256", "typ" to "JWT"), header)))
        val p = b64uEncode(Ap2Js.json(payload))
        return h + "." + p + "." + es256Sign(privateKey, "$h.$p")
    }

    /** A parsed compact JWT. */
    class ParsedJwt internal constructor(val header: MutableMap<String, Any?>, val payload: MutableMap<String, Any?>, val signingInput: String, val signature: ByteArray)

    @JvmStatic
    fun parseJwt(jwt: String, what: String): ParsedJwt {
        val seg = jwt.split(".")
        if (seg.size != 3 || seg[0].isEmpty() || seg[1].isEmpty() || seg[2].isEmpty()) throw Ap2Error("$what: must be header.payload.signature")
        val header = decodeJsonSegment(seg[0], "$what header")
        val payload = decodeJsonSegment(seg[1], "$what payload")
        return ParsedJwt(header, payload, seg[0] + "." + seg[1], b64uDecode(seg[2], "$what signature"))
    }

    @JvmStatic
    fun verifyJwtEs256(parsed: ParsedJwt, key: Map<String, Any?>?): Boolean {
        if (parsed.header["alg"] != "ES256") return false
        return es256Verify(assertP256Jwk(key, "verification key"), parsed.signingInput, parsed.signature)
    }
}
