package net.atlasauth.pca.webauthn

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Approval
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Phishing-resistant human co-sign for PCA step-up via WebAuthn / FIDO2: the server-side assertion verifier. The WebAuthn challenge is
 * the PCA step-up challenge (the action digest), so a valid assertion proves a human holding a hardware-bound credential approved THIS
 * action. Self-contained: ES256 (P-256, DER or raw r||s) and strict RFC 8032 EdDSA, SHA-256, and a minimal COSE_Key / CBOR reader.
 * Every verification entry point fails CLOSED and never throws on hostile input.
 *
 * The assertion, the expectations and the payment expectation are JSON-shaped maps with the reference's member names: byte members
 * are [ByteArray], JSON numbers are [Json.Num] (or any [Number]), `onSignCountRegression` is a `(Map<String, Any?>) -> Unit`. A member
 * of the wrong type fails the check that names it, as in the reference.
 */
@Suppress("UNCHECKED_CAST")
object Webauthn {
    /** Input size caps (bytes). */
    const val MAX_AUTHENTICATOR_DATA_BYTES = 4096
    const val MAX_CLIENT_DATA_BYTES = 8192
    const val MAX_SIGNATURE_BYTES = 1024

    private fun bytesEqual(a: ByteArray, b: ByteArray) = a.size == b.size && MessageDigest.isEqual(a, b)

    private fun asRecord(v: Any?) = v as? Map<String, Any?>

    /** Tolerant base64url (URL alphabet, optional padding, '+' and '/' accepted) -> bytes, strictly canonical; null when undecodable. */
    private fun base64urlToBytes(s: Any?): ByteArray? {
        if (s !is String) return null
        return Pca.decodeB64uStrict(s.replace(Regex("=+$"), "").replace('+', '-').replace('/', '_'), -1)
    }

    // ---- minimal COSE_Key / CBOR reader ----

    private class Item(val value: Any?, val next: Int) // Long | ByteArray | Map<Long, Any?>

    private fun u8(b: ByteArray, at: Int): Int {
        if (at < 0 || at >= b.size) throw IllegalArgumentException("Offset is outside the bounds of the DataView")
        return b[at].toInt() and 0xff
    }

    private fun readItem(b: ByteArray, offset: Int): Item {
        val initial = u8(b, offset)
        val major = initial shr 5
        val ai = initial and 0x1f
        var p = offset + 1
        val arg: Long = when {
            ai < 24 -> ai.toLong()
            ai == 24 -> u8(b, p).toLong().also { p += 1 }
            ai == 25 -> ((u8(b, p) shl 8) or u8(b, p + 1)).toLong().also { p += 2 }
            ai == 26 -> ((u8(b, p).toLong() shl 24) or (u8(b, p + 1).toLong() shl 16) or (u8(b, p + 2).toLong() shl 8) or u8(b, p + 3).toLong()).also { p += 4 }
            else -> throw IllegalArgumentException("cose: unsupported CBOR argument encoding (8-byte or indefinite length)")
        }
        return when (major) {
            0 -> Item(arg, p)
            1 -> Item(-1 - arg, p)
            2 -> {
                val end = p + arg
                if (end > b.size) throw IllegalArgumentException("cose: byte string length out of range")
                Item(b.copyOfRange(p, end.toInt()), end.toInt())
            }
            5 -> {
                val map = LinkedHashMap<Long, Any?>()
                var q = p
                var i = 0L
                while (i < arg) {
                    val key = readItem(b, q)
                    val k = key.value as? Long ?: throw IllegalArgumentException("cose: non-integer map key")
                    val v = readItem(b, key.next)
                    map[k] = v.value
                    q = v.next
                    i++
                }
                Item(map, q)
            }
            else -> throw IllegalArgumentException("cose: unsupported CBOR major type $major")
        }
    }

    private const val COSE_KTY = 1L
    private const val COSE_CRV = -1L
    private const val COSE_X = -2L
    private const val COSE_Y = -3L

    /**
     * Decodes a raw COSE_Key (an attested credential public key) into a JWK: ES256 (EC2 / P-256) or EdDSA (OKP / Ed25519), with `alg`.
     * Throws on malformed input or an unsupported key type.
     */
    @JvmStatic
    fun coseKeyToJwk(bytes: ByteArray?): Map<String, Any?> {
        if (bytes == null) throw IllegalArgumentException("coseKeyToJwk: expected a Uint8Array")
        val m = readItem(bytes, 0).value as? Map<Long, Any?> ?: throw IllegalArgumentException("coseKeyToJwk: COSE_Key is not a CBOR map")
        val kty = m[COSE_KTY]
        if (kty == 2L) {
            val x = m[COSE_X]
            val y = m[COSE_Y]
            if (m[COSE_CRV] != 1L) throw IllegalArgumentException("coseKeyToJwk: EC2 key is not P-256 (crv != 1)")
            if (x !is ByteArray || y !is ByteArray) throw IllegalArgumentException("coseKeyToJwk: EC2 key missing an x/y coordinate")
            if (x.size != 32 || y.size != 32) throw IllegalArgumentException("coseKeyToJwk: EC2 coordinate is not 32 bytes")
            return linkedMapOf("kty" to "EC", "crv" to "P-256", "x" to Jose.b64u(x), "y" to Jose.b64u(y), "alg" to "ES256")
        }
        if (kty == 1L) {
            val x = m[COSE_X]
            if (m[COSE_CRV] != 6L) throw IllegalArgumentException("coseKeyToJwk: OKP key is not Ed25519 (crv != 6)")
            if (x !is ByteArray) throw IllegalArgumentException("coseKeyToJwk: OKP key missing its public key")
            if (x.size != 32) throw IllegalArgumentException("coseKeyToJwk: Ed25519 public key is not 32 bytes")
            return linkedMapOf("kty" to "OKP", "crv" to "Ed25519", "x" to Jose.b64u(x), "alg" to "EdDSA")
        }
        throw IllegalArgumentException("coseKeyToJwk: unsupported COSE key type (kty=${kty ?: "undefined"})")
    }

    /** A credential key resolved to its signature algorithm and the bytes the verifier uses (ES256: 0x04 || X || Y; EdDSA: the key). */
    private class ResolvedKey(val alg: String, val raw: ByteArray)

    private fun resolveKey(pub: Any?): ResolvedKey {
        val jwk = if (pub is ByteArray) coseKeyToJwk(pub) else asRecord(pub)
        if (jwk == null) {
            if (pub == null) throw IllegalArgumentException("Cannot read properties of null (reading 'kty')")
            throw IllegalArgumentException("resolveKey: unsupported public key")
        }
        when (jwk["kty"]) {
            "EC" -> {
                if (jwk["crv"] != "P-256") throw IllegalArgumentException("resolveKey: EC JWK is not P-256")
                val x = base64urlToBytes(jwk["x"])
                val y = base64urlToBytes(jwk["y"])
                if (x == null || y == null || x.size != 32 || y.size != 32) throw IllegalArgumentException("resolveKey: invalid EC JWK coordinates")
                return ResolvedKey("ES256", byteArrayOf(4) + x + y)
            }
            "OKP" -> {
                if (jwk["crv"] != "Ed25519") throw IllegalArgumentException("resolveKey: OKP JWK is not Ed25519")
                val x = base64urlToBytes(jwk["x"])
                if (x == null || x.size != 32) throw IllegalArgumentException("resolveKey: invalid OKP JWK public key")
                return ResolvedKey("EdDSA", x)
            }
        }
        throw IllegalArgumentException("resolveKey: unsupported public key")
    }

    // ---- authenticatorData ----

    /** Parsed fixed header of authenticatorData: rpIdHash[32] || flags[1] || signCount[4]. */
    class ParsedAuthenticatorData internal constructor(val rpIdHash: ByteArray, flags: Int, val signCount: Long) {
        val up = flags and 0x01 != 0
        val uv = flags and 0x04 != 0
        val be = flags and 0x08 != 0
        val bs = flags and 0x10 != 0
        val at = flags and 0x40 != 0
        val ed = flags and 0x80 != 0

        internal fun flagsMap(): Map<String, Any?> = linkedMapOf("up" to up, "uv" to uv, "be" to be, "bs" to bs, "at" to at, "ed" to ed)

        /** `{rpIdHash, flags: {up, uv, be, bs, at, ed}, signCount}` as the reference returns it. */
        fun toMap(): Map<String, Any?> = linkedMapOf("rpIdHash" to rpIdHash, "flags" to flagsMap(), "signCount" to signCount)
    }

    /** Parses the fixed 37-byte header of authenticatorData; null when the buffer is missing or shorter than 37 bytes. */
    @JvmStatic
    fun parseAuthenticatorData(authData: ByteArray?): ParsedAuthenticatorData? {
        if (authData == null || authData.size < 37) return null
        val sc = ((authData[33].toLong() and 0xff) shl 24) or ((authData[34].toLong() and 0xff) shl 16) or
            ((authData[35].toLong() and 0xff) shl 8) or (authData[36].toLong() and 0xff)
        return ParsedAuthenticatorData(authData.copyOfRange(0, 32), authData[32].toInt() and 0xff, sc)
    }

    // ---- step-up challenge binding ----

    /**
     * The WebAuthn challenge bytes for a PCA step-up: `sha256(thresholdMessage(pcactn))`, the bytes whose base64url form is the FROST
     * action digest. Accepts a PCActn (or body) map, the base64url digest string, or raw 32-byte digest bytes; throws for a digest that is
     * not 32 bytes / not canonical base64url.
     */
    @JvmStatic
    fun buildStepUpChallenge(pcActnOrDigest: Any?): ByteArray {
        when (pcActnOrDigest) {
            is ByteArray -> {
                if (pcActnOrDigest.size != 32) throw IllegalArgumentException("buildStepUpChallenge: digest bytes must be 32 bytes")
                return pcActnOrDigest.clone()
            }
            is String -> return Pca.decodeB64uStrict(pcActnOrDigest, 32)
                ?: throw IllegalArgumentException("buildStepUpChallenge: digest is not a canonical base64url 32-byte value")
            null -> throw IllegalArgumentException("Cannot destructure null")
        }
        val body: Map<String, Any?> = when (pcActnOrDigest) {
            is Map<*, *> -> pcActnOrDigest as Map<String, Any?>
            // object rest of an array: its index members
            is List<*> -> LinkedHashMap<String, Any?>().also { b -> pcActnOrDigest.forEachIndexed { i, x -> b[i.toString()] = x } }
            else -> emptyMap() // a number or boolean has no own members
        }
        return Jose.sha256(Pca.thresholdMessage(body))
    }

    /** The challenge for an approval that commits to the canonical render: `SHA-256(domain || action_digest || H(R))`. */
    @JvmStatic
    fun buildApprovalChallenge(pcActnOrDigest: Any?, renderDigest: Any?): ByteArray = Keys.unb64u(approvalChallengeForActn(pcActnOrDigest, renderDigest))

    /** The base64url form of [buildApprovalChallenge]. */
    @JvmStatic
    fun approvalChallengeForActn(pcActnOrDigest: Any?, renderDigest: Any?): String =
        Approval.challenge(Jose.b64u(buildStepUpChallenge(pcActnOrDigest)), renderDigest)

    /** The base64url step-up challenge (the FROST `action_digest`) for a PCActn / body / digest. */
    @JvmStatic
    fun stepUpChallengeB64u(pcActnOrDigest: Any?): String = Jose.b64u(buildStepUpChallenge(pcActnOrDigest))

    // ---- Secure Payment Confirmation ----

    /** Null if the signed payment data equals the expectation (`topOrigin`, `total`, payee). Total over hostile `payment`. */
    @JvmStatic
    fun spcPaymentError(payment: Any?, e: Map<String, Any?>?, rpId: String?): String? {
        val p = asRecord(payment) ?: return "clientData.payment is missing"
        if (e == null) throw IllegalArgumentException("Cannot use 'in' operator to search for 'payeeName' in undefined")
        if (!e.containsKey("payeeName") && !e.containsKey("payeeOrigin")) return "the expectation names no payee (refused: a payment approval must bind the payee)"
        val pr = p["rpId"]
        if (pr !is String || pr != rpId) return "clientData.payment.rpId is not the verifier rpId"
        if (!same(p, "topOrigin", e, "topOrigin")) return "clientData.payment.topOrigin is not the verifier approval origin"
        val total = asRecord(p["total"]) ?: return "clientData.payment.total does not equal the canonical render"
        val et = asRecord(e["total"]) ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'currency')")
        if (!same(total, "currency", et, "currency") || !same(total, "value", et, "value")) return "clientData.payment.total does not equal the canonical render"
        for (k in listOf("payeeName", "payeeOrigin")) {
            if (e.containsKey(k) && !same(p, k, e, k)) return "clientData.payment.$k does not equal the canonical render"
        }
        return null
    }

    /** `a[ka] === b[kb]` for JSON values: both absent is equal, one absent is not, primitives by value, objects never. */
    private fun same(a: Map<String, Any?>, ka: String, b: Map<String, Any?>, kb: String): Boolean {
        val pa = a.containsKey(ka)
        val pb = b.containsKey(kb)
        if (!pa || !pb) return !pa && !pb
        val x = a[ka]
        val y = b[kb]
        if (x is String && y is String) return x == y
        if (x == null && y == null) return true
        if (x is Boolean && y is Boolean) return x == y
        val dx = Js.num(x)
        val dy = Js.num(y)
        return dx != null && dy != null && dx == dy
    }

    // ---- ECDSA P-256 ----

    private val N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    private fun pad32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        val out = ByteArray(32)
        if (b.size > 32) System.arraycopy(b, b.size - 32, out, 0, 32) else System.arraycopy(b, 0, out, 32 - b.size, b.size)
        return out
    }

    /** Strict DER ECDSA signature (single-byte total length, minimal positive INTEGERs, no trailing bytes) -> (r, s); null when invalid. */
    private fun parseDer(d: ByteArray): Pair<BigInteger, BigInteger>? {
        if (d.size < 2 || d[0].toInt() and 0xff != 0x30 || d[1].toInt() and 0xff != d.size - 2) return null
        val pos = intArrayOf(2)
        val r = derInt(d, pos) ?: return null
        val s = derInt(d, pos) ?: return null
        if (pos[0] != d.size) return null
        return r to s
    }

    private fun derInt(d: ByteArray, pos: IntArray): BigInteger? {
        val i = pos[0]
        if (d.size - i < 2 || d[i].toInt() and 0xff != 0x02) return null
        val len = d[i + 1].toInt() and 0xff
        if (len == 0 || i + 2 + len > d.size) return null
        val b0 = d[i + 2].toInt() and 0xff
        if (b0 and 0x80 != 0) return null
        if (b0 == 0 && len > 1 && d[i + 3].toInt() and 0x80 == 0) return null
        if (b0 == 0 && len == 1) {
            pos[0] = i + 3
            return BigInteger.ZERO
        }
        pos[0] = i + 2 + len
        return BigInteger(1, d.copyOfRange(i + 2, i + 2 + len))
    }

    private fun verifyEs256(sig: ByteArray, msg: ByteArray, rawPoint: ByteArray, lowS: Boolean, der: Boolean): Boolean = try {
        val rs = if (der) parseDer(sig) else if (sig.size == 64) BigInteger(1, sig.copyOfRange(0, 32)) to BigInteger(1, sig.copyOfRange(32, 64)) else null
        if (rs == null) {
            false
        } else {
            val (r, s) = rs
            if (r.signum() == 0 || s.signum() == 0 || r >= N || s >= N) {
                false
            } else if (lowS && s > N.shiftRight(1)) {
                false
            } else {
                val jwk = linkedMapOf<String, Any?>(
                    "kty" to "EC", "crv" to "P-256", "x" to Jose.b64u(rawPoint.copyOfRange(1, 33)), "y" to Jose.b64u(rawPoint.copyOfRange(33, 65)),
                )
                Jose.verifySignature("ES256", jwk, pad32(r) + pad32(s), msg)
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    // ---- assertion verification ----

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    private fun errMsg(e: RuntimeException) = e.message ?: "unknown"

    /**
     * Verifies a WebAuthn / FIDO2 assertion as a human step-up co-sign. `assertion`: `authenticatorData`, `clientDataJSON`, `signature`
     * (ByteArray) and `publicKey` (a JWK map or a raw COSE_Key ByteArray). `expect`: `expectedChallenge` (ByteArray or base64url String),
     * `rpId`, `origins` (list), `requireUV`, `requireLowS`, `storedSignCount` (required), `onSignCountRegression`, `rejectCrossOrigin`,
     * `payment`. Returns `{ok:true, alg, signCount, flags}` or `{ok:false, reason}`; never throws.
     */
    @JvmStatic
    fun verifyAssertion(assertion: Map<String, Any?>, expect: Map<String, Any?>): Map<String, Any?> = try {
        verifyInner(assertion, expect)
    } catch (e: RuntimeException) {
        fail("verification error (fail closed): ${errMsg(e)}")
    }

    private fun verifyInner(assertion: Map<String, Any?>, expect: Map<String, Any?>): Map<String, Any?> {
        val authenticatorData = assertion["authenticatorData"] as? ByteArray ?: return fail("authenticatorData is not bytes")
        val clientDataJSON = assertion["clientDataJSON"] as? ByteArray ?: return fail("clientDataJSON is not bytes")
        val signature = assertion["signature"] as? ByteArray ?: return fail("signature is not bytes")
        if (authenticatorData.size > MAX_AUTHENTICATOR_DATA_BYTES) return fail("authenticatorData is too large")
        if (clientDataJSON.size > MAX_CLIENT_DATA_BYTES) return fail("clientDataJSON is too large")
        if (signature.size > MAX_SIGNATURE_BYTES) return fail("signature is too large")
        val rpId = expect["rpId"] as? String
        if (rpId == null || rpId.isEmpty()) return fail("rpId is required")
        val origins = expect["origins"] as? List<*>
        if (origins == null || origins.isEmpty()) return fail("origins allowlist is empty")
        if (!expect.containsKey("storedSignCount")) return fail("storedSignCount is required (use 0 for a credential never used)")
        val spc = expect.containsKey("payment")

        // clientDataJSON (TextDecoder: fatal UTF-8, a leading BOM is consumed)
        var clientText = try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(clientDataJSON)).toString()
        } catch (e: CharacterCodingException) {
            return fail("clientDataJSON is not valid UTF-8")
        }
        if (clientText.startsWith("﻿")) clientText = clientText.substring(1)
        val clientParsed = try {
            Json.parseNoDuplicates(clientText)
        } catch (e: RuntimeException) {
            return fail("clientDataJSON is not valid JSON")
        }
        val client = asRecord(clientParsed) ?: return fail("clientDataJSON is not a JSON object")
        val wantType = if (spc) "payment.get" else "webauthn.get"
        if (client["type"] != wantType) return fail("clientData.type is not \"$wantType\" (${if (client.containsKey("type")) Js.template(client["type"]) else "undefined"})")
        if (spc) spcPaymentError(client["payment"], asRecord(expect["payment"]), rpId)?.let { return fail(it) }

        val gotChallenge = Pca.decodeB64uStrict(client["challenge"], -1) ?: return fail("clientData.challenge is missing or not canonical base64url")
        val ec = expect["expectedChallenge"]
        val expChallenge = (ec as? ByteArray ?: Pca.decodeB64uStrict(ec, -1)) ?: return fail("expectedChallenge is not decodable")
        if (!bytesEqual(gotChallenge, expChallenge)) return fail("clientData.challenge does not match the step-up challenge")

        val origin = client["origin"]
        if (expect["rejectCrossOrigin"] != false) {
            val co = client["crossOrigin"]
            if (co == true) return fail("clientData.crossOrigin is true")
            if (client.containsKey("crossOrigin") && co != false) return fail("clientData.crossOrigin is not a boolean")
        }
        if (origin !is String) return fail("clientData.origin is missing")
        if (!origins.contains(origin)) return fail("clientData.origin \"$origin\" is not in the allowlist")

        // authenticatorData
        val parsed = parseAuthenticatorData(authenticatorData) ?: return fail("authenticatorData is too short (< 37 bytes)")
        if (!bytesEqual(parsed.rpIdHash, Jose.sha256(Jose.utf8(rpId)))) return fail("rpIdHash does not match sha256(rpId)")
        if (!parsed.up) return fail("User Present (UP) flag is not set")
        if (Js.truthy(expect["requireUV"]) && !parsed.uv) return fail("User Verified (UV) flag is required but not set")

        // signature over authenticatorData || sha256(clientDataJSON)
        val signedData = authenticatorData + Jose.sha256(clientDataJSON)
        val key = try {
            resolveKey(assertion["publicKey"])
        } catch (e: RuntimeException) {
            return fail("public key could not be resolved: ${errMsg(e)}")
        }
        val valid = if (key.alg == "ES256") {
            val isDer = signature.isNotEmpty() && signature[0].toInt() and 0xff == 0x30 && signature.size != 64
            verifyEs256(signature, signedData, key.raw, expect["requireLowS"] == true, isDer)
        } else {
            Jose.verifyEd25519Strict(key.raw, signedData, signature)
        }
        if (!valid) return fail("assertion signature did not verify")

        // signature counter (clone detection), only after the signature verified
        val stored = Js.num(expect["storedSignCount"])
        if (stored == null || stored != Math.rint(stored) || stored.isInfinite() || stored < 0 || Js.isNegZero(stored) || stored > 4294967295.0) {
            return fail("storedSignCount is not a uint32")
        }
        if ((parsed.signCount != 0L || stored != 0.0) && parsed.signCount <= stored) {
            (expect["onSignCountRegression"] as? Function1<Map<String, Any?>, Any?>)
                ?.invoke(linkedMapOf("storedSignCount" to expect["storedSignCount"], "reportedSignCount" to parsed.signCount))
            return fail("signCount did not increase (possible cloned authenticator)")
        }
        return linkedMapOf("ok" to true, "alg" to key.alg, "signCount" to parsed.signCount, "flags" to parsed.flagsMap())
    }
}
