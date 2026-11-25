package net.atlasauth.pca.a2a

import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js

/**
 * Detached-payload flattened JWS for A2A Agent Cards and AgentFacts attestations. Keys are JWK maps. Profiles: the legacy detached
 * profile (`b64:false`, `crit:["b64"]`) and the A2A 1.0 section 8.4 profile (payload base64url in the signing input, `typ:"JOSE"`).
 * Verification gates the protected and signature segments for canonical spelling first, then applies the header rules (`alg`, `crit`,
 * `b64`) and key selection (single key, or a JWKS matched by `kid` / `alg` / `kty`).
 */
@Suppress("UNCHECKED_CAST")
object A2aJws {
    /** Sign [payload]; returns `{protected, signature}`. [header] members follow `kid` in the protected header. */
    @JvmStatic
    fun signDetached(payload: ByteArray, jwk: Map<String, Any?>, alg: String, kid: String?, standardPayload: Boolean, header: Map<String, Any?>?): Map<String, Any?> {
        val prot = LinkedHashMap<String, Any?>()
        prot["alg"] = alg
        if (standardPayload) prot["typ"] = "JOSE"
        else {
            prot["b64"] = false
            prot["crit"] = arrayListOf<Any?>("b64")
        }
        if (kid != null) prot["kid"] = kid
        if (header != null) prot.putAll(header)
        val protectedB64 = Jose.b64u(Jose.utf8(Jose.stringify(prot)))
        val input = signingInput(protectedB64, payload, standardPayload)
        // importJWK(jwk, alg) takes the algorithm from the argument; a different `alg` member of the JWK is not compared
        val sig = Jose.signRaw(alg, LinkedHashMap(jwk).also { it.remove("alg") }, input)
        val out = LinkedHashMap<String, Any?>()
        out["protected"] = protectedB64
        out["signature"] = Jose.b64u(sig)
        return out
    }

    private fun signingInput(protectedB64: String, payload: ByteArray, b64: Boolean): ByteArray {
        val p = if (b64) Jose.b64u(payload).toByteArray(Charsets.US_ASCII) else payload
        val h = "$protectedB64.".toByteArray(Charsets.US_ASCII)
        return h + p
    }

    /** What a verify call resolves its key from. */
    class Resolver internal constructor(
        internal val key: Map<String, Any?>?, // a single JWK (null when a JWKS is used)
        internal val jwks: List<Any?>?, // the JWKS keys (null when a single key is used)
        internal val alg: String?, // importJWK algorithm for a single key
        internal val invalid: Boolean, // a key that is not a JWK: no signature verifies under it
    )

    /** [error] non-null: key resolution failed (the message). */
    class Resolved internal constructor(val resolver: Resolver?, val error: String?)

    /**
     * Resolve the verification key. [jwks] (a parsed JWKS, truthy) wins over [key]; neither: "no verification key or JWKS supplied".
     * [key] must be a JWK map (an object with `kty`); [alg] is the importJWK algorithm (default EdDSA).
     */
    @JvmStatic
    fun resolveVerifyKey(jwks: Any?, key: Any?, alg: String?): Resolved {
        if (Js.truthy(jwks)) {
            val ks = (jwks as? Map<String, Any?>)?.get("keys") as? List<Any?> ?: return Resolved(null, "could not resolve verification key: JSON Web Key Set malformed")
            for (k in ks) if (k !is Map<*, *>) return Resolved(null, "could not resolve verification key: JSON Web Key Set malformed")
            return Resolved(Resolver(null, ks, null, false), null)
        }
        if (key != null) {
            if (key !is Map<*, *> || !key.containsKey("kty")) return Resolved(Resolver(null, null, null, true), null)
            val jwk = key as Map<String, Any?>
            val kty = jwk["kty"]
            if (kty !is String) return Resolved(null, "could not resolve verification key: JWK must have a kty")
            if (kty != "oct") { // importJWK fails at resolve time for a key that cannot be imported at all
                val probe = when (kty) {
                    "OKP" -> "EdDSA"
                    "RSA" -> "RS256"
                    "EC" -> when (jwk["crv"]) { "P-384" -> "ES384"; "P-521" -> "ES512"; else -> "ES256" }
                    else -> "EdDSA"
                }
                try {
                    Jose.verifySignature(probe, jwk, ByteArray(64), ByteArray(0))
                } catch (e: Jose.JoseException) {
                    return Resolved(null, "could not resolve verification key: " + e.message)
                }
            }
            return Resolved(Resolver(jwk, null, alg ?: "EdDSA", false), null)
        }
        return Resolved(null, "no verification key or JWKS supplied")
    }

    /** [ok] false: [reason] says why (the library's wording is not reproduced); [protectedHeader] when ok. */
    class Result internal constructor(val ok: Boolean, val reason: String?, val protectedHeader: Map<String, Any?>?)

    private fun fail(why: String) = Result(false, why, null)

    /** Verify a detached-payload JWS ([sig] = `{protected, signature}`) over [payload]. Never throws. */
    @JvmStatic
    fun verifyDetached(payload: ByteArray, sig: Any?, resolver: Resolver): Result {
        try {
            val sm = sig as? Map<String, Any?>
            val prot = sm?.get("protected") as? String
            val sg = sm?.get("signature") as? String
            if (prot == null || sg == null) return fail("signature is malformed")
            // canonical-spelling gate BEFORE the JOSE rules (a payload segment of one byte stands in: only the two segments are gated)
            if (prot.length + sg.length > Jose.DEFAULT_MAX_JWS_BYTES) return fail("non-canonical compact JWS: too-long")
            val gate = Jose.assertCanonicalCompactJws("$prot.AA.$sg", 3, Int.MAX_VALUE, false)
            val header = gate.header
            val algO = header["alg"]
            if (algO !is String || algO.isEmpty()) return fail("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")
            val alg: String = algO
            var b64 = true
            if (header.containsKey("crit")) {
                val crit = header["crit"]
                if (crit !is List<*> || crit.isEmpty()) return fail("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present")
                var b64Listed = false
                for (c in crit) {
                    if (c !is String || c.isEmpty()) return fail("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present")
                    if (c != "b64") return fail("Extension Header Parameter \"$c\" is not recognized")
                    if (!header.containsKey("b64")) return fail("Extension Header Parameter \"b64\" is missing")
                    b64Listed = true
                }
                if (b64Listed) {
                    val b = header["b64"]
                    if (b !is Boolean) return fail("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean")
                    b64 = b
                }
            }
            // the payload the caller hands over: raw bytes under a header that says b64:false, else base64url text
            val rawGiven = header["b64"] == false
            if (b64 && rawGiven) return fail("JWS Payload must be a string")
            if (resolver.invalid) throw Jose.JoseException("Key must be a key object")
            val jwk = pickKey(resolver, alg, header)
            val signature = Jose.decodeCanonicalBase64url(sg)
            val ok = Jose.verifySignature(alg, jwk, signature, signingInput(prot, payload, b64))
            return if (ok) Result(true, null, header) else fail("signature verification failed")
        } catch (e: Jose.JoseException) {
            return fail(e.message ?: "invalid")
        } catch (e: Jose.CanonicalJwsError) {
            return fail(e.message ?: "invalid")
        } catch (e: RuntimeException) {
            return fail("signature verification failed")
        }
    }

    private fun ktyOf(alg: String): String {
        if (alg.startsWith("RS") || alg.startsWith("PS")) return "RSA"
        if (alg.startsWith("ES")) return "EC"
        if (alg == "EdDSA") return "OKP"
        throw Jose.JoseException("Unsupported \"alg\" value for a JSON Web Key Set")
    }

    private fun crvOf(alg: String): String? = when (alg) {
        "ES256" -> "P-256"
        "ES384" -> "P-384"
        "ES512" -> "P-521"
        else -> null
    }

    private fun pickKey(r: Resolver, alg: String, header: Map<String, Any?>): Map<String, Any?> {
        if (r.jwks == null) return r.key!!
        val kty = ktyOf(alg)
        val kid = header["kid"] as? String
        val cand = ArrayList<Map<String, Any?>>()
        for (o in r.jwks) {
            val k = o as Map<String, Any?>
            var c = kty == k["kty"]
            if (c && kid != null) c = kid == k["kid"]
            if (c && k["alg"] is String) c = alg == k["alg"]
            if (c && k["use"] is String) c = "sig" == k["use"]
            if (c && k["key_ops"] is List<*>) c = (k["key_ops"] as List<*>).contains("verify")
            if (c) {
                if (alg == "EdDSA") c = k["crv"] == "Ed25519" || k["crv"] == "Ed448"
                else if (crvOf(alg) != null) c = crvOf(alg) == k["crv"]
            }
            if (c) cand.add(k)
        }
        if (cand.isEmpty()) throw Jose.JoseException("no applicable key found in the JSON Web Key Set")
        if (cand.size != 1) throw Jose.JoseException("multiple matching keys found in the JSON Web Key Set")
        return cand[0]
    }
}
