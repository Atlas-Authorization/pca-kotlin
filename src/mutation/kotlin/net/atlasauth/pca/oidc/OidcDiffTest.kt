package net.atlasauth.pca.oidc

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Base64
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.Jws
import net.atlasauth.pca.oauth.Fetch
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/** Replays the TypeScript-reference vectors of the OIDC package (discovery, ID-token verification, principal, JWKS resolver). */
@Suppress("UNCHECKED_CAST")
class OidcDiffTest {
    private val m = "ref-oidc-java"

    /** An exception that carries the reference's stable code, as the replay helper compares it. */
    class Coded(val code: String) : RuntimeException(code)

    private fun mm(o: Any?) = o as Map<String, Any?>

    private fun verifyOpts(opts: Map<String, Any?>?): Map<String, Any?>? {
        if (opts == null) return null
        val o = LinkedHashMap(opts)
        if (o.containsKey("jwks")) o["key"] = Jws.localJwks(o.remove("jwks"))
        return o
    }

    private fun respond(r: Map<String, Any?>): Fetch.Response {
        if (r.containsKey("throws")) throw java.io.IOException("net")
        val status = Js.num(r["status"])!!.toInt()
        return Fetch.Response(status in 200..299, status, r["contentLength"] as String?, r["text"] as String)
    }

    @Test fun discoveryUrl() = OracleCases.each(m, "discoveryUrl") { Oidc.discoveryUrl(it[0] as String) }

    @Test fun discoverOidc() = OracleCases.each(m, "discoverOidc") { a ->
        if (a[0] !is String) throw OidcDiscoveryError("issuer must be a string")
        val resp = mm(a[2])
        val o = LinkedHashMap(mm(a[1])).also { it["fetch"] = Fetch { _, _, _ -> respond(resp) } }
        Oidc.discoverOidc(a[0] as String, o)
    }

    @Test fun verifyIdToken() = OracleCases.each(m, "verifyIdToken") { a ->
        if (a[0] !is String) throw Coded("invalid_token")
        try {
            Oidc.verifyIdToken(a[0] as String, verifyOpts(a[1] as Map<String, Any?>?)) { net.atlasauth.pca.verifier.BaseOracle.clockLong("$m.json.gz") }
        } catch (e: OidcVerificationError) {
            throw Coded(e.code)
        }
    }

    @Test fun oidcPrincipal() = OracleCases.each(m, "oidcPrincipal") { Oidc.oidcPrincipal(mm(it[0]), if (it.size > 1) it[1] as Map<String, Any?>? else null) }

    @Test fun isOidcSubjectCaveat() = OracleCases.each(m, "isOidcSubjectCaveat") { Oidc.isOidcSubjectCaveat(it[0]) }

    @Test fun jwksScenario() = OracleCases.each(m, "jwksScenario") { a ->
        var cur = 0L
        var fetches = 0
        var queue: Any? = null
        val o = LinkedHashMap<String, Any?>()
        o["jwksUri"] = "https://idp.example.com/jwks"
        o.putAll(mm(a[0]))
        o["fetch"] = Fetch { _, _, _ ->
            fetches++
            val q = queue
            if (q == null || q == "throw") throw java.io.IOException("net")
            val st = Js.num(mm(q)["status"])!!.toInt()
            Fetch.Response(st in 200..299, st, null, mm(q)["text"] as String)
        }
        o["now"] = { cur }
        val r = Oidc.createOidcJwks(o)
        (a[1] as List<*>).map { s ->
            val step = mm(s)
            cur = Js.num(step["t"])!!.toLong()
            queue = step["resp"]
            val res = Js.obj()
            try {
                r.getKey(mm(step["header"]))
                res["fetches"] = Js.n(fetches.toLong())
                res["ok"] = true
            } catch (e: OidcVerificationError) {
                res["fetches"] = Js.n(fetches.toLong())
                res["ok"] = false
                res["code"] = e.code
            } catch (e: RuntimeException) {
                res["fetches"] = Js.n(fetches.toLong())
                res["ok"] = false
                res["code"] = "other"
            }
            res
        }
    }

    // ---- RSA and RSA-PSS (their signatures are randomized or need a fresh key, so no shared vector) ----

    private fun b64u(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun rsaToken(alg: String, kp: KeyPair, kid: String): String {
        val h = b64u("{\"alg\":\"$alg\",\"kid\":\"$kid\"}".toByteArray())
        val p = b64u("{\"iss\":\"https://idp.example.com\",\"sub\":\"u\",\"aud\":\"c\",\"iat\":1700000000,\"exp\":4000000000}".toByteArray())
        val s = if (alg.startsWith("PS")) {
            Signature.getInstance("RSASSA-PSS").also { it.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)) }
        } else Signature.getInstance("SHA256withRSA")
        s.initSign(kp.private)
        s.update("$h.$p".toByteArray())
        return "$h.$p." + b64u(s.sign())
    }

    private fun unsigned(b: ByteArray) = if (b.size > 1 && b[0].toInt() == 0) b.copyOfRange(1, b.size) else b

    private fun code(f: () -> Unit): String {
        try { f() } catch (e: OidcVerificationError) { return e.code }
        fail("expected an OidcVerificationError")
        return ""
    }

    @Test fun rsaAndPssTokensVerify() {
        val kp = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.generateKeyPair()
        val pub = kp.public as RSAPublicKey
        val jwk = Js.obj("kty" to "RSA", "kid" to "r1", "n" to b64u(unsigned(pub.modulus.toByteArray())), "e" to b64u(unsigned(pub.publicExponent.toByteArray())))
        val opts = Js.obj("issuer" to "https://idp.example.com", "audience" to "c", "key" to Jws.localJwks(Js.obj("keys" to listOf(jwk))))
        for (alg in listOf("RS256", "PS256")) assertEquals("u", Oidc.verifyIdToken(rsaToken(alg, kp, "r1"), opts)["sub"])
        val tampered = rsaToken("RS256", kp, "r1")
        val at = tampered.length - 10
        val bad = tampered.substring(0, at) + (if (tampered[at] == 'A') 'B' else 'A') + tampered.substring(at + 1)
        assertEquals("signature", code { Oidc.verifyIdToken(bad, opts) })
        val only = LinkedHashMap(opts).also { it["algorithms"] = listOf("ES256") }
        assertEquals("invalid_token", code { Oidc.verifyIdToken(rsaToken("RS256", kp, "r1"), only) })
    }
}
