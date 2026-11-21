package net.atlasauth.pca.idjag

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.Jws
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Test

/** Replays the TypeScript-reference vectors of the ID-JAG / cross-app-access package. */
@Suppress("UNCHECKED_CAST")
class IdJagDiffTest {
    private val m = "ref-idjag-java"

    private fun mm(o: Any?) = o as Map<String, Any?>
    private fun opt(a: List<Any?>, i: Int) = if (a.size > i) a[i] as Map<String, Any?>? else null

    @Test fun verifyIdJag() = OracleCases.each(m, "verifyIdJag") { a ->
        val consumed = ArrayList<Any?>()
        val out = Js.obj()
        try {
            val opts = (a[1] as Map<String, Any?>?)?.let { LinkedHashMap(it) }
            if (opts != null) {
                val jwks = opts.remove("jwks")
                val consume = opts.remove("consume")
                if (jwks != null) opts["key"] = Jws.localJwks(jwks)
                if (consume != null) {
                    opts["consumeJti"] = JtiStore { jti, exp ->
                        consumed.add(listOf(jti, exp))
                        when (consume) {
                            "throws" -> throw IllegalStateException("store down")
                            "seen" -> false
                            "truthy" -> 1
                            else -> true
                        }
                    }
                }
            }
            if (a[0] !is String) throw IdJagVerificationError("invalid_token", "jwt must be a non-empty string")
            out["grant"] = IdJag.verifyIdJag(a[0] as String, opts)
            out["ok"] = true
        } catch (e: IdJagVerificationError) {
            out["ok"] = false
            out["code"] = e.code
        } catch (e: RuntimeException) {
            out["ok"] = false
            out["code"] = "other"
        }
        out["consumed"] = consumed
        out
    }

    @Test fun idJagToPcaPrincipal() = OracleCases.each(m, "idJagToPcaPrincipal") { IdJag.idJagToPcaPrincipal(mm(it[0]), opt(it, 1)) }

    @Test fun idJagToCapability() = OracleCases.each(m, "idJagToCapability") { a ->
        val o = (a[1] as Map<String, Any?>?)?.let { LinkedHashMap(it) }
        if (o != null && o.containsKey("principalSecretLabel")) o["principalSecret"] = OracleCases.seed(o.remove("principalSecretLabel") as String)
        IdJag.idJagToCapability(a[0] as Map<String, Any?>?, o)
    }

    @Test fun isIdJagAuthorityCaveat() = OracleCases.each(m, "isIdJagAuthorityCaveat") { IdJag.isIdJagAuthorityCaveat(it[0]) }
    @Test fun isIdJagProvenanceCaveat() = OracleCases.each(m, "isIdJagProvenanceCaveat") { IdJag.isIdJagProvenanceCaveat(it[0]) }
    @Test fun readIdJagAuthority() = OracleCases.each(m, "readIdJagAuthority") { IdJag.readIdJagAuthority(it[0]) }
    @Test fun readIdJagProvenance() = OracleCases.each(m, "readIdJagProvenance") { IdJag.readIdJagProvenance(it[0]) }
    @Test fun tokenExchangeRequest() = OracleCases.each(m, "tokenExchangeRequest") { IdJag.tokenExchangeRequest(it[0] as Map<String, Any?>?) }
    @Test fun jwtBearerAssertion() = OracleCases.each(m, "jwtBearerAssertion") { IdJag.jwtBearerAssertion(it[0] as Map<String, Any?>?) }

    @Test fun constants() {
        assertEquals("urn:ietf:params:oauth:grant-type:token-exchange", IdJag.GRANT_TYPE_TOKEN_EXCHANGE)
        assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", IdJag.GRANT_TYPE_JWT_BEARER)
        assertEquals("urn:ietf:params:oauth:token-type:id-jag", IdJag.TOKEN_TYPE_ID_JAG)
        assertEquals("urn:ietf:params:oauth:token-type:id_token", IdJag.TOKEN_TYPE_ID_TOKEN)
        assertEquals("urn:ietf:params:oauth:token-type:access_token", IdJag.TOKEN_TYPE_ACCESS_TOKEN)
        assertEquals("urn:ietf:params:oauth:token-type:jwt", IdJag.TOKEN_TYPE_JWT)
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", IdJag.CLIENT_ASSERTION_TYPE_JWT_BEARER)
        assertEquals("idjag_authority", IdJag.IDJAG_AUTHORITY_CAVEAT)
        assertEquals("idjag_provenance", IdJag.IDJAG_PROVENANCE_CAVEAT)
        assertEquals(16384, IdJag.MAX_ID_JAG_CHARS)
    }
}
