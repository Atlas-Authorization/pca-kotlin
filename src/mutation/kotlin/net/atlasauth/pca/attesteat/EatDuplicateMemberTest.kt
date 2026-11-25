package net.atlasauth.pca.attesteat

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/** A repeated member in the EAT header or payload is refused before the signature is read (the canonical JWS gate parses both segments). */
class EatDuplicateMemberTest {
    private fun b64u(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
    private fun eat(header: String, payload: String) = b64u(header) + "." + b64u(payload) + "." + b64u("x".repeat(64))
    private val header = "{\"alg\":\"EdDSA\",\"typ\":\"${AttestEat.EAT_TYP}\"}"

    private fun refusal(t: String): String = try {
        AttestEat.verifyEAT(t, null)
        fail("accepted")
        ""
    } catch (e: IllegalArgumentException) {
        e.message!!
    }

    @Test fun aRepeatedPayloadMemberIsRefused() =
        assertEquals("EAT invalid: non-canonical compact JWS: bad-json (strict JSON: duplicate key \"iss\" (at offset 16))", refusal(eat(header, "{\"iss\":\"a\",\"iss\":\"b\",\"iat\":1}")))

    @Test fun aRepeatedHeaderMemberIsRefused() =
        assertEquals("EAT invalid: non-canonical compact JWS: bad-json (strict JSON: duplicate key \"alg\" (at offset 20))", refusal(eat("{\"alg\":\"EdDSA\",\"alg\":\"none\",\"typ\":\"${AttestEat.EAT_TYP}\"}", "{\"iss\":\"a\",\"iat\":1}")))
}
