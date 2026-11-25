package net.atlasauth.pca.sdjwt

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** present() runs the canonical compact-JWS gate on the issuer JWT first: a repeated member and a non-canonical number (8.0, 1e3) are refused there; a canonical 8 is accepted. */
class SdjwtDuplicateMemberTest {
    private fun b64u(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
    private fun sdjwt(payload: String) = b64u("{\"alg\":\"EdDSA\"}") + "." + b64u(payload) + "." + b64u("x".repeat(64)) + "~"

    private fun refusal(t: String): String = try {
        Sdjwt.present(t, emptyList<Any?>(), null)
        fail("accepted")
        ""
    } catch (e: RuntimeException) {
        e.message!!
    }

    @Test fun aRepeatedMemberIsRefusedByTheGate() =
        assertEquals("non-canonical compact JWS: bad-json (strict JSON: duplicate key \"_sd\" (at offset 15))", refusal(sdjwt("{\"_sd\":[],\"_sd\":[\"x\"]}")))

    @Test fun nonCanonicalNumbersAreRefusedByTheGate() {
        for (n in listOf("8.0", "1e3")) assertTrue(n, refusal(sdjwt("{\"a\":$n,\"_sd\":[]}")).startsWith("non-canonical compact JWS: bad-json (strict JSON: "))
    }

    @Test fun aCanonicalNumberIsAccepted() {
        val t = sdjwt("{\"a\":8,\"_sd\":[]}")
        assertEquals(t, Sdjwt.present(t, emptyList<Any?>(), null))
    }
}
