package net.atlasauth.pca.vc

import java.security.SecureRandom
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Test

/** A disclosure whose JSON text repeats a member is refused (a plain parse keeps the last); other number spellings stay accepted. Signed with a key generated here. */
class VcDuplicateMemberTest {
    private val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val pub = Keys.edFromSeed(seed).pub
    private val jwk = linkedMapOf<String, Any?>("kty" to "OKP", "crv" to "Ed25519", "x" to Jose.b64u(pub), "d" to Jose.b64u(seed))

    private fun b64u(s: String) = Jose.b64u(s.toByteArray(Charsets.UTF_8))
    private fun digest(d: String) = Jose.b64u(Jose.sha256(d.toByteArray(Charsets.US_ASCII)))

    private fun vcWith(disclosureText: String): String {
        val disclosure = b64u(disclosureText)
        val subject = linkedMapOf<String, Any?>(
            "id" to "did:example:s", "passport_id" to "p", "model_id" to "m", "operator" to "o", "hardware_rooted" to true,
            "issued_at" to Json.Num("1"), "_sd" to listOf(digest(disclosure)),
        )
        val vc = linkedMapOf<String, Any?>(
            "@context" to listOf(Vc.VC_CONTEXT, Vc.AGENT_PASSPORT_CONTEXT), "type" to listOf("VerifiableCredential", Vc.AGENT_PASSPORT_VC_TYPE),
            "credentialSubject" to subject,
        )
        val payload = linkedMapOf<String, Any?>("vc" to vc, "_sd_alg" to "sha-256", "iss" to "did:example:i", "sub" to "did:example:s")
        val jwt = Jose.signJwt(linkedMapOf<String, Any?>("alg" to "EdDSA", "typ" to "vc+sd-jwt"), payload, jwk)
        return "$jwt~$disclosure~"
    }

    @Test fun aRepeatedMemberInsideADisclosureIsRefused() {
        try {
            Vc.verifyPassportVC(vcWith("[\"s\",\"weights_digest\",{\"a\":1,\"a\":2}]"), pub, null)
            fail("accepted")
        } catch (e: IllegalArgumentException) {
            assertEquals("pca-vc: malformed disclosure", e.message)
        }
    }

    @Test fun nonCanonicalNumbersInADisclosureAreAccepted() {
        val r = Vc.verifyPassportVC(vcWith("[8.0,\"weights_digest\",\"dd\"]"), pub, null)
        assertEquals("dd", (r["passport"] as Map<*, *>)["weights_digest"])
        assertNotNull(Vc.verifyPassportVC(vcWith("[1e3,\"weights_digest\",\"dd\"]"), pub, null))
    }
}
