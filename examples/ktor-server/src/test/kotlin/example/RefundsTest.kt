package example

import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.server.testing.testApplication
import java.util.Base64
import kotlinx.coroutines.runBlocking
import net.atlasauth.pca.ktor.Protected
import net.atlasauth.pca.verifier.ArgProvenance
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A grant and two signed proofs (a $50 and a $400 payment under a $100 limit) from the shared test vectors. */
@Suppress("UNCHECKED_CAST")
class RefundsTest {
    private val proofs = Json.parse(javaClass.getResource("/proofs.json")!!.readText()) as Map<String, Any?>
    private val grant = proofs["grant"] as Map<String, Any?>
    private val now = Json.asLong(proofs["now"])

    private fun proofHeader(case: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalize((proofs[case] as Map<String, Any?>)["pcactn"]).toByteArray())

    private fun proofBody(case: String): String = Json.canonicalize((proofs[case] as Map<String, Any?>)["body"])

    // the agent harness's recorder (its key pinned below): the payment the principal asked for, recorded principal-direct
    private fun recorder() = ArgProvenance.Recorder("conformance-harness", "k1", Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 1 })))

    private fun provenanceHeader(case: String): String = ArgProvenance.headerOf(
        ArgProvenance.principalDirect(recorder(), Authorize.Operation("payments.send", "payments/acme", Json.parse(proofBody(case)) as Map<String, Any?>)),
    )

    private fun withApp(block: suspend io.ktor.server.testing.ApplicationTestBuilder.(Protected) -> Unit) = runBlocking {
        val p = newProtection(listOf(grant), Authorize.ProvenanceOptions(listOf(recorder().pin))) { now }
        testApplication {
            application { refundsModule(p) }
            block(p)
        }
    }

    @Test
    fun aValidProofIsAllowed() = withApp {
        val r = client.post("/refunds") {
            header("PCA-Action", proofHeader("valid")); header("PCA-Provenance", provenanceHeader("valid")); setBody(proofBody("valid"))
        }
        assertEquals(r.bodyAsText(), 200, r.status.value)
        assertTrue(r.bodyAsText().contains("\"refunded\":true"))
    }

    @Test
    fun aProofWithoutProvenanceIsHeldForThePrincipal() = withApp {
        val r = client.post("/refunds") { header("PCA-Action", proofHeader("valid")); setBody(proofBody("valid")) }
        assertEquals(403, r.status.value)
        assertTrue(r.bodyAsText(), r.bodyAsText().contains("provenance_flow: escalate: "))
    }

    @Test
    fun aProofOverTheLimitIsRefusedWithADocLink() = withApp {
        val r = client.post("/refunds") {
            header("PCA-Action", proofHeader("overLimit")); header("PCA-Provenance", provenanceHeader("overLimit")); setBody(proofBody("overLimit"))
        }
        assertEquals(403, r.status.value)
        val doc = (Json.parse(r.bodyAsText()) as Map<String, Any?>)["doc"] as String
        assertEquals("https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#policy", doc)
    }

    @Test
    fun noProofIsRefused() = withApp {
        val r = client.post("/refunds") { setBody(proofBody("valid")) }
        assertEquals(401, r.status.value)
        assertTrue(r.headers["WWW-Authenticate"]!!.startsWith("PCA"))
    }

    @Test
    fun aRevokedGrantIsRefused() = withApp { p ->
        p.revoke(grant["id"] as String)
        val r = client.post("/refunds") {
            header("PCA-Action", proofHeader("valid")); header("PCA-Provenance", provenanceHeader("valid")); setBody(proofBody("valid"))
        }
        assertEquals(403, r.status.value)
    }
}
