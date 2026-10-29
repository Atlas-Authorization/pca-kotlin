package net.atlasauth.pca.ktor

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.guard.PCA_DOCS
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.guard.explainRefusal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** `protect()` end to end, and `explainRefusal()` over the reasons the guard really produces. */
class ProtectTest {
    private fun run(p: Protected, block: suspend io.ktor.server.testing.ApplicationTestBuilder.() -> Unit) = runBlocking {
        testApplication {
            application {
                routing { route("/pay") { install(PcaGuardPlugin, p.configure); get("/send") { call.respondText("ran") } } }
            }
            block()
        }
    }

    @Test
    fun defaultsAllowAValidProofOnceAndRefuseItsReplay() {
        val sc = GuardFixtures.within()
        val p = protect(sc.audience, listOf(sc.grant), provenance = GuardFixtures.provenanceOptions, customize = { clock = { sc.now } }) { _, _ -> sc.operation }
        run(p) {
            val ok = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }
            assertEquals(ok.bodyAsText(), 200, ok.status.value)
            val again = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }
            assertEquals(403, again.status.value)
            val body = GuardFixtures.parse(again.bodyAsText())
            assertTrue(body.toString(), (body["reason"] as String).startsWith("replay"))
            assertEquals("$PCA_DOCS/reference/refusals.md#replay", body["doc"])
        }
    }

    @Test
    fun aGrantLookupFunctionWorksAndAnUnknownGrantIsRefused() {
        val sc = GuardFixtures.within()
        val p = protect(sc.audience, { _: String -> null }, provenance = GuardFixtures.provenanceOptions, customize = { clock = { sc.now } }) { _, _ -> sc.operation }
        run(p) {
            val r = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }
            assertTrue(r.status.value == 401 || r.status.value == 403)
        }
    }

    @Test
    fun revokeRefusesEveryFurtherActionUnderTheGrant() {
        val sc = GuardFixtures.within()
        val p = protect(sc.audience, listOf(sc.grant), provenance = GuardFixtures.provenanceOptions, customize = { clock = { sc.now } }) { _, _ -> sc.operation }
        p.revoke(sc.grant["id"] as String)
        run(p) {
            val r = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }
            assertEquals(403, r.status.value)
            assertEquals("$PCA_DOCS/reference/refusals.md#revocation", GuardFixtures.parse(r.bodyAsText())["doc"])
        }
    }

    @Test
    fun anExtraRevocationSourceIsConsulted() {
        val sc = GuardFixtures.within()
        val p = protect(sc.audience, listOf(sc.grant), isRevoked = { true }, provenance = GuardFixtures.provenanceOptions, customize = { clock = { sc.now } }) { _, _ -> sc.operation }
        run(p) { assertEquals(403, client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }.status.value) }
    }

    @Test
    fun theOperationComesFromTheRouteNotTheProof() {
        val sc = GuardFixtures.otherVerb()
        val p = protect(sc.audience, listOf(sc.grant), provenance = GuardFixtures.provenanceOptions, customize = { clock = { sc.now } }) { _, _ -> sc.operation }
        run(p) { assertEquals(403, client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }.status.value) }
    }

    @Test
    fun callerOptionsWin() {
        val sc = GuardFixtures.within()
        val p = protect(sc.audience, listOf(sc.grant), provenance = GuardFixtures.provenanceOptions, customize = { clock = { sc.now }; audience = "other-server" }) { _, _ -> sc.operation }
        run(p) { assertTrue(client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }.status.value in listOf(401, 403)) }
    }

    @Test
    fun provenanceIsOnByDefault() {
        val sc = GuardFixtures.within()
        // no PCA-Provenance: a payment whose choice and values are not shown to come from the principal is held, never run
        val p = protect(sc.audience, listOf(sc.grant), provenance = GuardFixtures.provenanceOptions, customize = { clock = { sc.now } }) { _, _ -> sc.operation }
        run(p) {
            val r = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header) }
            assertEquals(403, r.status.value)
            val body = GuardFixtures.parse(r.bodyAsText())
            assertTrue(body.toString(), (body["reason"] as String).startsWith("provenance_flow: escalate: "))
            // a header that does not decode fails closed
            val bad = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, "not base64url!") }
            assertEquals(403, bad.status.value)
            assertTrue(bad.bodyAsText(), bad.bodyAsText().contains("the provenance bundle is unreadable (fail closed)"))
            // the same proof with the recorder's bundle runs (the refusals above spent nothing)
            val ok = client.get("/pay/send") { header(PcaGuard.HEADER, sc.header); header(PcaGuard.PROVENANCE_HEADER, sc.provenanceHeader) }
            assertEquals(ok.bodyAsText(), 200, ok.status.value)
        }
    }

    @Test
    fun explainRefusalMapsTheLeadingCheck() {
        val h = explainRefusal("operation: verb mismatch")
        assertEquals("operation", h.check)
        assertEquals("The signed action is not the operation this route executes (other verb, resource or params).", h.meaning)
        assertEquals("$PCA_DOCS/reference/refusals.md#operation", h.docs)
        assertEquals("authorize_config", explainRefusal("authorize_config: missing required component(s): stateStore").check)
        assertEquals("$PCA_DOCS/guides/resource-server-quickstart.md", explainRefusal("authorize_config: x").docs)
        assertEquals("wire", explainRefusal("wire: bad").check)
        assertEquals("threshold", explainRefusal("something threshold: late").check)
    }

    @Test
    fun explainRefusalProvenanceAndUndo() {
        val p = explainRefusal("provenance_flow: escalate: the choice of payments.send derives from untrusted content")
        assertEquals("provenance_flow", p.check)
        assertEquals("$PCA_DOCS/guides/prompt-injection-provenance.md", p.docs)
        assertTrue(p.fix.contains("PCA-Provenance"))
        val u = explainRefusal("undo_window: runs now under a veto window until 1 (compensation payments.refund)")
        assertEquals("undo_window", u.check)
        assertEquals("$PCA_DOCS/guides/undo-windows.md", u.docs)
        assertTrue(u.fix.contains("undo coordinator"))
    }

    @Test
    fun explainRefusalNeverThrowsAndFallsBackToTheTable() {
        for (r in listOf(null, 42, "", "NOT lowercase", "zzz: unknown")) {
            val h = explainRefusal(r)
            assertEquals("unknown", h.check)
            assertEquals("$PCA_DOCS/reference/refusals.md", h.docs)
        }
    }
}
