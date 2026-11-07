package net.atlasauth.pca.ktor

import net.atlasauth.pca.guard.GuardFixtures
import net.atlasauth.pca.verifier.Authorize
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** `protect()` read straight off the configuration it builds: every default, the grant lookup and the revocation hook. */
@Suppress("UNCHECKED_CAST")
class Kill06KtorProtectTest {
    private val op = Authorize.Operation("v.x", "r:1", emptyMap<String, Any?>())
    private val g1: Map<String, Any?> = mapOf("id" to "g1", "n" to 1)
    private val g2: Map<String, Any?> = mapOf("id" to "g2", "n" to 2)

    private fun built(p: Protected): PcaKtorConfig = PcaKtorConfig().also { p.configure(it) }

    private fun revoked(c: PcaKtorConfig, grant: Map<String, Any?>): Any? = c.authorize!!.isRevoked!!.invoke(emptyMap(), grant)

    @Test
    fun allDefaultsOfTheListOverload() {
        val c = built(protect("aud", listOf(g1, g2)) { _, _ -> op })
        assertEquals("aud", c.audience)
        assertSame(g1, c.resolveGrant!!("g1"))
        assertSame(g2, c.resolveGrant!!("g2"))
        assertNull(c.resolveGrant!!("g3"))
        assertNotNull(c.operation)
        val az = c.authorize!!
        assertTrue(az.stateStore is Authorize.MemoryStateStore)
        assertEquals(Authorize.SINGLE_STEP, az.plan)
        assertNull(az.provenance)
        assertNull(az.context)
        assertTrue(az.require.isEmpty())
        assertFalse(az.insecureUnboundApproval)
        assertEquals(false, revoked(c, g1))
        assertFalse(c.signatureOnly)
        assertNull(c.executor)
    }

    @Test
    fun allDefaultsOfTheLookupOverload() {
        val c = built(protect("aud2", { ref: String -> if (ref == "x") g1 else null }) { _, _ -> op })
        assertEquals("aud2", c.audience)
        assertSame(g1, c.resolveGrant!!("x"))
        assertNull(c.resolveGrant!!("y"))
        val az = c.authorize!!
        assertTrue(az.stateStore is Authorize.MemoryStateStore)
        assertEquals(Authorize.SINGLE_STEP, az.plan)
        assertNull(az.provenance)
        assertEquals(false, revoked(c, g2))
    }

    @Test
    fun theGivenOptionsAreCarriedInEveryDefaultCombination() {
        val prov = GuardFixtures.provenanceOptions
        val seen = ArrayList<String>()
        // provenance only
        assertSame(prov, built(protect("a", listOf(g1), provenance = prov) { _, _ -> op }).authorize!!.provenance)
        assertSame(prov, built(protect("a", { _: String -> null }, provenance = prov) { _, _ -> op }).authorize!!.provenance)
        // customize only
        val cz = built(protect("a", listOf(g1), customize = { seen.add("list"); audience = "custom" }) { _, _ -> op })
        assertEquals("custom", cz.audience)
        val cz2 = built(protect("a", { _: String -> null }, customize = { seen.add("fn"); audience = "custom2" }) { _, _ -> op })
        assertEquals("custom2", cz2.audience)
        assertEquals(listOf("list", "fn"), seen)
        // isRevoked only
        assertEquals(true, revoked(built(protect("a", listOf(g1), isRevoked = { true }) { _, _ -> op }), g1))
        assertEquals(true, revoked(built(protect("a", { _: String -> null }, isRevoked = { true }) { _, _ -> op }), g1))
        // all three
        val all = built(protect("a", listOf(g1), { false }, { seen.add("all") }, prov) { _, _ -> op })
        assertSame(prov, all.authorize!!.provenance)
        assertEquals(false, revoked(all, g1))
        assertEquals("all", seen.last())
        val all2 = built(protect("a", { _: String -> g1 }, { false }, { seen.add("all2") }, prov) { _, _ -> op })
        assertSame(prov, all2.authorize!!.provenance)
        assertEquals("all2", seen.last())
    }

    @Test
    fun customizeRunsLastSoItsOptionsWin() {
        val replaced = Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, null)
        val c = built(protect("aud", listOf(g1), customize = { authorize = replaced; audience = "mine" }) { _, _ -> op })
        assertSame(replaced, c.authorize)
        assertEquals("mine", c.audience)
        assertNull(c.authorize!!.plan)
    }

    @Test
    fun theReplayStoreIsPerInstall() {
        val p = protect("aud", listOf(g1)) { _, _ -> op }
        val a = built(p).authorize!!.stateStore
        val b = built(p).authorize!!.stateStore
        assertNotSame(a, b)
    }

    @Test
    fun aListedGrantWithoutAStringIdIsIgnoredAndTheRestStillResolve() {
        val noId: Map<String, Any?> = mapOf("n" to 3)
        val numeric: Map<String, Any?> = mapOf("id" to 5, "n" to 4)
        val nullId: Map<String, Any?> = mapOf("id" to null, "n" to 5)
        val c = built(protect("aud", listOf(noId, numeric, nullId, g1)) { _, _ -> op })
        assertSame(g1, c.resolveGrant!!("g1"))
        assertNull(c.resolveGrant!!("5"))
        assertNull(c.resolveGrant!!("null"))
        assertNull(c.resolveGrant!!(""))
    }

    @Test
    fun theRevocationHookTreatsARevokedIdAndTheExtraSourceAsOr() {
        val calls = ArrayList<Map<String, Any?>>()
        val p = protect("aud", listOf(g1, g2), isRevoked = { g -> calls.add(g); g["id"] == "g2" }) { _, _ -> op }
        val c = built(p)
        // nothing revoked yet: the extra source decides, and it is handed the grant itself
        assertEquals(false, revoked(c, g1))
        assertEquals(1, calls.size)
        assertSame(g1, calls[0])
        assertEquals(true, revoked(c, g2))
        assertEquals(2, calls.size)
        // revoked by id: true without needing the extra source
        p.revoke("g1")
        assertEquals(true, revoked(c, g1))
        assertEquals(2, calls.size)
        // the revoke set is shared by every install of this Protected
        assertEquals(true, revoked(built(p), g1))
    }

    @Test
    fun withoutAnExtraSourceOnlyTheRevokedIdsAreRevoked() {
        val p = protect("aud", listOf(g1, g2)) { _, _ -> op }
        val c = built(p)
        assertEquals(false, revoked(c, g1))
        assertEquals(false, revoked(c, mapOf("n" to 9)))
        assertEquals(false, revoked(c, mapOf("id" to 7)))
        p.revoke("g2")
        assertEquals(true, revoked(c, g2))
        assertEquals(false, revoked(c, g1))
        // a revoked id never matches a grant with a non-string id
        p.revoke("7")
        assertEquals(false, revoked(c, mapOf("id" to 7)))
    }

    @Test
    fun theConfigureLambdaReturnsUnit() {
        val f = protect("aud", listOf(g1)) { _, _ -> op }.configure as (Any?) -> Any?
        assertSame(Unit, f(PcaKtorConfig()))
    }
}
