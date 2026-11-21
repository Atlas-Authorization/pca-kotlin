package net.atlasauth.pca.verifier

import net.atlasauth.pca.durable.DurableStateOptions
import net.atlasauth.pca.durable.openDurableState
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.op
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/** The state stores over an atomic kv and the build-once authorizer. */
class AuthorizersTest {
    private val c = case("envelope-predicate-within")

    private fun options(store: Authorize.StateStore) = Authorize.AuthorizeOptions(
        stateStore = store, isRevoked = { _, _ -> false }, plan = Authorize.SINGLE_STEP, provenance = ProvHarness.options, risk = AuthorizeTestKit.calmRisk,
    )

    private fun stores(): List<Authorize.StateStore> = listOf(
        memoryPcaStore(), durablePcaStateStore(MemoryAtomicKv()),
        durablePcaStateStore(openDurableState(DurableStateOptions(Files.createTempDirectory("pca-kvstate").toFile().path))),
    )

    @Test fun claimsAreMonotoneAndAtomicOnEveryStore() {
        for (s in stores()) {
            assertTrue(s.claim("k", 5)!!.ok)
            val again = s.claim("k", 5)!!
            assertFalse(again.ok)
            assertEquals(5L, again.lastCounter)
            assertFalse(s.claim("k", 4)!!.ok)
            assertTrue(s.claim("k", 6)!!.ok)
            assertEquals(6L, (s as Authorize.LastStore).last("k"))
            assertNull(s.let { it as Authorize.LastStore }.last("other"))
            assertTrue(isAtomicPcaStateStore(s))
        }
    }

    @Test fun consumeOnceHoldsUntilTheHorizon() {
        for (s in stores()) {
            assertTrue(s.consumeOnce("u", 100, 10))
            assertFalse(s.consumeOnce("u", 50, 20)) // live: refused, and the horizon is not shortened
            assertFalse(s.consumeOnce("u", 150, 99)) // still live (100 >= 99): refused, horizon raised to 150
            assertFalse(s.consumeOnce("u", 160, 120)) // live (150 >= 120): refused, horizon raised to 160
            assertFalse(s.consumeOnce("u", 300, 160)) // live at exactly the horizon: refused, horizon raised to 300
            assertTrue(s.consumeOnce("u", 500, 301)) // expired: consumable again
        }
    }

    @Test fun budgetsCompareAndSwap() {
        for (s in stores().filterIsInstance<Authorize.BudgetStore>()) {
            assertNull(s.budget("g:h"))
            val b1 = Risk.Budget(10.0, 5.0)
            assertTrue(s.budgetCas("g:h", null, b1))
            assertFalse(s.budgetCas("g:h", null, b1))
            assertEquals(b1, s.budget("g:h"))
            val b2 = Risk.Budget(7.5, 5.0, 9.0)
            assertTrue(s.budgetCas("g:h", b1, b2))
            assertFalse(s.budgetCas("g:h", b1, b2))
            assertEquals(b2, s.budget("g:h"))
        }
    }

    @Test fun anAuthorizerBuiltOnceAllowsOnceAndRefusesTheReplay() {
        for (s in stores()) {
            val az = createAuthorizer(options(s), AuthorizeTestKit.AUD) { grant(c) }
            val first = az.authorize(pcactn(c), op(c), now = AuthorizeTestKit.NOW, provenance = ProvHarness.bundle(op(c)))
            assertTrue(first.reasons.toString(), first.allow)
            val replay = az.authorize(pcactn(c), op(c), now = AuthorizeTestKit.NOW, provenance = ProvHarness.bundle(op(c)))
            assertFalse(replay.allow)
        }
    }

    @Test fun anAuthorizerWithoutItsComponentsRefusesAndNamesThem() {
        val az = createAuthorizer(Authorize.AuthorizeOptions(null, null), null, null)
        val r = az.authorize(pcactn(c), op(c))
        assertFalse(r.allow)
        assertEquals(403, r.status)
        assertTrue(r.reason!!, r.reason!!.contains("authorize_config"))
    }
}
