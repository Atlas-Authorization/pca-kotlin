package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.AUD
import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.input
import net.atlasauth.pca.verifier.AuthorizeTestKit.op
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** H14 (a host callback that throws any non-fatal Throwable denies) and H18 (the guard's allowedSuites reaches the core verifier). */
class Kill14BContainmentAndSuitesTest {
    private val c = case("envelope-max-spend-within")
    private val throwables: List<() -> Throwable> = listOf(
        { AssertionError("x") }, { NoClassDefFoundError("x") }, { StackOverflowError() }, { IllegalStateException("x") },
    )

    @Test fun resolveGrantThrowing() {
        for (t in throwables) {
            val r = Authorize.authorize(pcactn(c), input(c, resolveGrant = { throw t() }))
            assertFalse(r.allow)
            assertEquals("resolve_grant: grant resolution failed (fail closed)", r.reason)
        }
    }

    @Test fun contextThrowing() {
        for (t in throwables) {
            val r = Authorize.authorize(pcactn(c), input(c, context = { throw t() }))
            assertEquals("context: the context callback failed (fail closed)", r.reason)
        }
    }

    @Test fun isRevokedThrowing() {
        for (t in throwables) {
            val r = Authorize.authorize(pcactn(c), input(c, isRevoked = { _, _ -> throw t() }))
            assertEquals("revocation: the revocation check failed (fail closed)", r.reason)
        }
    }

    @Test fun storeClaimThrowing() {
        for (t in throwables) {
            val store = object : Authorize.StateStore { override fun claim(key: String, counter: Long): Authorize.ClaimResult? = throw t() }
            assertFalse(Authorize.authorize(pcactn(c), input(c, stateStore = store)).allow)
        }
    }

    @Test fun anInternalAssertionErrorIsADenialAtTheOuterHandler() {
        val r = Authorize.authorize(pcactn(c), input(c, resolveGrant = { throw AssertionError("x") }))
        assertEquals(403, r.status)
    }

    @Test fun fatalErrorsAreNeverSwallowed() {
        assertThrows(OutOfMemoryError::class.java) { Authorize.authorize(pcactn(c), input(c, resolveGrant = { throw OutOfMemoryError() })) }
        assertThrows(OutOfMemoryError::class.java) { Authorize.authorize(pcactn(c), input(c, isRevoked = { _, _ -> throw OutOfMemoryError() })) }
        assertThrows(OutOfMemoryError::class.java) { Authorize.authorize(pcactn(c), input(c, context = { throw OutOfMemoryError() })) }
    }

    @Test fun guardAllowedSuites() {
        fun run(suites: List<String>?): Authorize.Result =
            Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, allowedSuites = suites, provenance = ProvHarness.options, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk)
                .run(pcactn(c), op(c), AUD, { grant(c) }, now = AuthorizeTestKit.NOW, provenance = ProvHarness.bundle(op(c)))
        assertTrue(run(null).reasons.toString(), run(null).allow)
        assertTrue(run(listOf("ed25519")).allow)
        for (denied in listOf(emptyList(), listOf("ml-dsa-65"))) {
            val r = run(denied)
            assertFalse(r.allow)
            assertTrue(r.reason, r.reason!!.contains("signature suite is not allowed by this verifier's suite policy"))
        }
    }

    @Test fun aBareGuardHasNoPlanAndDeniesPlanRootAuthorized() {
        fun run(plan: String?): Authorize.Result =
            Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), { _, _ -> false }, plan = plan, provenance = ProvHarness.options, risk = AuthorizeTestKit.calmRisk)
                .run(pcactn(c), op(c), AUD, { grant(c) }, now = AuthorizeTestKit.NOW, provenance = ProvHarness.bundle(op(c)))
        val bare = run(null)
        assertFalse(bare.allow)
        assertEquals("fail", bare.checks["plan_root_authorized"])
        assertTrue(bare.reasons.toString(), bare.reasons.contains(
            "plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)",
        ))
        assertTrue(run(Authorize.SINGLE_STEP).allow)
    }
}
