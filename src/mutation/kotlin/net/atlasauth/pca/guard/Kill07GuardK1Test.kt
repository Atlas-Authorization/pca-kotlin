package net.atlasauth.pca.guard

import net.atlasauth.pca.guard.Kill06GuardKit.cfg
import net.atlasauth.pca.guard.Kill06GuardKit.decide
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.AuthorizeTestKit
import net.atlasauth.pca.verifier.CaveatLang
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** `authorize` mode hands the configured caveat-language input to the verifier: a presented-but-malformed narrow block refuses. */
class Kill07GuardK1Test {
    private val sc = GuardFixtures.within()

    private fun options(k1: CaveatLang.K1Input?) = Authorize.AuthorizeOptions(
        Authorize.MemoryStateStore(), { _, _ -> false }, insecureUnboundApproval = true, provenance = GuardFixtures.provenanceOptions, k1 = k1, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk,
    )

    @Test
    fun theConfiguredK1InputReachesTheVerifier() {
        assertTrue(decide(sc, cfg(sc, options(null))).allowed)
        val d = decide(sc, cfg(sc, options(CaveatLang.K1Input(narrow = null))))
        assertFalse(d.body, d.allowed)
        assertTrue(d.body, d.body.contains("narrow"))
    }
}
