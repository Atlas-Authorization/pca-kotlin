package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** H16: stores declare their scope; multiInstance with a process-scoped store is refused at construction. */
class Kill14BMultiInstanceTest {
    private val shared = object : Authorize.StateStore { override fun claim(key: String, counter: Long): Authorize.ClaimResult? = null }
    private val msg = "multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)"

    @Test fun scopes() {
        assertEquals("process", Authorize.MemoryStateStore().scope)
        assertEquals("shared", shared.scope)
    }

    @Test fun processStoreWithMultiInstanceIsRefused() {
        val e = assertThrows(IllegalArgumentException::class.java) { Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), null, multiInstance = true, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk) }
        assertEquals(msg, e.message)
    }

    @Test fun sharedStoreAccepted() {
        assertTrue(Authorize.AuthorizeOptions(shared, null, multiInstance = true, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk).multiInstance)
    }

    @Test fun defaultFollowsTheStoreScope() {
        assertTrue(Authorize.AuthorizeOptions(shared, null, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk).multiInstance)
        assertFalse(Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), null, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk).multiInstance)
        assertFalse(Authorize.AuthorizeOptions(Authorize.MemoryStateStore(), null, multiInstance = false, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk).multiInstance)
        assertFalse(Authorize.AuthorizeOptions(shared, null, multiInstance = false, plan = Authorize.SINGLE_STEP, risk = AuthorizeTestKit.calmRisk).multiInstance)
    }
}
