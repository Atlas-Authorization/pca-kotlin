package net.atlasauth.pca.payments

import net.atlasauth.pca.verifier.Budgets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** encodeURIComponent throws (URIError) on a lone surrogate: two scope ids or token refs must never share one percent-encoded key. */
class UriEncodeLoneSurrogateTest {
    @Test
    fun budgetScopeKeyRefusesALoneSurrogate() {
        assertThrows(IllegalArgumentException::class.java) { Budgets.scopeKey("principal", "a\uD800b") }
        assertThrows(IllegalArgumentException::class.java) { Budgets.scopeKey("principal", "a\uDC00b") }
        assertEquals("principal/a%F0%9F%98%80", Budgets.scopeKey("principal", "a😀"))
    }

    @Test
    fun networkTokenRefEncodingRefusesALoneSurrogate() {
        assertThrows(IllegalArgumentException::class.java) { NetworkToken.encodeUriComponent("tok\uD800") }
        assertThrows(IllegalArgumentException::class.java) { NetworkToken.encodeUriComponent("\uDFFFtok") }
        assertEquals("tok%20%C3%A9", NetworkToken.encodeUriComponent("tok é"))
    }
}
