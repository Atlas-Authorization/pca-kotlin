package net.atlasauth.pca.ktor

import net.atlasauth.pca.verifier.Authorize
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** `protect()`'s grant index never holds a grant under a missing id (not even under the null key). */
@Suppress("UNCHECKED_CAST")
class Kill07KtorProtectTest {
    @Test
    fun aGrantWithoutAStringIdIsNotIndexedUnderTheNullKey() {
        val op = Authorize.Operation("v.x", "r:1", emptyMap<String, Any?>())
        val noId: Map<String, Any?> = mapOf("n" to 3)
        val g1: Map<String, Any?> = mapOf("id" to "g1")
        val c = PcaKtorConfig().also { protect("aud", listOf(noId, g1)) { _, _ -> op }.configure(it) }
        // a lambda has no parameter null check: an absent grant_ref reaches the lookup as null and must find nothing
        val lookup = c.resolveGrant as ((String?) -> Map<String, Any?>?)
        // protect$lambda carries Kotlin's parameter null check, so the null key can only be reached through the map's own lookup
        assertNull(runCatching { lookup(null) }.getOrNull())
        assertSame(g1, lookup("g1"))
    }
}
