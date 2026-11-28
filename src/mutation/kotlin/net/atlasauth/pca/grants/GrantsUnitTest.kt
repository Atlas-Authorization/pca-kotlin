package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.MemoryAtomicKv
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.atomic.AtomicReference

/** The I/O wrappers the oracle cannot reach: the lease store conformance kit and the grant client. */
class GrantsUnitTest {
    @Test fun leaseStoreConformanceMemory() {
        val passed = LeaseStoreConformance.runLeaseStoreConformance(object : LeaseStoreConformance.Kit {
            override fun open(): AtomicKv = MemoryAtomicKv()
            override fun reopen(kv: AtomicKv): AtomicKv? = kv
            override fun supportsReopen(): Boolean = true
        })
        assertEquals(listOf("spread", "atomic update", "independent leases", "revocation placement", "shard count is pinned", "state survives a restart", "pruning bounds revocations"), passed)
    }

    @Test fun grantClientCarriesFreshToken() {
        val signer = Keys.edFromSeed(ByteArray(32))
        val state = linkedMapOf<String, Any?>("revocation_epoch" to 2L, "ledger_tree_size" to 3L, "budget_version" to 4L, "policy_revision" to 5L, "policy_digest" to "pd")
        val tok = Issue.signFreshAt(signer, "scope", state, 1_800_000_000_000L)
        val seenHeader = AtomicReference<String?>()
        MockWebServer().use { srv ->
            srv.dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    val path = request.path ?: ""
                    if (path.startsWith("/pca/grants/missing")) return MockResponse().setResponseCode(404).setBody("{\"error\":\"not_found\",\"message\":\"no such grant\"}")
                    seenHeader.set(request.getHeader("pca-fresh-at"))
                    return MockResponse().setResponseCode(200).addHeader("pca-fresh-at", Json.canonicalize(tok)).setBody("{\"grants\":[]}")
                }
            }
            srv.start()
            val base = srv.url("/").toString()
            val c = GrantClient(base, freshSigner = signer.id())
            assertNull(c.freshAt())
            assertTrue(c.list(mapOf("status" to "active"))["grants"] is List<*>)
            assertNull(seenHeader.get())
            assertNotNull(c.freshAt())
            c.list()
            assertNotNull(seenHeader.get())
            try {
                c.inspect("missing")
                fail("expected an ApiError")
            } catch (e: GrantClient.ApiError) {
                assertEquals(404, e.status)
                assertEquals("not_found", e.code)
            }
            // a token that does not verify under the pinned signer is ignored
            val strict = GrantClient(base, freshSigner = Keys.edFromSeed(ByteArray(32) { (it + 1).toByte() }).id())
            strict.list()
            assertNull(strict.freshAt())
        }
    }
}
