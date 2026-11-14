package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for Lease.kt after the durable-store rewrite (Registry over AtomicKv): the shard hash, the shard-count and
 * shard-index bounds, the pinned shard-count meta document, the default and injected clock behind the revocation pruning, the fatal-error
 * rethrow, a store whose documents are not the expected shape, and the number of leases a revocation covers.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K1LeaseTest {
    private val K = "k08k1-lease/authority"
    private val AUTH = pub(K)
    private val BODY = listOf(
        "v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at",
        "renewed_at", "expires_at", "max_ttl", "authority",
    )
    private val REV = listOf("v", "target", "value", "revoked_at", "authority")

    private fun rec(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = jm(
            "v", 1L, "lease_id", "L1", "path", "db/prod", "grant_ref", "g1", "holder", "H", "requester", "R", "approvers", jl("A1"),
            "justification_digest", "j1", "seq", 1L, "issued_at", 1000L, "renewed_at", 1000L, "expires_at", 2000L, "max_ttl", 5000L,
            "authority", AUTH,
        )
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        val body = LinkedHashMap<String, Any?>()
        for (k in BODY) body[k] = m[k]
        m["sig"] = sign(K, IntentJs.message(Lease.DOMAIN, body))
        return m
    }

    private fun rev(target: String, value: String, revokedAt: Long): LinkedHashMap<String, Any?> {
        val m = jm("v", 1L, "target", target, "value", value, "revoked_at", revokedAt, "authority", AUTH)
        val body = LinkedHashMap<String, Any?>()
        for (k in REV) body[k] = m[k]
        m["sig"] = sign(K, IntentJs.message(Lease.REVOKE_DOMAIN, body))
        return m
    }

    private fun reg(kv: AtomicKv, shards: Int = 16, ceiling: Long? = null) =
        Lease.Registry(Lease.Policy(listOf(AUTH), 1, null, true, ceiling), kv, shards)

    private fun values(r: Lease.Registry, shard: Int): List<Any?> = r.shardRevocations(shard).map { it["value"] }

    @Test fun shardOfIsTheFirstFourBytesOfSha256ModuloTheCount() {
        val ids = listOf("a", "b", "L1", "L2", "lease-7", "x".repeat(40), "héllo", "0", "zz9", "db/prod")
        val want16 = listOf(2, 6, 6, 8, 0, 6, 13, 6, 7, 12)
        val want4096 = listOf(274, 2070, 1430, 1240, 1488, 4086, 2333, 2918, 1463, 508)
        val wantMillion = listOf(916416, 537440, 988239, 600385, 134320, 403378, 371332, 357451, 648831, 521302)
        val wantMax = listOf(1251442963, 1042540566, 1610515863, 1466127577, 96134608, 1032929271, 1011374365, 1609362278, 1029174712, 2047050237)
        for ((i, id) in ids.withIndex()) {
            assertEquals(id, want16[i], Lease.shardOf(id, 16))
            assertEquals(id, want4096[i], Lease.shardOf(id, 4096))
            assertEquals(id, wantMillion[i], Lease.shardOf(id, 1000003))
            assertEquals(id, wantMax[i], Lease.shardOf(id, Int.MAX_VALUE))
        }
    }

    @Test fun theShardCountIsOneToFourThousandNinetySix() {
        reg(MemoryAtomicKv(), 1)
        reg(MemoryAtomicKv(), 4096)
        for (bad in listOf(0, -1, 4097)) assertThrows(IllegalArgumentException::class.java) { reg(MemoryAtomicKv(), bad) }
    }

    @Test fun theDefaultClockPrunesARevocationOlderThanTheCeiling() {
        val r = Lease.Registry(Lease.Policy(listOf(AUTH), 1, null, true, 5000L), MemoryAtomicKv())
        assertTrue(r.revoke(rev("grant", "gOld", 1000L)).ok)
        assertTrue(r.revoke(rev("grant", "gFuture", 8_000_000_000_000L)).ok)
        // the old one is beyond revoked_at + ceiling on the wall clock and is gone from every shard; the future one stays
        for (i in 0 until Lease.DEFAULT_SHARDS) assertEquals("shard $i", listOf<Any?>("gFuture"), values(r, i))
    }

    @Test fun aRevocationIsPrunedExactlyWhenItsHorizonHasPassedOnTheInjectedClock() {
        var now = 0L
        val r = Lease.Registry(Lease.Policy(listOf(AUTH), 1, null, true, 5000L), MemoryAtomicKv(), 16) { now }
        assertTrue(r.revoke(rev("grant", "gX", 1000L)).ok)
        now = 6000L // 1000 + 5000 < 6000 is false: kept
        assertTrue(r.revoke(rev("grant", "gZ", 999_999L)).ok)
        assertEquals(listOf<Any?>("gX", "gZ"), values(r, 0))
        now = 6001L
        assertTrue(r.revoke(rev("grant", "gW", 999_999L)).ok)
        assertEquals(listOf<Any?>("gZ", "gW"), values(r, 0))
        assertEquals(listOf<Any?>("gZ", "gW"), values(r, 15))
    }

    @Test fun acceptPrunesTheStaleRevocationsOfTheLeasesShardOnly() {
        var now = 0L
        val r = Lease.Registry(Lease.Policy(listOf(AUTH), 1, null, true, 5000L), MemoryAtomicKv(), 16) { now }
        assertTrue(r.revoke(rev("grant", "gX", 1000L)).ok)
        now = 10_000L
        assertTrue(r.accept(rec()).ok)
        val own = Lease.shardOf("L1", 16)
        assertEquals(emptyList<Any?>(), values(r, own))
        assertEquals(listOf<Any?>("gX"), values(r, (own + 1) % 16))
    }

    @Test fun theShardCountMetaIsPinnedOnFirstUseAndReadOnlyOnce() {
        val kv = Kill08K1CountingKv()
        val r = reg(kv)
        assertTrue(r.accept(rec()).ok)
        assertTrue(r.revoke(rev("lease", "L1", 1500L)).ok)
        assertNotNull(r.get("L1"))
        assertEquals(1, kv.updates.count { it == "lease/meta" })
        val meta = kv.get("lease/meta") as Map<String, Any?>
        assertEquals(IntentJs.ofLong(1), meta["v"])
        assertEquals(IntentJs.ofLong(16), meta["shards"])
    }

    @Test fun aDifferentPinnedShardCountRefusesEveryOperation() {
        for (pinned in listOf<Any?>(linkedMapOf("v" to IntentJs.ofLong(1), "shards" to IntentJs.ofLong(8)), "junk", linkedMapOf("v" to IntentJs.ofLong(1), "shards" to Json.Num("16.5")))) {
            val kv = MemoryAtomicKv()
            kv.set("lease/meta", pinned)
            val r = reg(kv)
            val a = r.accept(rec())
            assertFalse(a.ok)
            assertEquals("store_unreachable", a.code)
            assertFalse(a.replaced)
            val v = r.revoke(rev("lease", "L1", 1500L))
            assertFalse(v.ok)
            assertEquals("store_unreachable", v.code)
            assertEquals(0, v.revoked)
            val e1 = assertThrows(IllegalStateException::class.java) { r.get("L1") }
            assertEquals("shard count mismatch", e1.message)
            assertThrows(IllegalStateException::class.java) { r.history("L1") }
            assertEquals("deny", Lease.checkLease(rec(), r, 1500L).decision)
            assertEquals("store_unreachable", Lease.checkLease(rec(), r, 1500L).code)
        }
    }

    @Test fun aStoreThatThrowsIsUnreachableAndAFatalErrorIsRethrown() {
        val r = reg(Kill08K1ThrowingKv { IllegalStateException("down") })
        val a = r.accept(rec())
        assertFalse(a.ok)
        assertEquals("store_unreachable", a.code)
        assertFalse(a.replaced)
        val v = r.revoke(rev("grant", "gX", 1000L))
        assertFalse(v.ok)
        assertEquals("store_unreachable", v.code)
        assertEquals("store_unreachable", Lease.checkLease(rec(), r, 1500L).code)
        val fatal = reg(Kill08K1ThrowingKv { OutOfMemoryError("fatal") })
        assertThrows(OutOfMemoryError::class.java) { fatal.accept(rec()) }
        assertThrows(OutOfMemoryError::class.java) { fatal.revoke(rev("grant", "gX", 1000L)) }
        assertThrows(OutOfMemoryError::class.java) { Lease.checkLease(rec(), fatal, 1500L) }
    }

    @Test fun shardRevocationsRefusesAnIndexOutsideTheShardRange() {
        val r = reg(MemoryAtomicKv(), 4)
        assertEquals(emptyList<Any?>(), values(r, 0))
        assertEquals(emptyList<Any?>(), values(r, 3))
        for (bad in listOf(-1, 4, 5)) {
            val e = assertThrows(IllegalArgumentException::class.java) { r.shardRevocations(bad) }
            assertEquals("no such shard", e.message)
        }
    }

    @Test fun aStoreHoldingDocumentsOfTheWrongShapeIsReadAsEmpty() {
        val key = "lease/16/${Lease.shardOf("L1", 16)}"
        val docs = listOf<Any?>(
            "junk",
            linkedMapOf("leases" to "junk", "revocations" to "junk"),
            linkedMapOf("leases" to linkedMapOf("L1" to "junk")),
            linkedMapOf("leases" to linkedMapOf("L1" to linkedMapOf("current" to "junk", "history" to "junk"))),
        )
        for (d in docs) {
            val kv = MemoryAtomicKv()
            kv.set(key, d)
            val r = reg(kv)
            val a = r.accept(rec())
            assertTrue("$d ${a.code}", a.ok)
            assertTrue(a.replaced)
            assertEquals("L1", r.get("L1")!!["lease_id"])
        }
    }

    @Test fun aRevocationReportsExactlyTheLeasesItCovers() {
        val r = reg(MemoryAtomicKv(), 1)
        assertTrue(r.accept(rec()).ok)
        assertTrue(r.accept(rec("lease_id", "L2", "path", "db/stage", "grant_ref", "g2")).ok)
        assertTrue(r.accept(rec("lease_id", "L3", "path", "db/prod/x", "grant_ref", "g3", "issued_at", 3000L, "renewed_at", 3000L, "expires_at", 4000L)).ok)
        // L3 was issued after the revocation, L2 is not under the prefix: only L1 is covered
        assertEquals(1, r.revoke(rev("prefix", "db/prod", 2000L)).revoked)
        assertEquals(1, r.revoke(rev("grant", "g1", 5000L)).revoked)
        assertEquals(1, r.revoke(rev("lease", "L2", 5000L)).revoked)
        assertEquals(0, r.revoke(rev("lease", "nope", 5000L)).revoked)
        assertEquals(3, r.revoke(rev("prefix", "db", 5000L)).revoked)
        // idempotent: the same record is stored once
        val again = rev("grant", "g3", 5000L)
        assertEquals(1, r.revoke(again).revoked)
        val before = r.shardRevocations(0).size
        assertEquals(1, r.revoke(again).revoked)
        assertEquals(before, r.shardRevocations(0).size)
    }
}
