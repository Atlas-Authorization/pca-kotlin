package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** H15 (strict): lease, break-glass and blueprint registries keep every decision in a durable kv; F4 admitted hook; F5 revocation pruning. */
class Kill14BDurableRegistriesTest {
    private fun n(s: String) = Json.Num(s)

    private val throwing = object : AtomicKv {
        override fun get(key: String): Any? = throw IllegalStateException("down")
        override fun set(key: String, value: Any?) = throw IllegalStateException("down")
        override fun update(key: String, fn: (Any?) -> Any?): Any? = throw IllegalStateException("down")
    }

    // ---- lease

    private val lk = "k14-lease/authority"
    private val lauth = IntentTestKit.pub(lk)
    private val lbody = listOf("v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority")

    private fun lease(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = IntentTestKit.jm(
            "v", 1L, "lease_id", "L1", "path", "db/prod", "grant_ref", "g1", "holder", "H", "requester", "R", "approvers", IntentTestKit.jl("A1"),
            "justification_digest", "j1", "seq", 1L, "issued_at", 1000L, "renewed_at", 1000L, "expires_at", 2000L, "max_ttl", 5000L, "authority", lauth,
        )
        for ((k, v) in over) m[k] = v
        val body = LinkedHashMap<String, Any?>()
        for (k in lbody) body[k] = m[k]
        m["sig"] = IntentTestKit.sign(lk, IntentJs.message(Lease.DOMAIN, body))
        return m
    }

    private fun revocation(target: String, value: String, at: Long): LinkedHashMap<String, Any?> {
        val m = IntentTestKit.jm("v", 1L, "target", target, "value", value, "revoked_at", at, "authority", lauth)
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "target", "value", "revoked_at", "authority")) body[k] = m[k]
        m["sig"] = IntentTestKit.sign(lk, IntentJs.message(Lease.REVOKE_DOMAIN, body))
        return m
    }

    private fun lreg(kv: AtomicKv, ceiling: Long? = null, clock: () -> Long = { 0L }) = Lease.Registry(Lease.Policy(listOf(lauth), maxTtlCeiling = ceiling), kv, clock = clock)

    @Test fun aLeaseRevocationSurvivesANewRegistryOverTheSameKv() {
        val kv = MemoryAtomicKv()
        val rec = lease()
        assertTrue(lreg(kv).accept(rec).ok)
        assertEquals("allow", Lease.checkLease(rec, lreg(kv), 1500L).decision)
        assertTrue(lreg(kv).revoke(revocation("lease", "L1", 1200L)).ok)
        val fresh = lreg(kv)
        val d = Lease.checkLease(rec, fresh, 1500L)
        assertEquals("deny", d.decision)
        assertEquals("revoked", d.code)
        assertEquals("revoked", fresh.accept(lease("seq" to 2L, "renewed_at" to 1500L, "expires_at" to 2500L, "justification_digest" to "j2")).code)
    }

    @Test fun aPrefixRevocationReachesEveryShard() {
        val kv = MemoryAtomicKv()
        val r = lreg(kv)
        for (i in 0 until 20) assertTrue(r.accept(lease("lease_id" to "L$i", "path" to "db/prod/x$i")).ok)
        val out = r.revoke(revocation("prefix", "db/prod", 1500L))
        assertTrue(out.ok)
        assertEquals(20, out.revoked)
        for (i in 0 until Lease.DEFAULT_SHARDS) assertEquals(1, r.shardRevocations(i).size)
    }

    @Test fun twoRegistriesOverOneKvAcceptOnlyOneRenewal() {
        val kv = MemoryAtomicKv()
        val a = lreg(kv)
        val b = lreg(kv)
        assertTrue(a.accept(lease()).ok)
        val one = lease("seq" to 2L, "renewed_at" to 1500L, "expires_at" to 2500L, "justification_digest" to "j2")
        val two = lease("seq" to 2L, "renewed_at" to 1600L, "expires_at" to 2600L, "justification_digest" to "j3")
        assertTrue(a.accept(one).ok)
        assertEquals("lease_fork", b.accept(two).code)
    }

    @Test fun aStoreThatThrowsIsStoreUnreachable() {
        val r = lreg(throwing)
        assertEquals("store_unreachable", r.accept(lease()).code)
        assertEquals("store_unreachable", r.revoke(revocation("lease", "L1", 1L)).code)
        val d = Lease.checkLease(lease(), r, 1500L)
        assertEquals("deny", d.decision)
        assertEquals("store_unreachable", d.code)
    }

    @Test fun aShardCountMismatchRefusesTheStore() {
        val kv = MemoryAtomicKv()
        assertTrue(lreg(kv).accept(lease()).ok)
        val other = Lease.Registry(Lease.Policy(listOf(lauth)), kv, shards = 4)
        assertEquals("store_unreachable", other.accept(lease("lease_id" to "L2")).code)
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { Lease.Registry(Lease.Policy(listOf(lauth)), kv, shards = 0) }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { Lease.Registry(Lease.Policy(listOf(lauth)), kv, shards = 4097) }
    }

    private fun sameShardAs(id: String): String {
        val want = Lease.shardOf(id, Lease.DEFAULT_SHARDS)
        var i = 0
        while (Lease.shardOf("M$i", Lease.DEFAULT_SHARDS) != want) i++
        return "M$i"
    }

    private fun other(id: String) = lease("lease_id" to id, "issued_at" to 5000L, "renewed_at" to 5000L, "expires_at" to 5500L, "max_ttl" to 900L, "path" to "db/other")

    @Test fun revocationsArePrunedOnlyWithACeiling() {
        val now = longArrayOf(0L)
        val r = lreg(MemoryAtomicKv(), ceiling = 1000L, clock = { now[0] })
        val shard = Lease.shardOf("L1", Lease.DEFAULT_SHARDS)
        val mate = sameShardAs("L1")
        assertTrue(r.accept(other("L1")).ok)
        assertTrue(r.revoke(revocation("lease", "L1", 0L)).ok)
        assertEquals(1, r.shardRevocations(shard).size)
        now[0] = 1000L
        assertTrue(r.accept(other(mate)).ok)
        assertEquals("revoked_at + ceiling == now is kept", 1, r.shardRevocations(shard).size)
        now[0] = 1001L
        assertTrue(r.revoke(revocation("lease", "L1", 0L)).ok)
        assertEquals(0, r.shardRevocations(shard).size)
        // without a ceiling nothing is ever pruned
        val keep = lreg(MemoryAtomicKv(), ceiling = null, clock = { 10_000_000L })
        assertTrue(keep.accept(other("L1")).ok)
        assertTrue(keep.revoke(revocation("lease", "L1", 0L)).ok)
        assertTrue(keep.accept(other(mate)).ok)
        assertEquals(1, keep.shardRevocations(shard).size)
    }

    // ---- break-glass

    private val bga = IntentTestKit.pub("k14-bg-authority")
    private val bgr = IntentTestKit.pub("k14-bg-reviewer")
    private val t0 = 1_000_000L

    private fun bgGrant(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to 1L, "id" to "bg1", "holder" to "agent", "grant_ref" to "g", "reason_digest" to "why", "max_uses" to 1L,
            "issued_at" to t0, "expires_at" to t0 + 3_600_000L, "review_within" to 1_800_000L, "notify_to" to "secops", "authority" to bga)
        for ((k, v) in over) m[k] = v
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority")) body[k] = m[k]
        m["sig"] = IntentTestKit.sign("k14-bg-authority", IntentJs.message(BreakGlass.DOMAIN, body))
        return m
    }

    private fun bgReg(kv: AtomicKv) = BreakGlass.Registry(BreakGlass.Policy(listOf(bga), listOf(bgr)), kv)

    @Test fun aBreakGlassBudgetIsSpentAcrossRegistriesOverOneKv() {
        val kv = MemoryAtomicKv()
        val a = bgReg(kv)
        val b = bgReg(kv)
        assertTrue(a.accept(bgGrant(), t0).ok)
        assertEquals("allow", a.use("bg1", "agent", "d1", t0 + 5, true).decision)
        val second = b.use("bg1", "agent", "d2", t0 + 6, true)
        assertEquals("deny", second.decision)
        assertEquals("budget_exhausted", second.code)
        assertEquals(1, b.uses("agent", "bg1").size)
        assertEquals("d1", b.uses("agent", "bg1")[0].actionDigest)
    }

    @Test fun anOverdueReviewFreezesTheHolderInEveryRegistry() {
        val kv = MemoryAtomicKv()
        val a = bgReg(kv)
        assertTrue(a.accept(bgGrant(), t0).ok)
        assertEquals("allow", a.use("bg1", "agent", "d1", t0 + 5, true).decision)
        assertFalse(bgReg(kv).frozen("agent", t0 + 100))
        assertTrue(bgReg(kv).frozen("agent", t0 + 5 + 1_800_000L))
    }

    @Test fun aBreakGlassStoreThatThrowsIsStoreUnreachableAndFrozen() {
        val r = bgReg(throwing)
        assertEquals("store_unreachable", r.accept(bgGrant(), t0).code)
        val d = r.use("bg1", "agent", "d1", t0 + 5, true)
        assertEquals("deny", d.decision)
        assertEquals("store_unreachable", d.code)
        assertEquals("bg1", d.id)
        assertTrue(r.frozen("agent", t0))
        assertTrue(r.uses("agent", "bg1").isEmpty())
    }

    // ---- blueprint

    private val bl = "k14-blueprint-operator"
    private val bop = IntentTestKit.pub(bl)
    private val bkeys = listOf("v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator")

    private fun bp(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        b["v"] = n("1"); b["id"] = "bp1"; b["key"] = "K1"; b["ceiling"] = ArrayList<Any?>(); b["epoch"] = n("1")
        b["status"] = "active"; b["issued_at"] = n("100"); b["operator"] = bop
        for ((k, v) in over) b[k] = v
        val body = LinkedHashMap<String, Any?>()
        for (k in bkeys) if (b.containsKey(k)) body[k] = b[k]
        b["sig"] = IntentTestKit.sign(bl, IntentJs.message(Blueprint.DOMAIN, body))
        return b
    }

    private val chain = listOf(mapOf("issuer" to "principal", "holder" to "K1"), mapOf("issuer" to "K1", "holder" to "inst"))

    @Test fun aDisabledBlueprintStaysDisabledAcrossRegistries() {
        val kv = MemoryAtomicKv()
        assertTrue(Blueprint.Registry(listOf(bop), kv).accept(bp("epoch" to n("4"))).code == null)
        assertTrue(Blueprint.Registry(listOf(bop), kv).accept(bp("epoch" to n("5"), "status" to "disabled")).code == null)
        val fresh = Blueprint.Registry(listOf(bop), kv)
        assertEquals("stale_epoch", fresh.accept(bp("epoch" to n("4"))).code)
        assertEquals(5L, fresh.epoch())
        val d = Blueprint.check(chain, fresh, n("1"), "require")
        assertEquals("blueprint_disabled", d.code)
    }

    @Test fun aBlueprintStoreThatThrowsIsStoreUnreachable() {
        val r = Blueprint.Registry(listOf(bop), throwing)
        assertEquals("store_unreachable", r.accept(bp()).code)
        val d = Blueprint.check(chain, r, n("1"), "require")
        assertEquals("deny", d.decision)
        assertEquals("store_unreachable", d.code)
    }

    @Test fun runtimePinsNeedTheAdmittedHook() {
        val reg = Blueprint.Registry(listOf(bop), MemoryAtomicKv())
        assertTrue(reg.accept(bp("runtime_pins" to arrayListOf<Any?>(linkedMapOf<String, Any?>("runtime_measurement" to "m1")))).code == null)
        assertEquals("admission_required", Blueprint.check(chain, reg, n("1"), "require").code)
        assertEquals("not_admitted", Blueprint.check(chain, reg, n("1"), "require", admitted = { _, _ -> false }).code)
        assertEquals("allow", Blueprint.check(chain, reg, n("1"), "require", admitted = { k, b -> k == "inst" && b["id"] == "bp1" }).decision)
        assertEquals("store_unreachable", Blueprint.check(chain, reg, n("1"), "require", admitted = { _, _ -> throw IllegalStateException("x") }).code)
    }
}
