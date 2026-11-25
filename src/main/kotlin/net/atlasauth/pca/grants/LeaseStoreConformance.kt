package net.atlasauth.pca.grants

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import net.atlasauth.pca.verifier.AtomicKv
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Lease

/**
 * Conformance kit for lease storage. Run it against any [AtomicKv] (the in-memory one, an opened durable state, or your own database adapter)
 * before trusting that store with leases. It throws `IllegalStateException("lease store conformance: <check>: <detail>")` on the first failure
 * and returns the list of checks passed. It proves: leases spread over the shards; an update is atomic (of many concurrent renewals of one
 * lease exactly one wins and the rest are forks); different leases do not interfere; a prefix revocation lands in every shard and a lease
 * revocation only in its own; a store opened with another shard count is refused rather than silently empty; state survives a reopen (give
 * [Kit.reopen]); a later-issued lease under a revoked prefix is a new lease; with a TTL ceiling, old revocations are pruned from every shard and
 * a longer `max_ttl` is refused.
 */
object LeaseStoreConformance {
    private val SK = Keys.edFromSeed(ByteArray(32) { 61 })
    private val AUTH = SK.id()
    private const val T0 = 1_800_000_000_000L
    private const val DAY = 86_400_000L

    /** The store under test. */
    interface Kit {
        /** A fresh, empty store. */
        @Throws(Exception::class)
        fun open(): AtomicKv

        /** The same store opened again as a restarted process would (state kept); null skips the restart check. */
        @Throws(Exception::class)
        fun reopen(kv: AtomicKv): AtomicKv? = null

        fun supportsReopen(): Boolean = false

        /** Shard count; 16 by default. */
        fun shards(): Int = 16
    }

    private fun mk(id: String, vararg over: Pair<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["lease_id"] = id
        m["path"] = "svc/" + (id.length % 3) + "/" + id
        m["grant_ref"] = "g-$id"
        m["holder"] = "agent"
        m["requester"] = "alice"
        m["approvers"] = arrayListOf<Any?>("bob")
        m["justification_digest"] = "j1"
        m["seq"] = 1L
        m["issued_at"] = T0
        m["renewed_at"] = T0
        m["expires_at"] = T0 + 600_000L
        m["max_ttl"] = 3_600_000L
        for ((k, v) in over) m[k] = v
        return m
    }

    private fun lease(id: String, vararg over: Pair<String, Any?>): Map<String, Any?> = GrantSigning.signLease(SK, mk(id, *over))

    private fun revocation(target: String, value: String, at: Long): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["target"] = target
        r["value"] = value
        r["revoked_at"] = at
        return GrantSigning.signLeaseRevocation(SK, r)
    }

    private fun fail(check: String, detail: String) = IllegalStateException("lease store conformance: $check: $detail")

    private fun expectEq(check: String, got: Any?, want: Any?) {
        val g = Json.canonicalize(got)
        val w = Json.canonicalize(want)
        if (g != w) throw fail(check, "got $g, want $w")
    }

    private fun obj(vararg kv: Pair<String, Any?>): Map<String, Any?> = GrantHttp.obj(*kv)

    private fun acc(a: Lease.Accept): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = a.code == null
        if (a.code != null) m["code"] = a.code
        return m
    }

    private fun rev(r: Lease.Revoke): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = r.code == null
        if (r.code == null) m["revoked"] = r.revoked.toLong()
        return m
    }

    private fun seqs(history: List<Lease.HistoryEntry>): List<Any?> = history.map { it.seq }

    private fun okAccept(reg: Lease.Registry, rec: Map<String, Any?>): Boolean = reg.accept(rec, ArrayList()).code == null

    private fun deny(reg: Lease.Registry, rec: Any?, now: Long): String = Lease.checkLease(rec, reg, now).decision

    @JvmStatic
    @Throws(Exception::class)
    fun runLeaseStoreConformance(kit: Kit): List<String> {
        val passed = ArrayList<String>()
        val shards = kit.shards()
        val policy = Lease.Policy(listOf(AUTH))
        val clock = { System.currentTimeMillis() }

        // 1. spread
        run {
            val reg = Lease.Registry(policy, kit.open(), shards, clock)
            val ids = (0 until 256).map { "lease-$it" }
            for (id in ids) expectEq("spread: issue $id", okAccept(reg, lease(id)), true)
            val per = IntArray(shards)
            for (id in ids) per[GrantSigning.shardOf(id, shards)]++
            var max = 0
            var used = 0
            for (n in per) { max = maxOf(max, n); if (n > 0) used++ }
            if (max > ids.size / 4.0 || used < shards / 2.0) throw fail("spread", "256 leases landed ${per.toList()}")
            for (id in ids) { val g = reg.get(id); if (g == null || id != g["lease_id"]) throw fail("spread", "$id not found after issue") }
            passed.add("spread")
        }

        // 2. atomic update
        run {
            val reg = Lease.Registry(policy, kit.open(), shards, clock)
            reg.accept(lease("hot"), ArrayList())
            val jobs = ArrayList<Callable<Lease.Accept>>()
            for (i in 0 until 8) {
                val r = lease("hot", "seq" to 2L, "renewed_at" to T0 + 1000, "expires_at" to T0 + 700_000L + i, "justification_digest" to "r$i")
                jobs.add(Callable { reg.accept(r, ArrayList()) })
            }
            val ex = Executors.newFixedThreadPool(8)
            var wins = 0L
            var forks = 0L
            try {
                for (f in ex.invokeAll(jobs)) {
                    val a = f.get()
                    if (a.code == null) wins++ else if (a.code == "lease_fork") forks++
                }
            } finally {
                ex.shutdown()
            }
            expectEq("atomic: one winner", wins, 1L)
            expectEq("atomic: the rest are forks", forks, 7L)
            expectEq("atomic: ledger length", seqs(reg.history("hot")), listOf(1L, 2L))
            passed.add("atomic update")
        }

        // 3. independence
        run {
            val reg = Lease.Registry(policy, kit.open(), shards, clock)
            val ids = (0 until 32).map { "ind-$it" }
            for (id in ids) reg.accept(lease(id), ArrayList())
            var all = true
            for (id in ids) all = okAccept(reg, lease(id, "seq" to 2L, "renewed_at" to T0 + 10, "expires_at" to T0 + 900_000L, "justification_digest" to "j2")) && all
            expectEq("independence", all, true)
            passed.add("independent leases")
        }

        // 4 + 5. revocation placement
        run {
            val reg = Lease.Registry(policy, kit.open(), shards, clock)
            val ids = (0 until 64).map { "rv-$it" }
            for (id in ids) reg.accept(lease(id, "path" to "db/prod/ro"), ArrayList())
            val lone = lease("lone", "path" to "other/x")
            reg.accept(lone, ArrayList())
            val byLease = revocation("lease", "lone", T0 + 5)
            expectEq("revoke by lease", rev(reg.revoke(byLease)), okRevoked(1))
            var holders = 0
            for (i in 0 until shards) if (reg.shardRevocations(i).isNotEmpty()) holders++
            expectEq("lease revocation lands in exactly one shard", holders.toLong(), 1L)
            expectEq("revoked lease is dead", deny(reg, lone, T0 + 6), "deny")
            val byPrefix = revocation("prefix", "db/prod", T0 + 10)
            expectEq("revoke by prefix covers every lease in every shard", rev(reg.revoke(byPrefix)), okRevoked(64))
            expectEq("revoke twice is idempotent", rev(reg.revoke(byPrefix)), okRevoked(64))
            for (i in 0 until shards) {
                var n = 0L
                for (r in reg.shardRevocations(i)) if (byPrefix["sig"] == K3Sig.map(r)!!["sig"]) n++
                if (n == 0L) throw fail("prefix revocation in every shard", "shard $i lacks it")
                expectEq("no duplicate in shard $i", n, 1L)
            }
            for (id in ids) {
                val cur = reg.get(id)
                expectEq("check $id", deny(reg, cur, T0 + 11), "deny")
                expectEq("renewal of $id refused", okAccept(reg, lease(id, "path" to "db/prod/ro", "seq" to 2L, "renewed_at" to T0 + 20, "expires_at" to T0 + 700_000L, "justification_digest" to "x")), false)
            }
            val fresh = lease("after", "path" to "db/prod/ro", "issued_at" to T0 + 100, "renewed_at" to T0 + 100, "expires_at" to T0 + 900_000L)
            expectEq("a lease issued after the revocation is new", okAccept(reg, fresh), true)
            passed.add("revocation placement")
        }

        // 6. shard-count mismatch
        run {
            val kv = kit.open()
            Lease.Registry(policy, kv, shards, clock).accept(lease("m1"), ArrayList())
            val other = Lease.Registry(policy, kv, shards * 2, clock)
            expectEq("shard mismatch accept", acc(other.accept(lease("m2"), ArrayList())), obj("ok" to false, "code" to "store_unreachable"))
            expectEq("shard mismatch check", deny(other, lease("m1"), T0 + 1), "deny")
            passed.add("shard count is pinned")
        }

        // 7. restart
        if (kit.supportsReopen()) {
            val kv = kit.open()
            val reg = Lease.Registry(policy, kv, shards, clock)
            val l = lease("persist")
            reg.accept(l, ArrayList())
            reg.accept(lease("persist", "seq" to 2L, "renewed_at" to T0 + 5, "expires_at" to T0 + 800_000L, "justification_digest" to "j2"), ArrayList())
            reg.revoke(revocation("prefix", "gone", T0 + 50))
            val reopened = kit.reopen(kv) ?: throw fail("restart", "the kit reports reopen support but returned no store")
            val again = Lease.Registry(policy, reopened, shards, clock)
            expectEq("restart: renewal ledger", seqs(again.history("persist")), listOf(1L, 2L))
            expectEq("restart: revocation kept", again.shardRevocations(0).size.toLong(), 1L)
            expectEq("restart: old record still superseded", deny(again, l, T0 + 6), "deny")
            passed.add("state survives a restart")
        }

        // 8. ceiling and pruning
        run {
            val now = AtomicLong(T0)
            val capped = Lease.Policy(listOf(AUTH), maxTtlCeiling = DAY)
            val reg = Lease.Registry(capped, kit.open(), shards) { now.get() }
            expectEq("ceiling refuses a longer max_ttl", acc(reg.accept(lease("big", "max_ttl" to DAY + 1, "expires_at" to T0 + 1000), ArrayList())), obj("ok" to false, "code" to "ttl_ceiling"))
            reg.accept(lease("small", "max_ttl" to DAY), ArrayList())
            reg.revoke(revocation("prefix", "svc", T0))
            for (i in 0 until shards) expectEq("kept before the ceiling passes (shard $i)", reg.shardRevocations(i).size.toLong(), 1L)
            now.set(T0 + DAY + 1)
            val t = now.get()
            reg.accept(lease("trigger", "issued_at" to t, "renewed_at" to t, "expires_at" to t + 1000, "max_ttl" to 5000L), ArrayList())
            reg.revoke(revocation("prefix", "zzz", t))
            for (i in 0 until shards) {
                var hasSvc = false
                var hasZzz = false
                for (r in reg.shardRevocations(i)) {
                    val v = K3Sig.map(r)!!["value"]
                    hasSvc = hasSvc || "svc" == v
                    hasZzz = hasZzz || "zzz" == v
                }
                if (hasSvc) throw fail("pruning", "shard $i still holds the expired revocation")
                if (!hasZzz) throw fail("pruning", "shard $i lost the fresh revocation")
            }
            passed.add("pruning bounds revocations")
        }
        return passed
    }

    private fun okRevoked(n: Long): Map<String, Any?> = obj("ok" to true, "revoked" to n)
}
