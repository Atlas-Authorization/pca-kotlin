package net.atlasauth.pca.verifier

import java.text.Collator
import java.util.Locale
import net.atlasauth.pca.compliance.ComplianceJs

/**
 * Guardian high-availability control logic (ha.ts): which guardians are live, whether a co-sign quorum is available, the degrade mode when it
 * is lost, signer selection and failover order, and a durable, FENCED leader lease (at most one holder, a strictly increasing fencing epoch,
 * store-side expiry, "no leader" whenever the store errs). It never fails OPEN: losing quorum or the lease restricts authority, never widens it.
 *
 * Guardian sets, lease records and results are JSON trees (maps and lists), the members of the reference's objects: a guardian set is
 * `{guardians: [{id, healthy, lastSeen, weight?}], quorum}`, a lease record `{holder, epoch, expiresAt}`. Every function is total over hostile
 * input as the reference is (a malformed set counts as no live guardian). Lease safety holds if the store's compare-and-swap is linearizable
 * and the holder's clock error stays under `skewMs`.
 *
 * Shortcut: signer ties on the id use [Collator] (root locale, tertiary) as the reference uses `localeCompare`; they agree on Latin text, a
 * rarer script may order differently.
 */
@Suppress("UNCHECKED_CAST")
object Ha {
    const val MAX_LEASE_TTL_MS = 3_600_000L
    const val DEFAULT_LEASE_SKEW_MS = 1_000L
    private const val MAX_HOLDER_LEN = 256
    private const val MAX_SAFE = 9007199254740991.0
    const val DEFAULT_LEASE_KEY = "ha/lease"

    private fun fin(o: Any?): Double? = Risk.fin(o)

    private fun isInteger(o: Any?): Boolean = fin(o)?.let { it == Math.rint(it) } == true

    private fun isSafeInteger(o: Any?): Boolean = fin(o)?.let { it == Math.rint(it) && Math.abs(it) <= MAX_SAFE } == true

    private fun num(d: Double): Json.Num = StoreJs.num(d)

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = Issue.obj(*kv)

    private fun member(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    private fun isObject(o: Any?): Boolean = o is Map<*, *> || o is List<*>

    /** `Number(v)` of a member that may be absent (undefined is NaN). */
    private fun jsNumber(v: Any?, present: Boolean): Double = if (!present) Double.NaN else ComplianceJs.toNumber(v)

    // ---- pure decisions ----

    /**
     * Guardians that are flagged healthy (the boolean true) AND have a fresh heartbeat at [now]. Fails closed: a malformed set, a non-finite
     * clock or stale window, a non-finite or FUTURE-dated heartbeat counts as down. [opts]: `{staleMs}`, default 30000.
     */
    @JvmOverloads
    fun liveGuardians(set: Any?, now: Any?, opts: Any? = null): List<Any?> {
        val out = ArrayList<Any?>()
        val st = member(opts, "staleMs")
        val staleMs = if (st == null) 30_000.0 else fin(st)
        val n = fin(now)
        val gs = member(set, "guardians")
        if (n == null || staleMs == null || staleMs < 0 || gs !is List<*>) return out
        for (g in gs) if (!isObject(g)) return out
        for (g in gs) {
            val seen = fin(member(g, "lastSeen"))
            if (member(g, "healthy") == true && seen != null && seen <= n && n - seen <= staleMs) out.add(g)
        }
        return out
    }

    /** `{total, live, quorum, available, degraded}`; `quorum` is echoed as given (absent when the set has none). */
    @JvmOverloads
    fun quorumStatus(set: Any?, now: Any?, opts: Any? = null): Map<String, Any?> {
        val live = liveGuardians(set, now, opts).size
        val gs = member(set, "guardians")
        val q = member(set, "quorum")
        val out = LinkedHashMap<String, Any?>()
        out["total"] = StoreJs.num((if (gs is List<*>) gs.size else 0).toLong())
        out["live"] = StoreJs.num(live.toLong())
        if (has(set, "quorum")) out["quorum"] = q
        out["available"] = isInteger(q) && fin(q)!! >= 1 && live >= fin(q)!!
        out["degraded"] = live > 0 && live < jsNumber(q, has(set, "quorum"))
        return out
    }

    /** `'normal'` with quorum, `'read-only'` below quorum with some guardian live (unless `allowReadOnly` is false), else `'halt'`. */
    @JvmOverloads
    fun degradeMode(status: Any?, policy: Any? = null): String {
        if (ZkJs.truthy(member(status, "available"))) return "normal"
        if (jsNumber(member(status, "live"), has(status, "live")) > 0 && member(policy, "allowReadOnly") != false) return "read-only"
        return "halt"
    }

    private fun weightOf(g: Any?): Double = fin(member(g, "weight")) ?: 0.0

    private fun compareGuardians(a: Any?, b: Any?): Int {
        val dw = weightOf(b) - weightOf(a)
        if (dw != 0.0) return if (dw < 0) -1 else 1
        val dl = fin(member(b, "lastSeen"))!! - fin(member(a, "lastSeen"))!!
        if (dl != 0.0) return if (dl < 0) -1 else 1
        val ia = member(a, "id")
        val ib = member(b, "id")
        if (ia !is String) throw IllegalArgumentException("a.id.localeCompare is not a function")
        val c = Collator.getInstance(Locale.ROOT)
        c.strength = Collator.TERTIARY
        return c.compare(ia, IntentRevocation.jsText(ib, has(b, "id")))
    }

    private fun byPreference(live: List<Any?>): List<Any?> = live.sortedWith { a, b -> compareGuardians(a, b) }

    /** The `quorum` freshest, highest-weight live guardians' ids; empty when no quorum is available. A null set throws, as the reference does. */
    @JvmOverloads
    fun selectSigners(set: Any?, now: Any?, opts: Any? = null): List<Any?> {
        if (set == null) throw IllegalArgumentException("Cannot read properties of null (reading 'quorum')")
        val live = liveGuardians(set, now, opts)
        val q = member(set, "quorum")
        val out = ArrayList<Any?>()
        if (!isInteger(q) || fin(q)!! < 1 || live.size < fin(q)!!) return out
        val sorted = byPreference(live)
        for (i in 0 until fin(q)!!.toInt()) out.add(member(sorted[i], "id"))
        return out
    }

    /** `{primary, standbys}`: the preferred live guardian (null when none) and the other live ones in preference order. */
    @JvmOverloads
    fun failoverPlan(set: Any?, now: Any?, opts: Any? = null): Map<String, Any?> {
        val live = byPreference(liveGuardians(set, now, opts))
        val standbys = ArrayList<Any?>()
        for (i in 1 until live.size) standbys.add(member(live[i], "id"))
        return obj("primary" to (if (live.isEmpty()) null else member(live[0], "id")), "standbys" to standbys)
    }

    /** An error text when the set is malformed (quorum in range, unique non-empty string ids), else null. */
    fun validateGuardianSet(set: Any?): String? {
        if (!isObject(set)) return "guardian set is not an object"
        val gs = member(set, "guardians")
        if (gs !is List<*> || gs.isEmpty()) return "guardian set is empty"
        val q = member(set, "quorum")
        if (!isInteger(q) || fin(q)!! < 1) return "quorum must be an integer ≥ 1"
        if (fin(q)!! > gs.size) return "quorum exceeds guardian count"
        val ids = HashSet<String>()
        for (g in gs) {
            val id = member(g, "id")
            if (g !is Map<*, *> || id !is String || id.isEmpty()) return "guardian id must be a non-empty string"
            ids.add(id)
        }
        return if (ids.size != gs.size) "duplicate guardian ids" else null
    }

    // ---- durable, fenced leader lease ----

    /**
     * The persistence contract. [cas] replaces the record iff the stored one equals `expected` (null = none), atomically and linearizably, and
     * says whether it did; `next.epoch` must never be below the stored epoch. [now] is the STORE's clock (epoch ms): every expiry decision uses
     * it, never the caller's. A store that cannot answer throws an unchecked exception: the caller then refuses.
     */
    interface LeaseStore {
        /** The stored record (a lease map), or null when none. */
        fun read(): Any?
        fun cas(expected: Any?, next: Any?): Boolean
        fun now(): Double
    }

    private fun validRecord(r: Any?): Boolean {
        if (r !is Map<*, *>) return false
        val e = fin(r["epoch"])
        val x = fin(r["expiresAt"])
        return r["holder"] is String && isSafeInteger(e) && e!! >= 1 && x != null && x >= 0
    }

    private fun eqLease(a: Any?, b: Any?): Boolean {
        if (a == null || b == null) return a == null && b == null
        val ae = fin(member(a, "epoch"))
        val be = fin(member(b, "epoch"))
        val ax = fin(member(a, "expiresAt"))
        val bx = fin(member(b, "expiresAt"))
        return member(a, "holder") is String && member(a, "holder") == member(b, "holder") && ae != null && be != null && ae == be && ax != null && bx != null && ax == bx
    }

    /** The lease options as `{ttl, skew}`, or null when invalid: holder 1..256 characters, ttlMs an integer in [2, 3600000], skewMs finite in [0, ttlMs). */
    private fun leaseOpts(holder: Any?, o: Any?): DoubleArray? {
        if (holder !is String || holder.isEmpty() || holder.length > MAX_HOLDER_LEN) return null
        if (o !is Map<*, *>) return null
        val sk = member(o, "skewMs")
        val skew = if (sk == null) DEFAULT_LEASE_SKEW_MS.toDouble() else fin(sk)
        val t = member(o, "ttlMs")
        if (!isInteger(t) || fin(t)!! < 2 || fin(t)!! > MAX_LEASE_TTL_MS) return null
        if (skew == null || skew < 0 || skew >= fin(t)!!) return null
        return doubleArrayOf(fin(t)!!, skew)
    }

    private class Snap(val cur: Any?, val now: Double)

    /** The record and the store clock; a corrupt record or clock is a store error (never "free"). */
    private fun snapshot(store: LeaseStore): Snap {
        val cur = store.read()
        val now = store.now()
        if (now.isNaN() || now.isInfinite() || (cur != null && !validRecord(cur))) throw IllegalStateException("corrupt lease state")
        return Snap(cur, now)
    }

    private fun ok(lease: Map<String, Any?>): Map<String, Any?> = obj("ok" to true, "lease" to lease)

    private fun no(reason: String): LinkedHashMap<String, Any?> = obj("ok" to false, "reason" to reason)

    private fun storeError(e: RuntimeException): Map<String, Any?> = no("store-error").also { it["detail"] = e.message ?: "unknown" }

    private fun record(holder: Any?, epoch: Double, expiresAt: Double): Map<String, Any?> =
        obj("holder" to holder, "epoch" to num(epoch), "expiresAt" to num(expiresAt))

    private fun d(o: Any?): Double = fin(o) ?: Double.NaN

    /**
     * Takes the lease when it is free (never held, released, or expired past the skew); the epoch increments on every takeover.
     * `{ok: true, lease}` or `{ok: false, reason, detail?}` with reason invalid, held, lost-race or store-error.
     */
    fun acquireLease(store: LeaseStore, holder: Any?, opts: Any?): Map<String, Any?> {
        val p = leaseOpts(holder, opts) ?: return no("invalid")
        return try {
            val s = snapshot(store)
            if (s.cur != null && !(d(member(s.cur, "expiresAt")) + p[1] <= s.now) && d(member(s.cur, "expiresAt")) != 0.0) return no("held")
            val next = record(holder, (if (s.cur == null) 0.0 else d(member(s.cur, "epoch"))) + 1, s.now + p[0])
            if (store.cas(s.cur, next)) ok(next) else no("lost-race")
        } catch (e: RuntimeException) {
            storeError(e)
        }
    }

    private fun sameToken(cur: Any?, token: Any?): Boolean {
        val ce = fin(member(cur, "epoch"))
        val te = fin(member(token, "epoch"))
        return member(cur, "holder") == member(token, "holder") && ce != null && te != null && ce == te
    }

    /** Extends a lease the caller still holds; refused once its own safe window (expiry minus skew) has passed, or after any takeover. */
    fun renewLease(store: LeaseStore, lease: Any?, opts: Any?): Map<String, Any?> {
        val p = (if (validRecord(lease)) leaseOpts(member(lease, "holder"), opts) else null) ?: return no("invalid")
        return try {
            val s = snapshot(store)
            if (s.cur == null || !sameToken(s.cur, lease)) return no("stale")
            if (!(d(member(s.cur, "expiresAt")) - p[1] > s.now)) return no("expired")
            val next = record(member(s.cur, "holder"), d(member(s.cur, "epoch")), s.now + p[0])
            if (store.cas(s.cur, next)) ok(next) else no("lost-race")
        } catch (e: RuntimeException) {
            storeError(e)
        }
    }

    /** Gives the lease up early (`expiresAt` 0, epoch kept); only the current holder at the current epoch can. */
    fun releaseLease(store: LeaseStore, lease: Any?): Map<String, Any?> {
        if (!validRecord(lease)) return no("invalid")
        return try {
            val s = snapshot(store)
            if (s.cur == null || !sameToken(s.cur, lease) || d(member(s.cur, "expiresAt")) == 0.0) return no("stale")
            val next = record(member(s.cur, "holder"), d(member(s.cur, "epoch")), 0.0)
            if (store.cas(s.cur, next)) ok(next) else no("lost-race")
        } catch (e: RuntimeException) {
            storeError(e)
        }
    }

    /**
     * Is this exact (holder, epoch) still the leader with its safe window open? `{ok: true}` or `{ok: false, reason}` (stale, expired,
     * store-error); any error answers no. [skewMs]: any value; null means the default, a non-number or negative one answers stale.
     */
    @JvmOverloads
    fun assertFence(store: LeaseStore, token: Any?, skewMs: Any? = null): Map<String, Any?> = try {
        val skew = if (skewMs == null) DEFAULT_LEASE_SKEW_MS.toDouble() else fin(skewMs)
        if (token == null || token == false || skew == null || skew < 0) {
            no("stale")
        } else {
            val s = snapshot(store)
            if (s.cur == null || !sameToken(s.cur, token)) no("stale")
            else if (d(member(s.cur, "expiresAt")) - skew > s.now) obj("ok" to true) else no("expired")
        }
    } catch (e: RuntimeException) {
        no("store-error")
    }

    /** Thrown by a fenced signer; [reason] is stale, expired, store-error or no-lease. */
    class FenceError(val reason: String) : RuntimeException("fenced: $reason")

    /** What a fenced signer returns: the signature step's result and the fencing epoch it ran under. */
    class Signed<R> internal constructor(val result: R, val epoch: Any?)

    /**
     * Wraps a co-sign step so it only runs while the caller is the fenced leader. The fence is checked before AND after the step: a leader that
     * lost the lease mid-signature gets a [FenceError] and the result is discarded. Check-then-sign is inherently racy: the downstream must
     * also [FenceGuard.admit] the epoch.
     */
    @JvmOverloads
    fun <R> fencedSigner(store: LeaseStore, getLease: () -> Any?, sign: () -> R, skewMs: Any? = null): () -> Signed<R> = {
        val lease = getLease() ?: throw FenceError("no-lease")
        val pre = assertFence(store, lease, skewMs)
        if (pre["ok"] != true) throw FenceError(pre["reason"] as String)
        val result = sign()
        val post = assertFence(store, lease, skewMs)
        if (post["ok"] != true) throw FenceError(post["reason"] as String)
        Signed(result, member(lease, "epoch"))
    }

    /** Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write). */
    class FenceGuard internal constructor(initial: Any?) {
        private var hi: Double = if (isSafeInteger(initial) && fin(initial)!! > 0) fin(initial)!! else 0.0

        @Synchronized
        fun admit(epoch: Any?): Boolean {
            val e = fin(epoch)
            if (!isSafeInteger(epoch) || e!! < 1 || e < hi) return false
            hi = e
            return true
        }

        @Synchronized
        fun highest(): Long = hi.toLong()
    }

    @JvmOverloads
    fun createFenceGuard(initial: Any? = 0L): FenceGuard = FenceGuard(initial)

    /** The reference [LeaseStore] over any [AtomicKv] (its `update` is the atomic compare-and-swap). */
    class KvLeaseStore @JvmOverloads constructor(private val kv: AtomicKv, key: String? = null, private val clock: (() -> Double)? = null) : LeaseStore {
        private val key: String = key ?: DEFAULT_LEASE_KEY

        override fun read(): Any? {
            val v = kv.get(key)
            if (v != null && !validRecord(v)) throw IllegalStateException("corrupt lease state")
            return v
        }

        override fun cas(expected: Any?, next: Any?): Boolean {
            if (!validRecord(next)) throw IllegalArgumentException("invalid lease record")
            val copy = LinkedHashMap(next as Map<String, Any?>)
            var matched = false
            kv.update(key) { prev ->
                matched = false
                if (prev != null && !validRecord(prev)) return@update null
                if (!eqLease(prev, expected) || d(copy["epoch"]) < (if (prev == null) 0.0 else d(member(prev, "epoch")))) return@update null
                matched = true
                copy
            }
            return matched
        }

        override fun now(): Double = clock?.invoke() ?: System.currentTimeMillis().toDouble()
    }
}
