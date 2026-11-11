package net.atlasauth.pca.verifier

/**
 * LEASES (verification side): a time-boxed grant or credential that must be renewed to stay alive, has a hard `max_ttl` it can never
 * outlive, and dies at once when revoked. A lease authority signs a record; [Registry] keeps the newest record per `lease_id`.
 * Port of packages/pca-grants/src/lease.ts; replays packages/pca/conformance/lease-vectors.json. Everything is total.
 */
object Lease {
    const val DOMAIN = "atlas-pca/lease/v1\u0000"
    const val REVOKE_DOMAIN = "atlas-pca/lease-revoke/v1\u0000"
    private const val MAX_APPROVERS = 16
    private val PATH_RE = Regex("^[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}$")
    private val BODY_KEYS = listOf(
        "v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at",
        "renewed_at", "expires_at", "max_ttl", "authority",
    )
    private val REV_KEYS = listOf("v", "target", "value", "revoked_at", "authority")

    private fun long(o: Any?): Long = IntentJs.lng(o)

    private fun isOne(o: Any?): Boolean = IntentJs.isSafeInteger(o) && long(o) == 1L

    private fun wellFormed(l: Map<String, Any?>): Boolean {
        if (!isOne(l["v"]) || !K3Sig.isStr(l["lease_id"], 128) || !K3Sig.isStr(l["grant_ref"], 256) || !K3Sig.isStr(l["holder"], 128) || !K3Sig.isStr(l["requester"], 128)) return false
        if (!K3Sig.isStr(l["authority"], 128) || !K3Sig.isStr(l["justification_digest"], 128)) return false
        val path = l["path"]
        if (path !is String || !PATH_RE.matches(path)) return false
        for (k in listOf("seq", "issued_at", "renewed_at", "expires_at", "max_ttl")) if (!K3Sig.isSafeInt(l[k])) return false
        val seq = long(l["seq"])
        val issued = long(l["issued_at"])
        val renewed = long(l["renewed_at"])
        if (seq < 1 || long(l["max_ttl"]) < 1) return false
        if (renewed < issued || long(l["expires_at"]) <= renewed || (seq == 1L && renewed != issued)) return false
        val ap = K3Sig.list(l["approvers"]) ?: return false
        if (ap.size > MAX_APPROVERS) return false
        for (a in ap) if (!K3Sig.isStr(a, 128)) return false
        return true
    }

    /** `issued_at + max_ttl`. */
    private fun cap(l: Map<String, Any?>): Long = long(l["issued_at"]) + long(l["max_ttl"])

    /** Well formed and signed by its `authority` over exactly its content. Does NOT check the cap (the registry reports `over_max_ttl`). */
    @JvmStatic
    fun verifyLease(v: Any?): Boolean {
        val l = K3Sig.map(v) ?: return false
        if (!wellFormed(l)) return false
        val body = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) body[k] = l[k]
        return K3Sig.verifyBody(DOMAIN, body, l["authority"], l["sig"])
    }

    private fun revWellFormed(r: Map<String, Any?>): Boolean {
        if (!isOne(r["v"]) || !K3Sig.isStr(r["value"], 256) || !K3Sig.isStr(r["authority"], 128) || !K3Sig.isSafeInt(r["revoked_at"])) return false
        val t = r["target"]
        if (t != "lease" && t != "prefix" && t != "grant") return false
        if (t == "prefix" && !PATH_RE.matches(r["value"] as String)) return false
        return true
    }

    @JvmStatic
    fun verifyLeaseRevocation(v: Any?): Boolean {
        val r = K3Sig.map(v) ?: return false
        if (!revWellFormed(r)) return false
        val body = LinkedHashMap<String, Any?>()
        for (k in REV_KEYS) body[k] = r[k]
        return K3Sig.verifyBody(REVOKE_DOMAIN, body, r["authority"], r["sig"])
    }

    /** `prefix` covers `path` iff equal or `path` continues it at a segment boundary. */
    @JvmStatic
    fun pathUnder(path: String, prefix: String): Boolean = path == prefix || path.startsWith("$prefix/")

    private fun covers(r: Map<String, Any?>, l: Map<String, Any?>): Boolean {
        if (long(l["issued_at"]) > long(r["revoked_at"])) return false
        return when (r["target"]) {
            "lease" -> l["lease_id"] == r["value"]
            "grant" -> l["grant_ref"] == r["value"]
            else -> pathUnder(l["path"] as String, r["value"] as String)
        }
    }

    private fun anyCovers(revs: List<Map<String, Any?>>, l: Map<String, Any?>): Boolean {
        for (r in revs) if (covers(r, l)) return true
        return false
    }

    /** Separation of duties over one record: a reason, or null. [chain] is every key in the holder's delegation chain. */
    @JvmStatic
    fun sodError(requester: String, holder: String, approvers: List<String>, minApprovals: Long = 1, eligibleApprovers: List<String>? = null, chain: List<String> = emptyList()): String? {
        if (minApprovals < 1) return "minApprovals must be a positive integer"
        val seen = HashSet<String>()
        for (a in approvers) {
            if (!seen.add(a)) return "an approver is listed twice"
            if (a == requester) return "the requester may not approve their own request"
            if (a == holder) return "the holder may not approve its own lease"
            if (a in chain) return "an approver appears in the holder's delegation chain"
            if (eligibleApprovers != null && a !in eligibleApprovers) return "an approver is not eligible"
        }
        return if (approvers.size < minApprovals) "${approvers.size} approver(s), need $minApprovals" else null
    }

    class Policy(val authorities: List<String>, val minApprovals: Long = 1, val eligibleApprovers: List<String>? = null, val freshJustification: Boolean = true, val maxTtlCeiling: Long? = null)

    /** [ok] true: [replaced] and [seq] are set. Otherwise [code] names the refusal. */
    class Accept(val ok: Boolean, val code: String? = null, val replaced: Boolean = false, val seq: Long = 0, val reason: String? = null)

    class Revoke(val ok: Boolean, val code: String? = null, val revoked: Int = 0)

    class HistoryEntry(val seq: Long, val renewedAt: Long, val expiresAt: Long, val justificationDigest: String)

    const val DEFAULT_SHARDS = 16
    const val MAX_SHARDS = 4096

    /** The shard a lease id lives in: the first four bytes of SHA-256 of the id, modulo the shard count. Stable across processes. */
    @JvmStatic
    fun shardOf(id: String, shards: Int): Int {
        val h = AttestUtil.sha256(id.toByteArray(Charsets.UTF_8))
        val n = ((h[0].toLong() and 0xff) shl 24) or ((h[1].toLong() and 0xff) shl 16) or ((h[2].toLong() and 0xff) shl 8) or (h[3].toLong() and 0xff)
        return (n % shards).toInt()
    }

    /**
     * Leases live in [kv] (one document per shard: the leases whose id hashes there and every revocation that could cover them), so a
     * revocation survives a restart and is seen by every instance over the same store. A path-prefix or grant revocation is written
     * to EVERY shard, a lease-id revocation only to that lease's shard; within a shard each operation is one atomic `update`. A store
     * that throws is `store_unreachable`. `MemoryAtomicKv` is the explicit single-process store. With `maxTtlCeiling` a revocation is
     * pruned once `revoked_at + ceiling` has passed on [clock] (every lease it could cover is then beyond its own cap).
     */
    class Registry @JvmOverloads constructor(
        private val policy: Policy,
        private val kv: AtomicKv,
        private val shards: Int = DEFAULT_SHARDS,
        private val clock: () -> Long = { System.currentTimeMillis() },
    ) {
        @Volatile private var metaOk = false

        init {
            if (shards < 1 || shards > MAX_SHARDS) throw IllegalArgumentException("LeaseRegistry: shards must be an integer from 1 to 4096")
            val c = policy.maxTtlCeiling
            if (c != null && (c < 1 || c > 9007199254740991L)) throw IllegalArgumentException("LeaseRegistry: maxTtlCeiling must be a positive integer")
        }

        private fun shardKey(i: Int) = "lease/$shards/$i"

        /** Pins the shard count in the store on first use: a different count would hide existing leases, so it is refused. */
        private fun ready(): Boolean {
            if (metaOk) return true
            val m = kv.update("lease/meta") { prev -> if (prev == null) linkedMapOf("v" to IntentJs.ofLong(1), "shards" to IntentJs.ofLong(shards.toLong())) else null }
            val got = (m as? Map<*, *>)?.get("shards")
            metaOk = got != null && IntentJs.isSafeInteger(got) && IntentJs.lng(got) == shards.toLong()
            return metaOk
        }

        @Suppress("UNCHECKED_CAST")
        private fun leasesOf(doc: Any?): LinkedHashMap<String, Any?> =
            LinkedHashMap(((doc as? Map<String, Any?>)?.get("leases") as? Map<String, Any?>) ?: emptyMap())

        @Suppress("UNCHECKED_CAST")
        private fun revsOf(doc: Any?): ArrayList<Map<String, Any?>> =
            ArrayList(((doc as? Map<String, Any?>)?.get("revocations") as? List<Map<String, Any?>>) ?: emptyList())

        private fun docOf(leases: Map<String, Any?>, revs: List<Map<String, Any?>>): Map<String, Any?> = linkedMapOf("leases" to leases, "revocations" to revs)

        @Suppress("UNCHECKED_CAST")
        private fun current(st: Any?): Map<String, Any?>? = (st as? Map<String, Any?>)?.get("current") as? Map<String, Any?>

        @Suppress("UNCHECKED_CAST")
        private fun historyOf(st: Any?): List<Map<String, Any?>> = ((st as? Map<String, Any?>)?.get("history") as? List<Map<String, Any?>>) ?: emptyList()

        private fun prune(revs: ArrayList<Map<String, Any?>>) {
            val c = policy.maxTtlCeiling ?: return
            val now = clock()
            revs.removeAll { long(it["revoked_at"]) + c < now }
        }

        /** Take an issue (seq 1) or a renewal (seq = current + 1). [chain]: the keys in the holder's delegation chain. */
        fun accept(rec: Any?, chain: List<String> = emptyList()): Accept {
            if (!verifyLease(rec)) return Accept(false, "bad_record")
            val l = K3Sig.map(rec)!!
            if (l["authority"] !in policy.authorities) return Accept(false, "unknown_authority")
            val ap = ArrayList<String>()
            for (a in K3Sig.list(l["approvers"])!!) ap.add(a as String)
            val sod = sodError(l["requester"] as String, l["holder"] as String, ap, policy.minApprovals, policy.eligibleApprovers, chain)
            if (sod != null) return Accept(false, "sod", reason = sod)
            if (long(l["expires_at"]) > cap(l)) return Accept(false, "over_max_ttl")
            val ceiling = policy.maxTtlCeiling
            if (ceiling != null && long(l["max_ttl"]) > ceiling) return Accept(false, "ttl_ceiling")
            val id = l["lease_id"] as String
            val seq = long(l["seq"])
            var out = Accept(false, "store_unreachable")
            fun fail(code: String, reason: String? = null): Any? { out = Accept(false, code, reason = reason); return null }
            try {
                if (!ready()) return out
                kv.update(shardKey(shardOf(id, shards))) { prev ->
                    val leases = leasesOf(prev)
                    val revs = revsOf(prev)
                    val st = if (leases.containsKey(id)) leases[id] else null
                    val cur = current(st)
                    if (anyCovers(revs, l)) return@update fail("revoked")
                    if (cur == null) {
                        if (seq != 1L) return@update fail("bad_seq", "a new lease starts at seq 1")
                    } else {
                        val cs = long(cur["seq"])
                        if (seq < cs) return@update fail("stale_seq")
                        if (seq == cs) {
                            if (cur["sig"] == l["sig"]) { out = Accept(true, null, false, seq); return@update null }
                            return@update fail("lease_fork")
                        }
                        if (seq != cs + 1) return@update fail("bad_seq", "renewals advance seq by exactly 1")
                        for (k in listOf("authority", "path", "grant_ref", "holder", "requester", "max_ttl", "issued_at")) if (l[k] != cur[k] && !sameNum(l[k], cur[k])) return@update fail("renewal_mismatch")
                        if (long(l["renewed_at"]) >= long(cur["expires_at"])) return@update fail("expired_lease", "an expired lease cannot be renewed")
                        if (long(l["renewed_at"]) < long(cur["renewed_at"]) || long(l["expires_at"]) <= long(cur["expires_at"])) return@update fail("not_extending")
                        if (policy.freshJustification && l["justification_digest"] == cur["justification_digest"]) return@update fail("stale_justification")
                    }
                    val entry = linkedMapOf<String, Any?>(
                        "seq" to l["seq"], "renewed_at" to l["renewed_at"], "expires_at" to l["expires_at"], "justification_digest" to l["justification_digest"],
                    )
                    leases[id] = linkedMapOf("current" to l, "history" to ArrayList(historyOf(st)).also { it.add(entry) })
                    prune(revs)
                    out = Accept(true, null, true, seq)
                    docOf(leases, revs)
                }
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Accept(false, "store_unreachable")
            }
            return out
        }

        /** Take a signed revocation. Idempotent; a prefix or grant revocation goes to every shard, the count is the leases covered across them. */
        fun revoke(rec: Any?): Revoke {
            if (!verifyLeaseRevocation(rec)) return Revoke(false, "bad_record")
            val r = K3Sig.map(rec)!!
            if (r["authority"] !in policy.authorities) return Revoke(false, "unknown_authority")
            val targets = if (r["target"] == "lease") listOf(shardOf(r["value"] as String, shards)) else (0 until shards).toList()
            var total = 0
            try {
                if (!ready()) return Revoke(false, "store_unreachable")
                for (i in targets) {
                    var n = 0
                    kv.update(shardKey(i)) { prev ->
                        val leases = leasesOf(prev)
                        val revs = revsOf(prev)
                        if (revs.none { it["sig"] == r["sig"] }) revs.add(r)
                        n = leases.values.count { covers(r, current(it)!!) }
                        prune(revs)
                        docOf(leases, revs)
                    }
                    total += n
                }
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Revoke(false, "store_unreachable")
            }
            return Revoke(true, null, total)
        }

        private fun shardDoc(id: String): Any? {
            if (!ready()) throw IllegalStateException("shard count mismatch")
            return kv.get(shardKey(shardOf(id, shards)))
        }

        fun get(id: String): Map<String, Any?>? = current(leasesOf(shardDoc(id))[id])

        fun history(id: String): List<HistoryEntry> =
            historyOf(leasesOf(shardDoc(id))[id]).map { HistoryEntry(long(it["seq"]), long(it["renewed_at"]), long(it["expires_at"]), it["justification_digest"] as String) }

        /** Revocations held by one shard (for operators and the conformance kit). */
        fun shardRevocations(i: Int): List<Map<String, Any?>> {
            if (i < 0 || i >= shards) throw IllegalArgumentException("no such shard")
            return revsOf(kv.get(shardKey(i)))
        }

        /** The [checkLease] verdict for a verified record with signature [sig]. A store that cannot be read denies. */
        internal fun decide(sig: Any?, id: String, n: Long): Decision {
            val st: Map<String, Any?>
            val revoked: Boolean
            try {
                val doc = shardDoc(id)
                st = current(leasesOf(doc)[id]) ?: return Decision("deny", "unknown_lease", id, null)
                revoked = anyCovers(revsOf(doc), st)
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Decision("deny", "store_unreachable", id, null)
            }
            if (st["sig"] != sig) return Decision("deny", "superseded", id, null)
            if (revoked) return Decision("deny", "revoked", id, null)
            if (n < long(st["renewed_at"])) return Decision("deny", "not_yet_valid", id, null)
            if (n >= cap(st)) return Decision("deny", "past_max_ttl", id, null)
            if (n >= long(st["expires_at"])) return Decision("deny", "expired", id, null)
            return Decision("allow", null, id, long(st["expires_at"]))
        }
    }

    /** Numbers are [Json.Num] (equal by source text); compare by value so `1` and `1.0`-style lexemes cannot differ. */
    private fun sameNum(a: Any?, b: Any?): Boolean = a is Json.Num && b is Json.Num && IntentJs.num(a) == IntentJs.num(b)

    /** [decision] is allow or deny; [code] is set on deny; [leaseId] when known; [expiresAt] on allow. */
    class Decision(val decision: String, val code: String? = null, val leaseId: String? = null, val expiresAt: Long? = null)

    /**
     * Is [presented] a live lease? It must verify, be the newest record the registry holds, be inside its window and its cap, and not
     * be covered by a revocation. Fails closed.
     */
    @JvmStatic
    fun checkLease(presented: Any?, registry: Registry, now: Any?): Decision {
        if (!K3Sig.isSafeInt(now)) return Decision("deny", "bad_input")
        if (!verifyLease(presented)) return Decision("deny", "bad_record")
        val p = K3Sig.map(presented)!!
        val id = p["lease_id"] as String
        return registry.decide(p["sig"], id, long(now))
    }
}
