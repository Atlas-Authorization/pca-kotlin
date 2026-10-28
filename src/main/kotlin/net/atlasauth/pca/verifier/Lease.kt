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

    private fun wellFormed(v: Any?): Map<String, Any?>? {
        val l = K3Sig.map(v) ?: return null
        if (!isOne(l["v"]) || !K3Sig.isStr(l["lease_id"], 128) || !K3Sig.isStr(l["grant_ref"], 256) || !K3Sig.isStr(l["holder"], 128) || !K3Sig.isStr(l["requester"], 128)) return null
        if (!K3Sig.isStr(l["authority"], 128) || !K3Sig.isStr(l["justification_digest"], 128)) return null
        val path = l["path"]
        if (path !is String || !PATH_RE.matches(path)) return null
        for (k in listOf("seq", "issued_at", "renewed_at", "expires_at", "max_ttl")) if (!K3Sig.isSafeInt(l[k])) return null
        val seq = long(l["seq"])
        val issued = long(l["issued_at"])
        val renewed = long(l["renewed_at"])
        if (seq < 1 || long(l["max_ttl"]) < 1) return null
        if (renewed < issued || long(l["expires_at"]) <= renewed || (seq == 1L && renewed != issued)) return null
        val ap = K3Sig.list(l["approvers"]) ?: return null
        if (ap.size > MAX_APPROVERS || !ap.all { K3Sig.isStr(it, 128) }) return null
        return l
    }

    /** `issued_at + max_ttl`. */
    private fun cap(l: Map<String, Any?>): Long = long(l["issued_at"]) + long(l["max_ttl"])

    /** Well formed and signed by its `authority` over exactly its content. Does NOT check the cap (the registry reports `over_max_ttl`). */
    @JvmStatic
    fun verifyLease(v: Any?): Boolean {
        val l = wellFormed(v) ?: return false
        val body = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) body[k] = l[k]
        return K3Sig.verifyBody(DOMAIN, body, l["authority"], l["sig"])
    }

    private fun revWellFormed(v: Any?): Map<String, Any?>? {
        val r = K3Sig.map(v) ?: return null
        if (!isOne(r["v"]) || !K3Sig.isStr(r["value"], 256) || !K3Sig.isStr(r["authority"], 128) || !K3Sig.isSafeInt(r["revoked_at"])) return null
        val t = r["target"]
        if (t != "lease" && t != "prefix" && t != "grant") return null
        if (t == "prefix" && !PATH_RE.matches(r["value"] as String)) return null
        return r
    }

    @JvmStatic
    fun verifyLeaseRevocation(v: Any?): Boolean {
        val r = revWellFormed(v) ?: return false
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

    class Policy(val authorities: List<String>, val minApprovals: Long = 1, val eligibleApprovers: List<String>? = null, val freshJustification: Boolean = true)

    /** [ok] true: [replaced] and [seq] are set. Otherwise [code] names the refusal. */
    class Accept(val ok: Boolean, val code: String? = null, val replaced: Boolean = false, val seq: Long = 0, val reason: String? = null)

    class Revoke(val ok: Boolean, val code: String? = null, val revoked: Int = 0)

    class HistoryEntry(val seq: Long, val renewedAt: Long, val expiresAt: Long, val justificationDigest: String)

    internal class State(var current: Map<String, Any?>, val history: MutableList<HistoryEntry>)

    class Registry(private val policy: Policy) {
        internal val leases = HashMap<String, State>()
        internal val revocations = ArrayList<Map<String, Any?>>()

        /** Take an issue (seq 1) or a renewal (seq = current + 1). [chain]: the keys in the holder's delegation chain. */
        @Synchronized
        fun accept(rec: Any?, chain: List<String> = emptyList()): Accept {
            if (!verifyLease(rec)) return Accept(false, "bad_record")
            val l = K3Sig.map(rec)!!
            if (l["authority"] !in policy.authorities) return Accept(false, "unknown_authority")
            val ap = K3Sig.list(l["approvers"])!!.map { it as String }
            val sod = sodError(l["requester"] as String, l["holder"] as String, ap, policy.minApprovals, policy.eligibleApprovers, chain)
            if (sod != null) return Accept(false, "sod", reason = sod)
            if (long(l["expires_at"]) > cap(l)) return Accept(false, "over_max_ttl")
            val id = l["lease_id"] as String
            val seq = long(l["seq"])
            if (revocations.any { covers(it, l) }) return Accept(false, "revoked")
            val cur = leases[id]?.current
            if (cur == null) {
                if (seq != 1L) return Accept(false, "bad_seq", reason = "a new lease starts at seq 1")
            } else {
                val cs = long(cur["seq"])
                if (seq < cs) return Accept(false, "stale_seq")
                if (seq == cs) return if (cur["sig"] == l["sig"]) Accept(true, null, false, seq) else Accept(false, "lease_fork")
                if (seq != cs + 1) return Accept(false, "bad_seq", reason = "renewals advance seq by exactly 1")
                for (k in listOf("authority", "path", "grant_ref", "holder", "requester", "max_ttl", "issued_at")) if (l[k] != cur[k] && !sameNum(l[k], cur[k])) return Accept(false, "renewal_mismatch")
                if (long(l["renewed_at"]) >= long(cur["expires_at"])) return Accept(false, "expired_lease", reason = "an expired lease cannot be renewed")
                if (long(l["renewed_at"]) < long(cur["renewed_at"]) || long(l["expires_at"]) <= long(cur["expires_at"])) return Accept(false, "not_extending")
                if (policy.freshJustification && l["justification_digest"] == cur["justification_digest"]) return Accept(false, "stale_justification")
            }
            val entry = HistoryEntry(seq, long(l["renewed_at"]), long(l["expires_at"]), l["justification_digest"] as String)
            val st = leases[id]
            if (st == null) leases[id] = State(l, mutableListOf(entry)) else { st.current = l; st.history.add(entry) }
            return Accept(true, null, true, seq)
        }

        /** Take a signed revocation. Idempotent. */
        @Synchronized
        fun revoke(rec: Any?): Revoke {
            if (!verifyLeaseRevocation(rec)) return Revoke(false, "bad_record")
            val r = K3Sig.map(rec)!!
            if (r["authority"] !in policy.authorities) return Revoke(false, "unknown_authority")
            if (revocations.none { it["sig"] == r["sig"] }) revocations.add(r)
            return Revoke(true, null, leases.values.count { covers(r, it.current) })
        }

        @Synchronized
        fun get(id: String): Map<String, Any?>? = leases[id]?.current

        @Synchronized
        fun history(id: String): List<HistoryEntry> = leases[id]?.history?.toList() ?: emptyList()
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
        val n = long(now)
        synchronized(registry) {
            val cur = registry.leases[id]?.current ?: return Decision("deny", "unknown_lease", id)
            if (cur["sig"] != p["sig"]) return Decision("deny", "superseded", id)
            if (registry.revocations.any { covers(it, cur) }) return Decision("deny", "revoked", id)
            if (n < long(cur["renewed_at"])) return Decision("deny", "not_yet_valid", id)
            if (n >= cap(cur)) return Decision("deny", "past_max_ttl", id)
            if (n >= long(cur["expires_at"])) return Decision("deny", "expired", id)
            return Decision("allow", null, id, long(cur["expires_at"]))
        }
    }
}
