package net.atlasauth.pca.verifier

/**
 * BREAK-GLASS GRANTS (verification side): a pre-authorized, short-lived, small-budget emergency grant with a mandatory signed review
 * after the fact. A use is recorded only when the enforcement point reports the notification delivered; a holder whose review is
 * overdue, or whose use was judged unjustified, is frozen. Port of packages/pca-grants/src/breakglass.ts; replays
 * packages/pca/conformance/break-glass-vectors.json. Everything is total. State is kept per holder (one atomic document per holder).
 */
object BreakGlass {
    const val DOMAIN = "atlas-pca/break-glass/v1\u0000"
    const val REVIEW_DOMAIN = "atlas-pca/break-glass-review/v1\u0000"
    const val MAX_WINDOW_MS = 86_400_000L
    const val MAX_USES = 16L
    const val MAX_REVIEW_WITHIN_MS = 30L * 86_400_000L
    private val BODY_KEYS = listOf("v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority")
    private val REVIEW_KEYS = listOf("v", "id", "outcome", "notes_digest", "at", "reviewer")

    private fun long(o: Any?): Long = IntentJs.lng(o)

    private fun isOne(o: Any?): Boolean = IntentJs.isSafeInteger(o) && long(o) == 1L

    private fun wellFormed(v: Any?): Map<String, Any?>? {
        val b = K3Sig.map(v) ?: return null
        if (!isOne(b["v"]) || !K3Sig.isStr(b["id"], 128) || !K3Sig.isStr(b["holder"], 128) || !K3Sig.isStr(b["grant_ref"], 256)) return null
        if (!K3Sig.isStr(b["reason_digest"], 128) || !K3Sig.isStr(b["notify_to"], 256) || !K3Sig.isStr(b["authority"], 128)) return null
        for (k in listOf("max_uses", "issued_at", "expires_at", "review_within")) if (!K3Sig.isSafeInt(b[k])) return null
        val uses = long(b["max_uses"])
        if (uses < 1 || uses > MAX_USES) return null
        val issued = long(b["issued_at"])
        val expires = long(b["expires_at"])
        if (expires <= issued || expires - issued > MAX_WINDOW_MS) return null
        val rw = long(b["review_within"])
        return if (rw in 1..MAX_REVIEW_WITHIN_MS) b else null
    }

    @JvmStatic
    fun verifyBreakGlass(v: Any?): Boolean {
        val b = wellFormed(v) ?: return false
        val body = LinkedHashMap<String, Any?>()
        for (k in BODY_KEYS) body[k] = b[k]
        return K3Sig.verifyBody(DOMAIN, body, b["authority"], b["sig"])
    }

    private fun reviewWellFormed(v: Any?): Map<String, Any?>? {
        val r = K3Sig.map(v) ?: return null
        if (!isOne(r["v"]) || !K3Sig.isStr(r["id"], 128) || !K3Sig.isStr(r["notes_digest"], 128) || !K3Sig.isStr(r["reviewer"], 128)) return null
        if (r["outcome"] != "justified" && r["outcome"] != "unjustified") return null
        return if (K3Sig.isSafeInt(r["at"])) r else null
    }

    @JvmStatic
    fun verifyBreakGlassReview(v: Any?): Boolean {
        val r = reviewWellFormed(v) ?: return false
        val body = LinkedHashMap<String, Any?>()
        for (k in REVIEW_KEYS) body[k] = r[k]
        return K3Sig.verifyBody(REVIEW_DOMAIN, body, r["reviewer"], r["sig"])
    }

    class Policy(val authorities: List<String>, val reviewers: List<String>)

    /** [ok] true: [replaced] is set. Otherwise [code] names the refusal. */
    class Result(val ok: Boolean, val code: String? = null, val replaced: Boolean = false)

    /** [decision] allow or deny; [code] on deny; [id] when known; [use], [remaining], [reviewDue] on allow. */
    class Decision(val decision: String, val code: String? = null, val id: String? = null, val use: Long = 0, val remaining: Long = 0, val reviewDue: Long = 0)

    class UseEntry(val n: Long, val actionDigest: String, val at: Long)

    private class Entry(val rec: Map<String, Any?>) {
        val uses = ArrayList<UseEntry>()
        var review: Map<String, Any?>? = null
    }

    class Registry(private val policy: Policy) {
        private val holders = HashMap<String, LinkedHashMap<String, Entry>>()

        private fun frozenIn(grants: Map<String, Entry>?, now: Long): Boolean =
            grants != null && grants.values.any { e ->
                val rv = e.review
                (rv != null && rv["outcome"] == "unjustified") || (rv == null && e.uses.isNotEmpty() && now >= e.uses[0].at + long(e.rec["review_within"]))
            }

        /** Register an issued record. A frozen holder gets no new one. */
        @Synchronized
        fun accept(rec: Any?, now: Any?): Result {
            if (!verifyBreakGlass(rec) || !K3Sig.isSafeInt(now)) return Result(false, "bad_record")
            val r = K3Sig.map(rec)!!
            if (r["authority"] !in policy.authorities) return Result(false, "unknown_authority")
            val grants = holders.getOrPut(r["holder"] as String) { LinkedHashMap() }
            val cur = grants[r["id"] as String]
            if (cur != null) return if (cur.rec["sig"] == r["sig"]) Result(true, null, false) else Result(false, "id_conflict")
            if (frozenIn(grants, long(now))) return Result(false, "holder_frozen")
            grants[r["id"] as String] = Entry(r)
            return Result(true, null, true)
        }

        /** Record one use; [notified] must be true. Checks in order: input, existence, holder, freeze, revocation, window, budget, notification. */
        @Synchronized
        fun use(id: Any?, holder: Any?, actionDigest: Any?, now: Any?, notified: Any?): Decision {
            if (!K3Sig.isStr(id, 128) || !K3Sig.isStr(holder, 128) || !K3Sig.isStr(actionDigest, 128) || !K3Sig.isSafeInt(now) || notified !is Boolean) return Decision("deny", "bad_input")
            val i = id as String
            val n = long(now)
            val grants = holders[holder as String]
            val e = grants?.get(i) ?: return Decision("deny", "unknown_break_glass", i)
            if (frozenIn(grants, n)) return Decision("deny", "holder_frozen", i)
            if (e.review?.get("outcome") == "unjustified") return Decision("deny", "revoked", i)
            if (n < long(e.rec["issued_at"])) return Decision("deny", "not_yet_valid", i)
            if (n >= long(e.rec["expires_at"])) return Decision("deny", "expired", i)
            if (e.uses.size >= long(e.rec["max_uses"])) return Decision("deny", "budget_exhausted", i)
            if (!notified) return Decision("deny", "not_notified", i)
            e.uses.add(UseEntry(e.uses.size + 1L, actionDigest as String, n))
            return Decision("allow", null, i, e.uses.size.toLong(), long(e.rec["max_uses"]) - e.uses.size, e.uses[0].at + long(e.rec["review_within"]))
        }

        /** Record the signed review. The first review of a grant is final; a late one lifts an overdue freeze. */
        @Synchronized
        fun review(rec: Any?, holder: Any?, now: Any?): Result {
            if (!verifyBreakGlassReview(rec) || !K3Sig.isStr(holder, 128) || !K3Sig.isSafeInt(now)) return Result(false, "bad_record")
            val r = K3Sig.map(rec)!!
            if (r["reviewer"] !in policy.reviewers) return Result(false, "unknown_reviewer")
            val e = holders[holder as String]?.get(r["id"] as String) ?: return Result(false, "unknown_break_glass")
            if (r["reviewer"] == e.rec["holder"] || r["reviewer"] == e.rec["authority"]) return Result(false, "sod")
            val rv = e.review
            if (rv != null) return if (rv["sig"] == r["sig"]) Result(true, null, false) else Result(false, "already_reviewed")
            if (e.uses.isEmpty()) return Result(false, "nothing_to_review")
            if (long(r["at"]) < e.uses[0].at || long(r["at"]) > long(now)) return Result(false, "bad_time")
            e.review = r
            return Result(true, null, true)
        }

        /** Fail closed: malformed input is frozen. */
        @Synchronized
        fun frozen(holder: Any?, now: Any?): Boolean {
            if (!K3Sig.isStr(holder, 128) || !K3Sig.isSafeInt(now)) return true
            return frozenIn(holders[holder as String], long(now))
        }
    }
}
