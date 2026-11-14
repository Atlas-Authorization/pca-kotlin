package net.atlasauth.pca.verifier

/**
 * BREAK-GLASS GRANTS (verification side): a pre-authorized, short-lived, small-budget emergency grant with a mandatory signed review
 * after the fact. A use is recorded only when the enforcement point reports the notification delivered; a holder whose review is
 * overdue, or whose use was judged unjustified, is frozen. Port of packages/pca-grants/src/breakglass.ts; replays
 * packages/pca/conformance/break-glass-vectors.json. Everything is total. State is kept in a durable key-value store, one atomic document per holder.
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

    /**
     * State lives in [kv], one atomic document per holder (`breakglass/holder/<holder>` = `{grants: {<id>: {rec, uses, review?}}}`), so a
     * restart or another instance over the same store sees every use and review. A store that throws is `store_unreachable`
     * (accept / use / review) and a frozen holder ([frozen]); the use budget is spent inside one atomic `update`, so two registries
     * over one store can never both take the last use. `MemoryAtomicKv` is the explicit single-process store.
     */
    class Registry(private val policy: Policy, private val kv: AtomicKv) {
        private fun key(holder: String) = "breakglass/holder/$holder"

        @Suppress("UNCHECKED_CAST")
        private fun grantsOf(doc: Any?): LinkedHashMap<String, Any?> {
            val m = doc as? Map<String, Any?>
            val g = m?.get("grants") as? Map<String, Any?>
            return if (g == null) LinkedHashMap() else LinkedHashMap(g)
        }

        private fun docOf(grants: Map<String, Any?>): Map<String, Any?> = linkedMapOf("grants" to grants)

        @Suppress("UNCHECKED_CAST")
        private fun entry(grants: Map<String, Any?>, id: String): Map<String, Any?>? = if (grants.containsKey(id)) grants[id] as? Map<String, Any?> else null

        @Suppress("UNCHECKED_CAST")
        private fun usesOf(e: Map<String, Any?>): List<Map<String, Any?>> = (e["uses"] as? List<Map<String, Any?>>) ?: emptyList()

        @Suppress("UNCHECKED_CAST")
        private fun recOf(e: Map<String, Any?>): Map<String, Any?> = e["rec"] as Map<String, Any?>

        @Suppress("UNCHECKED_CAST")
        private fun reviewOf(e: Map<String, Any?>): Map<String, Any?>? = e["review"] as? Map<String, Any?>

        private fun frozenIn(grants: Map<String, Any?>, now: Long): Boolean =
            grants.values.any { x ->
                @Suppress("UNCHECKED_CAST") val e = x as Map<String, Any?>
                val rv = reviewOf(e)
                val uses = usesOf(e)
                (rv != null && rv["outcome"] == "unjustified") || (rv == null && uses.isNotEmpty() && now >= long(uses[0]["at"]) + long(recOf(e)["review_within"]))
            }

        /** Register an issued record. A frozen holder gets no new one. */
        fun accept(rec: Any?, now: Any?): Result {
            if (!verifyBreakGlass(rec) || !K3Sig.isSafeInt(now)) return Result(false, "bad_record")
            val r = K3Sig.map(rec)!!
            if (r["authority"] !in policy.authorities) return Result(false, "unknown_authority")
            var out = Result(false, "store_unreachable")
            try {
                kv.update(key(r["holder"] as String)) { prev ->
                    val grants = grantsOf(prev)
                    val cur = entry(grants, r["id"] as String)
                    if (cur != null) {
                        out = if (recOf(cur)["sig"] == r["sig"]) Result(true, null, false) else Result(false, "id_conflict")
                        null
                    } else if (frozenIn(grants, long(now))) {
                        out = Result(false, "holder_frozen")
                        null
                    } else {
                        grants[r["id"] as String] = linkedMapOf("rec" to r, "uses" to ArrayList<Any?>())
                        out = Result(true, null, true)
                        docOf(grants)
                    }
                }
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Result(false, "store_unreachable")
            }
            return out
        }

        /** Record one use; [notified] must be true. Checks in order: input, existence, holder, freeze, revocation, window, budget, notification. */
        fun use(id: Any?, holder: Any?, actionDigest: Any?, now: Any?, notified: Any?): Decision {
            if (!K3Sig.isStr(id, 128) || !K3Sig.isStr(holder, 128) || !K3Sig.isStr(actionDigest, 128) || !K3Sig.isSafeInt(now) || notified !is Boolean) return Decision("deny", "bad_input")
            val i = id as String
            val n = long(now)
            var out = Decision("deny", "store_unreachable", i)
            fun deny(code: String): Any? { out = Decision("deny", code, i); return null }
            try {
                kv.update(key(holder as String)) { prev ->
                    val grants = grantsOf(prev)
                    val e = entry(grants, i) ?: return@update deny("unknown_break_glass")
                    val rec = recOf(e)
                    if (frozenIn(grants, n)) return@update deny("holder_frozen")
                    if (reviewOf(e)?.get("outcome") == "unjustified") return@update deny("revoked")
                    if (n < long(rec["issued_at"])) return@update deny("not_yet_valid")
                    if (n >= long(rec["expires_at"])) return@update deny("expired")
                    val uses = ArrayList(usesOf(e))
                    if (uses.size >= long(rec["max_uses"])) return@update deny("budget_exhausted")
                    if (!(notified as Boolean)) return@update deny("not_notified")
                    uses.add(linkedMapOf("n" to IntentJs.ofLong(uses.size + 1L), "action_digest" to actionDigest, "at" to IntentJs.ofLong(n)))
                    val next = LinkedHashMap(e)
                    next["uses"] = uses
                    grants[i] = next
                    out = Decision("allow", null, i, uses.size.toLong(), long(rec["max_uses"]) - uses.size, long(uses[0]["at"]) + long(rec["review_within"]))
                    docOf(grants)
                }
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Decision("deny", "store_unreachable", i)
            }
            return out
        }

        /** Record the signed review. The first review of a grant is final; a late one lifts an overdue freeze. */
        fun review(rec: Any?, holder: Any?, now: Any?): Result {
            if (!verifyBreakGlassReview(rec) || !K3Sig.isStr(holder, 128) || !K3Sig.isSafeInt(now)) return Result(false, "bad_record")
            val r = K3Sig.map(rec)!!
            if (r["reviewer"] !in policy.reviewers) return Result(false, "unknown_reviewer")
            var out = Result(false, "store_unreachable")
            fun fail(code: String): Any? { out = Result(false, code); return null }
            try {
                kv.update(key(holder as String)) { prev ->
                    val grants = grantsOf(prev)
                    val e = entry(grants, r["id"] as String) ?: return@update fail("unknown_break_glass")
                    val g = recOf(e)
                    if (r["reviewer"] == g["holder"] || r["reviewer"] == g["authority"]) return@update fail("sod")
                    val rv = reviewOf(e)
                    if (rv != null) {
                        if (rv["sig"] == r["sig"]) { out = Result(true, null, false); return@update null }
                        return@update fail("already_reviewed")
                    }
                    val uses = usesOf(e)
                    if (uses.isEmpty()) return@update fail("nothing_to_review")
                    if (long(r["at"]) < long(uses[0]["at"]) || long(r["at"]) > long(now)) return@update fail("bad_time")
                    val next = LinkedHashMap(e)
                    next["review"] = r
                    grants[r["id"] as String] = next
                    out = Result(true, null, true)
                    docOf(grants)
                }
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return Result(false, "store_unreachable")
            }
            return out
        }

        /** Fail closed: malformed input, or a store that cannot be read, is frozen. */
        fun frozen(holder: Any?, now: Any?): Boolean {
            if (!K3Sig.isStr(holder, 128) || !K3Sig.isSafeInt(now)) return true
            return try {
                frozenIn(grantsOf(kv.get(key(holder as String))), long(now))
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                true
            }
        }

        /** The numbered use log of a grant, oldest first (empty when unknown or the store cannot be read). */
        fun uses(holder: String, id: String): List<UseEntry> = try {
            val e = entry(grantsOf(kv.get(key(holder))), id)
            if (e == null) emptyList() else usesOf(e).map { UseEntry(long(it["n"]), it["action_digest"] as String, long(it["at"])) }
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            emptyList()
        }
    }
}
