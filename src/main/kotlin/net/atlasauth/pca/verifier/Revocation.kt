package net.atlasauth.pca.verifier

/**
 * Verifier-side revocation staleness (T9; the TypeScript `RevocationStalenessPolicy`, `checkRevocationAge`,
 * `checkRevocationEpoch` and the staleness branch of `createRevocationChecker`). The signer chooses an epoch's `not_after`;
 * this lets the VERIFIER cap how old (`now - issued_at`) the revocation state may be, with a stricter window for actions that
 * cannot be undone. The action's class is the stricter of the server's authoritative class and the PCActn's signed
 * `reversibility_class`; a missing or unknown class counts as irreversible (fail closed).
 *
 * Off unless a [StalenessPolicy] is given ([Authorize.Input.revocationStaleness]). Every function here is total.
 */
object Revocation {
    const val REFRESH_MS = 60_000.0
    const val VALIDITY_MS = 300_000.0

    /** Default window for an irreversible action: two refresh periods. */
    const val IRREVERSIBLE_MAX_AGE_MS = 120_000.0
    private const val SKEW_MS = 60_000.0

    /** Severity over both vocabularies a verifier sees (the RS strictness enum and the caveat enum); unknown = most restrictive. */
    private val CLASS_RANK = mapOf("reversible" to 0, "rate_limited" to 1, "costly" to 1, "irreversible" to 2)

    fun classRank(c: Any?): Int = if (c is String) CLASS_RANK[c] ?: 2 else 2

    /** True for one of the four reversibility classes. */
    fun isKnownClass(c: Any?): Boolean = c is String && CLASS_RANK.containsKey(c)

    /** The outcome of a check. [epoch] is the signed epoch that passed every check (only from [checkState]). */
    class Check(val ok: Boolean, val reason: String? = null, val epoch: Map<String, Any?>? = null) {
        override fun toString(): String = "Revocation.Check(ok=$ok, reason=$reason)"
    }

    private fun ok(epoch: Map<String, Any?>? = null) = Check(true, null, epoch)
    private fun no(reason: String) = Check(false, reason)

    /**
     * The staleness policy. Every window is a positive finite number of milliseconds (a malformed one throws
     * [IllegalArgumentException] at construction, never at request time).
     *  - `maxRevocationAgeMs`  maximum age for any action (default 5 minutes).
     *  - `irreversibleMs`, `costlyMs`  per-class windows, each capped by `maxRevocationAgeMs` (defaults: irreversible 2
     *    minutes; rate_limited (old name costly) = the maximum).
     *  - `allowUnsignedRootForIrreversible`  accept state that is not guardian-signed (a bare root) for an irreversible
     *    action (default false: an unsigned root can be any root the verifier was handed).
     *  - `guardianPublic`  the pinned guardian key (b64u) a signed epoch must verify under; `pqPins` pins a PQ suite.
     *  - `onEpochAccepted`  `(epoch, pcactn)`, called after an ADMITTED action whose epoch passed every check (persist it as
     *    the new last accepted epoch).
     *  - `ids`  `(pcactn)` -> the capability ids that need a non-membership proof (default: every `id` in the PCActn's
     *    `cap_chain`, so a revoked ancestor kills its descendants). Pass `{ emptyList() }` to check freshness only.
     *  - `proofFor`  `(pcactn, id)` -> the non-membership proof for a capability id, or null. No proof source, or a null
     *    proof, denies (fail closed).
     */
    class StalenessPolicy(
        val maxRevocationAgeMs: Double? = null,
        val irreversibleMs: Double? = null,
        val costlyMs: Double? = null,
        val allowUnsignedRootForIrreversible: Boolean = false,
        val guardianPublic: String? = null,
        val pqPins: Map<String, Any?>? = null,
        val onEpochAccepted: ((Map<String, Any?>, Map<String, Any?>) -> Unit)? = null,
        val ids: ((Map<String, Any?>) -> List<String>)? = null,
        val proofFor: ((Map<String, Any?>, String) -> Any?)? = null,
    ) {
        init {
            positive("maxRevocationAgeMs", maxRevocationAgeMs)
            positive("irreversibleMs", irreversibleMs)
            positive("costlyMs", costlyMs)
        }

        private fun positive(name: String, v: Double?) {
            require(v == null || (v.isFinite() && v > 0)) { "$name must be a positive number of milliseconds" }
        }
    }

    /** The revocation state one verification relies on. */
    sealed class State {
        /** A guardian-signed epoch (`root`, when given, must equal the epoch's; `lastAcceptedEpoch` pins against rollback). */
        class Epoch(val epoch: Any?, val root: Any? = null, val lastAcceptedEpoch: Long? = null) : State()

        /** A bare root with the time (epoch ms) YOUR trusted source issued it; null = unknown = denied under a policy. */
        class Root(val root: Any?, val issuedAt: Any? = null) : State()

        companion object {
            /**
             * From the JSON shape a context returns: `{kind: "epoch", epoch: {...}, root?, last_accepted_epoch?}` or
             * `{kind: "root", root, issued_at}`. Any other shape is null (no verifiable state).
             */
            fun fromJson(o: Any?): State? {
                if (o is State) return o
                if (o !is Map<*, *>) return null
                return when (o["kind"]) {
                    "epoch" -> Epoch(o["epoch"], o["root"], IntentJs.num(o["last_accepted_epoch"])?.takeIf { IntentJs.isSafeInteger(o["last_accepted_epoch"]) }?.toLong())
                    "root" -> Root(o["root"], o["issued_at"])
                    else -> null
                }
            }
        }
    }

    /** JavaScript `String(n)` of a number. */
    internal fun fmt(d: Double): String = when {
        d.isNaN() -> "NaN"
        d.isInfinite() -> if (d > 0) "Infinity" else "-Infinity"
        else -> IntentJs.shortest(d)
    }

    /** The stricter of the server's class and the signed one. Unknown or missing = irreversible. */
    fun effectiveReversibility(serverClass: Any?, signedClass: Any?): String {
        val rank = maxOf(if (serverClass == null) 0 else classRank(serverClass), classRank(signedClass))
        return if (rank >= 2) "irreversible" else if (rank == 1) "rate_limited" else "reversible"
    }

    /** The maximum age of revocation state the policy allows for an action of class `cls`. */
    fun maxAgeMs(policy: StalenessPolicy, cls: String): Double {
        val mx = policy.maxRevocationAgeMs ?: VALIDITY_MS
        return when (cls) {
            "irreversible" -> minOf(mx, policy.irreversibleMs ?: IRREVERSIBLE_MAX_AGE_MS)
            "costly", "rate_limited" -> minOf(mx, policy.costlyMs ?: mx)
            else -> mx
        }
    }

    /**
     * Age check of revocation state issued (or fetched from a trusted source) at `issuedAt` (a JSON number, else unknown).
     * An unknown issue time is unverifiable and denies; a time more than 60 s in the future denies (the signed epoch's skew).
     */
    fun checkAge(issuedAt: Any?, now: Double, maxAgeMs: Double, what: String = "revocation state"): Check {
        val t = IntentJs.num(issuedAt)
        if (t == null || !t.isFinite()) return no("$what age is unknown (unverifiable revocation state)")
        if (!(t <= now + SKEW_MS)) return no("$what issued in the future")
        if (!(now - t <= maxAgeMs)) return no("$what is ${fmt(now - t)} ms old, over the verifier's maximum of ${fmt(maxAgeMs)} ms (stale revocation state)")
        return ok()
    }

    /**
     * Verify a signed revocation epoch (a parsed JSON object): pinned guardian and suite, shape, signature (a PQ / hybrid
     * epoch only under `pqPins`), grant binding, expiry, the optional verifier-side age cap, rollback against
     * `lastAcceptedEpoch`, and the PCActn's signed `freshness.epoch` (`pcactnEpoch`) being at least the epoch.
     */
    fun checkEpoch(
        ep: Any?, guardianPublic: String?, now: Double, grantRef: String? = null, lastAcceptedEpoch: Long? = null,
        pcactnEpoch: Any? = null, maxAgeMs: Double? = null, pqPins: Map<String, Any?>? = null,
    ): Check = try {
        checkEpochUnchecked(ep, guardianPublic, now, grantRef, lastAcceptedEpoch, pcactnEpoch, maxAgeMs, pqPins)
    } catch (e: RuntimeException) {
        no("revocation epoch check error")
    }

    @Suppress("UNCHECKED_CAST")
    private fun checkEpochUnchecked(
        ep: Any?, guardianPublic: String?, now: Double, grantRef: String?, lastAcceptedEpoch: Long?, pcactnEpoch: Any?,
        maxAgeMs: Double?, pqPins: Map<String, Any?>?,
    ): Check {
        if (ep !is Map<*, *> || guardianPublic == null || ep["guardian"] != guardianPublic || IntentJs.suiteOf(IntentJs.obj(ep)) == null)
            return no("revocation epoch not signed by the pinned guardian")
        val m = IntentJs.normalize(ep) as Map<String, Any?>
        for (k in listOf("epoch", "set_size")) if (!IntentJs.isSafeInteger(m[k]) || IntentJs.num(m[k])!! < 0) return no("malformed revocation epoch")
        for (k in listOf("issued_at", "not_after")) if (!IntentJs.isSafeInteger(m[k])) return no("malformed revocation epoch")
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after")) body[k] = m[k]
        val msg = Pca.concat(
            IntentJs.utf8(IntentRevocation.REVEPOCH_DOMAIN),
            IntentJs.canonBytes(IntentJs.bindSuiteFields(body, m["alg"], m.containsKey("alg"), m["pq_pk"], m.containsKey("pq_pk"))),
        )
        if (!IntentJs.verifyPinnedSuite(m["alg"], m.containsKey("alg"), guardianPublic, m["pq_pk"], msg, m["sig"], m["pq_sig"], pqPins))
            return no("revocation epoch signature invalid")
        if (grantRef != null && m["grant_ref"] != grantRef) return no("revocation epoch is for a different grant")
        val issuedAt = IntentJs.num(m["issued_at"])!!
        val epoch = IntentJs.num(m["epoch"])!!
        if (!(now <= IntentJs.num(m["not_after"])!!)) return no("revocation epoch expired (stale revocation root)")
        if (!(issuedAt <= now + SKEW_MS)) return no("revocation epoch issued in the future")
        if (maxAgeMs != null) {
            val age = checkAge(issuedAt, now, maxAgeMs, "revocation epoch")
            if (!age.ok) return age
        }
        if (lastAcceptedEpoch != null && epoch < lastAcceptedEpoch.toDouble())
            return no("revocation epoch ${fmt(epoch)} is older than the last accepted $lastAcceptedEpoch (rollback)")
        if (pcactnEpoch != null) {
            val pe = IntentJs.num(pcactnEpoch)
            if (pe == null || !(pe >= epoch)) return no("PCActn freshness.epoch ${IntentRevocation.jsText(pcactnEpoch, true)} predates the revocation epoch ${fmt(epoch)}")
        }
        return ok()
    }

    /**
     * The revocation-state gate (`createRevocationChecker`): after the freshness step, every id in `ids` needs a valid
     * non-membership proof (`proofFor`; none = denied) against the epoch's (or bare) root. No ids = freshness only.
     *  - [State.Epoch]: checked against `guardianPublic` (default `policy.guardianPublic`) and, with a policy, the per-class
     *    age cap; a given `root` must equal the epoch's;
     *  - [State.Root]: with a policy refused for an irreversible action (unless allowed) and held to the same age cap via the
     *    time your trusted source issued it;
     *  - null: no signed epoch (denied).
     * `policy` null = staleness off: a signed epoch is still verified, with no verifier-side cap.
     */
    fun checkState(
        policy: StalenessPolicy?, state: State?, now: Double, grantRef: String? = null, signedClass: Any? = null,
        serverClass: Any? = null, pcactnEpoch: Any? = null, guardianPublic: String? = null,
        ids: List<String> = emptyList(), proofFor: (String) -> Any? = { null },
    ): Check = try {
        val cls: String? = if (policy != null) effectiveReversibility(serverClass, signedClass) else null
        val maxAge: Double? = if (policy != null && cls != null) maxAgeMs(policy, cls) else null
        var root: Any? = null
        var accepted: Map<String, Any?>? = null
        var early: Check? = null
        when (state) {
            is State.Epoch -> {
                val gp = guardianPublic ?: policy?.guardianPublic
                val ep = state.epoch
                if (ep !is Map<*, *> || gp.isNullOrEmpty()) early = no("no signed revocation epoch")
                else {
                    val chk = checkEpoch(ep, gp, now, grantRef, state.lastAcceptedEpoch, pcactnEpoch, maxAge, policy?.pqPins)
                    if (!chk.ok) early = chk
                    else if (state.root != null && state.root != ep["root"]) early = no("revocation root does not match the signed epoch")
                    else {
                        root = ep["root"]
                        accepted = IntentJs.obj(ep)
                    }
                }
            }
            is State.Root -> {
                root = state.root
                if (policy != null && maxAge != null) {
                    if (cls == "irreversible" && !policy.allowUnsignedRootForIrreversible)
                        early = no("unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)")
                    else {
                        val age = checkAge(state.issuedAt, now, maxAge, "revocation root")
                        if (!age.ok) early = age
                    }
                }
            }
            null -> early = no("no signed revocation epoch")
        }
        when {
            early != null -> early
            root !is String || root.isEmpty() -> no("no revocation root")
            else -> {
                val r: String = root
                ids.firstNotNullOfOrNull { id ->
                    val proof = proofFor(id)
                    if (proof == null) no("no non-membership proof for $id")
                    else if (!verifyNonMembership(r, proof, id)) no("capability $id is revoked or proof invalid")
                    else null
                } ?: ok(accepted)
            }
        }
    } catch (e: RuntimeException) {
        no("revocation state check error (fail closed)")
    }

    /** A leaf proof `{id, proof: {index, size, path}}` against the size-bound root: the (id, index) when it folds to it. */
    private fun leafOk(root: String, size: Long, leaf: Any?): Pair<String, Long>? {
        val id = IntentJs.get(leaf, "id") as? String ?: return null
        val pr = IntentJs.get(leaf, "proof") as? Map<*, *> ?: return null
        if (!Json.isSafeInt(pr["index"]) || !Json.isSafeInt(pr["size"])) return null
        val index = Json.asLong(pr["index"])
        if (Json.asLong(pr["size"]) != size || index < 0 || index >= size) return null
        val path = pr["path"] as? List<*> ?: return null
        val shape = Pca.pathShape(index, size)
        if (shape.size != path.size) return null
        var h = Pca.leafHash(id)
        for (i in path.indices) {
            val step = path[i] as? Map<*, *> ?: return null
            if (step["side"] != shape[i]) return null
            val sib = Pca.decodeB64uStrict(step["hash"], 32) ?: return null
            h = if (shape[i] == "L") Pca.nodeHash(sib, h) else Pca.nodeHash(h, sib)
        }
        return if (IntentRevocation.bindRoot(IntentJs.ofLong(size), Pca.b64(h)) == root) Pair(id, index) else null
    }

    /**
     * `verifyNonMembership`: `id` is NOT in the sorted revocation set `root` commits to (UTF-8 byte order, root bound to the
     * set size): adjacent neighbours `lo` < id < `hi` with inclusion proofs against the bound root, or the empty-set root.
     * Never throws; anything malformed is false.
     */
    fun verifyNonMembership(root: String, proof: Any?, id: String): Boolean = try {
        nonMembership(root, proof, id)
    } catch (e: RuntimeException) {
        false
    }

    private fun nonMembership(root: String, proof: Any?, id: String): Boolean {
        if (proof !is Map<*, *> || !Json.isSafeInt(proof["size"])) return false
        val size = Json.asLong(proof["size"])
        if (size < 0) return false
        val lo = proof["lo"]
        val hi = proof["hi"]
        if (size == 0L) return lo == null && hi == null && IntentRevocation.bindRoot(IntentJs.ofLong(0), IntentRevocation.EMPTY_TREE) == root
        if (lo == null && hi == null) return false
        var loIdx: Long? = null
        if (lo != null) {
            val l = leafOk(root, size, lo)
            if (l == null || Json.compareUtf8(l.first, id) >= 0) return false
            loIdx = l.second
            if (hi == null && loIdx != size - 1) return false // id above the maximum
        }
        if (hi != null) {
            val h = leafOk(root, size, hi)
            if (h == null || Json.compareUtf8(id, h.first) >= 0) return false
            if (lo == null && h.second != 0L) return false // id below the minimum
            if (loIdx != null && h.second != loIdx + 1) return false
        }
        return true
    }
}
