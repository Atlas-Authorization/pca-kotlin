package net.atlasauth.pca.verifier

/**
 * Durable, restart-safe bond settlement over a [BondStore] (packages/pca/src/bond-store.ts `StoreBondLedger`). INTERNAL ACCOUNTING
 * ONLY: nothing here moves money.
 *
 * Each transition is planned by the same [BondSettlementPlanner] a deployment's in-memory ledger would use (so a slash is authorised by a
 * verdict the ledger recomputes, never by the challenger), stamped from a clock the claimant cannot touch, and committed atomically and
 * idempotently. It FAILS CLOSED: no store (`store_missing`), no guardian key (`guardian_key_missing`), a non-finite clock
 * (`clock_invalid`), a store that throws (`store_unavailable`), malformed stored state (`store_corrupt`), a claim that fails verification
 * or the window floor (`invalid_claim`), a release inside the challenge window (`window_open`), a fraud or dispute slash after it
 * (`window_closed`), a release or slash of an unregistered bond (`unregistered`), a claim differing from the registered one
 * (`claim_mismatch`) and a conflicting concurrent transition (`conflict`) are each a [BondStoreError] with that code.
 *
 * The challenge window opens at the ledger's own `registeredAt`, lasts the claim's `challenge_window_ms`, and is never derived from the
 * claim's `issued_at`. "Now" is `max(clock(), highest time the store ever recorded)`, so a clock that steps backwards cannot reopen a
 * closed window or release early. Records, bond rows and statuses are JSON objects.
 */
class StoreBondLedger(opts: Options?) {
    /** [BondSettlementPlanner.Options] plus the store, clock and window policy. */
    class Options : BondSettlementPlanner.Options() {
        /** REQUIRED. There is deliberately no default store. */
        var store: BondStore? = null

        /** Epoch-ms clock (default the system clock). A non-finite reading fails the operation. */
        var clock: (() -> Double)? = null

        /** Window bounds applied by [openClaim] (default [Optimistic.DEFAULT_POLICY]); a window is never below the 30 s realistic floor. */
        var windowPolicy: Optimistic.ChallengeWindowPolicy? = null
    }

    private val planner: BondSettlementPlanner
    private val store: BondStore
    private val clock: () -> Double
    private val windowPolicy: Optimistic.ChallengeWindowPolicy

    init {
        if (opts == null) throw BondStoreError("store_missing", "a BondStore is required (there is no in-memory default)")
        val st = opts.store ?: throw BondStoreError("store_missing", "a BondStore is required (there is no in-memory default)")
        val gk = opts.guardianKey
        if (gk == null || gk.isDestroyed) throw BondStoreError("guardian_key_missing", "a guardian secret key is required")
        store = st
        planner = BondSettlementPlanner(opts)
        clock = opts.clock ?: { System.currentTimeMillis().toDouble() }
        windowPolicy = opts.windowPolicy ?: Optimistic.DEFAULT_POLICY
    }

    /** The guardian/settlement public key (b64u) the records verify under. */
    fun guardianPublicKey(): String = planner.guardianPublicKey()

    private fun <T> guard(fn: () -> T): T = try {
        fn()
    } catch (e: BondStoreError) {
        throw e
    } catch (e: RuntimeException) {
        throw BondStoreError("store_unavailable", e.message ?: "store failed", e)
    }

    private class Loaded(val snap: BondStore.Snapshot, val view: BondSettlementPlanner.View, val now: Double)

    private fun viewOf(bond: Map<String, Any?>?, balances: Map<String, Double>, totals: DoubleArray): BondSettlementPlanner.View = object : BondSettlementPlanner.View {
        override fun bond(claimId: String): Map<String, Any?>? = if (bond != null && claimId == bond["claimId"]) bond else null
        override fun balanceOf(account: String): Double = balances[account] ?: 0.0
        override fun openTotals(depositor: String): DoubleArray = totals
    }

    private fun load(claimId: String, depositor: String?): Loaded {
        val snap = guard { store.read(claimId, depositor) }
        val t = clock()
        if (t.isNaN() || t.isInfinite()) throw BondStoreError("clock_invalid", "the clock returned a non-finite time")
        return Loaded(snap, viewOf(snap.bond, snap.balances, doubleArrayOf(snap.openCount.toDouble(), snap.openSum)), Math.max(t, snap.highWater))
    }

    private fun lastRecord(bond: Map<String, Any?>): Map<String, Any?>? {
        val recs = bond["records"] as List<*>
        return if (recs.isEmpty()) null else StoreJs.map(recs[recs.size - 1])
    }

    private fun submit(plan: Map<String, Any?>, now: Double): Map<String, Any?>? {
        val out = guard { store.commit(plan, now) }
        if (out.outcome == "conflict") throw BondStoreError("conflict", out.reason ?: "conflict")
        return out.record
    }

    /** Settle: plan against the true view; if the bond is already settled, a retry that would have produced the same settlement returns the stored record. */
    private fun settle(claimId: String, plan: (BondSettlementPlanner.View, Double) -> Map<String, Any?>, gate: ((Map<String, Any?>, Double) -> Unit)?): Map<String, Any?>? {
        val l = load(claimId, null)
        val bond = l.snap.bond
        if (bond != null && bond["status"] != "open") {
            val last = lastRecord(bond)
            val reopened = LinkedHashMap(bond)
            reopened["status"] = "open"
            val again = plan(viewOf(reopened, l.snap.balances, doubleArrayOf(l.snap.openCount.toDouble(), l.snap.openSum)), l.now) // throws if the evidence no longer holds
            if (last != null && BondDoc.sameSettlement(last, StoreJs.map(again["record"])!!)) return last
            return StoreJs.map(plan(l.view, l.now)["record"]) // throws the standard double-settle refusal
        }
        if (bond != null && gate != null) gate(bond, l.now)
        return submit(plan(l.view, l.now), l.now)
    }

    /** Top up an account of the internal books (a positive finite amount). */
    fun deposit(account: String, amount: Double): Double = guard { store.deposit(account, amount) }

    fun balanceOf(account: String): Double {
        val snap = guard { store.read("", account) }
        return snap.balances[account] ?: 0.0
    }

    /** `none`, `open`, `released` or `slashed`. */
    fun bondStatus(claimId: String): String {
        val s = guard { store.read(claimId, null) }
        return if (s.bond == null) "none" else s.bond["status"] as String
    }

    /** The bond row `{claimId, amount, depositor, status, window?, records}`, or null. */
    fun getBond(claimId: String): Map<String, Any?>? = guard { store.read(claimId, null) }.bond

    /** `{phase: open|finalized, endsAt, now}` on the ledger's clock; throws `unregistered` for a bond with no claim. */
    fun challengeStatus(claimId: String): Map<String, Any?> {
        val l = load(claimId, null)
        val w = if (l.snap.bond == null) null else StoreJs.map(l.snap.bond["window"])
        if (w == null) throw BondStoreError("unregistered", "bond $claimId has no registered claim")
        val endsAt = StoreJs.dbl(w["registeredAt"])!! + StoreJs.dbl(w["windowMs"])!!
        // a finalized phase opens settlement, so a clock or window end that is not finite never reads as one
        if (!l.now.isFinite() || !endsAt.isFinite()) throw BondStoreError("clock_invalid", "the challenge window or the clock is not a finite time")
        return linkedMapOf("phase" to (if (l.now > endsAt) "finalized" else "open"), "endsAt" to StoreJs.num(endsAt), "now" to StoreJs.num(l.now))
    }

    /**
     * Register an optimistic claim and lock its bond in one atomic commit. The claim must pass [OptimisticAdjudication.verifyClaim] against
     * the ledger's clock and its window must be at least the realistic floor; the window then runs from the ledger's own `registeredAt`.
     * Retrying the same call returns the original `open` record. [exposure] may be null.
     */
    fun openClaim(claim: Map<String, Any?>?, pcactn: Map<String, Any?>?, signerPublic: String, amount: Double, depositor: String, exposure: Double? = null): Map<String, Any?>? {
        val bondRef = claim?.get("bond_ref")
        val l = load(bondRef.toString(), depositor)
        val verdict = OptimisticAdjudication.verifyClaim(claim, pcactn, signerPublic, l.now, windowPolicy)
        if (verdict["ok"] != true) throw BondStoreError("invalid_claim", verdict["reason"].toString())
        val floor = Math.max(windowPolicy.minWindowMs, OptimisticAdjudication.DEFAULT_MIN_CHALLENGE_WINDOW_MS)
        val windowMs = StoreJs.dbl(claim!!["challenge_window_ms"])!!
        if (windowMs < floor) {
            throw BondStoreError("invalid_claim", "challenge window ${AttestUtil.jsNumString(windowMs)} ms is below the ${AttestUtil.jsNumString(floor)} ms floor")
        }
        if (bondRef !is String || bondRef.isEmpty()) throw BondStoreError("invalid_claim", "claim has no bond_ref")
        val window = linkedMapOf<String, Any?>(
            "registeredAt" to StoreJs.num(l.now), "windowMs" to StoreJs.num(windowMs), "claimDigest" to StoreJs.hashLenient(claim),
        )
        if (l.snap.bond != null) return replayOpen(l.snap.bond, depositor, amount, window)
        return submit(planner.planOpen(l.view, bondRef, amount, depositor, exposure, l.now, window), l.now)
    }

    /** A retried open: the same terms return the original `open` record; anything else is the standard double-open refusal. */
    private fun replayOpen(prior: Map<String, Any?>, depositor: String, amount: Double, window: Map<String, Any?>?): Map<String, Any?>? {
        val pw = StoreJs.map(prior["window"])
        val sameWindow = if (pw == null) window == null else window != null && pw["claimDigest"] == window["claimDigest"]
        val same = prior["depositor"] == depositor && StoreJs.dbl(prior["amount"]) == amount && sameWindow
        val recs = prior["records"] as List<*>
        if (same && recs.isNotEmpty()) return StoreJs.map(recs[0])
        throw BondStoreError("conflict", "openBond: bond ${prior["claimId"]} already exists (double-open refused)")
    }

    /** Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with [slashCounterBond] or [releaseUnregistered]. */
    @JvmOverloads
    fun openBond(claimId: String, amount: Double, depositor: String, exposure: Double? = null): Map<String, Any?>? {
        val l = load(claimId, depositor)
        if (l.snap.bond != null) return replayOpen(l.snap.bond, depositor, amount, null)
        return submit(planner.planOpen(l.view, claimId, amount, depositor, exposure, l.now, null), l.now)
    }

    /** Release a registered claim's bond once its challenge window has closed on the ledger's clock. */
    fun release(claimId: String): Map<String, Any?>? = settle(claimId, { view, now -> planner.planRelease(view, claimId, now) }) { bond, now ->
        val w = StoreJs.map(bond["window"]) ?: throw BondStoreError("unregistered", "bond $claimId has no registered claim; use releaseUnregistered for a counter-bond")
        val end = StoreJs.dbl(w["registeredAt"])!! + StoreJs.dbl(w["windowMs"])!!
        if (!(now > end)) throw BondStoreError("window_open", "the challenge window of $claimId closes at ${AttestUtil.jsNumString(end)}")
    }

    /** Release a bond that backs no claim (a counter-bond). */
    fun releaseUnregistered(claimId: String): Map<String, Any?>? = settle(claimId, { view, now -> planner.planRelease(view, claimId, now) }) { bond, _ ->
        if (StoreJs.map(bond["window"]) != null) throw BondStoreError("conflict", "bond $claimId backs a registered claim; use release")
    }

    private fun challengeGate(claim: Map<String, Any?>?): (Map<String, Any?>, Double) -> Unit = { bond, now ->
        val w = StoreJs.map(bond["window"]) ?: throw BondStoreError("unregistered", "bond ${bond["claimId"]} has no registered claim")
        if (w["claimDigest"] != StoreJs.hashLenient(claim)) throw BondStoreError("claim_mismatch", "the claim is not the one registered for ${bond["claimId"]}")
        val end = StoreJs.dbl(w["registeredAt"])!! + StoreJs.dbl(w["windowMs"])!!
        if (!(now <= end)) throw BondStoreError("window_closed", "the challenge window of ${bond["claimId"]} closed at ${AttestUtil.jsNumString(end)}")
    }

    private fun idOf(p: Map<String, Any?>, k: String): String = p[k] as? String ?: p[k].toString()

    /** Slash on a fraud proof the ledger re-verifies itself, inside the challenge window. [params]: see [BondSettlementPlanner.planSlash]. */
    fun slashBond(params: Map<String, Any?>): Map<String, Any?>? =
        settle(idOf(params, "claimId"), { view, now -> planner.planSlash(view, params, now) }, challengeGate(StoreJs.map(params["claim"])))

    /** Slash on a dispute the ledger re-adjudicates itself, inside the challenge window. */
    fun slashBondOnDispute(params: Map<String, Any?>): Map<String, Any?>? =
        settle(idOf(params, "claimId"), { view, now -> planner.planSlashOnDispute(view, params, now) }, challengeGate(StoreJs.map(params["claim"])))

    /** Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated). */
    fun slashBondOnRevocation(params: Map<String, Any?>): Map<String, Any?>? {
        val claim = StoreJs.map(params["claim"])
        return settle(idOf(params, "claimId"), { view, now -> planner.planSlashOnRevocation(view, params, now) }) { bond, _ ->
            val w = StoreJs.map(bond["window"])
            if (w != null && w["claimDigest"] != StoreJs.hashLenient(claim)) throw BondStoreError("claim_mismatch", "the claim is not the one registered for ${bond["claimId"]}")
        }
    }

    /** Slash a challenger's counter-bond after a frivolous dispute. */
    fun slashCounterBond(params: Map<String, Any?>): Map<String, Any?>? =
        settle(idOf(params, "counterBondId"), { view, now -> planner.planSlashCounterBond(view, params, now) }, null)
}
