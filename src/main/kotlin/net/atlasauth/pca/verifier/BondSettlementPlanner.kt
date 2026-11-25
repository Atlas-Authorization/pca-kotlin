package net.atlasauth.pca.verifier

/**
 * The pure half of bond settlement (packages/pca/src/bond-settlement.ts `BondSettlementPlanner`): validates a transition against a read
 * [View], re-derives every slash verdict itself (a slash is never authorised by challenger assertion), computes the balance movements and
 * signs the record. It holds no state and touches no store. A [StoreBondLedger] commits the plans it returns to a [BondStore] atomically.
 *
 * A plan is `{claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?}, moves: [{account, op, amount}], record}`
 * (see [BondStore]); a window is `{registeredAt, windowMs, claimDigest}`.
 */
class BondSettlementPlanner(opts: Options?) {
    /** What deciding a transition needs to read. */
    interface View {
        /** The bond head `{claimId, amount, depositor, status, ...}`, or null. */
        fun bond(claimId: String): Map<String, Any?>?

        fun balanceOf(account: String): Double

        /** `[count, sum]` of the depositor's currently open bonds. */
        fun openTotals(depositor: String): DoubleArray
    }

    /** Planner configuration. Only [guardianKey] is required. */
    open class Options {
        /** The guardian/settlement key that signs every record. */
        var guardianKey: Keys.EdKey? = null

        /** Bound into every signed record when non-null (a non-negative safe integer). */
        var guardianEpoch: Long? = null

        /** Signature suite (null: ed25519). A PQ or hybrid suite binds its public key into the signed body. */
        var suite: Keys.SuiteKey? = null
        var escrowAccount: String? = null

        /** `{floor, k, maxOpenClaims, maxOpenAmount, curve?}` (null: [BondSettlement.defaultBondPolicy]). */
        var bondPolicy: Map<String, Any?>? = null

        /** `{challengerBps, victimBps}` (null: [BondSettlement.defaultSlashSplitPolicy]). */
        var slashSplitPolicy: Map<String, Any?>? = null
    }

    private val guardianPublicKey: String
    private val escrow: String
    private val bondPolicy: Map<String, Any?>
    private val slashSplitPolicy: Map<String, Any?>
    private val suite: Keys.SuiteKey
    private val guardianEpoch: Long?

    init {
        if (opts == null) throw IllegalArgumentException("BondLedger: guardianSecret must be a Uint8Array")
        val key = opts.guardianKey ?: throw IllegalArgumentException("BondLedger: guardianSecret must be a Uint8Array")
        guardianPublicKey = key.id()
        val ge = opts.guardianEpoch
        if (ge != null && (ge < 0 || ge > 9007199254740991L)) throw IllegalArgumentException("BondLedger: guardianEpoch must be a non-negative safe integer")
        guardianEpoch = ge
        val su = opts.suite
        if (su != null && su.ed != null && su.ed.id() != guardianPublicKey) throw IllegalArgumentException("BondLedger: the suite's Ed25519 key is not the guardian key")
        suite = su ?: Keys.ed25519(key)
        escrow = opts.escrowAccount ?: BondSettlement.ESCROW_ACCOUNT
        bondPolicy = opts.bondPolicy ?: BondSettlement.defaultBondPolicy()
        slashSplitPolicy = opts.slashSplitPolicy ?: BondSettlement.defaultSlashSplitPolicy()
    }

    /** The guardian/settlement public key (b64u) the signed records verify under. */
    fun guardianPublicKey(): String = guardianPublicKey

    fun escrow(): String = escrow

    fun bondPolicy(): Map<String, Any?> = bondPolicy

    fun slashSplitPolicy(): Map<String, Any?> = slashSplitPolicy

    private fun signRecord(base: Map<String, Any?>): Map<String, Any?> {
        val withEpoch = LinkedHashMap(base)
        if (guardianEpoch != null) withEpoch["guardian_epoch"] = StoreJs.num(guardianEpoch)
        val body = IntentJs.bindSuiteFields(withEpoch, suite.alg, true, suite.pqPk(), true)
        val sigs = suite.sign(BondSettlement.settlementMessage(body))
        val rec = LinkedHashMap(body)
        rec["sig"] = sigs.first
        if (sigs.second != null) rec["pq_sig"] = sigs.second
        return rec
    }

    private fun mv(account: String, op: String, amount: Double): Map<String, Any?> =
        linkedMapOf("account" to account, "op" to op, "amount" to StoreJs.num(amount))

    private fun base(claimId: String, action: String, amount: Double, from: String, to: String, at: Double, evidenceDigest: String): MutableMap<String, Any?> = linkedMapOf(
        "claimId" to claimId, "action" to action, "amount" to StoreJs.num(amount), "from" to from, "to" to to, "at" to StoreJs.num(at),
        "evidenceDigest" to evidenceDigest,
    )

    private fun plan(claimId: String, expect: String, next: String, moves: List<Any?>, record: Map<String, Any?>): MutableMap<String, Any?> =
        linkedMapOf("claimId" to claimId, "expect" to expect, "next" to next, "moves" to moves, "record" to record)

    private fun amountOf(bond: Map<String, Any?>): Double = StoreJs.dbl(bond["amount"])!!

    private fun openBondOrThrow(view: View, who: String, claimId: String?): Map<String, Any?> {
        val bond = (if (claimId == null) null else view.bond(claimId)) ?: throw IllegalStateException("$who: no bond for $claimId")
        if (bond["status"] != "open") throw IllegalStateException("$who: bond $claimId is already ${bond["status"]} (double-settle refused)")
        return bond
    }

    private fun stringParam(p: Map<String, Any?>, k: String): String? = p[k] as? String

    private fun needTreasury(p: Map<String, Any?>, who: String) {
        val t = stringParam(p, "treasury")
        if (t.isNullOrEmpty()) throw IllegalStateException("$who: treasury is required")
    }

    /** The balance movements of a slash: the full bond leaves escrow and is divided per [BondSettlement.computeSlashSplit]. */
    private fun slashPlan(bond: Map<String, Any?>, claimId: String, now: Double, evidenceDigest: String, p: Map<String, Any?>): Map<String, Any?> {
        val treasury = p["treasury"] as String
        val amount = amountOf(bond)
        val policy = StoreJs.map(p["splitPolicy"]) ?: slashSplitPolicy
        val dest = LinkedHashMap<String, Any?>()
        dest["challengerAccount"] = p["challengerAccount"]
        dest["victimAccount"] = p["compensationAccount"] ?: BondSettlement.COMPENSATION_POOL_ACCOUNT
        dest["treasuryAccount"] = treasury
        val split = BondSettlement.computeSlashSplit(amount, policy, dest)
        val moves = ArrayList<Any?>()
        moves.add(mv(escrow, "debit", amount)) // the full bond leaves escrow
        val ca = split.challengerAccount
        if (ca != null && ca.isNotEmpty() && split.challengerReward > 0) moves.add(mv(ca, "credit", split.challengerReward))
        if (split.victimCompensation > 0) moves.add(mv(split.victimAccount, "credit", split.victimCompensation))
        if (split.treasuryRemainder > 0) moves.add(mv(split.treasuryAccount, "credit", split.treasuryRemainder))
        val b = base(claimId, "slash", amount, escrow, treasury, now, evidenceDigest)
        b["split"] = split.toJson()
        return plan(claimId, "open", "slashed", moves, signRecord(b))
    }

    /**
     * Open (lock) a bond: refuses an unaffordable bond, one below `bondAmount(policy, exposure)`, one that breaches the depositor's
     * caps and a double-open. [exposure] and [window] may be null. The bond moves from the depositor into escrow.
     */
    fun planOpen(view: View, claimId: String?, amount: Double, depositor: String?, exposure: Double?, now: Double, window: Map<String, Any?>?): Map<String, Any?> {
        if (claimId.isNullOrEmpty()) throw IllegalStateException("openBond: claimId is required")
        if (amount.isNaN() || amount.isInfinite() || amount <= 0) throw IllegalStateException("openBond: amount must be a positive finite number")
        if (depositor.isNullOrEmpty()) throw IllegalStateException("openBond: depositor is required")
        if (view.bond(claimId) != null) throw IllegalStateException("openBond: bond $claimId already exists (double-open refused)")

        val required = BondSettlement.bondAmount(bondPolicy, exposure ?: 0.0)
        if (!(amount >= required)) throw IllegalStateException("openBond: amount ${AttestUtil.jsNumString(amount)} is below the required bond ${AttestUtil.jsNumString(required)}")
        val totals = view.openTotals(depositor)
        val maxClaims = StoreJs.dbl(bondPolicy["maxOpenClaims"])!!
        val maxAmount = StoreJs.dbl(bondPolicy["maxOpenAmount"])!!
        if (!(totals[0].isFinite() && totals[0] + 1 <= maxClaims)) throw IllegalStateException("openBond: depositor open-claim cap reached")
        if (!((totals[1] + amount).isFinite() && totals[1] + amount <= maxAmount)) throw IllegalStateException("openBond: depositor aggregate open-bond cap exceeded")
        if (!(view.balanceOf(depositor).isFinite() && view.balanceOf(depositor) >= amount)) throw IllegalStateException("openBond: insufficient balance for the bond")

        val record = signRecord(base(claimId, "open", amount, depositor, escrow, now, ""))
        val open = LinkedHashMap<String, Any?>()
        open["amount"] = StoreJs.num(amount)
        open["depositor"] = depositor
        open["maxOpenClaims"] = bondPolicy["maxOpenClaims"]
        open["maxOpenAmount"] = bondPolicy["maxOpenAmount"]
        if (window != null) open["window"] = window
        val moves = ArrayList<Any?>()
        moves.add(mv(depositor, "debit", amount)) // collateral is really taken
        moves.add(mv(escrow, "credit", amount))
        val p = plan(claimId, "none", "open", moves, record)
        p["open"] = open
        return p
    }

    /** Release a bond back to its depositor after an unchallenged window; refuses a missing or already settled bond. */
    fun planRelease(view: View, claimId: String, now: Double): Map<String, Any?> {
        val bond = view.bond(claimId) ?: throw IllegalStateException("releaseBond: no bond for $claimId")
        if (bond["status"] != "open") throw IllegalStateException("releaseBond: bond $claimId is already ${bond["status"]} (double-settle refused)")
        val amount = amountOf(bond)
        val depositor = bond["depositor"] as String
        val moves = ArrayList<Any?>()
        moves.add(mv(escrow, "debit", amount))
        moves.add(mv(depositor, "credit", amount))
        return plan(claimId, "open", "released", moves, signRecord(base(claimId, "release", amount, escrow, depositor, now, "")))
    }

    /**
     * Slash against a VERIFIED fraud verdict; re-runs the Policy VM itself. [params]: claimId, claim, fraudProof, grant, openSnapshot,
     * treasury, and optionally challengerAccount, compensationAccount, splitPolicy.
     */
    fun planSlash(view: View, params: Map<String, Any?>, now: Double): Map<String, Any?> {
        val claimId = stringParam(params, "claimId")
        val claim = StoreJs.map(params["claim"])!!
        val bond = openBondOrThrow(view, "slashBond", claimId)
        needTreasury(params, "slashBond")
        if (claim["bond_ref"] != claimId) throw IllegalStateException("slashBond: claim.bond_ref does not match claimId")
        val verdict = OptimisticAdjudication.verifyFraudProof(claim, params["fraudProof"], StoreJs.map(params["grant"]), params["openSnapshot"])
        if (verdict["fraudulent"] != true || verdict["slashBondRef"] != claimId) {
            throw IllegalStateException("slashBond: refused — no verified fraud verdict slashing $claimId (${verdict["reason"]})")
        }
        return slashPlan(bond, claimId!!, now, BondSettlement.settlementEvidenceDigest(claim, verdict), params)
    }

    /** Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). [params] adds revokedCapId. */
    fun planSlashOnRevocation(view: View, params: Map<String, Any?>, now: Double): Map<String, Any?> {
        val claimId = stringParam(params, "claimId")
        val claim = StoreJs.map(params["claim"])!!
        val bond = openBondOrThrow(view, "slashBondOnRevocation", claimId)
        needTreasury(params, "slashBondOnRevocation")
        if (claim["bond_ref"] != claimId) throw IllegalStateException("slashBondOnRevocation: claim.bond_ref does not match claimId")
        val revoked = stringParam(params, "revokedCapId")
        if (revoked.isNullOrEmpty()) throw IllegalStateException("slashBondOnRevocation: revokedCapId is required")
        return slashPlan(bond, claimId!!, now, BondSettlement.revocationEvidenceDigest(claim, revoked), params)
    }

    private fun oracleOf(params: Map<String, Any?>): OptimisticAdjudication.ObjectiveOracle? = params["oracle"] as? OptimisticAdjudication.ObjectiveOracle

    private fun rMargin(params: Map<String, Any?>): Double? = StoreJs.dbl(params["rMargin"])

    /** Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. [params] adds dispute, oracle, rMargin?. */
    fun planSlashOnDispute(view: View, params: Map<String, Any?>, now: Double): Map<String, Any?> {
        val claimId = stringParam(params, "claimId")
        val claim = StoreJs.map(params["claim"])!!
        val bond = openBondOrThrow(view, "slashBondOnDispute", claimId)
        needTreasury(params, "slashBondOnDispute")
        if (claim["bond_ref"] != claimId) throw IllegalStateException("slashBondOnDispute: claim.bond_ref does not match claimId")
        val verdict = OptimisticAdjudication.adjudicateDispute(claim, params["dispute"], StoreJs.map(params["grant"]), params["openSnapshot"], oracleOf(params), rMargin(params))
        if (verdict["outcome"] != "agent-fraud" || verdict["fraudulent"] != true || verdict["slashBondRef"] != claimId) {
            throw IllegalStateException("slashBondOnDispute: refused — no verified agent-fraud verdict slashing $claimId (${verdict["outcome"]}: ${verdict["reason"]})")
        }
        return slashPlan(bond, claimId!!, now, BondSettlement.disputeEvidenceDigest(claim, verdict), params)
    }

    /**
     * Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing); an anonymous slash, 100% to the treasury.
     * [params]: counterBondId, claim, dispute, grant, openSnapshot, oracle, treasury.
     */
    fun planSlashCounterBond(view: View, params: Map<String, Any?>, now: Double): Map<String, Any?> {
        val counterBondId = stringParam(params, "counterBondId")
        val claim = StoreJs.map(params["claim"])!!
        val bond = (if (counterBondId == null) null else view.bond(counterBondId)) ?: throw IllegalStateException("slashCounterBond: no counter-bond for $counterBondId")
        if (bond["status"] != "open") throw IllegalStateException("slashCounterBond: counter-bond $counterBondId is already ${bond["status"]} (double-settle refused)")
        needTreasury(params, "slashCounterBond")
        val verdict = OptimisticAdjudication.adjudicateDispute(claim, params["dispute"], StoreJs.map(params["grant"]), params["openSnapshot"], oracleOf(params), rMargin(params))
        if (verdict["outcome"] != "claim-upheld" || verdict["slashCounterBond"] != true) {
            throw IllegalStateException("slashCounterBond: refused — the dispute is not frivolous (${verdict["outcome"]}: ${verdict["reason"]})")
        }
        val p = LinkedHashMap<String, Any?>()
        p["treasury"] = params["treasury"]
        p["challengerAccount"] = null
        p["compensationAccount"] = params["compensationAccount"]
        p["splitPolicy"] = params["splitPolicy"]
        return slashPlan(bond, counterBondId!!, now, BondSettlement.disputeEvidenceDigest(claim, verdict), p)
    }
}
