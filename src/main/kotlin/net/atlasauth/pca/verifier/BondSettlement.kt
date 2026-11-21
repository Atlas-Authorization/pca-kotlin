package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.SecureRandom

/**
 * The pure accounting of bond settlement (packages/pca/src/bond-settlement.ts): exact micro-unit money arithmetic, the slash split,
 * bond sizing, the evidence digests a signed settlement record commits to, and record verification and anchoring. INTERNAL ACCOUNTING
 * ONLY; no money moves. Policies and records are JSON objects (maps); amounts are doubles on the micro grid. See
 * [BondSettlementPlanner] for the signing half.
 */
object BondSettlement {
    /** The default escrow account label. */
    const val ESCROW_ACCOUNT = "escrow"

    /** The default victim-compensation pool account (contains ':', so it can never be a challenger payout account). */
    const val COMPENSATION_POOL_ACCOUNT = "pca:pool:compensation"

    /** Micro-units per whole unit. */
    const val MICROS_PER_UNIT = 1_000_000L

    /** Domain-separated tag of the settlement transparency leaf. */
    const val SETTLEMENT_LEAF_DOMAIN = "atlas-pca/settlement-leaf/v1"

    private const val MAX_SAFE_MICROS = 1e15
    private val MIN_SHARE_QUANTUM = Math.pow(2.0, -30.0)

    /** The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder. Tunable, not a product decision. */
    @JvmStatic
    fun defaultSlashSplitPolicy(): MutableMap<String, Any?> =
        linkedMapOf("challengerBps" to StoreJs.num(5000L), "victimBps" to StoreJs.num(4000L))

    /** A fresh copy of the reference split ([defaultSlashSplitPolicy]). */
    @JvmStatic
    val DEFAULT_SLASH_SPLIT_POLICY: Map<String, Any?> get() = defaultSlashSplitPolicy()

    /** A fresh copy of the reference bond policy ([defaultBondPolicy]). */
    @JvmStatic
    val DEFAULT_BOND_POLICY: Map<String, Any?> get() = defaultBondPolicy()

    /** `{floor:1, k:1, maxOpenClaims:100, maxOpenAmount:Infinity}` (no curve: linear). */
    @JvmStatic
    fun defaultBondPolicy(): MutableMap<String, Any?> = linkedMapOf(
        "floor" to StoreJs.num(1L), "k" to StoreJs.num(1L), "maxOpenClaims" to StoreJs.num(100L),
        "maxOpenAmount" to StoreJs.num(Double.POSITIVE_INFINITY),
    )

    // ---- exact money ----

    /** Integer micro-units of [x] when it is a micro-grid amount below 1e15 micros, else null. */
    @JvmStatic
    fun toMicros(x: Double): Long? = BondDoc.toMicros(x)

    /** The number for an integer micro-unit amount (round-trips through [toMicros]). */
    @JvmStatic
    fun fromMicros(m: Long): Double = m.toDouble() / MICROS_PER_UNIT

    /** Snap a computed amount UP onto the micro grid (a bond is never rounded down); float noise below 1e-3 micro-units is absorbed. */
    @JvmStatic
    fun quantizeUp(x: Double): Double {
        if (x.isNaN() || x.isInfinite() || x <= 0) return x
        val scaled = x * MICROS_PER_UNIT
        if (scaled > MAX_SAFE_MICROS) return x
        val r = Math.floor(scaled + 0.5) // JavaScript Math.round
        val m = if (r / MICROS_PER_UNIT == x || Math.abs(scaled - r) <= 1e-3) r else Math.ceil(scaled)
        return m / MICROS_PER_UNIT
    }

    /** a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain float otherwise. */
    @JvmStatic
    fun exactAdd(a: Double, b: Double, sign: Int): Double = BondDoc.exactAdd(a, b, sign)

    // ---- slash split ----

    /** The exact division of one slashed bond. The three payouts sum exactly to [amount]. */
    class SlashSplit internal constructor(
        val amount: Double,
        val challengerReward: Double,
        val victimCompensation: Double,
        val treasuryRemainder: Double,
        /** The identified challenger's payout account, or null for an anonymous challenge. */
        val challengerAccount: String?,
        val hasChallengerAccount: Boolean,
        val victimAccount: String,
        val treasuryAccount: String,
    ) {
        /** The JSON form (the record's `split`). */
        fun toJson(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["amount"] = StoreJs.num(amount)
            m["challengerReward"] = StoreJs.num(challengerReward)
            m["victimCompensation"] = StoreJs.num(victimCompensation)
            m["treasuryRemainder"] = StoreJs.num(treasuryRemainder)
            if (hasChallengerAccount) m["challengerAccount"] = challengerAccount
            m["victimAccount"] = victimAccount
            m["treasuryAccount"] = treasuryAccount
            return m
        }
    }

    private fun isInteger(v: Double?): Boolean = v != null && !v.isNaN() && !v.isInfinite() && v == Math.floor(v)

    internal fun assertSplitPolicy(p: Map<String, Any?>?) {
        var sum = 0.0
        for (k in arrayOf("challengerBps", "victimBps")) {
            val v = if (p == null) null else StoreJs.dbl(p[k])
            if (v == null || !isInteger(v) || v < 0 || v > 10_000) throw IllegalStateException("slash split: $k must be an integer in [0,10000]")
            sum += v
        }
        if (sum > 10_000) throw IllegalStateException("slash split: challengerBps + victimBps must not exceed 10000")
    }

    private fun shareMicros(micros: Long, bps: Double): Long =
        BigInteger.valueOf(micros).multiply(BigInteger.valueOf(bps.toLong())).divide(BigInteger.valueOf(10_000)).toLong()

    private fun shareQuantum(amount: Double): Double {
        val u = Math.ulp(amount) // the exact power-of-two unit in the last place
        if (amount == Math.floor(amount)) return Math.max(1.0, u)
        return Math.max(MIN_SHARE_QUANTUM, u)
    }

    private fun shareOf(amount: Double, bps: Double, quantum: Double): Double {
        val raw = (amount * bps) / 10_000
        return Math.floor(raw / quantum) * quantum
    }

    /**
     * The challenger / victim / treasury division of a slashed [amount]. Exact (treasury = amount - challenger - victim) and
     * integer-safe. [dest] carries `challengerAccount` (a string, or an explicit null for an anonymous challenge, which pays the
     * whole bond to the treasury), `victimAccount` and `treasuryAccount`.
     */
    @JvmStatic
    fun computeSlashSplit(amount: Double, policy: Map<String, Any?>?, dest: Map<String, Any?>): SlashSplit {
        if (amount.isNaN() || amount.isInfinite() || amount <= 0) throw IllegalStateException("computeSlashSplit: amount must be a positive finite number")
        assertSplitPolicy(policy)
        val victim = dest["victimAccount"]
        val treasury = dest["treasuryAccount"]
        if (victim !is String || victim.isEmpty()) throw IllegalStateException("computeSlashSplit: victimAccount is required")
        if (treasury !is String || treasury.isEmpty()) throw IllegalStateException("computeSlashSplit: treasuryAccount is required")
        val has = dest.containsKey("challengerAccount")
        val ch = dest["challengerAccount"]
        val chAcct = ch as? String
        if (has && ch == null) return SlashSplit(amount, 0.0, 0.0, amount, null, true, victim, treasury) // anonymous
        val micros = if (amount == Math.floor(amount)) null else toMicros(amount) // integer bonds keep whole-unit shares
        val cbps = StoreJs.dbl(policy!!["challengerBps"])!!
        val vbps = StoreJs.dbl(policy["victimBps"])!!
        if (micros != null) {
            val c = shareMicros(micros, cbps)
            val v = shareMicros(micros, vbps)
            val t = micros - c - v
            return SlashSplit(fromMicros(micros), fromMicros(c), fromMicros(v), fromMicros(t), chAcct, has, victim, treasury)
        }
        val q = shareQuantum(amount)
        val challengerReward = Math.min(shareOf(amount, cbps, q), amount)
        val victimCompensation = Math.min(shareOf(amount, vbps, q), amount - challengerReward)
        val treasuryRemainder = amount - challengerReward - victimCompensation
        return SlashSplit(amount, challengerReward, victimCompensation, treasuryRemainder, chAcct, has, victim, treasury)
    }

    // ---- bond sizing ----

    private fun dnum(o: Any?): Double = StoreJs.dbl(o) ?: Double.NaN

    private fun fin(d: Double): Boolean = !d.isNaN() && !d.isInfinite()

    private fun curveComponent(curve: Map<String, Any?>?, k: Double, e: Double): Double {
        val kind = curve?.get("kind")
        if (curve == null || kind == "linear") return k * e
        if (kind == "power") {
            val gamma = dnum(curve["gamma"])
            if (!(fin(gamma) && gamma >= 1)) throw IllegalStateException("bondAmount: power curve requires finite gamma >= 1")
            return k * StrictMath.pow(e, gamma)
        }
        val tiersO = curve["tiers"]
        if (tiersO !is List<*> || tiersO.isEmpty()) throw IllegalStateException("bondAmount: piecewise curve requires at least one tier")
        var acc = 0.0
        var prevUpTo = 0.0
        var prevMarginal = 0.0
        for (to in tiersO) {
            val tier = StoreJs.map(to) ?: throw IllegalStateException("bondAmount: malformed tier")
            val upTo = dnum(tier["upTo"])
            val mk = dnum(tier["marginalK"])
            if (!(fin(upTo) && upTo > prevUpTo) && upTo != Double.POSITIVE_INFINITY) {
                throw IllegalStateException("bondAmount: piecewise tier `upTo` must be strictly increasing")
            }
            if (!(fin(mk) && mk >= 0)) throw IllegalStateException("bondAmount: piecewise `marginalK` must be a finite number >= 0")
            if (mk < prevMarginal) throw IllegalStateException("bondAmount: piecewise marginal rates must be non-decreasing (convex)")
            val width = Math.min(e, upTo) - prevUpTo
            if (width > 0) acc += width * mk
            prevUpTo = upTo
            prevMarginal = mk
            if (e <= upTo) break
        }
        if (e > prevUpTo) acc += (e - prevUpTo) * prevMarginal
        return k * acc
    }

    /** `max(floor, curve(k, exposure))` snapped up onto the micro grid; no curve = linear. Non-finite or non-positive exposure gives the floor. */
    @JvmStatic
    fun bondAmount(policy: Map<String, Any?>, exposure: Double): Double {
        val e = if (fin(exposure) && exposure > 0) exposure else 0.0
        return quantizeUp(Math.max(dnum(policy["floor"]), curveComponent(StoreJs.map(policy["curve"]), dnum(policy["k"]), e)))
    }

    // ---- evidence digests ----

    private fun claimIdentity(claim: Map<String, Any?>): MutableMap<String, Any?> =
        linkedMapOf("claimDigest" to claim["pcactn_digest"], "bond_ref" to claim["bond_ref"])

    /** Binds a slash to the server-derived fraud verdict (`fraudulent`, `slashBondRef`, `reason`). */
    @JvmStatic
    fun settlementEvidenceDigest(claim: Map<String, Any?>, fraudVerdict: Map<String, Any?>): String {
        val m = claimIdentity(claim)
        m["fraudulent"] = fraudVerdict["fraudulent"]
        m["slashBondRef"] = fraudVerdict["slashBondRef"]
        m["reason"] = fraudVerdict["reason"]
        return StoreJs.hashLenient(m)
    }

    /** Evidence digest of a revocation slash (a capability in the claim's chain was revoked after the bond opened). */
    @JvmStatic
    fun revocationEvidenceDigest(claim: Map<String, Any?>, revokedCapId: String?): String {
        val m = claimIdentity(claim)
        m["kind"] = "revocation"
        m["revokedCapId"] = revokedCapId
        return StoreJs.hashLenient(m)
    }

    /** Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion. */
    @JvmStatic
    fun disputeEvidenceDigest(claim: Map<String, Any?>, verdict: Map<String, Any?>): String {
        val m = claimIdentity(claim)
        m["kind"] = "dispute"
        m["outcome"] = verdict["outcome"]
        m["input"] = verdict["input"]
        m["agentValue"] = verdict["agentValue"]
        m["oracleValue"] = verdict["oracleValue"]
        m["slashBondRef"] = verdict["slashBondRef"]
        m["reason"] = verdict["reason"]
        return StoreJs.hashLenient(m)
    }

    // ---- verification and anchoring ----

    internal fun settlementMessage(body: Map<String, Any?>): ByteArray = Json.utf8(Optimistic.SETTLEMENT_DOMAIN + Json.canonicalize(body))

    /** Verify a settlement record's signature under the guardian public key; suite-agile (a PQ half needs a pin in [pins]). Never throws. */
    @JvmStatic
    @JvmOverloads
    fun verifySettlement(recordO: Any?, guardianPublicKey: String, pins: Map<String, Any?>? = null): Boolean = try {
        val r = StoreJs.map(recordO)
        if (r == null) {
            false
        } else {
            val body = LinkedHashMap(r)
            body.remove("sig")
            body.remove("pq_sig")
            if (r["sig"] !is String || Pq.resolveSigAlg(r["alg"], r.containsKey("alg")) == null) {
                false
            } else {
                IntentJs.verifyPinnedSuite(r["alg"], r.containsKey("alg"), guardianPublicKey, r["pq_pk"], settlementMessage(body), r["sig"], r["pq_sig"], StoreJs.map(pins?.get("pqPins")))
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    /** Canonical digest of a signed settlement record (the whole record, signature included). */
    @JvmStatic
    fun settlementRecordDigest(record: Map<String, Any?>): String =
        StoreJs.hashLenient(linkedMapOf("t" to SETTLEMENT_LEAF_DOMAIN, "record" to record))

    /** The salted commitment of a settlement record (the opaque transparency-log leaf). */
    @JvmStatic
    fun settlementCommit(salt: String?, record: Map<String, Any?>): String {
        if (salt.isNullOrEmpty()) throw IllegalStateException("settlementCommit: salt must be a non-empty string")
        return StoreJs.hashLenient(linkedMapOf("salt" to salt, "settlement_digest" to settlementRecordDigest(record)))
    }

    /** True iff [salt] + [record] reproduce the anchored [commit]. Never throws. */
    @JvmStatic
    fun verifySettlementCommit(commit: String?, salt: String?, record: Map<String, Any?>): Boolean = try {
        settlementCommit(salt, record) == commit
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Append a settlement record as a salted commitment through [append] (for example `MerkleLog::appendCommitment`, widened to a
     * long); returns `{index, commit, salt}`. A null [salt] draws 16 random bytes.
     */
    @JvmStatic
    @JvmOverloads
    fun appendSettlement(append: (String) -> Long, record: Map<String, Any?>, salt: String? = null): Map<String, Any?> {
        val s = salt ?: Keys.b64u(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val commit = settlementCommit(s, record)
        val index = append(commit)
        return linkedMapOf("index" to StoreJs.num(index), "commit" to commit, "salt" to s)
    }
}
