package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.RoundingMode
import net.atlasauth.pca.payments.ChargeBond

/**
 * The server-side judgments of the optimistic fast path (packages/pca/src/optimistic.ts): [verifyClaim], [fileFraudProof],
 * [verifyFraudProof] (re-runs the Policy VM on the frozen open-time snapshot under the grant the verifier trusts), [adjudicateDispute]
 * (substitutes an objective oracle's value for the one disputed input and re-adjudicates), [adjudicateDisputeGame] (refereed
 * bisection down to one contested step) and [freezeOpenSnapshot]. The settlement layer never takes a slash on a challenger's word: it
 * recomputes these itself. Claims, proofs, grants and snapshots are JSON objects; verdicts are JSON objects too. All verdict functions
 * are total (never throw) and FAIL CLOSED.
 */
object OptimisticAdjudication {
    /** The reversibility class that is never eligible for the optimistic path. */
    const val IRREVERSIBLE_CLASS = "irreversible"
    private const val IRREVERSIBLE = IRREVERSIBLE_CLASS
    private const val DEFAULT_R_MARGIN = 1e-9

    /** The realistic floor of a derived challenge window (30 s). */
    const val DEFAULT_MIN_CHALLENGE_WINDOW_MS = 30_000.0

    /** Resolves the truthful value of a disputed input from server-authoritative facts. Total: report `valid:false` rather than throw. */
    fun interface ObjectiveOracle {
        /** Returns `{input, value?, class?, valid, reason?}`. */
        fun resolve(input: String, snapshot: Map<String, Any?>): Map<String, Any?>?
    }

    /** A JSON object (and, like JavaScript, an array) as an object; anything else is not. */
    private fun obj(v: Any?): Map<String, Any?>? = when (v) {
        is Map<*, *> -> StoreJs.map(v)
        is List<*> -> LinkedHashMap()
        else -> null
    }

    private fun shallow(v: Any?): MutableMap<String, Any?> = obj(v)?.let { LinkedHashMap(it) } ?: LinkedHashMap()

    /** JavaScript `===` between two JSON members (numbers by value, otherwise by canonical form; both absent equal). */
    private fun memberEq(a: Map<String, Any?>, b: Map<String, Any?>, k: String): Boolean {
        val ha = a.containsKey(k)
        if (ha != b.containsKey(k)) return false
        if (!ha) return true
        val x = IntentJs.num(a[k])
        if (x != null) {
            val y = IntentJs.num(b[k])
            return y != null && x == y
        }
        return Ledger.same(a[k], b[k])
    }

    private fun dnum(o: Any?): Double = StoreJs.dbl(o) ?: Double.NaN

    private fun fixed3(x: Double): String = BigDecimal(x).setScale(3, RoundingMode.HALF_UP).toPlainString() // JavaScript toFixed(3)

    private fun js(x: Double): String = AttestUtil.jsNumString(x)

    private fun jsOf(v: Any?): String = IntentJs.num(v)?.let { js(it) } ?: IntentRevocation.jsText(v, true)

    private fun truthy(o: Any?): Boolean = when (o) {
        null -> false
        is Boolean -> o
        is String -> o.isNotEmpty()
        else -> IntentJs.num(o)?.let { it != 0.0 && !it.isNaN() } ?: true
    }

    /** `{ok, reason?}`: the claim covers this action, is not irreversible, and its signature and window verify against [serverNow]. Never throws. */
    @JvmStatic
    @JvmOverloads
    fun verifyClaim(claim: Any?, pcactn: Map<String, Any?>?, signerPublic: String, serverNow: Double, policyOrNull: Optimistic.ChallengeWindowPolicy? = null): Map<String, Any?> {
        val policy = policyOrNull ?: Optimistic.DEFAULT_POLICY
        val reason: String = try {
            when (Optimistic.claimCheck(claim, Pca.hashCanonical(pcactn), signerPublic, serverNow, policy)) {
                "ok" -> return linkedMapOf("ok" to true)
                "irreversible" -> "irreversible action is ineligible for the optimistic path"
                "digest" -> "claim does not cover this PCActn"
                "claimed_r" -> "claimed_r is not finite"
                "window" -> {
                    val c = obj(claim)!!
                    ChargeBond.validateWindow(dnum(c["issued_at"]), dnum(c["challenge_window_ms"]), serverNow, policy) ?: "malformed challenge window"
                }
                "signature" -> "claim signature does not verify"
                else -> "malformed claim"
            }
        } catch (e: RuntimeException) {
            "claim verification error: " + (e.message ?: "unknown")
        }
        return linkedMapOf("ok" to false, "reason" to reason)
    }

    private fun verdict(fraudulent: Boolean, bondRef: String?, reason: String): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["fraudulent"] = fraudulent
        if (bondRef != null) m["slashBondRef"] = bondRef
        m["reason"] = reason
        return m
    }

    private fun summary(release: Boolean, r: Any?, optimisticAllowed: Boolean): MutableMap<String, Any?> =
        linkedMapOf("releaseGuardianShare" to release, "r" to r, "optimisticAllowed" to optimisticAllowed)

    private fun numOf(o: Any?): Any? = StoreJs.dbl(o)?.let { StoreJs.num(it) }

    private fun summarizeDecision(d: Map<String, Any?>): MutableMap<String, Any?> {
        val thr = StoreJs.map(d["requiredThreshold"])
        return summary(d["releaseGuardianShare"] == true, numOf(d["r"]), thr != null && thr["optimisticAllowed"] == true)
    }

    /** `decide` on a frozen snapshot with the trusted [grant] (the grant a snapshot carries, if any, is replaced). */
    private fun decideUnder(snap: Map<String, Any?>, grant: Map<String, Any?>?): Map<String, Any?> {
        val input = LinkedHashMap(snap)
        input["grant"] = grant
        return Decide.decide(input)
    }

    /**
     * File a fraud proof against [claim] for [pcactn] under [grant]: replays `decide` on the FROZEN open-time [openSnapshot] (never a
     * caller-supplied decision). Returns the proof when the claim was false (irreversible, policy-denied, optimistic path not allowed
     * at the real risk, or risk understated by more than the margin), else null; null too for a snapshot-less call or a claim that does
     * not cover [pcactn].
     */
    @JvmStatic
    @JvmOverloads
    fun fileFraudProof(claim: Map<String, Any?>, pcactn: Map<String, Any?>, grant: Map<String, Any?>?, openSnapshot: Map<String, Any?>?, rMargin: Double? = null): Map<String, Any?>? {
        if (openSnapshot == null) return null
        val actual = decideUnder(openSnapshot, grant) // replay against the frozen open-time inputs under the supplied grant
        if (claim["pcactn_digest"] != Pca.hashCanonical(pcactn)) return null // cannot frame a different action
        val margin = if (rMargin != null && !rMargin.isNaN() && !rMargin.isInfinite()) Math.max(0.0, rMargin) else DEFAULT_R_MARGIN
        val s = summarizeDecision(actual)
        val r = dnum(s["r"])
        val evidence = StoreJs.deepCopy(openSnapshot.filterKeys { it != "grant" })
        val base = LinkedHashMap<String, Any?>()
        base["pcactn_digest"] = claim["pcactn_digest"]
        base["bond_ref"] = claim["bond_ref"]
        base["claimed_r"] = claim["claimed_r"]
        base["decision"] = s
        base["evidence"] = evidence
        base["r_margin"] = StoreJs.num(margin)
        val pcAction = obj(pcactn["action"])
        val thr = StoreJs.map(actual["requiredThreshold"])
        val kind: String
        val reason: String
        if (claim["reversibility_class"] == IRREVERSIBLE || pcAction?.get("reversibility_class") == IRREVERSIBLE) {
            kind = "irreversible"
            reason = "irreversible action took the optimistic path"
        } else if (actual["releaseGuardianShare"] != true) {
            kind = "policy-denied"
            val why = (actual["reasons"] as? List<*>)?.joinToString("; ") ?: ""
            reason = "Policy VM denied the action: " + why.ifEmpty { "not compliant" }
        } else if (thr == null || thr["optimisticAllowed"] != true) {
            kind = "optimistic-not-allowed"
            reason = "optimistic path not allowed at real r=${fixed3(r)} (t=${jsOf(thr?.get("t"))})"
        } else if (r > dnum(claim["claimed_r"]) + margin) {
            kind = "risk-understated"
            reason = "claimed r=${jsOf(claim["claimed_r"])} but real r=${fixed3(r)}"
        } else {
            return null
        }
        base["kind"] = kind
        base["reason"] = reason
        return base
    }

    /**
     * Independently verify a fraud proof: re-run the Policy VM on the frozen open-time snapshot under the trusted grant, confirm the proof's
     * decision matches, and confirm the recomputed decision refutes the claim. Returns `{fraudulent, slashBondRef?, reason}`. Never throws.
     */
    @JvmStatic
    fun verifyFraudProof(claim: Map<String, Any?>, proofO: Any?, grant: Map<String, Any?>?, snapO: Any?): Map<String, Any?> {
        try {
            val proof = obj(proofO) ?: return verdict(false, null, "malformed fraud proof")
            if (!memberEq(proof, claim, "pcactn_digest")) return verdict(false, null, "fraud proof targets a different PCActn than the claim")
            if (!memberEq(proof, claim, "bond_ref")) return verdict(false, null, "fraud proof names a different bond than the claim")
            val snap = obj(snapO) ?: return verdict(false, null, "no frozen open-time snapshot supplied; cannot judge the claim")
            val recomputed = decideUnder(snap, grant)
            val s = summarizeDecision(recomputed)
            val r = dnum(s["r"])
            val pdRaw = proof["decision"]
            // the reference reads pd.releaseGuardianShare: undefined / null throw, any other primitive has no members
            if (pdRaw == null) return verdict(false, null, "fraud-proof verification error: Cannot read properties of " + (if (proof.containsKey("decision")) "null" else "undefined") + " (reading 'releaseGuardianShare')")
            val pd = obj(pdRaw) ?: LinkedHashMap<String, Any?>()
            if (s["releaseGuardianShare"] != pd["releaseGuardianShare"] || s["optimisticAllowed"] != pd["optimisticAllowed"] ||
                !(Math.abs(r - dnum(pd["r"])) <= 1e-9) // a missing, NaN or non-numeric r never matches
            ) {
                return verdict(false, null, "proof decision does not match an independent recomputation")
            }
            val margin = if (IntentJs.isFinite(proof["r_margin"])) Math.max(0.0, dnum(proof["r_margin"])) else DEFAULT_R_MARGIN
            val inner = obj(obj(snap["action"])?.get("action"))
            val irreversible = claim["reversibility_class"] == IRREVERSIBLE || (inner != null && inner["reversibility_class"] == IRREVERSIBLE)
            val bond = claim["bond_ref"] as? String
            if (irreversible) return verdict(true, bond, "irreversible action is ineligible for the optimistic path")
            if (s["releaseGuardianShare"] != true) {
                val why = (recomputed["reasons"] as? List<*>)?.joinToString("; ") ?: ""
                return verdict(true, bond, "Policy VM denies the action: " + why.ifEmpty { "not compliant" })
            }
            if (s["optimisticAllowed"] != true) return verdict(true, bond, "optimistic path not allowed at real r=${fixed3(r)}")
            val claimed = dnum(claim["claimed_r"])
            if (r > claimed + margin) return verdict(true, bond, "risk understated: claimed ${js(claimed)}, real ${fixed3(r)}")
            return verdict(false, null, "claim is compliant under independent recomputation; bond stands")
        } catch (e: RuntimeException) {
            return verdict(false, null, "fraud-proof verification error: " + (e.message ?: "unknown"))
        }
    }

    // ---- dispute adjudication ----

    private fun disputable(i: Any?): Boolean = i == "reversibility_class" || i == "reversibility" || i == "blastRadius" || i == "semanticDistance"

    private fun indeterminate(input: String, reason: String, baseline: Map<String, Any?>?, agentValue: Any?): Map<String, Any?> {
        val worst = summary(false, StoreJs.num(1L), false)
        val m = LinkedHashMap<String, Any?>()
        m["outcome"] = "indeterminate"
        m["fraudulent"] = false
        m["slashCounterBond"] = false
        m["input"] = input
        if (agentValue != null) m["agentValue"] = agentValue
        m["baseline"] = baseline ?: worst
        m["adjudicated"] = worst
        m["reason"] = reason
        return m
    }

    private fun snapshotValueOf(snap: Map<String, Any?>, input: String): Any? {
        if (input == "reversibility_class") {
            val v = obj(snap["caveatContext"])?.get("reversibilityClass")
            if (v != null) return v
            return obj(obj(snap["action"])?.get("action"))?.get("reversibility_class")
        }
        return obj(snap["risk"])?.get(input)
    }

    /** The oracle's resolution folded into a COPY of the snapshot; throws when the value / class it needs is missing. */
    private fun substitute(snap: Map<String, Any?>, res: Map<String, Any?>): Map<String, Any?> {
        val input = res["input"] as String
        val next = LinkedHashMap(snap)
        val cc = obj(snap["caveatContext"])
        if (input == "reversibility_class") {
            val cls = res["class"]
            if (cls !is String || cls.isEmpty()) throw IllegalStateException("oracle reversibility_class resolution carries no class")
            val a = shallow(snap["action"])
            val inner = shallow(a["action"])
            inner["reversibility_class"] = cls
            a["action"] = inner
            next["action"] = a
            if (cc != null && cc.containsKey("reversibilityClass")) {
                val c2 = LinkedHashMap(cc)
                c2["reversibilityClass"] = cls
                next["caveatContext"] = c2
            }
            return next
        }
        if (!IntentJs.isFinite(res["value"])) throw IllegalStateException("oracle $input resolution carries no finite value")
        val risk = shallow(snap["risk"])
        risk[input] = res["value"]
        next["risk"] = risk
        if (input == "blastRadius" && cc != null && cc.containsKey("blastRadius")) {
            val c2 = LinkedHashMap(cc)
            c2["blastRadius"] = res["value"]
            next["caveatContext"] = c2
        }
        return next
    }

    private fun fastPathAdmits(s: Map<String, Any?>, claimedR: Double, margin: Double): Boolean =
        s["releaseGuardianShare"] == true && s["optimisticAllowed"] == true && dnum(s["r"]) <= claimedR + margin

    private fun jsonStr(v: Any?): String = if (v == null) "undefined" else Json.canonicalize(v)

    /**
     * Adjudicate a contestable dispute. Re-runs the Policy VM on the frozen snapshot with the oracle's value substituted for the single disputed
     * input, under the trusted grant. Fails closed to `indeterminate` (slashing no one) on a mismatched target, a missing snapshot or an
     * oracle that cannot resolve. [rMargin] may be null. Never throws.
     */
    @JvmStatic
    @JvmOverloads
    fun adjudicateDispute(claim: Map<String, Any?>, disputeO: Any?, grant: Map<String, Any?>?, snapO: Any?, oracle: ObjectiveOracle?, rMargin: Double? = null): Map<String, Any?> {
        val margin = if (rMargin != null && !rMargin.isNaN() && !rMargin.isInfinite()) Math.max(0.0, rMargin) else DEFAULT_R_MARGIN
        val dispute = obj(disputeO)
        val fallbackInput = (dispute?.get("input") as? String) ?: "reversibility_class"
        try {
            if (dispute == null) return indeterminate("reversibility_class", "malformed dispute", null, null)
            val inp = dispute["input"]
            if (!disputable(inp)) {
                return indeterminate("reversibility_class", "unknown disputed input: " + (if (inp is String) inp else if (inp == null) "undefined" else Json.canonicalize(inp)), null, null)
            }
            val input = inp as String
            if (!memberEq(dispute, claim, "pcactn_digest")) return indeterminate(input, "dispute targets a different PCActn than the claim", null, null)
            if (!memberEq(dispute, claim, "bond_ref")) return indeterminate(input, "dispute names a different bond than the claim", null, null)
            val open = obj(snapO) ?: return indeterminate(input, "no frozen open-time snapshot supplied; cannot adjudicate", null, null)
            if (oracle == null) return indeterminate(input, "no objective oracle supplied", null, null)

            val snap = shallow(open)
            snap["grant"] = grant
            val baseline = summarizeDecision(Decide.decide(snap))
            val agentValue = snapshotValueOf(snap, input)

            val res = oracle.resolve(input, snap)
            if (res == null || input != res["input"] || !truthy(res["valid"])) {
                val why = res?.get("reason")
                return indeterminate(input, "objective oracle could not authoritatively resolve $input" + (if (truthy(why)) ": ${jsOf(why)}" else ""), baseline, agentValue)
            }
            val oracleValue = res["class"] ?: res["value"]
            val substituted = substitute(snap, res)
            val adjudicated = summarizeDecision(Decide.decide(substituted))
            val claimedR = dnum(claim["claimed_r"])

            val m = LinkedHashMap<String, Any?>()
            m["input"] = input
            if (agentValue != null) m["agentValue"] = agentValue
            if (oracleValue != null) m["oracleValue"] = oracleValue
            m["baseline"] = baseline
            m["adjudicated"] = adjudicated
            if (!fastPathAdmits(adjudicated, claimedR, margin)) {
                val why = if (adjudicated["releaseGuardianShare"] != true) "the Policy VM denies the action"
                else if (adjudicated["optimisticAllowed"] != true) "the optimistic path is not allowed (higher threshold) at r=${fixed3(dnum(adjudicated["r"]))}"
                else "the real r=${fixed3(dnum(adjudicated["r"]))} exceeds the claimed r=${js(claimedR)}"
                m["outcome"] = "agent-fraud"
                m["fraudulent"] = true
                m["slashBondRef"] = claim["bond_ref"]
                m["slashCounterBond"] = false
                m["reason"] = "understated $input: agent relied on ${jsonStr(agentValue)}, oracle says ${jsonStr(oracleValue)} — $why"
                return m
            }
            m["outcome"] = "claim-upheld"
            m["fraudulent"] = false
            m["slashCounterBond"] = true
            m["reason"] = "the objective oracle upholds the agent's $input (${jsonStr(oracleValue)}); fast-path admission survives — the dispute is frivolous"
            return m
        } catch (e: RuntimeException) {
            return indeterminate(fallbackInput, "dispute adjudication error (fail closed): " + (e.message ?: "unknown"), null, null)
        }
    }

    // ---- the interactive dispute game (refereed bisection) ----

    /** Exact equality of two step assertions (NaN-safe, signed-zero-aware like `Object.is`): the bisection divergence predicate. */
    private fun assertionEquals(a: Map<String, Any?>, b: Map<String, Any?>): Boolean {
        val av = a["value"]
        val bv = b["value"]
        val ha = a.containsKey("value")
        val hb = b.containsKey("value")
        val valueEq = (!ha && !hb) || (ha && hb && IntentJs.num(av) != null && IntentJs.num(bv) != null &&
            java.lang.Double.compare(IntentJs.num(av)!!, IntentJs.num(bv)!!) == 0)
        return valueEq && memberEq(a, b, "class")
    }

    private fun applyAssertion(snap: Map<String, Any?>, input: String, a: Map<String, Any?>): Map<String, Any?> {
        val res = linkedMapOf<String, Any?>("input" to input, "valid" to true)
        if (a.containsKey("value")) res["value"] = a["value"]
        if (a.containsKey("class")) res["class"] = a["class"]
        return substitute(snap, res)
    }

    private fun stateAfter(snap: Map<String, Any?>, steps: List<*>, assertions: List<*>, j: Int): Map<String, Any?> {
        var s = snap
        for (i in 0 until j) {
            val input = steps[i] as? String
            val a = assertions[i]
            if (input == null || a == null) throw IllegalStateException("dispute game trace is shorter than its step list")
            s = applyAssertion(s, input, obj(a) ?: LinkedHashMap())
        }
        return summarizeDecision(Decide.decide(s))
    }

    /**
     * Adjudicate an INTERACTIVE multi-round dispute game by refereed bisection: narrow the parties' committed traces (`game.defender`,
     * `game.challenger`, parallel to `game.steps`) to the ONE step on which they first diverge, then resolve THAT step with the objective
     * oracle through [adjudicateDispute] against the mutually-agreed pre-state. Returns `{verdict, converged, contestedStep,
     * contestedInput?, transcript, rounds}`. Total; fails closed to `indeterminate` (slashing no one) on any malformed input, binding
     * mismatch, missing snapshot or oracle, absence of a genuine admission dispute, non-convergence or error.
     */
    @JvmStatic
    @JvmOverloads
    fun adjudicateDisputeGame(claim: Map<String, Any?>, gameO: Any?, grant: Map<String, Any?>?, openSnapshot: Any?, oracle: ObjectiveOracle?, rMargin: Double? = null): Map<String, Any?> {
        val margin = if (rMargin != null && !rMargin.isNaN() && !rMargin.isInfinite()) Math.max(0.0, rMargin) else DEFAULT_R_MARGIN
        val game = obj(gameO)
        fun fail(reason: String, input: String? = null): Map<String, Any?> {
            val first = (game?.get("steps") as? List<*>)?.firstOrNull()
            val worst = summary(false, StoreJs.num(1L), false)
            val v = LinkedHashMap<String, Any?>()
            v["outcome"] = "indeterminate"
            v["fraudulent"] = false
            v["slashCounterBond"] = false
            v["input"] = input ?: (if (disputable(first)) first as String else "reversibility_class")
            v["baseline"] = worst
            v["adjudicated"] = LinkedHashMap(worst)
            v["reason"] = reason
            return linkedMapOf("verdict" to v, "converged" to false, "contestedStep" to StoreJs.num(-1L), "transcript" to ArrayList<Any?>(), "rounds" to StoreJs.num(0L))
        }
        try {
            if (game == null) return fail("malformed dispute game")
            if (!memberEq(game, claim, "pcactn_digest")) return fail("dispute game targets a different PCActn than the claim")
            if (!memberEq(game, claim, "bond_ref")) return fail("dispute game names a different bond than the claim")
            val steps = game["steps"] as? List<*>
            val defender = game["defender"] as? List<*>
            val challenger = game["challenger"] as? List<*>
            if (steps == null || steps.isEmpty()) return fail("dispute game has no steps")
            for (s in steps) if (!disputable(s)) return fail("unknown disputed input: " + (if (s is String) s else IntentRevocation.jsText(s, true)))
            if (defender == null || challenger == null || defender.size != steps.size || challenger.size != steps.size) return fail("party assertions do not cover every step")
            val open = obj(openSnapshot) ?: return fail("no frozen open-time snapshot supplied; cannot adjudicate")
            if (oracle == null) return fail("no objective oracle supplied")

            val n = steps.size
            val snap = shallow(open)
            snap["grant"] = grant
            val claimedR = dnum(claim["claimed_r"])

            // GENUINE-DISPUTE GATE: the defender's full trace must still admit the fast path and the challenger's must not.
            val defenderFinal = stateAfter(snap, steps, defender, n)
            val challengerFinal = stateAfter(snap, steps, challenger, n)
            if (!fastPathAdmits(defenderFinal, claimedR, margin)) return fail("defender does not defend the fast-path admission; nothing to adjudicate")
            if (fastPathAdmits(challengerFinal, claimedR, margin)) return fail("the parties do not disagree on admission; no genuine dispute to bisect")

            fun move(list: List<*>, i: Int): Map<String, Any?>? = list[i]?.let { obj(it) ?: LinkedHashMap() }
            val prefixAgrees = { m: Int ->
                var ok = true
                for (i in 0 until m) {
                    val di = move(defender, i)
                    val ci = move(challenger, i)
                    if (di == null || ci == null || !assertionEquals(di, ci)) { ok = false; break }
                }
                ok
            }
            if (prefixAgrees(n)) return fail("the parties committed identical traces; no contested step to bisect")

            var lo = 0
            var hi = n
            val transcript = ArrayList<Any?>()
            while (hi - lo > 1) {
                val mid = (lo + hi) / 2
                val agreedAtMid = prefixAgrees(mid)
                transcript.add(linkedMapOf("lo" to StoreJs.num(lo.toLong()), "hi" to StoreJs.num(hi.toLong()), "mid" to StoreJs.num(mid.toLong()), "agreedAtMid" to agreedAtMid))
                if (agreedAtMid) lo = mid else hi = mid
            }
            val contestedStep = lo
            val contestedInput = steps[contestedStep] as? String ?: return fail("converged step is not a disputable input")

            // The AGREED pre-state: every earlier correction folded in, re-verifying that the prefix really is agreed.
            var preState: Map<String, Any?> = snap
            for (i in 0 until contestedStep) {
                val di = move(defender, i)
                val ci = move(challenger, i)
                val stepInput = steps[i]
                if (di == null || ci == null || !assertionEquals(di, ci)) return fail("agreed prefix is not actually agreed; cannot reconstruct the pre-state", contestedInput)
                if (stepInput !is String || !disputable(stepInput)) return fail("prefix step is not a disputable input", contestedInput)
                preState = applyAssertion(preState, stepInput, di)
            }

            val chalMove = move(challenger, contestedStep) ?: return fail("challenger has no assertion for the contested step", contestedInput)
            val dispute = LinkedHashMap<String, Any?>()
            dispute["pcactn_digest"] = claim["pcactn_digest"]
            dispute["bond_ref"] = claim["bond_ref"]
            dispute["input"] = contestedInput
            if (chalMove.containsKey("value")) dispute["asserted_value"] = chalMove["value"]
            if (chalMove.containsKey("class")) dispute["asserted_class"] = chalMove["class"]
            val verdict = adjudicateDispute(claim, dispute, grant, preState, oracle, margin)

            return linkedMapOf(
                "verdict" to verdict, "converged" to true, "contestedStep" to StoreJs.num(contestedStep.toLong()), "contestedInput" to contestedInput,
                "transcript" to transcript, "rounds" to StoreJs.num(transcript.size.toLong()),
            )
        } catch (e: RuntimeException) {
            return fail("dispute game adjudication error (fail closed): " + (e.message ?: "unknown"))
        }
    }

    /** A deep copy of a `decide` input captured at claim open (store it with the claim); the copy shares nothing with [input]. */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun freezeOpenSnapshot(input: Map<String, Any?>): Map<String, Any?> = StoreJs.deepCopy(input) as Map<String, Any?>
}
