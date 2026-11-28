package net.atlasauth.pca.invariants

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Caveats
import net.atlasauth.pca.verifier.ForbidWins
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Predicates
import net.atlasauth.pca.verifier.Risk

/**
 * The PCA core safety invariants as seeded property checks, with no property-testing library: each `*Property` runs ONE generated case
 * from a [Rng] and returns `true` when the invariant holds (any violation is `false`); [run] repeats it `numRuns` times from a fixed seed
 * and fails with the failing run index. Every property feeds the REAL core (nothing is re-implemented): chain verification, predicate and
 * caveat evaluation, the risk functional and admission, forbid-wins.
 */
@Suppress("UNCHECKED_CAST")
object InvariantProperties {
    private const val EPS = 1e-9

    private fun map(o: Any?) = o as Map<String, Any?>
    private fun mmap(o: Any?) = o as MutableMap<String, Any?>
    private fun list(o: Any?) = o as List<Any?>
    private fun d(o: Any?): Double = Js.num(o)!!
    private fun obj(vararg kv: Pair<String, Any?>): MutableMap<String, Any?> = linkedMapOf(*kv)

    private fun chainOk(caps: List<Any?>, rootIssuer: String): Boolean = Pca.verifyChain(caps, rootIssuer, true).isEmpty()

    private fun riskOf(inputs: Map<String, Any?>, weights: Map<String, Any?>): Double = Risk.riskScore(inputs, weights)

    /** The reference `admit(r, {B}, policy)`: {admit, needStepUp, t, metered}. */
    private fun admit(r: Double, budgetB: Double, theta1: Double, theta2: Double, kappa: Double): Map<String, Any?> {
        val t = threshold(r, theta1, theta2)
        val a = Risk.admitOf(t, budgetB.isFinite() && budgetB >= Risk.cost(r, kappa))
        return linkedMapOf("admit" to a.admit, "needStepUp" to a.needStepUp, "t" to a.t.toLong(), "metered" to a.metered)
    }

    private fun threshold(r: Double, theta1: Double, theta2: Double): Int =
        Risk.requiredThreshold(r, Risk.Policy(emptyMap(), theta1, theta2, 0.0, 0.0, 0.0, 0.0), false).t

    // ============================ 1. ATTENUATION MONOTONICITY ===============================

    /** Effective authority of a hop for a probe point: envelope predicates AND every caveat satisfied. */
    private fun authAllowed(caveats: Any?, predicates: Any?, pt: Map<String, Any?>): Boolean =
        Predicates.evaluatePredicates(predicates, map(pt["action"])) && Caveats.evaluateCaveats(caveats, pt["cavCtx"]).ok

    private fun prefixExtension(parent: Map<String, Any?>, child: Map<String, Any?>): Boolean {
        val pc = list(parent["caveats"])
        val cc = list(child["caveats"])
        if (cc.size < pc.size) return false
        for (j in pc.indices) if (Pca.hashCanonical(cc[j]) != Pca.hashCanonical(pc[j])) return false
        return true
    }

    /**
     * For any legal chain: (a) it verifies; (b) each hop's caveats are an append-only extension of its parent's; (c) budget_alloc limits
     * are monotone non-increasing; (d) at every probe point the per-hop allowed verdict is monotone non-increasing root to leaf.
     */
    @JvmStatic fun attenuationMonotonicityProperty(r: Rng): Boolean {
        val chain = Arbitraries.chain(r)
        val points = ArrayList<Map<String, Any?>>()
        var i = r.integer(1, 5)
        while (i > 0) { points.add(Arbitraries.evalPoint(r)); i-- }
        val caps = list(chain["caps"])
        if (!chainOk(caps, chain["rootIssuer"] as String)) return false
        for (k in 1 until caps.size) if (!prefixExtension(map(caps[k - 1]), map(caps[k]))) return false
        val leaf = map(caps[caps.size - 1])
        if (Pca.allocationsMonotone(leaf["caveats"]).isNotEmpty()) return false
        var prev = Double.NaN
        for (cv in list(leaf["caveats"])) {
            val c = map(cv)
            if ("budget_alloc" != c["type"]) continue
            val cur = Js.num(c["limit"]) ?: continue
            if (!prev.isNaN() && cur > prev) return false
            prev = cur
        }
        for (pt in points) {
            var ancestorAllowed = true
            for (cap in caps) {
                val allowed = authAllowed(map(cap)["caveats"], chain["predicates"], pt)
                if (allowed && !ancestorAllowed) return false // a true after a false would be a widening
                ancestorAllowed = allowed
            }
        }
        return true
    }

    // ================================ 2. BUDGET SOUNDNESS ===================================

    /** r is clamped to [0, 1] and monotone: a pointwise-worse input never yields a lower r. */
    @JvmStatic fun riskMonotoneProperty(r: Rng): Boolean {
        val policy = Arbitraries.riskPolicy(r)
        val inputs = Arbitraries.riskInputs(r)
        val deltas = Arbitraries.riskDeltas(r)
        val risk = riskOf(inputs, map(policy["weights"]))
        if (!(risk >= 0 && risk <= 1)) return false
        val worse = riskOf(Invariants.worsen(inputs, deltas), map(policy["weights"]))
        if (!(worse >= 0 && worse <= 1)) return false
        return worse + EPS >= risk
    }

    /** Whenever admit lets an action proceed without a human, the admitted cost kappa*r is covered by the budget; safetyBound is bMax/kappa. */
    @JvmStatic fun admissionSoundnessProperty(r: Rng): Boolean {
        val policy = Arbitraries.riskPolicy(r)
        val inputs = Arbitraries.riskInputs(r)
        val budget = Arbitraries.trustBudget(r)
        if (Authorize.riskPolicyError(policy) != null) return false
        val risk = riskOf(inputs, map(policy["weights"]))
        val c = Risk.cost(risk, d(policy["kappa"]))
        val adm = admit(risk, d(budget["B"]), d(policy["theta1"]), d(policy["theta2"]), d(policy["kappa"]))
        val admitted = adm["admit"] as Boolean
        val metered = adm["metered"] as Boolean
        val t = adm["t"] as Long
        if (metered) {
            if (t >= 3) return false
            if (!(d(budget["B"]) + EPS >= c)) return false
        }
        if (admitted) {
            if (t != 1L || !metered) return false
            if (!(d(budget["B"]) + EPS >= c)) return false
        }
        return true
    }

    private fun safetyBound(policy: Map<String, Any?>): Double {
        val kappa = d(policy["kappa"])
        return if (kappa > 0) Math.max(0.0, d(policy["bMax"])) / kappa else 0.0
    }

    /** Starting from a full budget, machine-only actions debit kappa*r each: B never goes negative and Sum(r) <= bMax/kappa. */
    @JvmStatic fun cumulativeBudgetBoundProperty(r: Rng): Boolean {
        val policy = Arbitraries.riskPolicy(r)
        val seq = ArrayList<Map<String, Any?>>()
        var i = r.integer(1, 40)
        while (i > 0) { seq.add(Arbitraries.riskInputs(r)); i-- }
        val bound = safetyBound(policy)
        val kappa = d(policy["kappa"])
        val bMax = d(policy["bMax"])
        var budget = Math.max(0.0, bMax)
        var sumR = 0.0
        for (inputs in seq) {
            val risk = riskOf(inputs, map(policy["weights"]))
            val adm = admit(risk, budget, d(policy["theta1"]), d(policy["theta2"]), kappa)
            if (adm["metered"] as Boolean && (adm["t"] as Long) < 3) {
                val c = Risk.cost(risk, kappa)
                if (!(budget + EPS >= c)) return false
                budget = Math.max(0.0, budget - c)
                sumR += risk
                if (budget < -EPS) return false
                if (!(kappa * sumR <= bMax + 1e-6)) return false
                if (!(sumR <= bound + 1e-6)) return false
            }
        }
        return true
    }

    // ================================== 3. FAIL-CLOSED ======================================

    private val KNOWN_CAVEAT_TYPES = setOf(
        "expires", "not_before", "rate", "max_blast_radius", "reversibility_max", "delegation_depth", "budget_alloc", "max_spend", "intent_session",
    )

    /** Every structurally undecidable (but well-typed) leaf evaluates to unknown, never true, so a predicate carrying it never grants. */
    @JvmStatic fun undecidableLeafFailsClosedProperty(r: Rng): Boolean {
        val pick = r.integer(0, 4).toInt()
        val verb = r.pick("read", "write", "delete")
        val f = "subject.role"
        val leaf = when (pick) {
            0 -> obj("field" to "$f.definitely_absent", "op" to "eq", "value" to "x") // missing field
            1 -> obj("field" to f, "op" to "lt", "value" to 5L) // string field vs number: incomparable
            2 -> obj("field" to f, "op" to "in", "value" to "not-an-array") // non-array operand
            3 -> obj("field" to f, "op" to "eq") // no value and no ref
            else -> obj("field" to f, "op" to "member_of", "value" to "g", "collection" to "env.no_such_collection") // missing collection
        }
        val ctx = obj("action" to obj("verb" to verb, "resource" to "/x"), "subject" to obj("role" to "admin"))
        if (Predicates.evaluateConditionTri(leaf, ctx) == Predicates.Tri.TRUE) return false
        if (Predicates.evaluateCondition(leaf, ctx)) return false
        val preds = arrayListOf<Any?>(obj("verb" to verb, "resource" to "/x", "where" to arrayListOf<Any?>(leaf)))
        return !Predicates.evaluatePredicates(preds, ctx)
    }

    /** A not / all_of / any_of built over undecidable or empty children fails closed (never true). */
    @JvmStatic fun undecidableGroupsFailClosedProperty(@Suppress("UNUSED_PARAMETER") r: Rng): Boolean {
        val ctx = obj("action" to obj("verb" to "read", "resource" to "/x"), "subject" to obj("role" to "admin"))
        val child = obj("field" to "subject.role", "op" to "lt", "value" to 5L)
        val none = ArrayList<Any?>()
        val one = arrayListOf<Any?>(child)
        for (g in listOf(obj("not" to child), obj("all_of" to none), obj("any_of" to none), obj("all_of" to one), obj("any_of" to one))) {
            if (Predicates.evaluateConditionTri(g, ctx) == Predicates.Tri.TRUE) return false
        }
        return true
    }

    /** member_of over a cyclic adjacency terminates with the correct verdict: reachable targets true, an unreachable one false. */
    @JvmStatic fun memberOfCycleSafeProperty(r: Rng): Boolean {
        val target = r.pick("a", "b", "c", "z")
        val rel = obj("a" to arrayListOf<Any?>("b"), "b" to arrayListOf<Any?>("a", "c"))
        val ctx = obj("action" to obj("verb" to "read", "resource" to "/x"), "subject" to obj("g" to "a"), "env" to obj("rel" to rel))
        val tri = Predicates.evaluateConditionTri(obj("field" to "subject.g", "op" to "member_of", "value" to target, "collection" to "env.rel"), ctx)
        val expected = if (target in setOf("a", "b", "c")) Predicates.Tri.TRUE else Predicates.Tri.FALSE
        return tri == expected
    }

    /** An unknown caveat TYPE is never satisfied, so a caveat set containing it is never ok. */
    @JvmStatic fun unknownCaveatTypeDeniesProperty(r: Rng): Boolean {
        var type: String
        do { type = r.string(1, 12) } while (type in KNOWN_CAVEAT_TYPES)
        val now = r.integer(0, 10_000_000)
        val cav = obj("type" to type)
        val ctx = obj("now" to now)
        if (Caveats.satisfied(cav, ctx)) return false
        return !Caveats.evaluateCaveats(arrayListOf<Any?>(cav), ctx).ok
    }

    private val ALL_MUTATIONS = listOf(
        "tamper-caveat", "drop-leaf-caveat", "swap-holder", "break-parent", "bad-sig", "wrong-root-issuer", "suite-mismatch", "break-id", "append-forged-hop",
    )

    private fun deepCopy(v: Any?): Any? = when (v) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { o -> for ((k, x) in v) o[k as String] = deepCopy(x) }
        is List<*> -> v.mapTo(ArrayList()) { deepCopy(it) }
        else -> v
    }

    private fun cloneCaps(caps: List<Any?>): MutableList<Any?> = deepCopy(caps) as MutableList<Any?>

    /** Every forged chain (nine distinct attacks on a legal one) fails verification. */
    @JvmStatic fun forgedChainRejectedProperty(r: Rng): Boolean {
        val chain = Arbitraries.chain(r)
        val mutation = r.pick(ALL_MUTATIONS)
        val pick = r.integer(0, 1_000_000)
        val aux = Arbitraries.keyPair(r)
        val caps = list(chain["caps"])
        val root = chain["rootIssuer"] as String
        if (!chainOk(caps, root)) return false
        val n = caps.size
        val idx = (pick % n).toInt()
        when (mutation) {
            "tamper-caveat" -> {
                val m = cloneCaps(caps)
                val hop = mmap(m[idx])
                val cv = ArrayList(list(hop["caveats"]))
                cv.add(obj("type" to "expires", "at" to 999L))
                hop["caveats"] = cv
                return !chainOk(m, root)
            }
            "drop-leaf-caveat" -> {
                val m = cloneCaps(caps)
                val hop = mmap(m[n - 1])
                val cv = list(hop["caveats"])
                if (cv.isEmpty()) return true // inapplicable: trivially pass
                hop["caveats"] = ArrayList(cv.subList(0, cv.size - 1))
                return !chainOk(m, root)
            }
            "swap-holder" -> {
                val m = cloneCaps(caps)
                mmap(m[idx])["holder"] = aux.pub // changes the signed body: digest mismatch
                return !chainOk(m, root)
            }
            "break-parent" -> {
                if (n < 2) return true // no non-root hop to detach
                val m = cloneCaps(caps)
                mmap(m[Math.max(1, idx)])["parent"] = Pca.hashCanonical(obj("bogus" to 32L, "tag" to "not-a-real-parent"))
                return !chainOk(m, root)
            }
            "bad-sig" -> {
                val m = cloneCaps(caps)
                // a well-formed but wrong signature: over different bytes, by a different key
                mmap(m[idx])["sig"] = Keys.b64u(aux.key.sign(byteArrayOf(1, 2, 3, 4)))
                return !chainOk(m, root)
            }
            "wrong-root-issuer" -> {
                if (aux.pub == root) return true // negligibly rare key collision: skip
                return !chainOk(caps, aux.pub)
            }
            "suite-mismatch" -> {
                val m = cloneCaps(caps)
                mmap(m[idx])["alg"] = "ml-dsa-65" // the suite fields are bound into body_digest
                return !chainOk(m, root)
            }
            "break-id" -> {
                val m = cloneCaps(caps)
                mmap(m[idx])["id"] = Pca.hashCanonical(obj("not" to "the-body-digest", "n" to idx.toLong()))
                return !chainOk(m, root)
            }
            else -> { // append-forged-hop: issued as if from the leaf, but signed by a key that is NOT the leaf's holder
                val forged = Issue.delegate(map(caps[n - 1]), aux.pub, ArrayList(), Keys.ed25519(aux.key), null)
                val m = ArrayList(caps)
                m.add(forged)
                return !chainOk(m, root)
            }
        }
    }

    /** Well-typed but never-signed "capabilities" (random fields) never verify; neither does the empty chain. */
    @JvmStatic fun garbageChainRejectedProperty(r: Rng): Boolean {
        val garbage = ArrayList<Any?>()
        var i = r.integer(0, 4)
        while (i > 0) {
            val cv = ArrayList<Any?>()
            var j = r.integer(0, 3)
            while (j > 0) { cv.add(obj("type" to r.string(0, 10))); j-- }
            val id = r.string(0, 10)
            val issuer = r.string(0, 10)
            val holder = r.string(0, 10)
            val bodyDigest = r.string(0, 10)
            garbage.add(obj("id" to id, "issuer" to issuer, "holder" to holder, "caveats" to cv, "body_digest" to bodyDigest, "sig" to r.string(0, 10)))
            i--
        }
        return Pca.verifyChain(garbage, "", false).isNotEmpty()
    }

    // =================================== 4. DETERMINISM =====================================

    /** verifyChain, evaluatePredicates, evaluateCaveats, riskScore, the threshold band and admit are all deterministic. */
    @JvmStatic fun determinismProperty(r: Rng): Boolean {
        val chain = Arbitraries.chain(r)
        val pt = Arbitraries.evalPoint(r)
        val preds = Arbitraries.predicateList(r)
        val policy = Arbitraries.riskPolicy(r)
        val inputs = Arbitraries.riskInputs(r)
        val budget = Arbitraries.trustBudget(r)
        val caps = list(chain["caps"])
        val root = chain["rootIssuer"] as String
        if (Pca.verifyChain(caps, root, true) != Pca.verifyChain(caps, root, true)) return false
        if (Predicates.evaluatePredicates(preds, map(pt["action"])) != Predicates.evaluatePredicates(preds, map(pt["action"]))) return false
        val leaf = map(caps[caps.size - 1])
        val c1 = Caveats.evaluateCaveats(leaf["caveats"], pt["cavCtx"])
        val c2 = Caveats.evaluateCaveats(leaf["caveats"], pt["cavCtx"])
        if (c1.ok != c2.ok || c1.failed.joinToString("|") != c2.failed.joinToString("|")) return false
        val r1 = riskOf(inputs, map(policy["weights"]))
        val r2 = riskOf(inputs, map(policy["weights"]))
        if (java.lang.Double.doubleToLongBits(r1) != java.lang.Double.doubleToLongBits(r2)) return false
        val th1 = d(policy["theta1"])
        val th2 = d(policy["theta2"])
        val kappa = d(policy["kappa"])
        if (threshold(r1, th1, th2) != threshold(r1, th1, th2)) return false
        return admit(r1, d(budget["B"]), th1, th2, kappa) == admit(r1, d(budget["B"]), th1, th2, kappa)
    }

    /**
     * Forbid-wins is monotone and order-independent: adding a forbid clause only moves a decision down, a matching forbid always denies
     * whatever the permits say, and the decision does not depend on the order of the clauses.
     */
    @JvmStatic fun forbidMonotoneProperty(r: Rng): Boolean {
        val permits = Arbitraries.predicateList(r)
        val forbids = Arbitraries.predicateList(r)
        val extra = Arbitraries.predicateList(r)
        val pt = Arbitraries.evalPoint(r)
        val rot = r.integer(0, 5)
        val ctx = map(pt["action"])
        val base = ArrayList<Any?>()
        base.addAll(clauses("permit", permits, "p"))
        base.addAll(clauses("escalate", extra, "e"))
        val withForbid = ArrayList(base)
        withForbid.addAll(clauses("forbid", forbids, "f"))
        val before = rank(ForbidWins.decide(base, ctx).decision)
        val afterDecision = ForbidWins.decide(withForbid, ctx).decision
        if (rank(afterDecision) > before) return false // adding a forbid must never grow the admit set
        val anyForbid = forbids.any { ForbidWins.whenMatches(it, ctx) }
        if (anyForbid && "deny" != afterDecision) return false // a matching forbid beats every permit
        val k = (rot % withForbid.size).toInt()
        val rotated = ArrayList(withForbid.subList(k, withForbid.size))
        rotated.addAll(withForbid.subList(0, k))
        return ForbidWins.decide(rotated, ctx).decision == afterDecision // order-independent
    }

    private fun clauses(kind: String, ps: List<Any?>, tag: String): List<Any?> =
        ps.mapIndexed { i, p -> obj("id" to "$tag$i", "kind" to kind, "when" to p) }

    private fun rank(decision: String): Int = if ("deny" == decision) 0 else if ("escalate" == decision) 1 else 2

    // =================================== runner / registry ==================================

    /** The twelve invariants by name, in registry order (the same names as [Invariants.INVARIANT_NAMES]). */
    @JvmField val INVARIANTS: Map<String, (Rng) -> Boolean> = linkedMapOf<String, (Rng) -> Boolean>(
        "attenuation-monotonicity" to { r: Rng -> attenuationMonotonicityProperty(r) },
        "risk-wellformed-and-monotone" to { r: Rng -> riskMonotoneProperty(r) },
        "admission-soundness" to { r: Rng -> admissionSoundnessProperty(r) },
        "cumulative-budget-bound" to { r: Rng -> cumulativeBudgetBoundProperty(r) },
        "fail-closed:undecidable-leaf" to { r: Rng -> undecidableLeafFailsClosedProperty(r) },
        "fail-closed:undecidable-groups" to { r: Rng -> undecidableGroupsFailClosedProperty(r) },
        "fail-closed:member-of-cycle-safe" to { r: Rng -> memberOfCycleSafeProperty(r) },
        "fail-closed:unknown-caveat-type" to { r: Rng -> unknownCaveatTypeDeniesProperty(r) },
        "fail-closed:forged-chain-rejected" to { r: Rng -> forgedChainRejectedProperty(r) },
        "fail-closed:garbage-chain-rejected" to { r: Rng -> garbageChainRejectedProperty(r) },
        "forbid-monotone" to { r: Rng -> forbidMonotoneProperty(r) },
        "determinism" to { r: Rng -> determinismProperty(r) },
    )

    /**
     * Run one property [numRuns] times from [seed]; throws an [AssertionError] naming the failing run (a property that throws fails too).
     * The same (seed, numRuns) always generates the same cases.
     */
    @JvmStatic fun run(property: (Rng) -> Boolean, numRuns: Long, seed: Long) {
        val rng = Rng(seed)
        var i = 0L
        while (i < numRuns) {
            val ok = try {
                property(rng)
            } catch (e: RuntimeException) {
                throw AssertionError("Property failed after " + (i + 1) + " test(s) (seed " + seed + "): threw " + e, e)
            }
            if (!ok) throw AssertionError("Property failed after " + (i + 1) + " test(s) (seed " + seed + ")")
            i++
        }
    }

    /**
     * Machine-check every invariant: one result per invariant `{name, ok, numRuns, seed[, error]}`. `ok: false` with an `error` is a
     * surfaced counterexample (a candidate core bug). A check that runs zero cases passes vacuously, so it is refused.
     */
    @JvmStatic fun checkInvariants(numRunsOpt: Long? = null, seedOpt: Long? = null, bail: Boolean = false): List<Map<String, Any?>> {
        val numRuns = numRunsOpt ?: Invariants.DEFAULT_NUM_RUNS.toLong()
        val seed = seedOpt ?: Invariants.DEFAULT_SEED
        require(numRuns in 1..9007199254740991L) { "checkInvariants: numRuns must be a positive integer" }
        require(seed in -9007199254740991L..9007199254740991L) { "checkInvariants: seed must be an integer" }
        val results = ArrayList<Map<String, Any?>>()
        for ((name, prop) in INVARIANTS) {
            try {
                run(prop, numRuns, seed)
                results.add(obj("name" to name, "ok" to true, "numRuns" to numRuns, "seed" to seed))
            } catch (e: Throwable) {
                if (e !is AssertionError && e !is RuntimeException) throw e
                results.add(obj("name" to name, "ok" to false, "numRuns" to numRuns, "seed" to seed, "error" to e.message.toString()))
                if (bail) break
            }
        }
        return results
    }
}
