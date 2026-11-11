package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.RoundingMode

/**
 * Risk functional, threshold map and decaying trust budget (spec section 10, layer 3): a port of packages/pca/src/risk.ts and of the
 * numeric kernels of the policy VM (PolicyVm.dfy: ReqThr, Escalate, AdmitOf). Pure and deterministic. Time is epoch milliseconds;
 * `lambda` is budget drained PER SECOND. A non-finite input fails closed (it is the input's worst case).
 */
object Risk {
    val WEIGHT_KEYS = listOf("alpha", "beta", "gamma", "delta", "epsilon", "zeta")
    val INPUT_KEYS = listOf("semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age")

    /** The worst case of each input: a missing or non-finite value counts as this. */
    val WORST: Map<String, Double> = mapOf("semanticDistance" to 1.0, "reversibility" to 0.0, "blastRadius" to 1.0, "taint" to 1.0, "confidence" to 0.0, "age" to 1.0)

    /** A finite JavaScript number (a boolean, a string or null is not one). */
    fun fin(x: Any?): Double? = IntentJs.num(x)?.takeIf { !it.isNaN() && !it.isInfinite() }

    fun clamp01(x: Double): Double = if (x < 0) 0.0 else if (x > 1) 1.0 else x

    /** Non-finite => `worst`; else clamped to [0, 1]. */
    private fun unit(x: Any?, worst: Double): Double = fin(x)?.let { clamp01(it) } ?: worst

    private fun wt(x: Any?): Double = fin(x)?.takeIf { it > 0 } ?: 0.0
    private fun nz(x: Double?): Double = if (x != null && !x.isNaN() && !x.isInfinite() && x > 0) x else 0.0

    /** The validated `risk_policy` of a grant envelope. */
    class Policy(val weights: Map<String, Any?>, val theta1: Double, val theta2: Double, val kappa: Double, val lambda: Double, val rho: Double, val bMax: Double) {
        companion object {
            /** Reads a policy map already accepted by the envelope validator (every number finite). Null when a member is not a finite number. */
            fun of(m: Map<String, Any?>?): Policy? {
                if (m == null) return null
                val w = m["weights"] as? Map<String, Any?> ?: return null
                return Policy(
                    w, fin(m["theta1"]) ?: return null, fin(m["theta2"]) ?: return null, fin(m["kappa"]) ?: return null,
                    fin(m["lambda"]) ?: return null, fin(m["rho"]) ?: return null, fin(m["bMax"]) ?: return null,
                )
            }
        }
    }

    /** r = clamp(a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1); the weights are clamped to >= 0. */
    fun riskScore(i: Map<String, Any?>, w: Map<String, Any?>): Double {
        val r = wt(w["alpha"]) * unit(i["semanticDistance"], 1.0) +
            wt(w["beta"]) * (1 - unit(i["reversibility"], 0.0)) +
            wt(w["gamma"]) * unit(i["blastRadius"], 1.0) +
            wt(w["delta"]) * unit(i["taint"], 1.0) +
            wt(w["epsilon"]) * (1 - unit(i["confidence"], 0.0)) +
            wt(w["zeta"]) * unit(i["age"], 1.0)
        return clamp01(r)
    }

    /** A required threshold: `t` 1..3, the proof strength, and whether an optimistic fast path may rely on it. */
    class Threshold(val t: Int, val proof: String, val optimisticAllowed: Boolean)

    private val PROOF_FOR_T = mapOf(1 to "claim", 2 to "standard", 3 to "strong")
    private val PROOF_RANK = mapOf("claim" to 0, "standard" to 1, "strong" to 2)

    /** r <= theta1 -> t=1 (claim; optimistic ok unless irreversible); r <= theta2 -> t=2; else t=3. A NaN r is the worst case. */
    fun requiredThreshold(r: Double, p: Policy, irreversible: Boolean = false): Threshold {
        val x = if (r.isNaN() || r.isInfinite()) 1.0 else r
        return when {
            x <= p.theta1 -> Threshold(1, "claim", !irreversible)
            x <= p.theta2 -> Threshold(2, "standard", false)
            else -> Threshold(3, "strong", false)
        }
    }

    /** Raises a threshold to at least [minT] and keeps it coherent; never lowers anything. */
    fun escalateThreshold(rt: Threshold, minT: Int): Threshold {
        val t = if (minT > rt.t) minT else rt.t
        val floor = PROOF_FOR_T.getValue(t)
        val proof = if (PROOF_RANK.getValue(rt.proof) >= PROOF_RANK.getValue(floor)) rt.proof else floor
        return Threshold(t, proof, if (t > 1) false else rt.optimisticAllowed)
    }

    /** The trust budget: `B` remaining, `tau` the last human touch, `asOf` the last leak (null = tau). */
    data class Budget(val B: Double, val tau: Double, val asOf: Double? = null)

    /** c(A) = kappa * r(A); a non-finite r is the cost of r = 1. */
    fun cost(r: Double, kappa: Double): Double = nz(kappa) * clamp01(if (r.isNaN() || r.isInfinite()) 1.0 else r)

    /** The passive leak dB/dt = -lambda since the last update. Idempotent for repeated calls at the same `now`. */
    fun leak(b: Budget, now: Double, lambda: Double): Budget {
        val from = b.asOf ?: b.tau
        val nowOk = !now.isNaN() && !now.isInfinite()
        val dt = if (nowOk && !from.isNaN() && !from.isInfinite()) maxOf(0.0, now - from) else 0.0
        val bb = maxOf(0.0, b.B - nz(lambda) * (dt / 1000.0))
        return Budget(bb, b.tau, if (nowOk) maxOf(now, from) else from)
    }

    /** B <- max(0, B - cost). The caller checks B >= cost first. */
    fun debit(b: Budget, c: Double): Budget = b.copy(B = maxOf(0.0, b.B - nz(c)))

    /** The normalised age since the last human touch: clamp((now - tau) / horizon, 0, 1); a bad input is 1. */
    fun ageSinceTouch(b: Budget, now: Double, horizonMs: Double = 3_600_000.0): Double {
        if (now.isNaN() || now.isInfinite() || b.tau.isNaN() || b.tau.isInfinite() || horizonMs.isNaN() || horizonMs.isInfinite() || horizonMs <= 0) return 1.0
        return clamp01((now - b.tau) / horizonMs)
    }

    /** The machine-only band is t=1 AND t=2 (both metered): an action at t<3 proceeds only if the budget covers its cost. */
    class Admission(val admit: Boolean, val needStepUp: Boolean, val t: Int, val metered: Boolean)

    fun admitOf(t: Int, budgetCovers: Boolean): Admission = when {
        t < 3 && !budgetCovers -> Admission(false, true, 3, false)
        t == 1 -> Admission(true, false, 1, true)
        t == 2 -> Admission(false, true, 2, true)
        else -> Admission(false, true, 3, false)
    }

    /** `r.toFixed(3)` for r in [0, 1]: JavaScript rounds an exact tie up (0.0625 -> "0.063"). */
    fun toFixed3(r: Double): String {
        val n = BigDecimal(r).multiply(BigDecimal(1000)).add(BigDecimal("0.5")).setScale(0, RoundingMode.FLOOR).toLong()
        return "%d.%03d".format(n / 1000, n % 1000)
    }

    /**
     * The riskier of two partial input sets per input (higher is riskier, except reversibility and confidence); a non-finite or missing
     * value of the second never replaces the first; with only one side present that side stands.
     */
    fun riskier(a: Map<String, Any?>?, b: Map<String, Any?>?): Map<String, Any?>? {
        if (a == null) return b
        if (b == null) return a
        val out = LinkedHashMap(a)
        for ((k, y) in b) {
            val yd = fin(y) ?: continue
            val xd = fin(a[k])
            out[k] = if (xd == null) y else if (k == "reversibility" || k == "confidence") (if (xd <= yd) a[k] else y) else (if (xd >= yd) a[k] else y)
        }
        return out
    }

    private val PRE_KEYS = listOf("after", "depends_on", "requires", "nodes")
    private val POST_KEYS = listOf("before", "enables", "then", "next")

    private fun refsOf(x: Any?, keys: List<String>): List<String> {
        val out = ArrayList<String>()
        fun add(v: Any?) {
            if (v is String) out.add(v) else if (v is List<*>) for (s in v) if (s is String) out.add(s)
        }
        add(x)
        if (x is Map<*, *>) for (k in keys) add(x[k])
        return out
    }

    /**
     * The normalised geodesic distance in the committed plan DAG, in [0, 1] (an approximation, as the reference): edges come from node
     * references (`pre` ids are predecessors, `post` ids successors); the BFS hop count over the undirected graph divided by (n - 1);
     * unreachable or an unknown node id is 1; with no edges the index distance |i - j| / (n - 1); the same node is 0.
     */
    fun planGeodesic(plan: Any?, fromId: Any?, toId: Any?): Double {
        if (plan !is List<*>) return 1.0
        val idx = HashMap<Any?, Int>()
        plan.forEachIndexed { i, n -> idx[(n as? Map<*, *>)?.get("id")] = i }
        val a = idx[fromId]
        val b = idx[toId]
        if (a == null || b == null) return 1.0
        if (a == b) return 0.0
        val n = plan.size
        val adj = List(n) { ArrayList<Int>() }
        var edges = 0
        fun link(i: Int, j: Int) {
            if (i == j) return
            if (!adj[i].contains(j)) { edges++; adj[i].add(j) }
            if (!adj[j].contains(i)) adj[j].add(i)
        }
        plan.forEachIndexed { i, node ->
            val m = node as? Map<*, *> ?: return@forEachIndexed
            for (id in refsOf(m["pre"], PRE_KEYS)) idx[id]?.let { link(it, i) }
            for (id in refsOf(m["post"], POST_KEYS)) idx[id]?.let { link(i, it) }
        }
        if (edges == 0) return clamp01(Math.abs(a - b).toDouble() / (n - 1))
        val dist = IntArray(n) { -1 }
        dist[a] = 0
        val q = ArrayList<Int>()
        q.add(a)
        var h = 0
        while (h < q.size) {
            val u = q[h]
            for (v in adj[u].sorted()) {
                if (dist[v] != -1) continue
                dist[v] = dist[u] + 1
                q.add(v)
            }
            h++
        }
        return if (dist[b] < 0) 1.0 else clamp01(dist[b].toDouble() / (n - 1))
    }
}
