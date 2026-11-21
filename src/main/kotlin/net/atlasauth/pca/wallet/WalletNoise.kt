package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js

/**
 * Attention canaries and the approval-fatigue model (the reference's canary.ts and fatigue.ts). A canary is a question about a
 * cell whose label the system already knows; its answer only updates the per-principal noise counts (it never reaches a learner
 * or a grant). The fatigue model turns the counts and the questions asked in the last hour into the admission policy.
 */
@Suppress("UNCHECKED_CAST")
object WalletNoise {
    // ---- noise counts and estimates ----

    fun emptyNoise(): Map<String, Any?> = Wallet.obj("falseYes", Js.n(0), "correctNo", Js.n(0), "falseNo", Js.n(0), "correctYes", Js.n(0))

    private fun bump(n: Map<String, Any?>, key: String): Map<String, Any?> {
        val m = LinkedHashMap(n)
        m[key] = Wallet.nv(n[key]) + 1
        return m
    }

    /** Fold one canary answer into the counts (pure): expected and y are 0 or 1. */
    fun recordCanary(n: Map<String, Any?>, expected: Any?, y: Any?): Map<String, Any?> {
        val y1 = Wallet.nv(y) == 1.0
        if (Wallet.nv(expected) == 0.0) return if (y1) bump(n, "falseYes") else bump(n, "correctNo")
        return if (Wallet.nv(y) == 0.0) bump(n, "falseNo") else bump(n, "correctYes")
    }

    const val PRIOR_A = 1.0
    const val PRIOR_B = 9.0

    /** Posterior means and bounds of the false-yes / false-no rates; throws unless deltaC is in (0, 1). */
    fun estimateNoise(n: Map<String, Any?>, deltaC: Double = 0.05): Map<String, Any?> {
        if (!(deltaC > 0 && deltaC < 1)) throw IllegalArgumentException("estimateNoise: deltaC must be in (0, 1)")
        val falseYes = Wallet.nv(n["falseYes"])
        val correctNo = Wallet.nv(n["correctNo"])
        val falseNo = Wallet.nv(n["falseNo"])
        val correctYes = Wallet.nv(n["correctYes"])
        val ap = PRIOR_A + falseYes
        val bp = PRIOR_B + correctNo
        val an = PRIOR_A + falseNo
        val bn = PRIOR_B + correctYes
        val knownNo = falseYes + correctNo
        val knownYes = falseNo + correctYes
        val out = LinkedHashMap<String, Any?>()
        out["etaPos"] = ap / (ap + bp)
        out["etaNeg"] = an / (an + bn)
        out["etaPosUpper"] = WalletStats.betaQuantile(1 - deltaC, ap, bp)
        out["etaNegUpper"] = WalletStats.betaQuantile(1 - deltaC, an, bn)
        out["etaPosCP"] = if (knownNo == 0.0) 1.0 else WalletStats.clopperPearsonUpper(falseYes, knownNo, deltaC)
        out["etaNegCP"] = if (knownYes == 0.0) 1.0 else WalletStats.clopperPearsonUpper(falseNo, knownYes, deltaC)
        out["asked"] = knownNo + knownYes
        return out
    }

    // ---- selection ----

    /** Why a cell is a known no ("ceiling" or "veto"), or null when it is not one. */
    fun interface KnownNo { fun why(verb: String, idx: IntArray): String? }

    class CanaryContext {
        lateinit var omega: Map<String, Any?>
        /** Cells inside the confirmed region: maps {verb, idx}. */
        var confirmed: List<Map<String, Any?>> = ArrayList()
        lateinit var knownNo: KnownNo
        /** Cells with an earlier verified high-friction yes: maps {verb, idx}. */
        var knownYes: List<Map<String, Any?>> = ArrayList()
        /** Cells not to use, as "verb|i,j,..." keys. */
        var exclude: Set<String> = emptySet()
        lateinit var rand: () -> Double
        /** Insertion probability (default 0.1); null for the default. */
        var rho: Double? = null
        var lowHarmSession: Boolean = false
        var canariesSoFar: Double = 0.0
    }

    fun cellKey(verb: String, idx: IntArray): String {
        val sb = StringBuilder(verb).append('|')
        for (i in idx.indices) sb.append(if (i == 0) "" else ",").append(idx[i])
        return sb.toString()
    }

    fun idxOf(o: Any?): IntArray {
        val l = o as List<Any?>
        return IntArray(l.size) { Js.num(l[it])!!.toInt() }
    }

    fun idxList(idx: IntArray): List<Any?> = idx.map { it.toLong() }

    internal fun cellAt(verb: String, idx: IntArray): Map<String, Any?> = Wallet.obj("verb", verb, "idx", idxList(idx))

    /** Cells one step outside the confirmed region in exactly one dimension (deterministic order): maps {verb, idx}. */
    fun boundaryNeighbours(omega: Map<String, Any?>, confirmed: List<Map<String, Any?>>): List<Map<String, Any?>> {
        val inside = HashSet<String>()
        for (c in confirmed) inside.add(cellKey(c["verb"] as String, idxOf(c["idx"])))
        val out = LinkedHashMap<String, Map<String, Any?>>()
        for (c in confirmed) {
            val vs = WalletOmega.verbSpace(omega, c["verb"]) ?: continue
            val ci = idxOf(c["idx"])
            for (k in WalletOmega.dims(vs).indices) {
                val d = WalletOmega.dim(vs, k)
                val n = WalletOmega.cellCount(d)
                val alts: IntArray = if ("num" == d["kind"]) intArrayOf(ci[k] - 1, ci[k] + 1) else IntArray(n) { it }
                for (a in alts) {
                    if (a < 0 || a >= n || a == ci[k]) continue
                    val idx = ci.clone()
                    idx[k] = a
                    val key = cellKey(c["verb"] as String, idx)
                    if (!inside.contains(key)) out[key] = cellAt(c["verb"] as String, idx)
                }
            }
        }
        // Java String.compareTo orders by UTF-16 code unit, as Kotlin's String comparison does.
        return out.keys.sorted().map { out[it]!! }
    }

    /** Decide whether to insert a canary now, and which: {verb, idx, expected, source}, or null for no canary this time. */
    fun pickCanary(ctx: CanaryContext): Map<String, Any?>? {
        val rho = ctx.rho ?: 0.1
        if (!(rho >= 0 && rho <= 1)) throw IllegalArgumentException("pickCanary: rho must be in [0, 1]")
        if (ctx.lowHarmSession && ctx.canariesSoFar >= 1) return null
        if (!(ctx.rand() < rho)) return null
        val no = ArrayList<Map<String, Any?>>()
        for (c in boundaryNeighbours(ctx.omega, ctx.confirmed)) {
            val idx = idxOf(c["idx"])
            if (ctx.exclude.contains(cellKey(c["verb"] as String, idx))) continue
            val why = ctx.knownNo.why(c["verb"] as String, idx)
            if (why != null) no.add(Wallet.obj("verb", c["verb"], "idx", c["idx"], "expected", Js.n(0), "source", why))
        }
        val yes = ArrayList<Map<String, Any?>>()
        for (c in ctx.knownYes) {
            val idx = idxOf(c["idx"])
            if (ctx.exclude.contains(cellKey(c["verb"] as String, idx))) continue
            yes.add(Wallet.obj("verb", c["verb"], "idx", idxList(idx), "expected", Js.n(1), "source", "confirmed-yes"))
        }
        if (no.isEmpty() && yes.isEmpty()) return null
        val pool = if (no.isNotEmpty() && yes.isNotEmpty()) (if (ctx.rand() < 0.5) no else yes) else if (no.isNotEmpty()) no else yes
        return pool[Math.min((pool.size - 1).toDouble(), Math.floor(ctx.rand() * pool.size)).toInt()]
    }

    // ---- approval fatigue ----

    /** {betaF: 0.005, etaStop: 0.15, deltaC: 0.05, freezeOn: "mean", assumeNoiseFree: false, delta: 0.05}. */
    fun defaultFatigue(): Map<String, Any?> = Wallet.obj("betaF", 0.005, "etaStop", 0.15, "deltaC", 0.05, "freezeOn", "mean", "assumeNoiseFree", false, "delta", 0.05)

    /** Eta+ under load: base + betaF * nRecent, capped at 1/2. */
    fun etaUnderLoad(base: Double, betaF: Double, nRecent: Double): Double {
        if (!(base >= 0 && betaF >= 0 && nRecent == Math.rint(nRecent) && !nRecent.isInfinite() && nRecent >= 0)) throw IllegalArgumentException("etaUnderLoad: bad arguments")
        return Math.min(0.5, base + betaF * nRecent)
    }

    /** {etaPos, etaPosBar, etaNegBar, frozen}. */
    fun noiseState(counts: Map<String, Any?>, nRecent: Double, model: Map<String, Any?> = defaultFatigue()): Map<String, Any?> {
        val e = estimateNoise(counts, if (Wallet.defined(model, "deltaC")) Wallet.nv(model["deltaC"]) else 0.05)
        val betaF = Wallet.nv(model["betaF"])
        val etaPos = etaUnderLoad(e["etaPos"] as Double, betaF, nRecent)
        val etaPosBar = etaUnderLoad(e["etaPosUpper"] as Double, betaF, nRecent)
        val stat = if ("mean" == model["freezeOn"]) etaPos else etaPosBar
        return Wallet.obj("etaPos", etaPos, "etaPosBar", etaPosBar, "etaNegBar", Math.min(0.5, e["etaNegUpper"] as Double), "frozen", stat > Wallet.nv(model["etaStop"]))
    }

    private const val BELOW_HALF = 0.5 - 1e-9

    /** {tau, etaPos, etaNeg, doubleConfirmIrreversible, falseAdmitBound}. */
    fun admissionPolicy(state: Map<String, Any?>, model: Map<String, Any?> = defaultFatigue()): Map<String, Any?> {
        if (Js.truthy(model["assumeNoiseFree"]))
            return Wallet.obj("tau", Js.n(1), "etaPos", Js.n(0), "etaNeg", Js.n(0), "doubleConfirmIrreversible", false, "falseAdmitBound", Js.n(0))
        val delta = Wallet.nv(model["delta"])
        if (!(delta > 0 && delta < 1)) throw IllegalArgumentException("admissionPolicy: delta must be in (0, 1)")
        val ep = Math.min(BELOW_HALF, Wallet.nv(state["etaPosBar"]))
        val en = Math.min(BELOW_HALF, Wallet.nv(state["etaNegBar"]))
        return Wallet.obj("tau", 1 - delta, "etaPos", ep, "etaNeg", en, "doubleConfirmIrreversible", ep > 0, "falseAdmitBound", ep * ep)
    }

    /**
     * Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split
     * around it by opening sessions). Keeps only timestamps inside the window.
     */
    class SlidingWindowCounter(@JvmField val windowMs: Double = 3_600_000.0) {
        private val times = ArrayList<Double>()

        init {
            if (!(windowMs == Math.rint(windowMs) && windowMs > 0 && !windowMs.isInfinite())) throw IllegalArgumentException("SlidingWindowCounter: windowMs must be a positive integer")
        }

        private fun prune(now: Double) {
            if (!now.isFinite()) return // an infinite clock must never forget a recorded event
            while (times.isNotEmpty() && times[0] <= now - windowMs) times.removeAt(0)
        }

        fun count(now: Double): Int {
            prune(now)
            return times.size
        }

        /** Record one event at [now] if the count is below [cap]; false (and nothing recorded) otherwise. */
        fun tryAdd(now: Double, cap: Double): Boolean {
            prune(now)
            if (times.size >= cap) return false
            if (times.isNotEmpty() && !(now >= times[times.size - 1])) throw IllegalStateException("SlidingWindowCounter: time went backwards")
            if (!now.isFinite()) return false
            times.add(now)
            return true
        }
    }

    /**
     * Double confirmation of an irreversible cell: two "yes" answers at typed or device tier, on different screens, with at
     * least one other screen between them. Records are maps {screen, tier}.
     */
    fun doubleConfirmed(records: List<Map<String, Any?>>): Boolean {
        val strong = ArrayList<Double>()
        for (r in records) if ("typed" == r["tier"] || "device" == r["tier"]) strong.add(Wallet.nv(r["screen"]))
        strong.sort()
        for (i in strong.indices) for (j in i + 1 until strong.size) if (strong[j] - strong[i] >= 2) return true
        return false
    }
}
