package net.atlasauth.pca.wallet

import java.security.SecureRandom
import java.util.IdentityHashMap
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Pca

/**
 * Opt-in, privacy-preserving population priors. A principal who opts in contributes cell-level answers keyed by (schema digest,
 * verb, semantic cell); each principal contributes at most ONE vote per cell per period and to at most a fixed number of cells
 * per period. The aggregator releases noisy counts under the Gaussian mechanism (central DP); a principal who does not trust the
 * aggregator uses randomized response (local DP). The mixture prior (beta below 1) keeps full support, so at tau = 1 under
 * noise-free answers the grant does not depend on it.
 *
 * `priorAdmittedPpm` (the grant mass the prior alone admits) is [WalletLearner.priorAdmittedPpm], over the intent learner.
 */
@Suppress("UNCHECKED_CAST")
object WalletPopulation {
    const val POPULATION_VOTE_DOMAIN = "atlas-pca/intent-population-cell/v1"
    const val BETA_MAX = 0.9

    /** The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb. */
    fun populationCellKey(schemaDigest: String, vs: Map<String, Any?>, idx: IntArray): String =
        Pca.hashCanonical(Wallet.obj("d", POPULATION_VOTE_DOMAIN, "s", schemaDigest, "v", vs["verb"], "c", WalletBox.coordsOfCell(vs, idx)))

    private val SECURE = SecureRandom()

    /** Uniform (0, 1) from 53 random bits of a CSPRNG. */
    fun cryptoRand(): Double {
        val hi = (SECURE.nextInt().toLong() and 0xffffffffL) ushr 5
        val lo = (SECURE.nextInt().toLong() and 0xffffffffL) ushr 6
        return (hi * 67108864.0 + lo + 0.5) / 9007199254740992.0
    }

    /** A standard normal draw (Box-Muller) from a uniform source. */
    fun gaussian(rand: () -> Double): Double {
        var u = rand()
        while (u <= 0) u = rand()
        val v = rand()
        return Math.sqrt(-2 * StrictMath.log(u)) * StrictMath.cos(2 * Math.PI * v)
    }

    /** Sigma of the Gaussian mechanism for L2 sensitivity (requires epsilon in (0, 1), delta in (0, 1), sensitivity > 0). */
    fun gaussianSigma(epsilon: Double, delta: Double, l2Sensitivity: Double): Double {
        if (!(epsilon > 0 && epsilon < 1)) throw IllegalArgumentException("gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)")
        if (!(delta > 0 && delta < 1)) throw IllegalArgumentException("gaussianSigma: delta must be in (0, 1)")
        if (!(l2Sensitivity > 0)) throw IllegalArgumentException("gaussianSigma: sensitivity must be > 0")
        return (l2Sensitivity * Math.sqrt(2 * StrictMath.log(1.25 / delta))) / epsilon
    }

    /** The central aggregator (normally the Atlas instance). [maxCellsPerPrincipal] (default 32) and [rand] (default a CSPRNG) may be null. */
    class Aggregator(
        @JvmField val schemaDigest: String,
        @JvmField val period: Double,
        maxCellsPerPrincipal: Double? = null,
        rand: (() -> Double)? = null,
    ) {
        private val votes = HashMap<Any?, DoubleArray>()
        private val perPrincipal = HashMap<Any?, MutableSet<Any?>>()
        private val maxCells: Double
        private val rand: () -> Double

        init {
            if (!Wallet.isB64u32(schemaDigest)) throw IllegalArgumentException("PopulationAggregator: schemaDigest must be a canonical b64u digest")
            maxCells = maxCellsPerPrincipal ?: 32.0
            if (!(maxCells == Math.rint(maxCells) && maxCells > 0 && !maxCells.isInfinite())) throw IllegalArgumentException("PopulationAggregator: maxCellsPerPrincipal must be a positive integer")
            this.rand = rand ?: { cryptoRand() }
        }

        /**
         * Accept a vote {principal, schemaDigest, cellKey, y, period}; refuses a second vote on a cell, a vote past the
         * per-principal cell cap, or a foreign schema or period. Returns {ok:true} or {ok:false, reason}.
         */
        fun contribute(v: Map<String, Any?>): Map<String, Any?> {
            if (schemaDigest != v["schemaDigest"]) return Wallet.obj("ok", false, "reason", "vote for another schema")
            if (!(Js.isNumber(v["period"]) && Wallet.nv(v["period"]) == period)) return Wallet.obj("ok", false, "reason", "vote for another period")
            val y = v["y"]
            if (!(Js.isNumber(y) && (Wallet.nv(y) == 0.0 || Wallet.nv(y) == 1.0))) return Wallet.obj("ok", false, "reason", "y must be 0 or 1")
            val principal = v["principal"]
            if (principal !is String || principal.isEmpty()) return Wallet.obj("ok", false, "reason", "an accountable principal is required")
            val mine = perPrincipal[principal] ?: HashSet()
            val key = v["cellKey"]
            if (mine.contains(key)) return Wallet.obj("ok", false, "reason", "one vote per principal per cell per period (sensitivity 1)")
            if (mine.size >= maxCells) return Wallet.obj("ok", false, "reason", "at most " + WalletCard.jsNum(maxCells) + " cells per principal per period")
            mine.add(key)
            perPrincipal[principal] = mine
            val c = votes[key] ?: doubleArrayOf(0.0, 0.0)
            votes[key] = doubleArrayOf(c[0] + Wallet.nv(y), c[1] + 1)
            return Wallet.obj("ok", true)
        }

        /**
         * The (epsilon, delta)-DP release. Cells whose noisy count is below [minCountO] (default 3 sigma) are suppressed.
         * [qMinO] defaults to 0.02. Returns the population-prior object.
         */
        fun release(epsilon: Double, delta: Double, qMinO: Double? = null, minCountO: Double? = null): Map<String, Any?> {
            val sensitivity = Math.sqrt(2 * maxCells)
            val sigma = gaussianSigma(epsilon, delta, sensitivity)
            val qMin = qMinO ?: 0.02
            if (!(qMin > 0 && qMin < 0.5)) throw IllegalArgumentException("release: qMin must be in (0, 0.5)")
            val minCount = minCountO ?: (3 * sigma)
            val cells = LinkedHashMap<String, Any?>()
            val keys = votes.keys.map { it as String }.sorted()
            for (key in keys) {
                val c = votes[key]!!
                val yes = c[0] + sigma * gaussian(rand)
                val total = c[1] + sigma * gaussian(rand)
                if (!(total >= minCount)) continue
                cells[key] = Wallet.obj("q", Math.min(1 - qMin, Math.max(qMin, yes / total)), "n", Math.floor(total + 0.5))
            }
            return Wallet.obj("v", Js.n(1), "kind", "pca-intent-population-prior", "schema", schemaDigest, "period", period, "epsilon", epsilon, "delta", delta,
                "sigma", sigma, "sensitivity", sensitivity, "cells", cells)
        }
    }

    // ---- local DP ----

    fun rrKeepProbability(epsilon: Double): Double {
        if (!(epsilon > 0 && !epsilon.isInfinite())) throw IllegalArgumentException("randomized response: epsilon must be > 0")
        return StrictMath.exp(epsilon) / (1 + StrictMath.exp(epsilon))
    }

    /** epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y. */
    fun randomizedResponse(y: Long, epsilon: Double, rand: () -> Double = { cryptoRand() }): Long =
        if (rand() < rrKeepProbability(epsilon)) y else 1 - y

    /** Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1). */
    fun debiasRandomizedResponse(yesReports: Double, total: Double, epsilon: Double): Double {
        val ok = yesReports == Math.rint(yesReports) && total == Math.rint(total) && total > 0 && yesReports >= 0 && yesReports <= total && !total.isInfinite()
        if (!ok) throw IllegalArgumentException("debias: bad counts")
        val p = rrKeepProbability(epsilon)
        return (yesReports / total - (1 - p)) / (2 * p - 1)
    }

    // ---- the mixture prior ----

    /** The learner's prior mixture for a population release: a weight per hypothesis (a set of cells) mixed with weight beta. */
    class PriorMix internal constructor(private val release: Map<String, Any?>, @JvmField val beta: Double) {
        private val tables = IdentityHashMap<Map<String, Any?>, Array<DoubleArray>>()
        private val cellIds = IdentityHashMap<Map<String, Any?>, IntArray>()

        private fun tablesOf(vs: Map<String, Any?>) {
            if (tables.containsKey(vs)) return
            val cells = ArrayList<Int>()
            val lq = ArrayList<DoubleArray>()
            val n = WalletOmega.verbCellCount(vs)
            val rc = release["cells"] as Map<String, Any?>
            val schema = release["schema"] as String
            var c = 0
            while (c < n) {
                val r = rc[populationCellKey(schema, vs, WalletOmega.decodeCell(vs, c.toDouble()))]
                if (r != null) {
                    val q = Wallet.nv((r as Map<String, Any?>)["q"])
                    cells.add(c)
                    lq.add(doubleArrayOf(StrictMath.log(q), StrictMath.log(1 - q)))
                }
                c++
            }
            tables[vs] = lq.toTypedArray()
            cellIds[vs] = cells.toIntArray()
        }

        /** weight(theta) = product over the released cells of q^[c in theta] (1 - q)^[c not in theta]. */
        fun weight(vs: Map<String, Any?>, contains: (Int) -> Boolean): Double {
            tablesOf(vs)
            val t = tables[vs]!!
            val ids = cellIds[vs]!!
            var lw = 0.0
            for (i in ids.indices) lw += if (contains(ids[i])) t[i][0] else t[i][1]
            return StrictMath.exp(lw)
        }
    }

    /** The prior mixture for a release; throws unless beta is in [0, BETA_MAX] (full support needs beta below 1). */
    fun populationPrior(release: Map<String, Any?>, beta: Double): PriorMix {
        if (!(beta >= 0 && beta <= BETA_MAX)) throw IllegalArgumentException("populationPrior: beta must be in [0, $BETA_MAX] (full support needs beta < 1)")
        return PriorMix(release, beta)
    }
}
