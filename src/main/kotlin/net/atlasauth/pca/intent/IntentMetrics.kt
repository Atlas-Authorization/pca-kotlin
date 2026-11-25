package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.HarmModel
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace

/**
 * Measuring a grant against an intent over the outcome space: risk R(G) = E[1_G (1 - a) h], burden B(G) = E[1_notG a],
 * R_max = E[(1 - a) h], fidelity F = 1 - R / R_max, by Monte Carlo with the real evaluator on both sides or exactly by summing
 * over cells.
 */
object IntentMetrics {
    /** The acceptability of an outcome in [0, 1]. */
    fun interface Acceptability {
        fun of(vs: VerbSpace, o: Outcome): Double
    }

    fun acceptabilityOf(policy: Any?): Acceptability {
        val a = IntentPolicy.admitter(policy)
        return Acceptability { vs, o -> if (a.admits(vs, o)) 1.0 else 0.0 }
    }

    data class GrantMetrics(val risk: Double, val burden: Double, val riskMax: Double, val fidelity: Double, val samples: Double, val riskHalfWidth: Double, val meanHarm: Double?) {
        fun toJson(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["risk"] = risk
            m["burden"] = burden
            m["riskMax"] = riskMax
            m["fidelity"] = fidelity
            if (meanHarm == null) {
                m["samples"] = samples
                m["riskHalfWidth"] = riskHalfWidth
            } else m["meanHarm"] = meanHarm
            return m
        }
    }

    /** Monte Carlo over the workload; [hMax] null = the largest harm drawn. */
    @JvmOverloads
    fun measureGrant(omega: Omega, grant: Any?, acceptability: Acceptability, samples: Double = 20000.0, seed: Double = 1.0, harm: HarmModel = IntentOmega.DEFAULT_HARM, hMax: Double? = null): GrantMetrics {
        val m = samples
        val rand = IntentOmega.rng(seed)
        val g = IntentPolicy.admitter(grant)
        var r = 0.0
        var b = 0.0
        var rm = 0.0
        var hm = 0.0
        var i = 0.0
        while (i < m) {
            val s = IntentOmega.sampleOutcome(omega, rand)
            val a = acceptability.of(s.vs, s.o)
            val h = IntentOmega.harmOf(s.vs, s.o, harm)
            hm = Math.max(hm, h)
            if (g.admits(s.vs, s.o)) r += (1 - a) * h else b += a
            rm += (1 - a) * h
            i++
        }
        r /= m
        b /= m
        rm /= m
        return GrantMetrics(r, b, rm, if (rm > 0) 1 - r / rm else 1.0, m, IntentStats.hoeffdingHalfWidth(hMax ?: hm, m), null)
    }

    /** Exact R, B, R_max, F by summing over the cells; valid when grant and acceptability are constant on each cell. */
    @JvmOverloads
    fun measureGrantExact(omega: Omega, grant: Any?, acceptability: Acceptability, harm: HarmModel = IntentOmega.DEFAULT_HARM): GrantMetrics {
        val g = IntentPolicy.admitter(grant)
        var r = 0.0
        var b = 0.0
        var rm = 0.0
        var eh = 0.0
        for (vs in omega.verbs) {
            val n = IntentOmega.verbCellCount(vs)
            var c = 0.0
            while (c < n) {
                val idx = IntentOmega.decodeCell(vs, c)
                val o = IntentOmega.cellRep(vs, idx)
                val st = IntentOmega.cellStats(vs, idx, harm)
                val a = acceptability.of(vs, o)
                eh += st.mass * st.harm
                rm += st.mass * (1 - a) * st.harm
                if (g.admits(vs, o)) r += st.mass * (1 - a) * st.harm else b += st.mass * a
                c++
            }
        }
        return GrantMetrics(r, b, rm, if (rm > 0) 1 - r / rm else 1.0, 0.0, 0.0, eh)
    }
}
