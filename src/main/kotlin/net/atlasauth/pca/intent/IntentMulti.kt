package net.atlasauth.pca.intent

import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil

/**
 * The joint-grant rules of multi-principal intent (unanimity, quorum(k), weighted with a threshold, plus vetoers), the exact
 * joint acceptance probability, and the common refinement of several outcome spaces. A rule is a JSON tree
 * {kind, vetoers?, k?, weights?, threshold?}.
 */
object IntentMulti {
    /** A rule in normal form: integer weights, an integer threshold, per-principal veto flags. */
    class NormalRule(val weights: DoubleArray, val threshold: Double, val veto: BooleanArray) {
        fun toJson(): MutableMap<String, Any?> = linkedMapOf("weights" to weights.toMutableList(), "threshold" to threshold, "veto" to veto.toMutableList())

        companion object {
            @JvmStatic
            fun fromJson(o: Any?): NormalRule {
                val m = IntentOmega.obj(o)
                val w = IntentOmega.arr(m["weights"])
                val v = IntentOmega.arr(m["veto"])
                return NormalRule(DoubleArray(w.size) { IntentOmega.dbl(w[it]) }, IntentOmega.dbl(m["threshold"]), BooleanArray(v.size) { v[it] as Boolean })
            }
        }
    }

    private fun isInteger(o: Any?): Boolean {
        if (!IntentOmega.isNumber(o)) return false
        val d = IntentOmega.dbl(o)
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d)
    }

    fun normalizeRule(rule: Map<String, Any?>, refs: List<String>): NormalRule {
        val vetoers = LinkedHashSet<String>()
        val vr = rule["vetoers"]
        if (vr is List<*>) for (v in vr) vetoers.add(v.toString())
        for (v in vetoers) require(refs.contains(v)) { "aggregateIntentMaps: vetoer $v is not one of the maps" }
        val veto = BooleanArray(refs.size) { vetoers.contains(refs[it]) }
        val ones = DoubleArray(refs.size) { 1.0 }
        val kind = rule["kind"]
        if ("unanimity" == kind) return NormalRule(ones, refs.size.toDouble(), veto)
        if ("quorum" == kind) {
            val k = rule["k"]
            require(isInteger(k) && IntentOmega.dbl(k) >= 1 && IntentOmega.dbl(k) <= refs.size) { "aggregateIntentMaps: quorum k must be an integer in [1, " + refs.size + "]" }
            return NormalRule(ones, IntentOmega.dbl(k), veto)
        }
        val wr = rule["weights"]
        if (wr == null && refs.isNotEmpty()) throw IllegalArgumentException("Cannot read properties of " + (if (rule.containsKey("weights")) "null" else "undefined") + " (reading '" + refs[0] + "')")
        val wm: Map<*, *> = wr as? Map<*, *> ?: emptyMap<Any?, Any?>() // another primitive has no members: each weight reads undefined
        val weights = DoubleArray(refs.size)
        for (i in weights.indices) {
            val w = wm[refs[i]]
            require(isInteger(w) && IntentOmega.dbl(w) >= 0) { "aggregateIntentMaps: every principal needs a non-negative integer weight" }
            weights[i] = IntentOmega.dbl(w)
        }
        var total = 0.0
        for (w in weights) total += w
        val t = rule["threshold"]
        require(isInteger(t) && IntentOmega.dbl(t) >= 1 && IntentOmega.dbl(t) <= total) { "aggregateIntentMaps: threshold must be an integer in [1, " + AttestUtil.jsNumString(total) + "]" }
        return NormalRule(weights, IntentOmega.dbl(t), veto)
    }

    /** Principals that bound the joint grant: explicit vetoers plus implicit ones (threshold > W - w_i). */
    fun effectiveVetoers(rule: Map<String, Any?>, refs: List<String>): List<String> {
        val n = normalizeRule(rule, refs)
        var total = 0.0
        for (w in n.weights) total += w
        return refs.indices.filter { n.veto[it] || n.threshold > total - n.weights[it] }.map { refs[it] }
    }

    /** Does the rule admit, given which principals admit (vetoers must; the admitting weight must reach the threshold)? */
    fun ruleAdmits(n: NormalRule, ins: BooleanArray): Boolean {
        var s = 0.0
        for (i in ins.indices) {
            if (n.veto[i] && !ins[i]) return false
            if (ins[i]) s += n.weights[i]
        }
        return s >= n.threshold
    }

    /** P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the capped admitting weight. */
    fun jointAcceptance(n: NormalRule, ps: DoubleArray): Double {
        val t = n.threshold.toInt()
        var dist = DoubleArray(t + 1)
        dist[0] = 1.0
        for (i in ps.indices) {
            val next = DoubleArray(t + 1)
            val w = n.weights[i]
            val p = ps[i]
            for (s in 0..t) {
                val m = dist[s]
                if (m == 0.0) continue
                val to = Math.min(t.toDouble(), s + w).toInt()
                next[to] = next[to] + m * p
                if (!n.veto[i]) next[s] = next[s] + m * (1 - p)
            }
            dist = next
        }
        return dist[t]
    }

    // ---- common refinement ----

    private val SEV = listOf("reversible", "rate_limited", "irreversible")

    private fun js(d: Double) = AttestUtil.jsNumString(d)

    private fun mergeDim(a: Dim, b: Dim): Dim {
        require(a.kind == b.kind) { "commonRefinement: " + a.path + " is numeric in one Omega and categorical in another" }
        if (a is NumDim && b is NumDim) {
            require(a.lo == b.lo && a.hi == b.hi) { "commonRefinement: " + a.path + " has different domains ([" + js(a.lo) + ", " + js(a.hi) + "] vs [" + js(b.lo) + ", " + js(b.hi) + "])" }
            val cuts = LinkedHashSet<Double>()
            for (c in a.cuts) cuts.add(c + 0.0)
            for (c in b.cuts) cuts.add(c + 0.0)
            return NumDim(a.path, a.lo, a.hi, IntentOmega.toArray(IntentOmega.sortedNums(cuts)), a.dist)
        }
        val ex = TreeSet<String>()
        val pre = TreeSet<String>()
        for (v in (a as CatDim).values + (b as CatDim).values) {
            if (v.kind == "exact") ex.add(v.value) else if (v.kind == "prefix") pre.add(v.value)
        }
        val values = ArrayList<CatValue>()
        for (v in ex) values.add(CatValue("exact", v))
        for (v in pre) values.add(CatValue("prefix", v))
        values.add(CatValue("other", IntentOmega.OTHER))
        return CatDim(a.path, values)
    }

    /** The union of the spaces' verbs, dimensions, cuts and named values (every input cell is a union of result cells). */
    fun commonRefinement(omegas: List<Omega>): Omega {
        val revs = LinkedHashMap<String, String>()
        val dimsByVerb = LinkedHashMap<String, MutableList<Dim>>()
        val approx = TreeSet<String>()
        for (o in omegas) {
            approx.addAll(o.approximate)
            for (vs in o.verbs) {
                val cur = dimsByVerb[vs.verb]
                if (cur == null) {
                    revs[vs.verb] = vs.reversibility
                    dimsByVerb[vs.verb] = vs.dims.map { IntentOmega.dimFromJson(IntentOmega.dimToJson(it)) }.toMutableList()
                    continue
                }
                if (SEV.indexOf(vs.reversibility) > SEV.indexOf(revs[vs.verb])) revs[vs.verb] = vs.reversibility
                for (d in vs.dims) {
                    val i = cur.indexOfFirst { it.path == d.path }
                    if (i < 0) cur.add(IntentOmega.dimFromJson(IntentOmega.dimToJson(d))) else cur[i] = mergeDim(cur[i], d)
                }
            }
        }
        val names = TreeSet(dimsByVerb.keys).toList()
        val verbs = names.map { v ->
            val dims = dimsByVerb[v]!!
            dims.sortWith { x, y -> x.path.compareTo(y.path) }
            VerbSpace(v, revs[v]!!, 1.0 / names.size, dims)
        }
        return Omega(verbs, ArrayList(approx))
    }
}
