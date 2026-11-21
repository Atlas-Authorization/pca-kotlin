package net.atlasauth.pca.intent

import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/**
 * Dimensions beyond the action's own parameters: world state (an observed quantity such as slack against an optimum),
 * argument provenance, and classifier labels. Each lives under its own path prefix; an outcome is lifted onto them from an
 * environment of observed values.
 */
object IntentWorld {
    const val WORLD_PREFIX = "env.world."
    const val PROV_PREFIX = "env.prov."
    const val CLASS_PREFIX = "env.class."

    /** A numeric world dimension; [cuts] may be null, [dist] null = uniform. */
    fun worldDim(name: String, lo: Double, hi: Double, cuts: Collection<Double>?, dist: String?): NumDim {
        val uniq = LinkedHashSet<Double>()
        if (cuts != null) for (c in cuts) uniq.add(c + 0.0)
        val kept = uniq.filter { it >= lo && it <= hi }
        return NumDim(WORLD_PREFIX + name, lo, hi, IntentOmega.toArray(IntentOmega.sortedNums(kept)), dist ?: "uniform")
    }

    /** Excess over an optimum: cut at 0 and at each slack, log-uniform. */
    fun excessDim(name: String, hi: Double, slacks: List<Double>?): NumDim {
        val cuts = arrayListOf(0.0)
        if (slacks != null) cuts.addAll(slacks)
        return worldDim(name, 0.0, hi, cuts, "loguniform")
    }

    /** The condition "the observed quantity is at most the slack". */
    fun optimalityCondition(name: String, slack: Double): MutableMap<String, Any?> =
        linkedMapOf("field" to WORLD_PREFIX + name, "op" to "lte", "value" to Json.Num(AttestUtil.jsNumString(slack)))

    fun provenanceDim(paramPath: String): CatDim =
        CatDim(PROV_PREFIX + paramPath, listOf(CatValue("exact", "first_party"), CatValue("exact", "trusted"), CatValue("other", IntentOmega.OTHER)))

    fun classifierDim(id: String, labels: List<String>): CatDim {
        val sorted = TreeSet<String>(Comparator { a, b -> Json.compareUtf8(a, b) })
        sorted.addAll(labels)
        val v = sorted.mapTo(ArrayList()) { CatValue("exact", it) }
        v.add(CatValue("other", IntentOmega.OTHER))
        return CatDim(CLASS_PREFIX + id, v)
    }

    /** The space with [dims] added to one verb (a duplicate path throws), dimensions re-sorted by path. */
    fun withDims(omega: Omega, verb: String, dims: List<Dim>): Omega {
        val verbs = ArrayList<VerbSpace>()
        var found = false
        for (vs in omega.verbs) {
            if (vs.verb != verb) {
                verbs.add(VerbSpace(vs.verb, vs.reversibility, vs.weight, ArrayList(vs.dims)))
                continue
            }
            found = true
            val have = vs.dims.mapTo(LinkedHashSet()) { it.path }
            for (d in dims) require(!have.contains(d.path)) { "withDims: $verb already has a dimension " + d.path }
            val all = ArrayList(vs.dims)
            all.addAll(dims)
            all.sortWith { a, b -> a.path.compareTo(b.path) }
            verbs.add(VerbSpace(vs.verb, vs.reversibility, vs.weight, all))
        }
        require(found) { "withDims: no verb $verb in the space" }
        return Omega(verbs, omega.approximate)
    }

    private fun get(root: Any?, vararg segs: String): Any? {
        var cur = root
        for (s in segs) {
            if (cur !is Map<*, *> || !cur.containsKey(s)) return null
            cur = cur[s]
        }
        return cur
    }

    /** Lift an outcome onto the world / provenance / classifier dimensions from the environment {world?, prov?, class?}. */
    fun liftOutcome(o: Outcome, env: Map<String, Any?>, dimPaths: List<String>): Outcome {
        val values = LinkedHashMap(o.values)
        for (p in dimPaths) {
            if (p.startsWith(WORLD_PREFIX)) {
                val v = get(env["world"], p.substring(WORLD_PREFIX.length))
                if (IntentOmega.isNumber(v)) values[p] = IntentOmega.dbl(v) else if (v is String) values[p] = v
            } else if (p.startsWith(PROV_PREFIX)) {
                val v = get(env["prov"], *p.substring(PROV_PREFIX.length).split(".").toTypedArray())
                values[p] = if (v is String) v else "agent"
            } else if (p.startsWith(CLASS_PREFIX)) {
                val v = get(env["class"], p.substring(CLASS_PREFIX.length))
                if (v is String) values[p] = v
            }
        }
        return Outcome(o.verb, values)
    }
}
