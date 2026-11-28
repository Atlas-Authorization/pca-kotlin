package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.Catalog

/**
 * Specification by example for a fixed grant: boundary facets (admission changes when exactly one dimension moves to an
 * adjacent cell), one verb witness per verb, and one unconstrained witness per dimension the grant ignores. The question count
 * is linear in the number of facets, not in the size of the space.
 */
object IntentWitnesses {
    /** One question: an action inside or outside the grant, isolating one literal. */
    class Witness(val kind: String, val side: String, val verb: String, val cell: IntArray, val outcome: Outcome, val grantAllows: Boolean, val facet: String, val question: String) {
        fun toJson(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["kind"] = kind
            m["side"] = side
            m["verb"] = verb
            m["cell"] = cell.toMutableList()
            m["outcome"] = IntentOmega.outcomeToJson(outcome)
            m["grantAllows"] = grantAllows
            m["facet"] = facet
            m["question"] = question
            return m
        }
    }

    private class Best(val ins: IntArray, val outs: IntArray, val score: Double)

    @JvmOverloads
    fun boundaryWitnesses(grant: Any?, omega: Omega, catalog: Catalog = Catalog.DEFAULT): List<Witness> {
        val g = IntentPolicy.admitter(grant)
        val out = ArrayList<Witness>()
        val seen = HashSet<String>()
        for (vs in omega.verbs) {
            val n = IntentOmega.verbCellCount(vs).toInt()
            val acc = BooleanArray(n)
            val mass = DoubleArray(n)
            var typical = -1
            var typicalOut = -1
            for (c in 0 until n) {
                val idx = IntentOmega.decodeCell(vs, c.toDouble())
                acc[c] = g.admits(vs, IntentOmega.cellRep(vs, idx))
                mass[c] = IntentOmega.cellStats(vs, idx).mass
                if (acc[c] && (typical < 0 || mass[c] > mass[typical])) typical = c
                if (typicalOut < 0 || mass[c] > mass[typicalOut]) typicalOut = c
            }
            if (typical < 0) {
                push(out, seen, vs, "verb", IntentOmega.decodeCell(vs, typicalOut.toDouble()), false, vs.verb + "|verb", catalog)
                continue
            }
            val base = IntentOmega.decodeCell(vs, typical.toDouble())
            push(out, seen, vs, "verb", base, true, vs.verb + "|verb", catalog)
            val best = HashMap<String, Best>()
            for (c in 0 until n) {
                if (!acc[c]) continue
                val idx = IntentOmega.decodeCell(vs, c.toDouble())
                for (k in vs.dims.indices) {
                    val d = vs.dims[k]
                    val nk = IntentOmega.cellCount(d)
                    val neigh = ArrayList<Int>()
                    if (d is NumDim) {
                        for (x in intArrayOf(idx[k] - 1, idx[k] + 1)) if (x >= 0 && x < nk) neigh.add(x)
                    } else for (x in 0 until nk) if (x != idx[k]) neigh.add(x)
                    for (x in neigh) {
                        val j = idx.clone()
                        j[k] = x
                        val cj = IntentOmega.encodeCell(vs, j).toInt()
                        if (acc[cj]) continue
                        val facet = if (d is NumDim) vs.verb + "|" + d.path + "|" + Math.min(x, idx[k]) + "~" + Math.max(x, idx[k]) else vs.verb + "|" + d.path + "|" + x
                        var shared = 0
                        for (t in idx.indices) if (t != k && idx[t] == base[t]) shared++
                        val score = shared * 10 + mass[c]
                        val prev = best[facet]
                        if (prev == null || score > prev.score) best[facet] = Best(idx, j, score)
                    }
                }
            }
            val facets = best.keys.sorted()
            for (facet in facets) {
                push(out, seen, vs, "boundary", best[facet]!!.ins, true, facet, catalog)
                push(out, seen, vs, "boundary", best[facet]!!.outs, false, facet, catalog)
            }
            for (k in vs.dims.indices) {
                val d = vs.dims[k]
                val nk = IntentOmega.cellCount(d)
                if (nk < 2) continue
                var depends = false
                var c = 0
                while (c < n && !depends) {
                    val idx = IntentOmega.decodeCell(vs, c.toDouble())
                    var x = 0
                    while (x < nk && !depends) {
                        val j = idx.clone()
                        j[k] = x
                        if (acc[IntentOmega.encodeCell(vs, j).toInt()] != acc[c]) depends = true
                        x++
                    }
                    c++
                }
                if (depends) continue
                val j = base.clone()
                if (d is NumDim) j[k] = nk - 1
                else j[k] = (d as CatDim).values.indexOfFirst { it.kind == "other" }
                push(out, seen, vs, "unconstrained", j, true, vs.verb + "|" + d.path + "|unconstrained", catalog)
            }
        }
        return out
    }

    private fun push(out: MutableList<Witness>, seen: MutableSet<String>, vs: VerbSpace, kind: String, idx: IntArray, allows: Boolean, facet: String, catalog: Catalog) {
        val key = vs.verb + "|" + idx.joinToString(",")
        if (!seen.add(key)) return
        out.add(Witness(kind, if (allows) "inside" else "outside", vs.verb, idx.clone(), IntentOmega.cellRep(vs, idx), allows, facet, IntentRender.renderQuestion(vs, idx, catalog)))
    }

    /** The oracle's disagreements with the grant, with the number of questions asked. */
    data class WitnessCheck(val questions: Int, val mismatches: List<Witness>)

    /** Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree. */
    fun checkWitnesses(witnesses: List<Witness>, oracle: (Witness) -> Boolean): WitnessCheck =
        WitnessCheck(witnesses.size, witnesses.filter { oracle(it) != it.grantAllows })
}
