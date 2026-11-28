package net.atlasauth.pca.intent

import java.math.BigDecimal
import java.math.RoundingMode
import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * Classifier error folded into the residual risk: a confusion matrix estimated on a labelled calibration set with per-entry Clopper-Pearson upper
 * bounds (union bound), the risk in true coordinates (exact decomposition), the label-sound bound, the classifier-aware residual risk of a learner
 * over the augmented space, and the cells a maximum-error gate sends to just-in-time consent. Calibrations and specs are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object IntentClassifierKit {
    private fun lm() = LinkedHashMap<String, Any?>()

    private fun m(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    private fun row(r: DoubleArray): List<Any?> = r.map { it }

    /** Calibrate a classifier on labelled examples ({truth, predicted}); labels outside the set are refused. `deltaGamma` defaults to 0.05. */
    @JvmStatic
    fun calibrateConfusion(samples: List<Any?>, labels: List<Any?>, deltaGamma: Double?): Map<String, Any?> {
        val delta = deltaGamma ?: 0.05
        val set = TreeSet<String>(Comparator { a, b -> Json.compareUtf8(a, b) })
        for (l in labels) set.add(l as String)
        val labs = ArrayList(set)
        if (labs.isEmpty()) throw IllegalArgumentException("calibrateConfusion: empty label set")
        if (!(delta > 0 && delta < 1)) throw IllegalArgumentException("calibrateConfusion: delta must be in (0, 1)")
        val n = labs.size
        val counts = Array(n) { DoubleArray(n) }
        for (so in samples) {
            val s = m(so)
            val t = (s["truth"] as? String)?.let { labs.indexOf(it) } ?: -1
            val p = (s["predicted"] as? String)?.let { labs.indexOf(it) } ?: -1
            if (t < 0 || p < 0) throw IllegalArgumentException("calibrateConfusion: label outside L (${s["truth"]} / ${s["predicted"]})")
            counts[t][p] = counts[t][p] + 1
        }
        val alpha = delta / (n.toDouble() * n)
        val cs = ArrayList<Any?>()
        val gs = ArrayList<Any?>()
        val bs = ArrayList<Any?>()
        for (r in counts) {
            var total = 0.0
            for (c in r) total += c
            val g = DoubleArray(n)
            val b = DoubleArray(n)
            for (i in 0 until n) {
                g[i] = if (total != 0.0) r[i] / total else 0.0
                b[i] = IntentStats.clopperPearsonUpper(r[i], total, alpha)
            }
            cs.add(row(r)); gs.add(row(g)); bs.add(row(b))
        }
        val out = lm()
        out["labels"] = ArrayList<Any?>(labs)
        out["counts"] = cs
        out["gamma"] = gs
        out["gammaBar"] = bs
        out["delta_ppm"] = IntentMapKit.jsRound(delta * 1_000_000)
        return out
    }

    /** The calibration's content address (labels, counts, delta). */
    @JvmStatic
    fun confusionDigest(c: Map<String, Any?>): String {
        val body = lm()
        body["d"] = "atlas-pca/intent-classifier-calibration/v1"
        body["labels"] = c["labels"]
        body["counts"] = c["counts"]
        body["delta_ppm"] = c["delta_ppm"]
        return Pca.hashCanonical(IntentJs.normalize(body))
    }

    /** The published error rate shown on cards: the maximum over true labels of the upper bound of any other label, capped at 1. */
    @JvmStatic
    fun publishedErrorRate(c: Map<String, Any?>): Double {
        var worst = 0.0
        val gb = IntentOmega.arr(c["gammaBar"])
        for (t in gb.indices) {
            var s = 0.0
            val r = IntentOmega.arr(gb[t])
            for (p in r.indices) if (p != t) s = s + IntentOmega.dbl(r[p])
            val e = Math.min(1.0, s)
            if (e > worst) worst = e
        }
        return worst
    }

    /** The fixed card note for a classifier dimension. */
    @JvmStatic
    fun classifierCardNote(id: String, c: Map<String, Any?>): String {
        val pct = BigDecimal(publishedErrorRate(c) * 100).setScale(1, RoundingMode.HALF_UP).toPlainString()
        return "\"$id\" is decided by an attested classifier, not by a person. Published error rate: up to $pct%."
    }

    // ---- risk on explicit arrays ----

    private fun mat(o: Any?): Array<DoubleArray> {
        val rows = IntentOmega.arr(o)
        return Array(rows.size) { i ->
            val r = IntentOmega.arr(rows[i])
            DoubleArray(r.size) { j -> IntentOmega.dbl(r[j]) }
        }
    }

    private fun bmat(o: Any?): Array<BooleanArray> {
        val rows = IntentOmega.arr(o)
        return Array(rows.size) { i ->
            val r = IntentOmega.arr(rows[i])
            BooleanArray(r.size) { j -> r[j] == true }
        }
    }

    private fun gammaOfSet(g: Array<DoubleArray>, a: List<Int>, t: Int): Double {
        var s = 0.0
        for (p in a) s = s + g[p][t]
        return Math.min(1.0, s)
    }

    private fun members(inG: BooleanArray): List<Int> = inG.indices.filter { inG[it] }

    /** R_kappa(G) over explicit arrays {mu, a, h, inG, g}: sum of mu (1 - a) h Gamma(A_G(x) | l), the set mass capped at 1. */
    @JvmStatic
    fun classifierRisk(arrays: Map<String, Any?>): Double {
        val mu = mat(arrays["mu"])
        val a = mat(arrays["a"])
        val h = mat(arrays["h"])
        val g = mat(arrays["g"])
        val inG = bmat(arrays["inG"])
        var r = 0.0
        for (x in mu.indices) {
            val set = members(inG[x])
            for (t in mu[x].indices) r += mu[x][t] * (1 - a[x][t]) * h[x][t] * gammaOfSet(g, set, t)
        }
        return r
    }

    /** True iff a(x, l) = 1 for every (x, l) in G. */
    @JvmStatic
    fun labelSound(arrays: Map<String, Any?>): Boolean {
        val a = mat(arrays["a"])
        val inG = bmat(arrays["inG"])
        for (x in inG.indices) for (p in inG[x].indices) if (inG[x][p] && a[x][p] != 1.0) return false
        return true
    }

    /** The bound for a label-sound grant: hMax times the mass of unacceptable cells weighted by the set error. */
    @JvmStatic
    fun labelSoundBound(arrays: Map<String, Any?>, hMax: Double): Double {
        val mu = mat(arrays["mu"])
        val a = mat(arrays["a"])
        val g = mat(arrays["g"])
        val inG = bmat(arrays["inG"])
        var s = 0.0
        for (x in mu.indices) {
            val set = members(inG[x])
            for (t in mu[x].indices) if (a[x][t] == 0.0) s += mu[x][t] * gammaOfSet(g, set, t)
        }
        return hMax * s
    }

    // ---- risk from a learner over the augmented space ----

    private class Member(val cell: IntArray, val p: Double, val mass: Double, val harm: Double, val inGrant: Boolean)

    private class Groups(val dim: CatDim, val groups: Map<String, Map<Int, Member>>)

    private fun verbOf(l: IntentLearner, verb: String): VerbSpace? = l.omega.verbs.firstOrNull { it.verb == verb }

    private fun groupsOf(l: IntentLearner, spec: Map<String, Any?>): Groups {
        val verb = spec["verb"] as String
        val path = spec["path"] as String
        val vs = verbOf(l, verb) ?: throw IllegalArgumentException("classifier: no verb $verb in Ω")
        var k = -1
        for (i in vs.dims.indices) if (vs.dims[i].path == path) { k = i; break }
        val dim = if (k >= 0) vs.dims[k] else null
        if (k < 0 || dim !is CatDim) throw IllegalArgumentException("classifier: $verb has no categorical dimension $path")
        val groups = LinkedHashMap<String, MutableMap<Int, Member>>()
        for (c in l.cells()) {
            if (c.verb != verb) continue
            val key = StringBuilder()
            for (i in c.cell.indices) if (i != k) key.append(c.cell[i]).append(',')
            groups.getOrPut(key.toString()) { LinkedHashMap() }[c.cell[k]] = Member(c.cell, c.p, c.mass, c.harm, c.inGrant)
        }
        return Groups(dim, groups)
    }

    private fun gbar(spec: Map<String, Any?>, dim: CatDim, pred: Int, truth: Int): Double {
        val pv = dim.values[pred]
        val tv = dim.values[truth]
        if (pv.kind != "exact") return 0.0
        val cal = m(spec["cal"])
        val labels = IntentOmega.arr(cal["labels"])
        val pi = labels.indexOf(pv.value)
        if (pi < 0) return 0.0
        val ti = if (tv.kind == "exact") labels.indexOf(tv.value) else -1
        if (ti < 0) return 1.0
        return IntentOmega.dbl(IntentOmega.arr(IntentOmega.arr(cal["gammaBar"])[ti])[pi])
    }

    private fun admitted(g: Map<Int, Member>): List<Int> = g.entries.filter { it.value.inGrant }.map { it.key }

    private fun setError(spec: Map<String, Any?>, dim: CatDim, a: List<Int>, t: Int): Double {
        var s = 0.0
        for (p in a) s = s + gbar(spec, dim, p, t)
        return Math.min(1.0, s)
    }

    /** R-hat of the learner's grant with classifier error folded in: {total, perVerb}. `specs`: [{verb, path, cal}]. */
    @JvmStatic
    fun classifierAwareResidualRisk(l: IntentLearner, specs: List<Any?>): Map<String, Any?> {
        val perVerb = LinkedHashMap<String, Double>()
        val specOf = LinkedHashMap<String, Any?>()
        for (s in specs) specOf[m(s)["verb"] as String] = s
        for (c in l.cells()) {
            if (specOf.containsKey(c.verb)) continue
            val prev = perVerb[c.verb] ?: 0.0
            perVerb[c.verb] = if (c.inGrant) prev + c.mass * (1 - c.p) * c.harm else prev
        }
        for (so in specs) {
            val spec = m(so)
            val gr = groupsOf(l, spec)
            var r = 0.0
            for (g in gr.groups.values) {
                val a = admitted(g)
                for ((key, mem) in g) r += mem.mass * (1 - mem.p) * mem.harm * setError(spec, gr.dim, a, key)
            }
            perVerb[spec["verb"] as String] = r
        }
        var total = 0.0
        val pv = lm()
        for ((k, v) in perVerb) { total += v; pv[k] = v }
        val out = lm()
        out["total"] = total
        out["perVerb"] = pv
        return out
    }

    /** The maximum-error gate: cells admitted on a classifier label that go to just-in-time consent, as [{verb, cell, flat}] sorted by flat index. */
    @JvmStatic
    fun classifierJitCells(l: IntentLearner, spec: Map<String, Any?>, gammaMax: Double): List<Map<String, Any?>> {
        val gr = groupsOf(l, spec)
        val vs = verbOf(l, spec["verb"] as String)!!
        val out = ArrayList<Map<String, Any?>>()
        for (g in gr.groups.values) {
            val a = admitted(g)
            if (a.isEmpty()) continue
            var worst = 0.0
            for ((key, mem) in g) {
                if (mem.inGrant || gr.dim.values[key].kind != "exact") continue
                worst = Math.max(worst, setError(spec, gr.dim, a, key))
            }
            if (worst > gammaMax) {
                for (p in a) {
                    val cell = g[p]!!.cell
                    val o = lm()
                    o["verb"] = spec["verb"]
                    o["cell"] = cell.map { it.toDouble() }
                    o["flat"] = IntentOmega.encodeCell(vs, cell)
                    out.add(o)
                }
            }
        }
        out.sortWith(Comparator { x, y -> (x["flat"] as Double).compareTo(y["flat"] as Double) })
        return out
    }
}
