package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentLearner.ElicitOptions
import net.atlasauth.pca.intent.IntentLearner.Observation
import net.atlasauth.pca.intent.IntentLearner.Question
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.intent.IntentRegion.Region
import java.util.TreeSet

/**
 * Cut refinement and partial answers: a "partly" answer refines the outcome space (inserts cuts, names values or adds a
 * dimension), replays every earlier observation as a value-space region over the refined space, and records one observation
 * per new sub-cell of the questioned cell.
 */
object IntentRefine {
    /** One refinement of a verb's space: numeric cuts, categorical values / prefixes, or a whole new dimension. */
    class Refinement(@JvmField var verb: String, @JvmField var path: String) {
        @JvmField var cuts: DoubleArray? = null
        @JvmField var values: List<String>? = null
        @JvmField var prefixes: List<String>? = null
        @JvmField var newDim: Dim? = null

        companion object {
            @JvmStatic
            fun fromJson(o: Any?): Refinement {
                val m = IntentOmega.obj(o)
                val r = Refinement(m["verb"] as String, m["path"] as String)
                if (m["cuts"] != null) r.cuts = doubles(m["cuts"])
                if (m["values"] != null) r.values = strings(m["values"])
                if (m["prefixes"] != null) r.prefixes = strings(m["prefixes"])
                if (m["newDim"] != null) r.newDim = IntentOmega.dimFromJson(m["newDim"])
                return r
            }
        }
    }

    internal fun doubles(o: Any?): DoubleArray = IntentOmega.arr(o).let { l -> DoubleArray(l.size) { IntentOmega.dbl(l[it]) } }

    internal fun strings(o: Any?): List<String> = IntentOmega.arr(o).map { it as String }

    private fun sortedCat(values: List<CatValue>): List<CatValue> {
        val ex = TreeSet<String>()
        val pre = TreeSet<String>()
        for (v in values) {
            if (v.kind == "exact") ex.add(v.value)
            if (v.kind == "prefix") pre.add(v.value)
        }
        val out = ArrayList<CatValue>()
        for (s in ex) out.add(CatValue("exact", s))
        for (s in pre) out.add(CatValue("prefix", s))
        out.add(CatValue("other", IntentOmega.OTHER))
        return out
    }

    private fun cutsOf(xs: Iterable<Double>, lo: Double, hi: Double): DoubleArray {
        val set = TreeSet<Double>()
        for (c in xs) if (c >= lo && c <= hi) set.add(if (c == 0.0) 0.0 else c)
        val out = DoubleArray(set.size)
        var i = 0
        for (c in set) out[i++] = c
        return out
    }

    private fun copyDim(d: Dim): Dim =
        if (d is NumDim) NumDim(d.path, d.lo, d.hi, d.cuts.clone(), d.dist) else CatDim(d.path, ArrayList((d as CatDim).values))

    /** The outcome space with one verb's dimension refined (the input is untouched). */
    @JvmStatic
    fun refineOmega(omega: Omega, r: Refinement): Omega {
        val src = omega.verbs.firstOrNull { it.verb == r.verb } ?: throw IllegalArgumentException("refineOmega: no verb ${r.verb} in Omega")
        val dims = ArrayList<Dim>()
        var i = -1
        for (k in src.dims.indices) {
            dims.add(copyDim(src.dims[k]))
            if (i < 0 && src.dims[k].path == r.path) i = k
        }
        val nd0 = r.newDim
        if (nd0 != null) {
            require(i < 0) { "refineOmega: ${r.path} is already a dimension of ${r.verb}" }
            require(nd0.path == r.path) { "refineOmega: newDim.path must equal path" }
            val cd = copyDim(nd0)
            val d: Dim = if (cd is CatDim) CatDim(cd.path, sortedCat(cd.values))
            else {
                val n = cd as NumDim
                NumDim(n.path, n.lo, n.hi, cutsOf(n.cuts.asIterable(), n.lo, n.hi), n.dist)
            }
            dims.add(d)
            dims.sortWith { a, b -> a.path.compareTo(b.path) }
        } else {
            require(i >= 0) { "refineOmega: ${r.verb} has no dimension ${r.path} (pass newDim to add it)" }
            val d = dims[i]
            if (d is NumDim) {
                require(!((r.values != null && r.values!!.isNotEmpty()) || (r.prefixes != null && r.prefixes!!.isNotEmpty()))) { "refineOmega: ${r.path} is numeric" }
                val all = ArrayList<Double>()
                for (c in d.cuts) all.add(c)
                r.cuts?.let { cs -> for (c in cs) if (c == Math.floor(c) && !c.isInfinite()) all.add(c) }
                dims[i] = NumDim(d.path, d.lo, d.hi, cutsOf(all, d.lo, d.hi), d.dist)
            } else {
                val c = d as CatDim
                require(!(r.cuts != null && r.cuts!!.isNotEmpty())) { "refineOmega: ${r.path} is categorical" }
                val all = ArrayList(c.values)
                r.values?.let { vs -> for (s in vs) all.add(CatValue("exact", s)) }
                r.prefixes?.let { ps -> for (s in ps) all.add(CatValue("prefix", s)) }
                val sorted = sortedCat(all)
                require(sorted.size <= 20) { "refineOmega: ${r.path} would have more than 20 values" }
                dims[i] = CatDim(c.path, sorted)
            }
        }
        val verbs = ArrayList<VerbSpace>()
        for (v in omega.verbs) {
            if (v === src) verbs.add(VerbSpace(v.verb, v.reversibility, v.weight, dims))
            else verbs.add(VerbSpace(v.verb, v.reversibility, v.weight, ArrayList(v.dims)))
        }
        return Omega(verbs, ArrayList(omega.approximate))
    }

    /** The value-space region an observation was about, in the space it was recorded in. */
    @JvmStatic
    fun regionOfObservation(omega: Omega, o: Observation): Region {
        o.region?.let { return it }
        for (v in omega.verbs) if (v.verb == o.verb) return IntentRegion.regionOfCell(v, o.cell)
        throw IllegalArgumentException("regionOfObservation: no verb ${o.verb}")
    }

    /** May rewrite the region of an earlier observation (used when a dimension is added). */
    fun interface Rescope { fun apply(o: Observation, region: Region): Region }

    @JvmStatic
    fun refineLearner(l: IntentLearner, r: Refinement, rescope: Rescope?): IntentLearner {
        val omega = refineOmega(l.omega, r)
        val next = IntentMapKit.createLearner(omega, IntentMapKit.learnerOptionsOf(l))
        for (o in l.observations) {
            var region = regionOfObservation(l.omega, o)
            if (rescope != null) region = rescope.apply(o, region)
            val vs = omega.verbs.first { it.verb == o.verb }
            val values = LinkedHashMap(o.values)
            for (d in vs.dims) if (!values.containsKey(d.path)) values[d.path] = IntentOmega.repValue(d, 0)
            next.observe(Outcome(o.verb, values), o.y, o.source, region)
        }
        return next
    }

    /** One labelled part of a partial answer: a numeric range, a set of exact values, or "every other value". */
    class PartialPart(@JvmField val lo: Double?, @JvmField val hi: Double?, @JvmField val values: List<String>?, @JvmField val isRange: Boolean, @JvmField val isValues: Boolean, @JvmField val y: Int) {
        companion object {
            @JvmStatic
            fun fromJson(o: Any?): PartialPart {
                val m = IntentOmega.obj(o)
                val y = IntentOmega.dbl(m["y"]).toInt()
                if (m.containsKey("lo")) return PartialPart(IntentLearner.numOrNull(m["lo"]), IntentLearner.numOrNull(m["hi"]), null, true, false, y)
                if (m.containsKey("values")) return PartialPart(null, null, strings(m["values"]), false, true, y)
                return PartialPart(null, null, null, false, false, y)
            }
        }
    }

    /** "Partly": the refinement the answer implies and the label of every part. */
    class PartialAnswer {
        @JvmField var path: String? = null
        @JvmField var cuts: DoubleArray? = null
        @JvmField var values: List<String>? = null
        @JvmField var newDim: Dim? = null
        @JvmField val parts = ArrayList<PartialPart>()

        companion object {
            @JvmStatic
            fun fromJson(o: Any?): PartialAnswer {
                val m = IntentOmega.obj(o)
                val a = PartialAnswer()
                a.path = m["path"] as String?
                if (m["cuts"] != null) a.cuts = doubles(m["cuts"])
                if (m["values"] != null) a.values = strings(m["values"])
                if (m["newDim"] != null) a.newDim = IntentOmega.dimFromJson(m["newDim"])
                for (p in IntentOmega.arr(m["parts"])) a.parts.add(PartialPart.fromJson(p))
                return a
            }
        }
    }

    private fun partLabel(d: Dim, j: Int, parts: List<PartialPart>): Int? {
        val x = IntentOmega.repValue(d, j)
        for (p in parts) {
            if (p.isRange) {
                if (d !is NumDim) continue
                val c = IntentOmega.numCells(d)[j]
                if (p.lo != null && p.hi != null && c.lo >= p.lo && c.hi <= p.hi) return p.y
            } else if (p.isValues) {
                if (d is CatDim && d.values[j].kind == "exact" && p.values!!.contains(x.toString())) return p.y
            } else if (d is CatDim && d.values[j].kind != "exact") return p.y
        }
        return null
    }

    private fun subCells(d: Dim, region: Region): List<Int> {
        val n = IntentOmega.cellCount(d)
        val rd = region.dims[d.path]
        val out = ArrayList<Int>()
        for (j in 0 until n) {
            if (rd == null) out.add(j)
            else if (d is NumDim && rd.kind == "num") {
                val c = IntentOmega.numCells(d)[j]
                if (c.lo >= rd.lo && c.hi <= rd.hi) out.add(j)
            } else if (d is CatDim && rd.kind == "cat") {
                val cell = IntentOmega.catCellOf(CatDim(d.path, rd.values!!), IntentOmega.repValue(d, j) as String)
                if (rd.cells!!.contains(cell)) out.add(j)
            }
        }
        return out
    }

    private fun rangePart(lo: Double, hi: Double): Map<String, Any?> = linkedMapOf("lo" to lo, "hi" to hi)

    private fun cellsPart(cells: List<Int>): Map<String, Any?> = linkedMapOf("cells" to ArrayList<Any?>(cells))

    private fun verbOf(o: Omega, verb: String): VerbSpace? = o.verbs.firstOrNull { it.verb == verb }

    class PartialResult internal constructor(@JvmField val learner: IntentLearner, @JvmField val added: List<Observation>)

    /** Apply a partial answer to question q: a NEW learner over the refined space and the observations the answer added. */
    @JvmStatic
    fun answerPartial(l: IntentLearner, q: Question, a: PartialAnswer): PartialResult {
        val oldVs = verbOf(l.omega, q.verb) ?: throw IllegalArgumentException("answerPartial: no verb ${q.verb}")
        val qRegion = IntentRegion.regionOfCell(oldVs, q.cell)
        val r = Refinement(q.verb, a.path!!)
        r.cuts = a.cuts; r.values = a.values; r.newDim = a.newDim
        val refined = refineOmega(l.omega, r)
        val nvs = verbOf(refined, q.verb)!!
        val dd: Dim = nvs.dims.first { it.path == a.path }
        var rescope: Rescope? = null
        if (a.newDim != null) {
            val yes = ArrayList<Int>()
            for (j in 0 until IntentOmega.cellCount(dd)) if (1 == partLabel(dd, j, a.parts)) yes.add(j)
            rescope = Rescope { o, region ->
                if (o.verb != q.verb || o.y != 1) region
                else if (dd is CatDim) IntentRegion.restrictRegion(region, dd, cellsPart(yes))
                else {
                    val nd = dd as NumDim
                    if (yes.isEmpty()) IntentRegion.restrictRegion(region, dd, rangePart(nd.hi + 1, nd.hi + 1))
                    else {
                        val cells = IntentOmega.numCells(nd)
                        IntentRegion.restrictRegion(region, dd, rangePart(cells[yes[0]].lo, cells[yes[yes.size - 1]].hi))
                    }
                }
            }
        }
        val next = refineLearner(l, r, rescope)
        val added = ArrayList<Observation>()
        for (j in subCells(dd, qRegion)) {
            val y = partLabel(dd, j, a.parts) ?: continue
            val region: Region = if (dd is NumDim) {
                val c = IntentOmega.numCells(dd)[j]
                IntentRegion.restrictRegion(qRegion, dd, rangePart(c.lo, c.hi))
            } else IntentRegion.restrictRegion(qRegion, dd, cellsPart(listOf(j)))
            val values = LinkedHashMap(q.outcome.values)
            values[dd.path] = IntentOmega.repValue(dd, j)
            for (x in nvs.dims) if (!values.containsKey(x.path)) values[x.path] = IntentOmega.repValue(x, 0)
            val ob = next.observe(Outcome(q.verb, values), y, "elicitation", region)
            if (ob != null) added.add(ob)
        }
        return PartialResult(next, added)
    }

    /** An adaptive answer is 0, 1 (a number) or a [PartialAnswer]. */
    fun interface AdaptiveAnswer { fun answer(q: Question, l: IntentLearner): Any? }

    class AdaptiveElicitResult internal constructor(
        @JvmField val stop: String, @JvmField val questions: Int, @JvmField val auditQuestions: Int, @JvmField val seedQuestions: Int,
        @JvmField val asked: List<Question>, @JvmField val learner: IntentLearner, @JvmField val refinements: Int,
    )

    /** Elicitation that accepts yes, no and partly; after maxRefinements (default 8) partial answers further ones count as "no". */
    @JvmStatic
    fun elicitAdaptive(learner: IntentLearner, answer: AdaptiveAnswer, o: ElicitOptions, maxRefinements: Int?): AdaptiveElicitResult {
        var cur = learner
        val asked = ArrayList<Question>()
        var refinements = 0
        val maxRef = maxRefinements ?: 8
        fun ask(q: Question) {
            val a = answer.answer(q, cur)
            asked.add(q)
            if (a is PartialAnswer) {
                if (refinements < maxRef) {
                    cur = answerPartial(cur, q, a).learner
                    refinements++
                } else cur.observe(q.outcome, 0, "elicitation", null)
            } else cur.observe(q.outcome, (a as Number).toInt(), "elicitation", null)
        }
        var seedQuestions = 0
        for (s in o.seed) {
            if (asked.size >= o.maxQuestions) break
            val vs = verbOf(cur.omega, s.first)
            val cell = s.second
            if (vs == null || cell.size != vs.dims.size) continue
            val values = LinkedHashMap<String, Any?>()
            for (k in vs.dims.indices) values[vs.dims[k].path] = IntentOmega.repValue(vs.dims[k], cell[k])
            val outcome = Outcome(s.first, values)
            val p = cur.acceptance(outcome)
            if (p <= 1e-9 || p >= 1 - 1e-9 || cur.isVetoed(outcome)) continue
            ask(Question(s.first, cell.clone(), outcome, p, 0.0))
            seedQuestions++
        }
        var stop: String? = null
        while (stop == null) {
            val m = cur.metrics()
            if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) stop = "converged"
            else if (asked.size >= o.maxQuestions) stop = "budget"
            else {
                val q = cur.nextQuestion()
                if (q == null) stop = "no-disagreement" else ask(q)
            }
        }
        var auditQuestions = 0
        if (o.audit) {
            while (true) {
                val pending = cur.unconfirmedGrantCells()
                var mass = 0.0
                for (x in pending) mass += x.weight
                if (pending.isEmpty() || mass <= o.epsRisk) break
                if (asked.size >= o.maxQuestions) { stop = "budget"; break }
                val top = pending[0]
                val vs = verbOf(cur.omega, top.verb)!!
                val outcome = IntentOmega.cellRep(vs, top.cell)
                ask(Question(top.verb, top.cell, outcome, cur.acceptance(outcome), top.weight))
                auditQuestions++
            }
        }
        return AdaptiveElicitResult(stop!!, asked.size, auditQuestions, seedQuestions, asked, cur, refinements)
    }
}
