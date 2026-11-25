package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.HarmModel
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.intent.IntentRegion.Region

/**
 * Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes,
 * decision lists), the conservative grant G_tau, the residual-risk / burden / uncertainty metrics, the next-question
 * rule and the synthesis of the grant as predicates. Floating-point evaluation order follows the reference exactly.
 */
@Suppress("UNCHECKED_CAST")
class IntentLearner(@JvmField val omega: Omega, private val opts: LearnerOptions = LearnerOptions()) {
    // ---- options ----

    /** The hypothesis class. kind is box, union or decision-list; k / maxRules / decay / conditions apply to the richer classes. */
    class HypothesisClassSpec(@JvmField val kind: String, @JvmField val k: Double?, @JvmField val maxRules: Double?, @JvmField val decay: Double?, @JvmField val conditions: String?) {
        companion object {
            @JvmField val BOX = HypothesisClassSpec("box", null, null, null, null)

            @JvmStatic
            fun fromJson(o: Any?): HypothesisClassSpec {
                val m = IntentOmega.obj(o)
                return HypothesisClassSpec(m["kind"] as String, numOrNull(m["k"]), numOrNull(m["maxRules"]), numOrNull(m["decay"]), m["conditions"] as String?)
            }
        }
    }

    class AnchorSpec(@JvmField val policy: Any?, @JvmField val lambda: Double)

    /** weight(verbSpace, contains) of a hypothesis for the mixture prior; contains tests a flat cell. */
    fun interface PriorWeight { fun weight(vs: VerbSpace, contains: (Int) -> Boolean): Double }

    class PriorMix(@JvmField val beta: Double, @JvmField val weight: PriorWeight)

    class Monotone(@JvmField val paths: List<String>, @JvmField val offMass: Double?)

    /** Learner options; every field is optional (null = the default). */
    class LearnerOptions {
        @JvmField var eta: Double? = null
        @JvmField var etaPos: Double? = null
        @JvmField var etaNeg: Double? = null
        @JvmField var tau: Double? = null
        @JvmField var priorMix: PriorMix? = null
        @JvmField var nullMass: Double? = null
        @JvmField var nullMassFn: ((VerbSpace) -> Double)? = null
        @JvmField var anchor: AnchorSpec? = null
        @JvmField var anchors: List<AnchorSpec>? = null
        @JvmField var harm: HarmModel? = null
        @JvmField var maxHypotheses: Int? = null
        @JvmField var maxEnumeration: Int? = null
        @JvmField var strategy: String? = null
        @JvmField var hypothesisClass: HypothesisClassSpec? = null
        @JvmField var agnosticSlack: Int? = null
        @JvmField var monotone: Monotone? = null

        companion object {
            /** Reads the plain-data options (functions, the harm model and the prior-mixture weight are set by the caller). */
            @JvmStatic
            fun fromJson(o: Any?): LearnerOptions {
                val p = LearnerOptions()
                if (o == null) return p
                val m = IntentOmega.obj(o)
                p.eta = numOrNull(m["eta"]); p.etaPos = numOrNull(m["etaPos"]); p.etaNeg = numOrNull(m["etaNeg"]); p.tau = numOrNull(m["tau"])
                p.nullMass = numOrNull(m["nullMass"])
                if (m["anchor"] != null) p.anchor = anchorOf(m["anchor"])
                if (m["anchors"] != null) p.anchors = IntentOmega.arr(m["anchors"]).map { anchorOf(it) }
                val mh = numOrNull(m["maxHypotheses"])
                val me = numOrNull(m["maxEnumeration"])
                val sl = numOrNull(m["agnosticSlack"])
                if (mh != null) p.maxHypotheses = Math.min(Int.MAX_VALUE.toDouble(), mh).toInt()
                if (me != null) p.maxEnumeration = Math.min(Int.MAX_VALUE.toDouble(), me).toInt()
                if (sl != null) {
                    require(!(sl != Math.floor(sl) || sl < 0 || sl > Int.MAX_VALUE)) { "pca-intent: agnosticSlack must be a non-negative integer" }
                    p.agnosticSlack = sl.toInt()
                }
                p.strategy = m["strategy"] as String?
                if (m["hypothesisClass"] != null) p.hypothesisClass = HypothesisClassSpec.fromJson(m["hypothesisClass"])
                if (m["monotone"] != null) {
                    val mo = IntentOmega.obj(m["monotone"])
                    p.monotone = Monotone(IntentOmega.arr(mo["paths"]).map { it as String }, numOrNull(mo["offMass"]))
                }
                return p
            }

            private fun anchorOf(o: Any?): AnchorSpec {
                val m = IntentOmega.obj(o)
                return AnchorSpec(m["policy"], IntentOmega.dbl(m["lambda"]))
            }
        }
    }

    /** One recorded answer. */
    class Observation(@JvmField val verb: String, @JvmField val values: Map<String, Any?>, @JvmField val cell: IntArray, @JvmField val y: Int, @JvmField val source: String, @JvmField val region: Region?) {
        @JvmField var conflict: Boolean = false

        fun toJson(): MutableMap<String, Any?> {
            val o = LinkedHashMap<String, Any?>()
            o["verb"] = verb
            o["values"] = values
            o["cell"] = cell.map { it.toDouble() }.toMutableList()
            o["y"] = y.toDouble()
            o["source"] = source
            if (region != null) o["region"] = region.toJson()
            if (conflict) o["conflict"] = true
            return o
        }
    }

    class Question(@JvmField val verb: String, @JvmField val cell: IntArray, @JvmField val outcome: Outcome, @JvmField val p: Double, @JvmField val score: Double)

    class LearnerMetrics {
        @JvmField var residualRisk = 0.0
        @JvmField var burden = 0.0
        @JvmField var uncertainty = 0.0
        @JvmField var entropyBits = 0.0
        @JvmField var disagreementMass = 0.0
        @JvmField var meanHarm = 0.0
        @JvmField var log2VersionSpace: Double? = null
        @JvmField var questions = 0
        @JvmField var conflicts = 0
    }

    class CellView internal constructor(@JvmField val verb: String, @JvmField val cell: IntArray, @JvmField val p: Double, @JvmField val mass: Double, @JvmField val harm: Double, @JvmField val inGrant: Boolean, @JvmField val vetoed: Boolean)

    class Unconfirmed internal constructor(@JvmField val verb: String, @JvmField val cell: IntArray, @JvmField val weight: Double)

    class Synthesis internal constructor(@JvmField val predicates: List<Map<String, Any?>>, @JvmField val caveats: List<Map<String, Any?>>)

    /** The non-empty hypotheses of a class as cell masks, with their Occam complexity. */
    class SetsResult {
        @JvmField val sets = ArrayList<BooleanArray>()
        @JvmField val complexity = ArrayList<Int>()
    }

    // ---- verb model ----

    private class VerbModel(
        val vs: VerbSpace, val nChoice: IntArray, val contains: Array<BooleanArray>, val nCellsD: IntArray, val nh: Int, val choice: IntArray, val member: BooleanArray?,
        val complexity: IntArray?, val nCells: Int, val cellIdx: IntArray, val mass: DoubleArray, val harm: DoubleArray,
    ) {
        val prior = DoubleArray(nh)
        val w = DoubleArray(nh)
        val err = IntArray(nh)
        val p = DoubleArray(nCells)
        val veto = BooleanArray(nCells)
        val seen = BooleanArray(nCells)
        var dirty = true
    }

    private class FullOpts(o: LearnerOptions) {
        val maxHypotheses: Int = o.maxHypotheses ?: 400000
        val maxEnumeration: Int = o.maxEnumeration ?: 4000000
        val hypothesisClass: HypothesisClassSpec = o.hypothesisClass ?: HypothesisClassSpec.BOX
    }

    private class SetsOut {
        val sets = ArrayList<BooleanArray>()
        val complexity = ArrayList<Int>()
    }

    // ---- state ----

    @JvmField val eta: Double = opts.eta ?: 0.0
    @JvmField val etaPos: Double
    @JvmField val etaNeg: Double
    private val noisy: Boolean
    @JvmField val tau: Double
    @JvmField val strategy: String
    @JvmField val harm: HarmModel
    @JvmField val hypothesisClass: HypothesisClassSpec
    @JvmField val agnosticSlack: Int?
    @JvmField val observations: MutableList<Observation> = ArrayList()
    private val models = ArrayList<VerbModel>()

    init {
        require(eta >= 0 && eta < 0.5) { "pca-intent: eta must be in [0, 0.5)" }
        etaPos = opts.etaPos ?: eta
        etaNeg = opts.etaNeg ?: eta
        require(etaPos >= 0 && etaPos < 0.5 && etaNeg >= 0 && etaNeg < 0.5) { "pca-intent: etaPos and etaNeg must be in [0, 0.5)" }
        noisy = etaPos != 0.0 || etaNeg != 0.0
        tau = opts.tau ?: (if (noisy) 0.95 else 1.0)
        strategy = opts.strategy ?: "disagreement"
        harm = opts.harm ?: IntentOmega.DEFAULT_HARM
        hypothesisClass = opts.hypothesisClass ?: HypothesisClassSpec.BOX
        agnosticSlack = opts.agnosticSlack
        if (agnosticSlack != null) {
            require(agnosticSlack >= 0) { "pca-intent: agnosticSlack must be a non-negative integer" }
            require(!noisy) { "pca-intent: agnostic selection replaces the noise model; use eta = 0" }
        }
        val full = FullOpts(opts)
        for (vs in omega.verbs) models.add(buildVerbModel(vs, full, harm))
        initPrior()
    }

    private fun initPrior() {
        val anchors = ArrayList<AnchorSpec>()
        opts.anchor?.let { anchors.add(it) }
        opts.anchors?.let { anchors.addAll(it) }
        anchors.removeAll { !(it.lambda > 0) }
        val admitters = anchors.map { IntentPolicy.admitter(it.policy) }
        val lambdas = anchors.map { it.lambda }
        val decay = if (hypothesisClass.kind == "box") 1.0 else (hypothesisClass.decay ?: 0.25)
        require(decay > 0 && decay <= 1) { "pca-intent: decay must be in (0, 1]" }
        for (m in models) {
            val fn = opts.nullMassFn
            val nm = if (fn != null) fn(m.vs) else (opts.nullMass ?: 0.2)
            require(nm >= 0 && nm <= 1) { "pca-intent: nullMass must be in [0, 1]" }
            m.w[0] = nm
            var z = 0.0
            for (h in 1 until m.nh) {
                val raw = if (m.complexity != null) net.atlasauth.pca.verifier.DetMath.detPowInt(decay, m.complexity[h] - 1) else 1.0
                m.w[h] = raw
                z += raw
            }
            for (h in 1 until m.nh) m.w[h] = ((1 - nm) * m.w[h]) / (if (z == 0.0) 1.0 else z)
            opts.monotone?.let { applyMonotonePrior(m, it) }
            if (admitters.isNotEmpty()) {
                var tot = 0.0
                for (c in 0 until m.nCells) tot += m.mass[c]
                val accs = ArrayList<BooleanArray>()
                for (adm in admitters) {
                    val acc = BooleanArray(m.nCells)
                    for (c in 0 until m.nCells) acc[c] = adm.admits(m.vs, IntentOmega.cellRep(m.vs, IntentOmega.decodeCell(m.vs, c.toDouble())))
                    accs.add(acc)
                }
                for (h in 0 until m.nh) {
                    var mix = 0.0
                    for (i in accs.indices) {
                        val acc = accs[i]
                        var dist = 0.0
                        for (c in 0 until m.nCells) {
                            val inH = if (h == 0) false else holds(m, h, c)
                            if (inH != acc[c]) dist += m.mass[c]
                        }
                        mix += net.atlasauth.pca.verifier.DetMath.detExp((-lambdas[i] * dist) / (if (tot == 0.0) 1.0 else tot))
                    }
                    m.w[h] = m.w[h] * (mix / accs.size)
                }
            }
            normalize(m.w)
            opts.priorMix?.let { mixPrior(m, it) }
            System.arraycopy(m.w, 0, m.prior, 0, m.nh)
            m.dirty = true
        }
    }

    private fun inGrant(m: VerbModel, c: Int): Boolean = !m.veto[c] && m.p[c] >= tau - 1e-12

    private fun model(verb: String): VerbModel? = models.firstOrNull { it.vs.verb == verb }

    private fun refresh(m: VerbModel) {
        if (!m.dirty) return
        java.util.Arrays.fill(m.p, 0.0)
        val anyIn = BooleanArray(m.nCells)
        val anyOut = BooleanArray(m.nCells)
        var live = false
        for (h in 0 until m.nh) {
            val w = m.w[h]
            if (w == 0.0) continue
            live = true
            for (c in 0 until m.nCells) {
                if (h > 0 && holds(m, h, c)) { m.p[c] = m.p[c] + w; anyIn[c] = true } else anyOut[c] = true
            }
        }
        for (c in 0 until m.nCells) m.p[c] = if (!live || !anyIn[c]) 0.0 else if (!anyOut[c]) 1.0 else Math.min(1.0, Math.max(0.0, m.p[c]))
        m.dirty = false
    }

    /** p_n(outcome); 0 outside the space (the conservative reading). */
    fun acceptance(o: Outcome): Double {
        val m = model(o.verb) ?: return 0.0
        val idx = IntentOmega.cellOf(m.vs, o) ?: return 0.0
        refresh(m)
        return m.p[flat(m, idx)]
    }

    /** Is the outcome inside the current conservative grant (p_n >= tau and not vetoed)? */
    fun admitsOutcome(o: Outcome): Boolean {
        val m = model(o.verb) ?: return false
        val idx = IntentOmega.cellOf(m.vs, o) ?: return false
        refresh(m)
        return inGrant(m, flat(m, idx))
    }

    fun isVetoed(o: Outcome): Boolean {
        val m = model(o.verb)
        val idx = if (m != null) IntentOmega.cellOf(m.vs, o) else null
        return m != null && idx != null && m.veto[flat(m, idx)]
    }

    /** Every vetoed cell as "verb|flat" keys. */
    fun vetoedCells(): List<String> {
        val out = ArrayList<String>()
        for (m in models) for (c in 0 until m.nCells) if (m.veto[c]) out.add(m.vs.verb + "|" + c)
        return out
    }

    fun observe(o: Outcome, y: Int): Observation? = observe(o, y, "elicitation", null)

    /** Record the answer y to "should the outcome (or every outcome of the region) be allowed?"; null outside the space or on an empty region. */
    fun observe(o: Outcome, y: Int, source: String, region: Region?): Observation? {
        val m = model(o.verb) ?: return null
        val idx = IntentOmega.cellOf(m.vs, o) ?: return null
        val cells: IntArray = if (region != null) {
            val rc = IntentRegion.regionCells(m.vs, region, y == 1)
            IntArray(rc.size) { rc[it].toInt() }
        } else intArrayOf(flat(m, idx))
        if (cells.isEmpty()) return null
        refresh(m)
        val obs = Observation(o.verb, LinkedHashMap(o.values), idx, y, source, region)
        var regionP = 0.0
        for (h in 1 until m.nh) if (m.w[h] > 0 && holdsAll(m, h, cells)) regionP += m.w[h]
        val contradictsAll = if (y == 0) regionP >= 1 - 1e-12 else regionP <= 1e-12
        if (source == "runtime" && y == 0) for (c in cells) m.veto[c] = true
        for (c in cells) m.seen[c] = true
        val slack = agnosticSlack
        if (slack != null) {
            for (h in 0 until m.nh) if ((if (holdsAll(m, h, cells)) 1 else 0) != y) m.err[h] = m.err[h] + 1
            var minErr = Double.POSITIVE_INFINITY
            for (h in 0 until m.nh) if (m.prior[h] > 0) minErr = Math.min(minErr, m.err[h].toDouble())
            for (h in 0 until m.nh) m.w[h] = if (m.err[h] <= minErr + slack) m.prior[h] else 0.0
            normalize(m.w)
            if (contradictsAll) {
                obs.conflict = true
                if (y == 0) for (c in cells) m.veto[c] = true
            }
        } else {
            val prev = if (etaPos == 0.0 || etaNeg == 0.0) m.w.clone() else null
            var sum = 0.0
            for (h in 0 until m.nh) {
                val inH = if (holdsAll(m, h, cells)) 1 else 0
                val lik = if (inH == 1) (if (y == 1) 1 - etaNeg else etaNeg) else if (y == 1) etaPos else 1 - etaPos
                m.w[h] = m.w[h] * lik
                sum += m.w[h]
            }
            if (sum == 0.0 && prev != null) {
                System.arraycopy(prev, 0, m.w, 0, m.nh)
                obs.conflict = true
                if (y == 0) for (c in cells) m.veto[c] = true
            } else normalize(m.w)
        }
        m.dirty = true
        observations.add(obs)
        return obs
    }

    fun cells(): List<CellView> {
        val out = ArrayList<CellView>()
        for (m in models) {
            refresh(m)
            for (c in 0 until m.nCells) out.add(CellView(m.vs.verb, IntentOmega.decodeCell(m.vs, c.toDouble()), m.p[c], m.mass[c], m.harm[c], inGrant(m, c), m.veto[c]))
        }
        return out
    }

    fun metrics(): LearnerMetrics {
        var rr = 0.0
        var bb = 0.0
        var uu = 0.0
        var hh = 0.0
        var vsum = 0.0
        var dis = 0.0
        var meanHarm = 0.0
        for (m in models) {
            refresh(m)
            for (c in 0 until m.nCells) {
                val p = m.p[c]
                val mu = m.mass[c]
                meanHarm += mu * m.harm[c]
                if (inGrant(m, c)) rr += mu * (1 - p) * m.harm[c] else bb += mu * p
                uu += mu * Math.min(p, 1 - p)
                if (p > 1e-12 && p < 1 - 1e-12) dis += mu
            }
            var alive = 0
            for (h in 0 until m.nh) {
                val w = m.w[h]
                if (w > 0) { alive++; hh -= w * net.atlasauth.pca.verifier.DetMath.detLog2(w) }
            }
            vsum += net.atlasauth.pca.verifier.DetMath.detLog2(Math.max(1, alive).toDouble())
        }
        val r = LearnerMetrics()
        r.residualRisk = rr; r.burden = bb; r.uncertainty = uu; r.entropyBits = hh
        r.log2VersionSpace = if (noisy) null else vsum
        r.disagreementMass = dis; r.meanHarm = meanHarm
        for (o in observations) {
            if (o.source == "elicitation") r.questions++
            if (o.conflict) r.conflicts++
        }
        return r
    }

    /** The next question: argmax expected information (times mass and harm for the risk strategy); null when nothing is uncertain. */
    fun nextQuestion(): Question? {
        var best: Question? = null
        val hPos = binEnt(etaPos)
        val hNeg = binEnt(etaNeg)
        for (m in models) {
            refresh(m)
            for (c in 0 until m.nCells) {
                if (m.veto[c]) continue
                val p = m.p[c]
                if (p <= 1e-9 || p >= 1 - 1e-9) continue
                val pe = p * (1 - etaNeg) + (1 - p) * etaPos
                var score = binEnt(pe) - (if (etaPos == etaNeg) hPos else p * hNeg + (1 - p) * hPos)
                if (strategy == "risk") score *= m.mass[c] * m.harm[c]
                if (score <= 1e-15) continue
                if (best == null || score > best.score + 1e-12) {
                    val cell = IntentOmega.decodeCell(m.vs, c.toDouble())
                    best = Question(m.vs.verb, cell, IntentOmega.cellRep(m.vs, cell), p, score)
                }
            }
        }
        return best
    }

    /** Grant cells inferred but never directly observed, most consequential first. */
    fun unconfirmedGrantCells(): List<Unconfirmed> {
        val out = ArrayList<Unconfirmed>()
        for (m in models) {
            refresh(m)
            for (c in 0 until m.nCells) {
                if (m.seen[c] || !inGrant(m, c)) continue
                out.add(Unconfirmed(m.vs.verb, IntentOmega.decodeCell(m.vs, c.toDouble()), m.mass[c] * m.harm[c]))
            }
        }
        out.sortWith { a, b -> java.lang.Double.compare(b.weight, a.weight) }
        return out
    }

    /** The conservative grant as predicates plus the reversibility caveat. */
    fun synthesize(): Synthesis {
        val predicates = ArrayList<Map<String, Any?>>()
        val order = listOf("reversible", "rate_limited", "irreversible")
        var worst = -1
        for (m in models) {
            refresh(m)
            val allowed = BooleanArray(m.nCells)
            var any = false
            for (c in 0 until m.nCells) if (inGrant(m, c)) { allowed[c] = true; any = true }
            if (!any) continue
            worst = Math.max(worst, order.indexOf(m.vs.reversibility))
            predicates.addAll(boxesToPredicates(m.vs, allowed))
        }
        val caveats = ArrayList<Map<String, Any?>>()
        if (worst >= 0) caveats.add(linkedMapOf<String, Any?>("type" to "reversibility_max", "class" to order[worst]))
        return Synthesis(predicates, caveats)
    }

    // ---- elicitation loop ----

    fun interface Answer { fun answer(q: Question): Int }

    class ElicitOptions(@JvmField var epsRisk: Double, @JvmField var epsBurden: Double, @JvmField var maxQuestions: Int, @JvmField var audit: Boolean) {
        /** (verb, cell) seeds asked first. */
        @JvmField val seed = ArrayList<Pair<String, IntArray>>()
    }

    class ElicitResult internal constructor(@JvmField val stop: String, @JvmField val questions: Int, @JvmField val auditQuestions: Int, @JvmField val seedQuestions: Int, @JvmField val asked: List<Question>)

    companion object {
        @JvmStatic
        fun numOrNull(o: Any?): Double? = if (o == null) null else IntentOmega.dbl(o)

        // the same argument recurs for every cell of a model, so the value is memoized (bounded: cleared when it grows past 4096 entries)
        private val BIN_ENT_MEMO = HashMap<Double, Double>()

        /** Binary entropy in bits; detLog2 (not a libm log2) so that the chosen question is identical on every platform and language. */
        @JvmStatic
        fun binEnt(p: Double): Double {
            if (p <= 0 || p >= 1) return 0.0
            synchronized(BIN_ENT_MEMO) {
                val hit = BIN_ENT_MEMO[p]
                if (hit != null) return hit
            }
            val v = -(p * net.atlasauth.pca.verifier.DetMath.detLog2(p) + (1 - p) * net.atlasauth.pca.verifier.DetMath.detLog2(1 - p))
            synchronized(BIN_ENT_MEMO) {
                if (BIN_ENT_MEMO.size >= 4096) BIN_ENT_MEMO.clear()
                BIN_ENT_MEMO[p] = v
            }
            return v
        }

        /** The canonical name of a hypothesis class (stored in the Intent Map). */
        @JvmStatic
        fun hypothesisClassName(h: HypothesisClassSpec): String {
            if (h.kind == "box") return "per-verb-box/v1"
            if (h.kind == "union") return "per-verb-union/v1"
            return if ((h.conditions ?: "box") == "atomic") "per-verb-decision-list/v1" else "per-verb-decision-list/v2"
        }

        private fun flat(m: VerbModel, idx: IntArray): Int {
            var f = 0
            for (d in idx.indices) f = f * m.nCellsD[d] + idx[d]
            return f
        }

        private fun rangeChoices(n: Int): List<IntArray> {
            val out = ArrayList<IntArray>()
            for (i in 0 until n) for (j in i until n) out.add(intArrayOf(i, j))
            return out
        }

        private fun buildBoxTables(vs: VerbSpace, nCellsD: IntArray, contains: MutableList<BooleanArray>, nChoice: IntArray) {
            for (k in vs.dims.indices) {
                val d = vs.dims[k]
                val n = nCellsD[k]
                if (d.kind == "num") {
                    val ch = rangeChoices(n)
                    val t = BooleanArray(ch.size * n)
                    for (c in ch.indices) for (x in ch[c][0]..ch[c][1]) t[c * n + x] = true
                    contains.add(t)
                    nChoice[k] = ch.size
                } else {
                    check(n <= 20) { "pca-intent: categorical dimension ${d.path} has $n values (max 20 for exact enumeration)" }
                    val m = (1 shl n) - 1
                    val t = BooleanArray(m * n)
                    for (mask in 1..m) for (x in 0 until n) if ((mask and (1 shl x)) != 0) t[(mask - 1) * n + x] = true
                    contains.add(t)
                    nChoice[k] = m
                }
            }
        }

        private fun keyOf(m: BooleanArray): String {
            val c = CharArray(m.size)
            for (i in m.indices) c[i] = if (m[i]) '1' else '0'
            return String(c)
        }

        private fun jsNum(x: Double): String = if (x == Math.rint(x) && Math.abs(x) < 1e21) x.toLong().toString() else x.toString()

        private fun boxMasks(vs: VerbSpace, nCells: Int, cellIdx: IntArray, nCellsD: IntArray, contains: Array<BooleanArray>, nChoice: IntArray, cap: Int): List<BooleanArray> {
            val dn = vs.dims.size
            var boxes = 1.0
            for (c in nChoice) boxes *= c
            check(!(boxes > cap)) { "pca-intent: ${jsNum(boxes)} boxes for ${vs.verb} exceed the enumeration cap; coarsen the cuts" }
            val out = ArrayList<BooleanArray>()
            val cur = IntArray(dn)
            var b = 0L
            while (b < boxes.toLong()) {
                val mask = BooleanArray(nCells)
                for (c in 0 until nCells) {
                    var inside = true
                    var d = 0
                    while (d < dn && inside) {
                        if (!contains[d][cur[d] * nCellsD[d] + cellIdx[c * dn + d]]) inside = false
                        d++
                    }
                    if (inside) mask[c] = true
                }
                out.add(mask)
                for (d in dn - 1 downTo 0) {
                    cur[d]++
                    if (cur[d] < nChoice[d]) break
                    cur[d] = 0
                }
                b++
            }
            return out
        }

        private fun enumerateUnions(boxes: List<BooleanArray>, k: Int, cap: Int, verb: String): SetsOut {
            val seen = LinkedHashMap<String, Int>()
            val out = SetsOut()
            var frontier = ArrayList<BooleanArray>()
            for (b in boxes) {
                val key = keyOf(b)
                if (seen.containsKey(key)) continue
                seen[key] = out.sets.size
                out.sets.add(b)
                out.complexity.add(1)
                frontier.add(b)
            }
            var work = 0L
            for (level in 2..k) {
                val next = ArrayList<BooleanArray>()
                for (s in frontier) {
                    for (b in boxes) {
                        work += 1
                        check(work <= cap) { "pca-intent: the union-of-$k-boxes class for $verb exceeds the enumeration cap; coarsen the cuts or lower k" }
                        val u = BooleanArray(s.size) { s[it] || b[it] }
                        val key = keyOf(u)
                        if (seen.containsKey(key)) continue
                        seen[key] = out.sets.size
                        out.sets.add(u)
                        out.complexity.add(level)
                        next.add(u)
                    }
                }
                frontier = next
            }
            return out
        }

        private fun addAtomic(tests: MutableList<BooleanArray>, nCells: Int, cellIdx: IntArray, dn: Int, k: Int, pred: (Int) -> Boolean) {
            val m = BooleanArray(nCells)
            var any = false
            var all = true
            for (c in 0 until nCells) {
                if (pred(cellIdx[c * dn + k])) { m[c] = true; any = true } else all = false
            }
            if (any && !all) tests.add(m)
        }

        private fun dedupMasks(masks: List<BooleanArray>): List<BooleanArray> {
            val seen = LinkedHashSet<String>()
            val out = ArrayList<BooleanArray>()
            for (t in masks) if (seen.add(keyOf(t))) out.add(t)
            return out
        }

        private fun atomicTests(vs: VerbSpace, nCells: Int, cellIdx: IntArray, nCellsD: IntArray): List<BooleanArray> {
            val dn = vs.dims.size
            val tests = ArrayList<BooleanArray>()
            for (k in 0 until dn) {
                val d = vs.dims[k]
                val n = nCellsD[k]
                if (d.kind == "num") {
                    for (i in 0 until n - 1) addAtomic(tests, nCells, cellIdx, dn, k) { x -> x <= i }
                    for (i in 1 until n) addAtomic(tests, nCells, cellIdx, dn, k) { x -> x >= i }
                    if (n > 2) for (i in 1 until n - 1) addAtomic(tests, nCells, cellIdx, dn, k) { x -> x == i }
                } else for (i in 0 until n) addAtomic(tests, nCells, cellIdx, dn, k) { x -> x == i }
            }
            return dedupMasks(tests)
        }

        private fun emitList(out: SetsOut, seen: MutableMap<String, Int>, acc: BooleanArray, decided: BooleanArray, rules: Int, nCells: Int) {
            for (def in 0..1) {
                val s = BooleanArray(nCells)
                var any = false
                for (c in 0 until nCells) {
                    s[c] = if (decided[c]) acc[c] else def == 1
                    if (s[c]) any = true
                }
                if (!any) continue
                val key = keyOf(s)
                if (seen.containsKey(key)) continue
                seen[key] = out.sets.size
                out.sets.add(s)
                out.complexity.add(Math.max(1, rules))
            }
        }

        private fun enumerateDecisionLists(tests: List<BooleanArray>, nCells: Int, maxLen: Int, cap: Int, verb: String): SetsOut {
            val seen = LinkedHashMap<String, Int>()
            val out = SetsOut()
            var frontier = ArrayList<Array<BooleanArray>>()
            frontier.add(arrayOf(BooleanArray(nCells), BooleanArray(nCells))) // {decided, acc}
            emitList(out, seen, frontier[0][1], frontier[0][0], 0, nCells)
            var work = 0L
            for (depth in 1..maxLen) {
                val states = LinkedHashMap<String, Array<BooleanArray>>()
                for (st in frontier) {
                    for (t in tests) {
                        for (label in 0..1) {
                            work += 1
                            check(work <= cap) { "pca-intent: the decision-list class (<= $maxLen rules) for $verb exceeds the enumeration cap" }
                            val decided = BooleanArray(nCells)
                            val acc = BooleanArray(nCells)
                            var fresh = false
                            for (c in 0 until nCells) {
                                if (st[0][c]) { decided[c] = true; acc[c] = st[1][c] }
                                else if (t[c]) { decided[c] = true; acc[c] = label == 1; fresh = true }
                            }
                            if (!fresh) continue
                            val key = keyOf(decided) + "|" + keyOf(acc)
                            if (states.containsKey(key)) continue
                            states[key] = arrayOf(decided, acc)
                        }
                    }
                }
                frontier = ArrayList(states.values)
                for (st in frontier) emitList(out, seen, st[1], st[0], depth, nCells)
            }
            return out
        }

        private fun isInt(x: Double?): Boolean = x != null && !x.isNaN() && !x.isInfinite() && x == Math.floor(x)

        private fun buildVerbModel(vs: VerbSpace, opts: FullOpts, harm: HarmModel): VerbModel {
            val dn = vs.dims.size
            val nCellsD = IntArray(dn) { IntentOmega.cellCount(vs.dims[it]) }
            val nChoice = IntArray(dn)
            val containsL = ArrayList<BooleanArray>()
            buildBoxTables(vs, nCellsD, containsL, nChoice)
            val contains = containsL.toTypedArray()
            val ncd = IntentOmega.verbCellCount(vs)
            check(!(ncd > Int.MAX_VALUE)) { "pca-intent: too many cells for ${vs.verb}" }
            val nCells = ncd.toInt()
            val cellIdx = IntArray(nCells * dn)
            val mass = DoubleArray(nCells)
            val hm = DoubleArray(nCells)
            for (c in 0 until nCells) {
                val idx = IntentOmega.decodeCell(vs, c.toDouble())
                for (d in 0 until dn) cellIdx[c * dn + d] = idx[d]
                val s = IntentOmega.cellStats(vs, idx, harm)
                mass[c] = s.mass
                hm[c] = s.harm
            }
            val hc = opts.hypothesisClass
            val nh: Int
            var choice = IntArray(1)
            var member: BooleanArray? = null
            var complexity: IntArray? = null
            if (hc.kind == "box") {
                var boxes = 1.0
                for (c in nChoice) boxes *= c
                check(!(boxes + 1 > opts.maxHypotheses)) { "pca-intent: |Theta_${vs.verb}| = ${jsNum(boxes + 1)} exceeds maxHypotheses ${opts.maxHypotheses}; coarsen the cuts" }
                nh = boxes.toInt() + 1
                choice = IntArray(Math.max(1, boxes.toInt() * dn))
                val cur = IntArray(dn)
                for (h in 0 until boxes.toInt()) {
                    for (d in 0 until dn) choice[h * dn + d] = cur[d]
                    for (d in dn - 1 downTo 0) {
                        cur[d]++
                        if (cur[d] < nChoice[d]) break
                        cur[d] = 0
                    }
                }
            } else {
                val so: SetsOut
                if (hc.kind == "union") {
                    require(isInt(hc.k) && hc.k!! >= 1) { "pca-intent: union class needs an integer k >= 1" }
                    val boxes = boxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.maxEnumeration)
                    so = enumerateUnions(boxes, hc.k!!.toInt(), opts.maxEnumeration, vs.verb)
                } else {
                    require(isInt(hc.maxRules) && hc.maxRules!! >= 1) { "pca-intent: decision-list class needs an integer maxRules >= 1" }
                    val cond = hc.conditions ?: "box"
                    require(cond == "box" || cond == "atomic") { "pca-intent: decision-list conditions must be 'box' or 'atomic'" }
                    val tests = if (cond == "atomic") atomicTests(vs, nCells, cellIdx, nCellsD) else dedupMasks(boxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.maxEnumeration))
                    so = enumerateDecisionLists(tests, nCells, hc.maxRules!!.toInt(), opts.maxEnumeration, vs.verb)
                }
                check(!(so.sets.size + 1 > opts.maxHypotheses)) { "pca-intent: |Theta_${vs.verb}| = ${so.sets.size + 1} exceeds maxHypotheses ${opts.maxHypotheses}; coarsen the cuts" }
                nh = so.sets.size + 1
                check(nh.toLong() * nCells <= Int.MAX_VALUE) { "pca-intent: hypothesis table too large for ${vs.verb}" }
                val mem = BooleanArray(nh * nCells)
                val cx = IntArray(nh)
                for (i in so.sets.indices) {
                    System.arraycopy(so.sets[i], 0, mem, (i + 1) * nCells, nCells)
                    cx[i + 1] = so.complexity[i]
                }
                member = mem
                complexity = cx
            }
            return VerbModel(vs, nChoice, contains, nCellsD, nh, choice, member, complexity, nCells, cellIdx, mass, hm)
        }

        private fun holds(m: VerbModel, h: Int, c: Int): Boolean {
            val mem = m.member
            if (mem != null) return mem[h * m.nCells + c]
            val dn = m.vs.dims.size
            val base = (h - 1) * dn
            for (d in 0 until dn) {
                val n = m.nCellsD[d]
                if (!m.contains[d][m.choice[base + d] * n + m.cellIdx[c * dn + d]]) return false
            }
            return true
        }

        /** The non-empty hypotheses of a verb's class as cell masks (index 0 = the empty hypothesis omitted), with their Occam complexity. */
        @JvmStatic
        fun hypothesisCellSets(vs: VerbSpace, hc: HypothesisClassSpec?, maxHypotheses: Int?, maxEnumeration: Int?): SetsResult {
            val o = LearnerOptions()
            o.maxHypotheses = maxHypotheses; o.maxEnumeration = maxEnumeration; o.hypothesisClass = hc ?: HypothesisClassSpec.BOX
            val m = buildVerbModel(vs, FullOpts(o), IntentOmega.DEFAULT_HARM)
            val r = SetsResult()
            for (h in 1 until m.nh) {
                val s = BooleanArray(m.nCells)
                for (c in 0 until m.nCells) if (holds(m, h, c)) s[c] = true
                r.sets.add(s)
                r.complexity.add(m.complexity?.get(h) ?: 1)
            }
            return r
        }

        private fun applyMonotonePrior(m: VerbModel, mono: Monotone) {
            val off = mono.offMass ?: 0.0
            require(off >= 0 && off <= 1) { "pca-intent: monotone.offMass must be in [0, 1]" }
            val dn = m.vs.dims.size
            val ks = ArrayList<Int>()
            for (k in 0 until dn) if (m.vs.dims[k].kind == "num" && mono.paths.contains(m.vs.dims[k].path)) ks.add(k)
            if (ks.isEmpty()) return
            val stride = IntArray(ks.size)
            for (i in ks.indices) {
                var s = 1
                for (j in ks[i] + 1 until dn) s *= m.nCellsD[j]
                stride[i] = s
            }
            for (h in 1 until m.nh) {
                var isMono = true
                var c = 0
                while (c < m.nCells && isMono) {
                    if (holds(m, h, c)) {
                        for (i in ks.indices) {
                            if (m.cellIdx[c * dn + ks[i]] > 0 && !holds(m, h, c - stride[i])) { isMono = false; break }
                        }
                    }
                    c++
                }
                if (!isMono) m.w[h] = m.w[h] * off
            }
        }

        private fun holdsAll(m: VerbModel, h: Int, cells: IntArray): Boolean {
            if (h == 0) return false
            for (c in cells) if (!holds(m, h, c)) return false
            return true
        }

        private fun normalize(w: DoubleArray) {
            var s = 0.0
            for (x in w) s += x
            if (s > 0) for (i in w.indices) w[i] = w[i] / s
        }

        private fun mixPrior(m: VerbModel, mix: PriorMix) {
            require(mix.beta >= 0 && mix.beta < 1) { "pca-intent: priorMix.beta must be in [0, 1)" }
            val pop = DoubleArray(m.nh)
            var z = 0.0
            for (h in 0 until m.nh) {
                val x = mix.weight.weight(m.vs) { c -> h != 0 && c >= 0 && c < m.nCells && holds(m, h, c) }
                require(!x.isNaN() && !x.isInfinite() && x >= 0) { "pca-intent: priorMix.weight must be finite and >= 0" }
                pop[h] = x
                z += x
            }
            if (!(z > 0)) return
            for (h in 0 until m.nh) m.w[h] = (1 - mix.beta) * m.w[h] + (mix.beta * pop[h]) / z
        }

        /** Replay observations onto a fresh learner. */
        @JvmStatic
        fun replay(omega: Omega, opts: LearnerOptions, observations: Collection<Observation>): IntentLearner {
            val l = IntentLearner(omega, opts)
            for (o in observations) l.observe(Outcome(o.verb, o.values), o.y, o.source, o.region)
            return l
        }

        // ---- synthesis: allowed cells -> union of boxes -> predicates ----

        private class Box(n: Int) {
            /** numeric: {lo, hi}; categorical: null here and a value set at the same index in sets. */
            val ranges = arrayOfNulls<IntArray>(n)
            val sets = arrayOfNulls<MutableSet<Int>>(n)
        }

        private fun boxCells(box: Box): List<IntArray> {
            var acc: List<IntArray> = listOf(IntArray(0))
            for (k in box.ranges.indices) {
                val vals = ArrayList<Int>()
                val r = box.ranges[k]
                if (r != null) for (i in r[0]..r[1]) vals.add(i)
                else { vals.addAll(box.sets[k]!!); vals.sort() }
                val next = ArrayList<IntArray>()
                for (pre in acc) for (v in vals) {
                    val n = pre.copyOf(pre.size + 1)
                    n[pre.size] = v
                    next.add(n)
                }
                acc = next
            }
            return acc
        }

        private fun encode(nCellsD: IntArray, idx: IntArray): Int {
            var f = 0
            for (i in nCellsD.indices) f = f * nCellsD[i] + idx[i]
            return f
        }

        private fun cond(field: String, op: String, value: Any?): MutableMap<String, Any?> = linkedMapOf("field" to field, "op" to op, "value" to value)

        private fun single(k: String, v: Any?): MutableMap<String, Any?> = linkedMapOf(k to v)

        private fun catCondition(d: CatDim, s: Set<Int>): Map<String, Any?>? {
            if (s.size == d.values.size) return null
            val exacts = ArrayList<String>()
            val prefixes = ArrayList<String>()
            for (v in d.values) {
                if (v.kind == "exact") exacts.add(v.value)
                if (v.kind == "prefix") prefixes.add(v.value)
            }
            val alts = ArrayList<Map<String, Any?>>()
            val allowedExacts = ArrayList<Any?>()
            for (i in s) if (d.values[i].kind == "exact") allowedExacts.add(d.values[i].value)
            if (allowedExacts.size == 1) alts.add(cond(d.path, "eq", allowedExacts[0]))
            else if (allowedExacts.size > 1) alts.add(cond(d.path, "in", allowedExacts))
            val sorted = ArrayList(s)
            sorted.sort()
            for (i in sorted) {
                val v = d.values[i]
                if (v.kind == "exact") continue
                val parts = ArrayList<Map<String, Any?>>()
                if (v.kind == "prefix") {
                    parts.add(cond(d.path, "prefix", v.value))
                    val under = ArrayList<Any?>()
                    for (e in exacts) if (e.startsWith(v.value)) under.add(e)
                    if (under.isNotEmpty()) parts.add(cond(d.path, "nin", under))
                    for (q in prefixes) if (q != v.value && q.startsWith(v.value)) parts.add(single("not", cond(d.path, "prefix", q)))
                } else {
                    if (exacts.isNotEmpty()) parts.add(cond(d.path, "nin", ArrayList<Any?>(exacts)))
                    for (q in prefixes) parts.add(single("not", cond(d.path, "prefix", q)))
                }
                if (parts.size == 1) alts.add(parts[0])
                else if (parts.size > 1) alts.add(single("all_of", ArrayList<Any?>(parts)))
            }
            if (alts.isEmpty()) return null
            return if (alts.size == 1) alts[0] else single("any_of", ArrayList<Any?>(alts))
        }

        private fun boxToPredicate(vs: VerbSpace, box: Box): Map<String, Any?> {
            val where = ArrayList<Any?>()
            for (k in vs.dims.indices) {
                val d = vs.dims[k]
                val r = box.ranges[k]
                val st = box.sets[k]
                if (d is NumDim && r != null) {
                    val cells = IntentOmega.numCells(d)
                    where.add(cond(d.path, "gte", cells[r[0]].lo))
                    where.add(cond(d.path, "lte", cells[r[1]].hi))
                } else if (d is CatDim && st != null) {
                    val c = catCondition(d, st)
                    if (c != null) where.add(c)
                }
            }
            val p = LinkedHashMap<String, Any?>()
            p["verb"] = vs.verb
            p["resource"] = "*"
            if (where.isNotEmpty()) p["where"] = where
            return p
        }

        private fun allIn(b: Box, allowed: BooleanArray, nCellsD: IntArray): Boolean {
            for (idx in boxCells(b)) if (!allowed[encode(nCellsD, idx)]) return false
            return true
        }

        /** Cover the allowed cell set exactly with greedily grown maximal boxes; one predicate per box. */
        @JvmStatic
        fun boxesToPredicates(vs: VerbSpace, allowed: BooleanArray): List<Map<String, Any?>> {
            val dn = vs.dims.size
            val nCellsD = IntArray(dn) { IntentOmega.cellCount(vs.dims[it]) }
            val covered = BooleanArray(allowed.size)
            val out = ArrayList<Map<String, Any?>>()
            for (c in allowed.indices) {
                if (!allowed[c] || covered[c]) continue
                val idx = IntentOmega.decodeCell(vs, c.toDouble())
                val box = Box(dn)
                for (k in 0 until dn) {
                    if (vs.dims[k].kind == "num") box.ranges[k] = intArrayOf(idx[k], idx[k])
                    else { val s = LinkedHashSet<Int>(); s.add(idx[k]); box.sets[k] = s }
                }
                for (k in 0 until dn) {
                    val d = vs.dims[k]
                    if (d.kind == "num") {
                        val n = nCellsD[k]
                        val r = box.ranges[k]!!
                        while (r[1] + 1 < n) {
                            r[1]++
                            if (!allIn(box, allowed, nCellsD)) { r[1]--; break }
                        }
                        while (r[0] > 0) {
                            r[0]--
                            if (!allIn(box, allowed, nCellsD)) { r[0]++; break }
                        }
                    } else {
                        val s = box.sets[k]!!
                        for (v in 0 until (d as CatDim).values.size) {
                            if (s.contains(v)) continue
                            s.add(v)
                            if (!allIn(box, allowed, nCellsD)) s.remove(v)
                        }
                    }
                }
                for (bi in boxCells(box)) covered[encode(nCellsD, bi)] = true
                out.add(boxToPredicate(vs, box))
            }
            return out
        }

        private fun seedQuestion(learner: IntentLearner, verb: String, cell: IntArray): Question? {
            val vs = learner.omega.verbs.firstOrNull { it.verb == verb }
            if (vs == null || cell.size != vs.dims.size) return null
            val outcome = IntentOmega.cellRep(vs, cell)
            val p = learner.acceptance(outcome)
            if (p <= 1e-9 || p >= 1 - 1e-9 || learner.isVetoed(outcome)) return null
            return Question(verb, cell.clone(), outcome, p, 0.0)
        }

        @JvmStatic
        fun elicit(learner: IntentLearner, answer: Answer, o: ElicitOptions): ElicitResult {
            val asked = ArrayList<Question>()
            var seedQuestions = 0
            for (s in o.seed) {
                if (asked.size >= o.maxQuestions) break
                val m = learner.metrics()
                if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) break
                val q = seedQuestion(learner, s.first, s.second) ?: continue
                learner.observe(q.outcome, answer.answer(q), "elicitation", null)
                asked.add(q)
                seedQuestions++
            }
            var stop: String? = null
            while (stop == null) {
                val m = learner.metrics()
                if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) stop = "converged"
                else if (asked.size >= o.maxQuestions) stop = "budget"
                else {
                    val q = learner.nextQuestion()
                    if (q == null) stop = "no-disagreement"
                    else {
                        learner.observe(q.outcome, answer.answer(q), "elicitation", null)
                        asked.add(q)
                    }
                }
            }
            val audit = auditRound(learner, answer, o.epsRisk, o.maxQuestions, o.audit, asked)
            if (audit[1] == 1) stop = "budget"
            return ElicitResult(stop!!, asked.size, audit[0], seedQuestions, asked)
        }

        /** The audit round on its own: {questions asked, 1 when the budget ran out before the unconfirmed weight fell to epsRisk}. Appends to asked. */
        @JvmStatic
        fun auditRound(learner: IntentLearner, answer: Answer, epsRisk: Double, maxQuestions: Int, audit: Boolean, asked: MutableList<Question>): IntArray {
            var n = 0
            if (!audit) return intArrayOf(0, 0)
            while (true) {
                val pending = learner.unconfirmedGrantCells()
                var mass = 0.0
                for (x in pending) mass += x.weight
                if (pending.isEmpty() || mass <= epsRisk) return intArrayOf(n, 0)
                if (asked.size >= maxQuestions) return intArrayOf(n, 1)
                val top = pending[0]
                val vs = learner.omega.verbs.first { it.verb == top.verb }
                val oc = IntentOmega.cellRep(vs, top.cell)
                val q = Question(top.verb, top.cell, oc, learner.acceptance(oc), top.weight)
                learner.observe(q.outcome, answer.answer(q), "elicitation", null)
                asked.add(q)
                n++
            }
        }
    }
}
