package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentLearner.AnchorSpec
import net.atlasauth.pca.intent.IntentLearner.HypothesisClassSpec
import net.atlasauth.pca.intent.IntentLearner.LearnerOptions
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * The Intent Map: a content-addressed JSON artifact holding the outcome space, the prior, every answer, the learned
 * acceptance per cell, the conservative grant and the quantified fidelity. Every probability and metric is an integer in parts
 * per million, so the digest is language-portable. [verifyIntentMap] replays the map and re-derives every number.
 * Maps are plain JSON trees (Map / List / String / Boolean / Json.Num or Number / null).
 */
@Suppress("UNCHECKED_CAST")
object IntentMapKit {
    const val INTENT_MAP_DOMAIN = "atlas-pca/intent-map/v1"
    private const val PPM = 1000000.0

    /** JavaScript Math.round for the finite values the map arithmetic produces. */
    internal fun jsRound(x: Double): Double = if (x.isNaN() || x.isInfinite() || Math.abs(x) >= 4503599627370496.0) x else Math.floor(x + 0.5)

    internal fun ppm(x: Double): Double = jsRound(x * PPM)

    internal fun qz(x: Double): Double = jsRound(x * PPM) / PPM

    internal fun num(d: Double): Any? = IntentJs.normalize(d)

    private fun lm(): MutableMap<String, Any?> = LinkedHashMap()

    // ---- options carried by a map ----

    class PolicyData(@JvmField val predicates: Any?, @JvmField val caveats: Any?) {
        internal fun toJson(): MutableMap<String, Any?> = linkedMapOf("predicates" to predicates, "caveats" to (caveats ?: ArrayList<Any?>()))
    }

    class AnchorIn(@JvmField val policy: PolicyData, @JvmField val lambda: Double) {
        internal fun toJson(): MutableMap<String, Any?> = linkedMapOf("policy" to policy.toJson(), "lambda" to num(lambda))

        companion object {
            internal fun fromJson(o: Any?): AnchorIn {
                val m = IntentOmega.obj(o)
                val p = IntentOmega.obj(m["policy"])
                return AnchorIn(PolicyData(p["predicates"], p["caveats"]), IntentOmega.dbl(m["lambda"]))
            }
        }
    }

    class PriorMixCell(@JvmField val verb: String, @JvmField val cell: Double, @JvmField val q: Double)

    /** The serialisable learner parameters (every field optional; null = the default). */
    class MapLearnerOptions {
        @JvmField var eta: Double? = null
        @JvmField var tau: Double? = null
        @JvmField var defaultNullMass: Double? = null
        @JvmField var etaPos: Double? = null
        @JvmField var etaNeg: Double? = null
        @JvmField var strategy: String? = null
        @JvmField var nullMassNumber: Double? = null
        @JvmField var nullMassByVerb: MutableMap<String, Double>? = null
        @JvmField var anchor: AnchorIn? = null
        @JvmField var anchors: MutableList<AnchorIn>? = null
        @JvmField var hypothesisClass: HypothesisClassSpec? = null
        @JvmField var agnosticSlack: Double? = null
        @JvmField var monotonePaths: MutableList<String>? = null
        @JvmField var monotoneOffMass: Double? = null
        @JvmField var priorMixBeta: Double? = null
        @JvmField var priorMixCells: MutableList<PriorMixCell>? = null

        /** The JSON form of these options (absent fields omitted). */
        fun toJson(): Map<String, Any?> {
            val m = lm()
            eta?.let { m["eta"] = num(it) }
            tau?.let { m["tau"] = num(it) }
            strategy?.let { m["strategy"] = it }
            nullMassNumber?.let { m["nullMass"] = num(it) }
            nullMassByVerb?.let { byVerb ->
                val nm = lm()
                for ((k, v) in byVerb) nm[k] = num(v)
                m["nullMass"] = nm
            }
            anchor?.let { m["anchor"] = it.toJson() }
            anchors?.let { m["anchors"] = it.map { a -> a.toJson() }.toMutableList() }
            hypothesisClass?.let { h ->
                val hm = lm()
                hm["kind"] = h.kind
                h.k?.let { hm["k"] = num(it) }
                h.maxRules?.let { hm["maxRules"] = num(it) }
                h.decay?.let { hm["decay"] = num(it) }
                h.conditions?.let { hm["conditions"] = it }
                m["hypothesisClass"] = hm
            }
            agnosticSlack?.let { m["agnosticSlack"] = num(it) }
            monotonePaths?.let { paths ->
                val mo = lm()
                mo["paths"] = ArrayList<Any?>(paths)
                monotoneOffMass?.let { mo["offMass"] = num(it) }
                m["monotone"] = mo
            }
            etaPos?.let { m["etaPos"] = num(it) }
            etaNeg?.let { m["etaNeg"] = num(it) }
            priorMixBeta?.let { beta ->
                val pm = lm()
                pm["beta"] = num(beta)
                pm["cells"] = priorMixCells!!.map { c -> linkedMapOf("verb" to c.verb, "cell" to num(c.cell), "q" to num(c.q)) }.toMutableList()
                m["priorMix"] = pm
            }
            return m
        }

        companion object {
            @JvmStatic
            fun fromJson(o: Any?): MapLearnerOptions {
                val r = MapLearnerOptions()
                if (o == null) return r
                val m = IntentOmega.obj(o)
                r.eta = IntentLearner.numOrNull(m["eta"]); r.tau = IntentLearner.numOrNull(m["tau"])
                r.defaultNullMass = IntentLearner.numOrNull(m["defaultNullMass"])
                r.etaPos = IntentLearner.numOrNull(m["etaPos"]); r.etaNeg = IntentLearner.numOrNull(m["etaNeg"])
                r.strategy = m["strategy"] as String?
                val nm = m["nullMass"]
                if (nm != null) {
                    if (IntentOmega.isNumber(nm)) r.nullMassNumber = IntentOmega.dbl(nm)
                    else {
                        val by = LinkedHashMap<String, Double>()
                        for ((k, v) in IntentOmega.obj(nm)) by[k] = IntentOmega.dbl(v)
                        r.nullMassByVerb = by
                    }
                }
                if (m["anchor"] != null) r.anchor = AnchorIn.fromJson(m["anchor"])
                if (m["anchors"] != null) r.anchors = IntentOmega.arr(m["anchors"]).mapTo(ArrayList()) { AnchorIn.fromJson(it) }
                if (m["hypothesisClass"] != null) r.hypothesisClass = HypothesisClassSpec.fromJson(m["hypothesisClass"])
                r.agnosticSlack = IntentLearner.numOrNull(m["agnosticSlack"])
                if (m["monotone"] != null) {
                    val mo = IntentOmega.obj(m["monotone"])
                    r.monotonePaths = IntentOmega.arr(mo["paths"]).mapTo(ArrayList()) { it as String }
                    r.monotoneOffMass = IntentLearner.numOrNull(mo["offMass"])
                }
                if (m["priorMix"] != null) {
                    val pm = IntentOmega.obj(m["priorMix"])
                    r.priorMixBeta = IntentOmega.dbl(pm["beta"])
                    r.priorMixCells = IntentOmega.arr(pm["cells"]).mapTo(ArrayList()) { c ->
                        val cm = IntentOmega.obj(c)
                        PriorMixCell(cm["verb"] as String, IntentOmega.dbl(cm["cell"]), IntentOmega.dbl(cm["q"]))
                    }
                }
                return r
            }
        }
    }

    // ---- omega <-> JSON ----

    fun omegaToJSON(o: Omega): Map<String, Any?> {
        var equal = true
        for (v in o.verbs) if (!(Math.abs(v.weight - o.verbs[0].weight) < 1e-15)) equal = false
        val verbs = ArrayList<Any?>()
        for (v in o.verbs) {
            val m = lm()
            m["verb"] = v.verb
            m["reversibility"] = v.reversibility
            m["w"] = if (equal) 1L else num(Math.max(1.0, jsRound(v.weight * PPM)))
            m["dims"] = v.dims.map { IntentOmega.dimToJson(it) }.toMutableList()
            verbs.add(m)
        }
        val out = lm()
        out["verbs"] = verbs
        out["approximate"] = ArrayList<Any?>(o.approximate)
        return out
    }

    fun omegaFromJSON(j: Any?): Omega {
        val jm = IntentOmega.obj(j)
        val vs = IntentOmega.arr(jm["verbs"])
        var tot = 0.0
        for (v in vs) tot += IntentOmega.dbl(IntentOmega.obj(v)["w"])
        val verbs = ArrayList<VerbSpace>()
        for (v in vs) {
            val vm = IntentOmega.obj(v)
            val dims = ArrayList<Dim>()
            for (d in IntentOmega.arr(vm["dims"])) {
                val dm = IntentOmega.obj(d)
                if ("num" == dm["kind"]) {
                    val cs: List<Any?> = if (dm["cuts"] == null) ArrayList() else IntentOmega.arr(dm["cuts"])
                    val cuts = DoubleArray(cs.size) { IntentOmega.dbl(cs[it]) }
                    dims.add(NumDim(dm["path"] as String, IntentOmega.dbl(dm["lo"]), IntentOmega.dbl(dm["hi"]), cuts, if (dm["dist"] == null) "uniform" else dm["dist"] as String))
                } else {
                    val cv = ArrayList<CatValue>()
                    // a categorical dimension holds one of its values: with none it can hold nothing, so it is refused (never read as an empty list)
                    val values = dm["values"]
                    if (values !is List<*> || values.isEmpty()) throw IllegalArgumentException("omegaFromJSON: categorical dimension '${dm["path"]}' has no values")
                    for (x in values) cv.add(CatValue(IntentOmega.obj(x)["kind"] as String, IntentOmega.obj(x)["value"] as String))
                    dims.add(IntentOmega.CatDim(dm["path"] as String, cv))
                }
            }
            verbs.add(VerbSpace(vm["verb"] as String, vm["reversibility"] as String, IntentOmega.dbl(vm["w"]) / tot, dims))
        }
        val approx = ArrayList<String>()
        for (x in IntentOmega.arr(jm["approximate"])) approx.add(x as String)
        return Omega(verbs, approx)
    }

    // ---- digests ----

    /** Content address of a grant ({predicates, caveats}). */
    fun grantDigest(g: Any?): String {
        val gm = IntentOmega.obj(g)
        val body = lm()
        body["predicates"] = gm["predicates"]
        body["caveats"] = if (gm.containsKey("caveats")) gm["caveats"] else ArrayList<Any?>()
        val top = lm()
        top["d"] = "atlas-pca/intent-grant/v1"
        top["g"] = body
        return Pca.hashCanonical(IntentJs.normalize(top))
    }

    /** Content address of an Intent Map. */
    fun intentMapDigest(m: Any?): String {
        val top = lm()
        top["d"] = INTENT_MAP_DOMAIN
        top["m"] = m
        return Pca.hashCanonical(IntentJs.normalize(top))
    }

    private fun metricsOf(l: IntentLearner): Map<String, Any?> {
        val m = l.metrics()
        var rmax = 0.0
        for (c in l.cells()) rmax += c.mass * (1 - c.p) * c.harm
        val o = lm()
        o["residual_risk_ppm"] = num(ppm(m.residualRisk))
        o["burden_ppm"] = num(ppm(m.burden))
        o["uncertainty_ppm"] = num(ppm(m.uncertainty))
        o["disagreement_ppm"] = num(ppm(m.disagreementMass))
        o["mean_harm_ppm"] = num(ppm(m.meanHarm))
        o["fidelity_est_ppm"] = num(ppm(if (rmax > 0) 1 - m.residualRisk / rmax else 1.0))
        o["entropy_mbits"] = num(jsRound(m.entropyBits * 1000))
        val lv = m.log2VersionSpace
        o["log2_vs_mbits"] = if (lv == null) null else num(jsRound(lv * 1000))
        o["questions"] = m.questions.toLong()
        o["conflicts"] = m.conflicts.toLong()
        return o
    }

    // ---- learner construction ----

    private val PARAMS: MutableMap<IntentLearner, MapLearnerOptions> = java.util.Collections.synchronizedMap(java.util.WeakHashMap())

    private fun nullMassOf(o: MapLearnerOptions, verb: String): Double {
        o.nullMassNumber?.let { return it }
        val own = o.nullMassByVerb?.get(verb)
        if (own != null) return own
        return o.defaultNullMass ?: 0.2
    }

    private fun anchorOpt(a: AnchorIn): AnchorSpec = AnchorSpec(a.policy.toJson(), jsRound(a.lambda * 1000) / 1000)

    private fun quantizeClass(h: HypothesisClassSpec?): HypothesisClassSpec {
        if (h == null || h.kind == "box") return HypothesisClassSpec.BOX
        val decay = qz(h.decay ?: 0.25)
        return if (h.kind == "union") HypothesisClassSpec("union", h.k, null, decay, null)
        else HypothesisClassSpec("decision-list", null, h.maxRules, decay, h.conditions ?: "box")
    }

    private fun priorMixOf(o: MapLearnerOptions): IntentLearner.PriorMix {
        val byVerb = LinkedHashMap<String, MutableList<DoubleArray>>()
        for (c in o.priorMixCells!!) {
            val q = qz(c.q)
            require(!(!(q >= 0 && q <= 1) || !(c.cell == Math.floor(c.cell) && Math.abs(c.cell) <= 9007199254740991.0) || c.cell < 0)) {
                "pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0"
            }
            byVerb.getOrPut(c.verb) { ArrayList() }.add(doubleArrayOf(c.cell, net.atlasauth.pca.verifier.DetMath.detLn(q), net.atlasauth.pca.verifier.DetMath.detLn(1 - q)))
        }
        return IntentLearner.PriorMix(qz(o.priorMixBeta!!), IntentLearner.PriorWeight { vs, contains ->
            var lw = 0.0
            val ts = byVerb[vs.verb]
            if (ts != null) for (t in ts) lw += if (t[0] <= Int.MAX_VALUE && contains(t[0].toInt())) t[1] else t[2]
            net.atlasauth.pca.verifier.DetMath.detExp(lw)
        })
    }

    /** Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised). */
    @JvmStatic
    fun createLearner(omega: Omega, o: MapLearnerOptions): IntentLearner {
        val opts = LearnerOptions()
        opts.eta = qz(o.eta ?: 0.0)
        opts.tau = qz(o.tau ?: (if ((o.eta ?: 0.0) == 0.0) 1.0 else 0.95))
        opts.strategy = o.strategy ?: "disagreement"
        opts.nullMassFn = { vs -> qz(nullMassOf(o, vs.verb)) }
        opts.hypothesisClass = quantizeClass(o.hypothesisClass)
        val slack = o.agnosticSlack
        if (slack != null) {
            require(slack == Math.floor(slack) && slack >= 0 && slack <= Int.MAX_VALUE) { "pca-intent: agnosticSlack must be a non-negative integer" }
            opts.agnosticSlack = slack.toInt()
        }
        o.anchor?.let { opts.anchor = anchorOpt(it) }
        val anchors = o.anchors
        if (anchors != null && anchors.isNotEmpty()) opts.anchors = anchors.map { anchorOpt(it) }
        o.monotonePaths?.let { opts.monotone = IntentLearner.Monotone(ArrayList(it), qz(o.monotoneOffMass ?: 0.0)) }
        o.etaPos?.let { opts.etaPos = qz(it) }
        o.etaNeg?.let { opts.etaNeg = qz(it) }
        if (o.priorMixBeta != null) opts.priorMix = priorMixOf(o)
        val l = IntentLearner(omega, opts)
        PARAMS[l] = o
        return l
    }

    /** The serialisable parameters a learner was built with (createLearner only). */
    @JvmStatic
    fun learnerOptionsOf(l: IntentLearner): MapLearnerOptions =
        PARAMS[l] ?: throw IllegalStateException("pca-intent: build the learner with createLearner() so its parameters are serialisable")

    private fun anchorJson(a: AnchorIn): Map<String, Any?> = linkedMapOf("policy" to a.policy.toJson(), "lambda_milli" to num(jsRound(a.lambda * 1000)))

    @JvmStatic
    @JvmOverloads
    fun emitIntentMap(l: IntentLearner, intentRef: String? = null): Map<String, Any?> {
        val o = learnerOptionsOf(l)
        val nullMass = lm()
        for (vs in l.omega.verbs) nullMass[vs.verb] = num(ppm(nullMassOf(o, vs.verb)))
        val syn = l.synthesize()
        val grant = lm()
        grant["predicates"] = syn.predicates
        grant["caveats"] = syn.caveats
        val hc = l.hypothesisClass
        val learner = lm()
        learner["hypothesis_class"] = IntentLearner.hypothesisClassName(hc)
        if (hc.kind == "union") {
            val cp = lm()
            cp["k"] = num(hc.k!!)
            cp["decay_ppm"] = num(ppm(hc.decay ?: 0.25))
            learner["class_params"] = cp
        }
        if (hc.kind == "decision-list") {
            val cp = lm()
            cp["max_rules"] = num(hc.maxRules!!)
            cp["decay_ppm"] = num(ppm(hc.decay ?: 0.25))
            learner["class_params"] = cp
        }
        l.agnosticSlack?.let { learner["agnostic_slack"] = it.toLong() }
        learner["eta_ppm"] = num(ppm(l.eta))
        learner["tau_ppm"] = num(ppm(l.tau))
        learner["strategy"] = l.strategy
        learner["null_mass_ppm"] = nullMass
        o.anchor?.let { learner["anchor"] = anchorJson(it) }
        val anchors = o.anchors
        if (anchors != null && anchors.isNotEmpty()) learner["anchors"] = anchors.map { anchorJson(it) }.toMutableList()
        o.monotonePaths?.let { paths ->
            val mo = lm()
            mo["paths"] = ArrayList<Any?>(paths)
            mo["off_ppm"] = num(ppm(o.monotoneOffMass ?: 0.0))
            learner["monotone"] = mo
        }
        if (o.etaPos != null || o.etaNeg != null) {
            val nz = lm()
            nz["eta_pos_ppm"] = num(ppm(l.etaPos))
            nz["eta_neg_ppm"] = num(ppm(l.etaNeg))
            learner["noise"] = nz
        }
        o.priorMixBeta?.let { beta ->
            val pm = lm()
            pm["beta_ppm"] = num(ppm(beta))
            pm["cells"] = o.priorMixCells!!.map { c -> linkedMapOf("verb" to c.verb, "cell" to num(c.cell), "q_ppm" to num(ppm(c.q))) }.toMutableList()
            learner["prior_mix"] = pm
        }
        val obs = ArrayList<Any?>()
        for (x in l.observations) {
            val m = lm()
            m["verb"] = x.verb
            m["values"] = LinkedHashMap(x.values)
            m["y"] = x.y.toLong()
            m["source"] = x.source
            if (x.region != null) m["region"] = x.region.toJson()
            obs.add(m)
        }
        val cells = ArrayList<Any?>()
        for (c in l.cells()) {
            val m = lm()
            m["verb"] = c.verb
            m["cell"] = c.cell.map { it.toLong() }.toMutableList()
            m["p_ppm"] = num(ppm(c.p))
            m["in_grant"] = c.inGrant
            cells.add(m)
        }
        val map = lm()
        map["v"] = 1L
        map["kind"] = "pca-intent-map"
        map["intent_ref"] = intentRef
        val principals = ArrayList<Any?>()
        if (intentRef != null && intentRef.isNotEmpty()) principals.add(intentRef)
        map["principals"] = principals
        map["omega"] = omegaToJSON(l.omega)
        map["learner"] = learner
        map["observations"] = obs
        map["cells"] = cells
        map["grant"] = grant
        map["grant_digest"] = grantDigest(grant)
        map["metrics"] = metricsOf(l)
        return map
    }

    /** The learner parameters a map records (inverse of what emitIntentMap writes). */
    @JvmStatic
    fun mapLearnerOptions(mapO: Any?): MapLearnerOptions {
        val m = IntentOmega.obj(mapO)
        val ln = IntentOmega.obj(m["learner"])
        val r = MapLearnerOptions()
        val by = LinkedHashMap<String, Double>()
        for ((k, v) in IntentOmega.obj(ln["null_mass_ppm"])) by[k] = IntentOmega.dbl(v) / PPM
        r.nullMassByVerb = by
        val cp = if (ln["class_params"] == null) null else IntentOmega.obj(ln["class_params"])
        val hcn = ln["hypothesis_class"] as String?
        val decay = (if (cp != null && cp["decay_ppm"] != null) IntentOmega.dbl(cp["decay_ppm"]) else 250000.0) / PPM
        if ("per-verb-union/v1" == hcn) {
            r.hypothesisClass = HypothesisClassSpec("union", if (cp != null && cp["k"] != null) IntentOmega.dbl(cp["k"]) else 2.0, null, decay, null)
        } else if ("per-verb-decision-list/v1" == hcn || "per-verb-decision-list/v2" == hcn) {
            r.hypothesisClass = HypothesisClassSpec("decision-list", null, if (cp != null && cp["max_rules"] != null) IntentOmega.dbl(cp["max_rules"]) else 2.0, decay,
                if ("per-verb-decision-list/v1" == hcn) "atomic" else "box")
        } else r.hypothesisClass = HypothesisClassSpec.BOX
        r.eta = IntentOmega.dbl(ln["eta_ppm"]) / PPM
        r.tau = IntentOmega.dbl(ln["tau_ppm"]) / PPM
        r.strategy = ln["strategy"] as String?
        if (ln["agnostic_slack"] != null) r.agnosticSlack = IntentOmega.dbl(ln["agnostic_slack"])
        if (ln["anchor"] != null) r.anchor = anchorBack(ln["anchor"])
        if (ln["anchors"] != null && IntentOmega.arr(ln["anchors"]).isNotEmpty()) r.anchors = IntentOmega.arr(ln["anchors"]).mapTo(ArrayList()) { anchorBack(it) }
        if (ln["monotone"] != null) {
            val mo = IntentOmega.obj(ln["monotone"])
            r.monotonePaths = IntentOmega.arr(mo["paths"]).mapTo(ArrayList()) { it as String }
            r.monotoneOffMass = IntentOmega.dbl(mo["off_ppm"]) / PPM
        }
        if (ln["noise"] != null) {
            val nz = IntentOmega.obj(ln["noise"])
            r.etaPos = IntentOmega.dbl(nz["eta_pos_ppm"]) / PPM
            r.etaNeg = IntentOmega.dbl(nz["eta_neg_ppm"]) / PPM
        }
        if (ln["prior_mix"] != null) {
            val pm = IntentOmega.obj(ln["prior_mix"])
            r.priorMixBeta = IntentOmega.dbl(pm["beta_ppm"]) / PPM
            r.priorMixCells = IntentOmega.arr(pm["cells"]).mapTo(ArrayList()) { c ->
                val cm = IntentOmega.obj(c)
                PriorMixCell(cm["verb"] as String, IntentOmega.dbl(cm["cell"]), IntentOmega.dbl(cm["q_ppm"]) / PPM)
            }
        }
        return r
    }

    private fun anchorBack(o: Any?): AnchorIn {
        val a = IntentOmega.obj(o)
        val p = IntentOmega.obj(a["policy"])
        return AnchorIn(PolicyData(p["predicates"], p["caveats"]), IntentOmega.dbl(a["lambda_milli"]) / 1000)
    }

    /** Rebuild the learner a map describes (outcome space + prior + observations). */
    @JvmStatic
    fun learnerFromMap(mapO: Any?): IntentLearner {
        val m = IntentOmega.obj(mapO)
        val l = createLearner(omegaFromJSON(m["omega"]), mapLearnerOptions(mapO))
        for (oo in IntentOmega.arr(m["observations"])) {
            val o = IntentOmega.obj(oo)
            val vals = LinkedHashMap<String, Any?>()
            for ((k, v) in IntentOmega.obj(o["values"])) vals[k] = if (IntentOmega.isNumber(v)) IntentOmega.dbl(v) else v
            l.observe(Outcome(o["verb"] as String, vals), IntentOmega.dbl(o["y"]).toInt(), o["source"] as String, if (o["region"] == null) null else IntentRegion.Region.fromJson(o["region"]))
        }
        return l
    }

    private fun jsStr(v: Any?): String {
        if (v == null) return "null"
        if (IntentOmega.isNumber(v)) return (IntentJs.normalize(IntentOmega.dbl(v)) as Json.Num).raw
        return v.toString()
    }

    /** Replay a single-principal map and check every number, every cell and the grant. */
    @JvmStatic
    fun verifyIntentMap(mapO: Any?): Map<String, Any?> {
        val problems = ArrayList<Any?>()
        try {
            if (mapO !is Map<*, *>) return result(false, listOf("not an intent map v1"))
            val m = IntentOmega.obj(mapO)
            if (!(IntentOmega.isNumber(m["v"]) && IntentOmega.dbl(m["v"]) == 1.0) || "pca-intent-map" != m["kind"]) return result(false, listOf("not an intent map v1"))
            if (IntentOmega.arr(m["principals"]).size > 1 || m["aggregation"] != null) {
                return result(false, listOf("combined map: verify each principal map and recombine with verifyAggregate"))
            }
            val ir = m["intent_ref"]
            val r = emitIntentMap(learnerFromMap(m), if (ir == null) null else ir as String)
            val gd = m["grant_digest"]
            if (r["grant_digest"] != gd || grantDigest(m["grant"]) != gd) problems.add("grant does not match the replayed posterior")
            val rc = IntentOmega.arr(r["cells"])
            val mc = IntentOmega.arr(m["cells"])
            if (rc.size != mc.size) problems.add("cell count differs")
            else {
                for (i in rc.indices) {
                    val c = IntentOmega.obj(rc[i])
                    val x = IntentOmega.obj(mc[i])
                    if (c["verb"] != x["verb"] || c["in_grant"] != x["in_grant"] || !(IntentOmega.isNumber(x["p_ppm"]) && Math.abs(IntentOmega.dbl(c["p_ppm"]) - IntentOmega.dbl(x["p_ppm"])) <= 2)) problems.add("cell $i differs") // a missing or non-numeric claim is a mismatch
                }
            }
            val rm = IntentOmega.obj(r["metrics"])
            val mm = IntentOmega.obj(m["metrics"])
            for (k in rm.keys) {
                val a = rm[k]
                val b = mm[k]
                val differs: Boolean = if (a == null || (mm.containsKey(k) && b == null)) !(a == null && mm.containsKey(k) && b == null)
                else !(mm.containsKey(k) && IntentOmega.isNumber(b) && Math.abs(IntentOmega.dbl(a) - IntentOmega.dbl(b)) <= 2) // missing, non-numeric or NaN: a mismatch
                if (differs) problems.add("metric $k differs (${if (mm.containsKey(k)) jsStr(b) else "undefined"} claimed, ${jsStr(a)} replayed)")
            }
        } catch (e: RuntimeException) {
            problems.add("replay failed")
        }
        return result(problems.isEmpty(), problems)
    }

    private fun result(ok: Boolean, problems: List<*>): Map<String, Any?> = linkedMapOf("ok" to ok, "problems" to ArrayList<Any?>(problems))

    /** A runtime divergence is one more labelled observation; a negative one also vetoes the cell. Returns {before, after, grant}. */
    @JvmStatic
    fun applyDivergence(l: IntentLearner, outcome: Outcome, y: Int): Map<String, Any?> {
        var before = 0L
        for (c in l.cells()) if (c.inGrant) before++
        l.observe(outcome, y, "runtime", null)
        var after = 0L
        for (c in l.cells()) if (c.inGrant) after++
        val s = l.synthesize()
        val grant = lm()
        grant["predicates"] = s.predicates
        grant["caveats"] = s.caveats
        val r = lm()
        r["before"] = before
        r["after"] = after
        r["grant"] = grant
        return r
    }

    // ---- committed (Merkle) form ----

    private fun numCellCount(lo: Double, hi: Double, cuts: List<Any?>): Long {
        var n = 0L
        var cur = lo
        for (co in cuts) {
            val c = IntentOmega.dbl(co)
            if (c < lo || c > hi) continue
            if (cur <= c - 1) n++
            n++
            cur = c + 1
        }
        return if (cur <= hi) n + 1 else n
    }

    private const val MAX_CELLS = 1L shl 20

    /** The committed form of an Intent Map; secret (32 bytes) derives every leaf salt. */
    @JvmStatic
    fun commitIntentMap(mapO: Any?, secret: ByteArray?): IntentMapCommit.CommittedMap {
        val m = IntentOmega.obj(mapO)
        val verbs = IntentOmega.arr(IntentOmega.obj(m["omega"])["verbs"])
        val headers = ArrayList<Map<String, Any?>>()
        for (vo in verbs) {
            val v = IntentOmega.obj(vo)
            val dims = ArrayList<Any?>()
            for (d in IntentOmega.arr(v["dims"])) {
                val dm = IntentOmega.obj(d)
                val o = lm()
                if ("num" == dm["kind"]) {
                    val lo = IntentOmega.dbl(dm["lo"])
                    val hi = IntentOmega.dbl(dm["hi"])
                    val cuts = ArrayList<Any?>()
                    if (dm["cuts"] != null) for (c in IntentOmega.arr(dm["cuts"])) if (IntentOmega.dbl(c) >= lo && IntentOmega.dbl(c) <= hi) cuts.add(c)
                    o["kind"] = "num"; o["path"] = dm["path"]; o["lo"] = dm["lo"]; o["hi"] = dm["hi"]; o["cuts"] = cuts
                } else {
                    val vals = ArrayList<Any?>()
                    if (dm["values"] != null) for (x in IntentOmega.arr(dm["values"])) {
                        val xm = IntentOmega.obj(x)
                        vals.add(linkedMapOf("kind" to xm["kind"], "value" to xm["value"]))
                    }
                    o["kind"] = "cat"; o["path"] = dm["path"]; o["values"] = vals
                }
                dims.add(o)
            }
            headers.add(linkedMapOf("verb" to v["verb"], "dims" to dims))
        }
        val cells = LinkedHashMap<String, List<Map<String, Any?>>>()
        for (vo in verbs) {
            val v = IntentOmega.obj(vo)
            val dims = IntentOmega.arr(v["dims"])
            val counts = LongArray(dims.size)
            var total = 1L
            for (j in counts.indices) {
                val dm = IntentOmega.obj(dims[j])
                counts[j] = if ("num" == dm["kind"]) numCellCount(IntentOmega.dbl(dm["lo"]), IntentOmega.dbl(dm["hi"]), if (dm["cuts"] == null) ArrayList() else IntentOmega.arr(dm["cuts"]))
                else if (dm["values"] == null) 0L else IntentOmega.arr(dm["values"]).size.toLong()
                total *= counts[j]
            }
            require(total <= MAX_CELLS) { "commitIntentMap: too many cells for ${v["verb"]}" }
            val slots = arrayOfNulls<Map<String, Any?>>(total.toInt())
            for (co in IntentOmega.arr(m["cells"])) {
                val c = IntentOmega.obj(co)
                if (v["verb"] != c["verb"]) continue
                val cell = IntentOmega.arr(c["cell"])
                require(cell.size == counts.size) { "commitIntentMap: cell of ${v["verb"]} has the wrong arity" }
                var flat = 0L
                for (j in cell.indices) {
                    val io = cell[j]
                    val i = if (IntentOmega.isNumber(io)) IntentOmega.dbl(io) else Double.NaN
                    require(i == Math.floor(i) && Math.abs(i) <= 9007199254740991.0 && i >= 0 && i < counts[j]) { "commitIntentMap: cell index out of range for ${v["verb"]}" }
                    flat = flat * counts[j] + i.toLong()
                }
                slots[flat.toInt()] = linkedMapOf("cell" to ArrayList<Any?>(cell), "p_ppm" to c["p_ppm"], "in_grant" to c["in_grant"])
            }
            for (s in slots) require(s != null) { "commitIntentMap: the map does not list every cell of ${v["verb"]}" }
            cells[v["verb"] as String] = slots.map { it!! }
        }
        val metrics = lm()
        val mm = IntentOmega.obj(m["metrics"])
        for ((k, x) in mm) if (k != "log2_vs_mbits") metrics[k] = x
        if (mm["log2_vs_mbits"] != null) metrics["log2_vs_mbits"] = mm["log2_vs_mbits"]
        return IntentMapCommit.commitMap(headers, cells, metrics, Pca.hashCanonical(IntentJs.normalize(m["learner"])), secret)
    }
}
