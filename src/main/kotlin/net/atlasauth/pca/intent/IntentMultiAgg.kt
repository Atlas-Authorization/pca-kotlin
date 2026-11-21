package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMulti.NormalRule
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json

/**
 * Multi-principal aggregation over replay-verified Intent Maps: the joint grant of a rule (unanimity, quorum, weighted, vetoers) per
 * cell, its recomputation check, and the cross-organisation form that lifts maps over different outcome spaces onto their common
 * refinement first. Maps are plain JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object IntentMultiAgg {
    private const val PPM = 1000000.0

    private fun ppm(x: Double): Double = IntentMapKit.jsRound(x * PPM)

    private fun num(d: Double): Any? = IntentJs.normalize(d)

    private fun lm(): MutableMap<String, Any?> = LinkedHashMap()

    private fun truthy(o: Any?): Boolean = o != null && o != false && !(o is String && o.isEmpty())

    /** The error text of an own (reference-defined) failure, else a generic marker for engine-specific faults. */
    internal fun ownMessage(e: RuntimeException): String {
        val m = e.message
        if (m != null && (m.startsWith("aggregateIntentMaps") || m.startsWith("ruleOf") || m.startsWith("liftIntentMap") || m.startsWith("crossOrgAggregate") ||
                m.startsWith("commonRefinement") || m.startsWith("pca-intent") || m.startsWith("refineOmega"))) return m
        return "error"
    }

    /** JSON.stringify of a JSON tree (insertion order). */
    internal fun stringify(v: Any?): String {
        val sb = StringBuilder()
        str(sb, v)
        return sb.toString()
    }

    private fun isSurrogate(c: Char): Boolean = Character.isSurrogate(c)

    private fun str(sb: StringBuilder, v: Any?) {
        if (v == null) sb.append("null")
        else if (v is Boolean) sb.append(v)
        else if (v is String) {
            sb.append('"')
            for (i in v.indices) {
                val c = v[i]
                when (c) {
                    '"' -> sb.append("\\\"")
                    '\\' -> sb.append("\\\\")
                    '\b' -> sb.append("\\b")
                    '\u000c' -> sb.append("\\f")
                    '\n' -> sb.append("\\n")
                    '\r' -> sb.append("\\r")
                    '\t' -> sb.append("\\t")
                    else -> {
                        val lone = isSurrogate(c) && !(Character.isHighSurrogate(c) && i + 1 < v.length && Character.isLowSurrogate(v[i + 1])) &&
                            !(Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(v[i - 1]))
                        if (c.code < 0x20 || lone) sb.append(String.format("\\u%04x", c.code)) else sb.append(c)
                    }
                }
            }
            sb.append('"')
        } else if (IntentOmega.isNumber(v)) sb.append((IntentJs.normalize(IntentOmega.dbl(v)) as Json.Num).raw)
        else if (v is List<*>) {
            sb.append('[')
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                str(sb, x)
            }
            sb.append(']')
        } else {
            sb.append('{')
            var first = true
            for ((k, x) in v as Map<String, Any?>) {
                if (!first) sb.append(',')
                first = false
                str(sb, k)
                sb.append(':')
                str(sb, x)
            }
            sb.append('}')
        }
    }

    private fun mp(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    private fun nullKey(m: Map<String, Any?>, k: String): Boolean = m.containsKey(k) && m[k] == null

    private fun metric(m: Map<String, Any?>, k: String): Double {
        val v = m[k]
        return if (v == null) 0.0 else IntentOmega.dbl(v)
    }

    /** Aggregate single-principal maps over a shared outcome space under a rule (orgs: intent_ref to organisation label, optional). */
    @JvmStatic
    fun aggregateIntentMaps(maps: List<Any?>, rule: Map<String, Any?>, orgs: Map<String, Any?>?): Map<String, Any?> {
        require(maps.isNotEmpty()) { "aggregateIntentMaps: no maps" }
        val om = stringify(mp(maps[0])["omega"])
        for (m in maps) require(stringify(mp(m)["omega"]) == om) { "aggregateIntentMaps: maps must share Omega (lift them with crossOrgAggregate)" }
        for (mo in maps) {
            val m = mp(mo)
            require(!(truthy(m["aggregation"]) || IntentOmega.arr(m["principals"]).size != 1 || m["intent_ref"] !is String)) {
                "aggregateIntentMaps: every input must be a single-principal map with an intent_ref"
            }
        }
        val refs = maps.map { mp(it)["intent_ref"] as String }
        require(LinkedHashSet(refs).size == refs.size) { "aggregateIntentMaps: duplicate principal" }
        val n: NormalRule = IntentMulti.normalizeRule(rule, refs)
        val omega = IntentMapKit.omegaFromJSON(mp(maps[0])["omega"])
        val stats = ArrayList<DoubleArray>()
        for (vs in omega.verbs) {
            val nc = IntentOmega.verbCellCount(vs)
            var c = 0
            while (c < nc) {
                val s = IntentOmega.cellStats(vs, IntentOmega.decodeCell(vs, c.toDouble()), IntentOmega.DEFAULT_HARM)
                stats.add(doubleArrayOf(s.mass, s.harm))
                c++
            }
        }
        val c0 = IntentOmega.arr(mp(maps[0])["cells"])
        val cells = ArrayList<Any?>()
        for (i in c0.indices) {
            val c = mp(c0[i])
            val ps = DoubleArray(maps.size)
            val ins = BooleanArray(maps.size)
            for (k in maps.indices) {
                val ck = mp(IntentOmega.arr(mp(maps[k])["cells"])[i])
                ps[k] = IntentOmega.dbl(ck["p_ppm"]) / PPM
                ins[k] = ck["in_grant"] == true
            }
            val o = lm()
            o["verb"] = c["verb"]
            o["cell"] = c["cell"]
            o["p_ppm"] = num(ppm(IntentMulti.jointAcceptance(n, ps)))
            o["in_grant"] = IntentMulti.ruleAdmits(n, ins)
            cells.add(o)
        }
        val predicates = ArrayList<Map<String, Any?>>()
        val order = listOf("reversible", "rate_limited", "irreversible")
        var worstRev = -1
        var off = 0
        for (vs in omega.verbs) {
            val nc = IntentOmega.verbCellCount(vs).toInt()
            val allowed = BooleanArray(nc)
            var any = false
            for (c in 0 until nc) if (mp(cells[off + c])["in_grant"] == true) { allowed[c] = true; any = true }
            off += nc
            if (!any) continue
            worstRev = Math.max(worstRev, order.indexOf(vs.reversibility))
            predicates.addAll(IntentLearner.boxesToPredicates(vs, allowed))
        }
        val caveats = ArrayList<Map<String, Any?>>()
        if (worstRev >= 0) caveats.add(linkedMapOf<String, Any?>("type" to "reversibility_max", "class" to order[worstRev]))
        val grant = lm()
        grant["predicates"] = predicates
        grant["caveats"] = caveats
        val pR = DoubleArray(maps.size)
        val pB = DoubleArray(maps.size)
        val pF = DoubleArray(maps.size)
        for (i in maps.indices) {
            var rr = 0.0
            var bb = 0.0
            var rmax = 0.0
            val mc = IntentOmega.arr(mp(maps[i])["cells"])
            for (j in mc.indices) {
                val p = IntentOmega.dbl(mp(mc[j])["p_ppm"]) / PPM
                val st = stats[j]
                rmax += st[0] * (1 - p) * st[1]
                if (mp(cells[j])["in_grant"] == true) rr += st[0] * (1 - p) * st[1]
                else bb += st[0] * p
            }
            pR[i] = rr; pB[i] = bb; pF[i] = if (rmax > 0) 1 - rr / rmax else 1.0
        }
        val kind = rule["kind"]
        val agg = lm()
        agg["rule"] = kind
        if ("quorum" == kind) agg["k"] = rule["k"]
        if ("weighted" == kind) {
            val w = lm()
            for (i in refs.indices) w[refs[i]] = num(n.weights[i])
            agg["weights"] = w
            agg["threshold"] = rule["threshold"]
        }
        val vetoers = ArrayList<Any?>()
        for (i in refs.indices) if (n.veto[i]) vetoers.add(refs[i])
        agg["vetoers"] = vetoers
        val per = ArrayList<Any?>()
        var maxR = Double.NEGATIVE_INFINITY
        var maxB = Double.NEGATIVE_INFINITY
        var minF = Double.POSITIVE_INFINITY
        for (i in refs.indices) {
            val x = lm()
            x["intent_ref"] = refs[i]
            val org = orgs?.get(refs[i])
            if (truthy(org)) x["org"] = org
            val r = ppm(pR[i])
            val b = ppm(pB[i])
            x["residual_risk_ppm"] = num(r)
            x["burden_ppm"] = num(b)
            per.add(x)
            maxR = Math.max(maxR, r); maxB = Math.max(maxB, b); minF = Math.min(minF, pF[i])
        }
        agg["per_principal"] = per
        var anyNull = false
        for (m in maps) if (nullKey(mp(mp(m)["metrics"]), "log2_vs_mbits")) anyNull = true
        val metrics = lm()
        metrics["residual_risk_ppm"] = num(maxR)
        metrics["burden_ppm"] = num(maxB)
        metrics["uncertainty_ppm"] = num(worstOf(maps, "uncertainty_ppm", false))
        metrics["disagreement_ppm"] = num(worstOf(maps, "disagreement_ppm", false))
        metrics["mean_harm_ppm"] = mp(mp(maps[0])["metrics"])["mean_harm_ppm"]
        metrics["fidelity_est_ppm"] = num(ppm(minF))
        metrics["entropy_mbits"] = num(worstOf(maps, "entropy_mbits", true))
        metrics["log2_vs_mbits"] = if (anyNull) null else num(worstOf(maps, "log2_vs_mbits", true))
        metrics["questions"] = num(worstOf(maps, "questions", true))
        metrics["conflicts"] = num(worstOf(maps, "conflicts", true))
        val obs = ArrayList<Any?>()
        for (m in maps) obs.addAll(IntentOmega.arr(mp(m)["observations"]))
        val out = lm()
        out["v"] = 1L
        out["kind"] = "pca-intent-map"
        out["intent_ref"] = null
        out["principals"] = ArrayList<Any?>(refs)
        out["omega"] = mp(maps[0])["omega"]
        out["learner"] = mp(maps[0])["learner"]
        out["observations"] = obs
        out["cells"] = cells
        out["grant"] = grant
        out["grant_digest"] = IntentMapKit.grantDigest(grant)
        out["metrics"] = metrics
        out["aggregation"] = agg
        return out
    }

    private fun worstOf(maps: List<Any?>, k: String, sum: Boolean): Double {
        var acc = if (sum) 0.0 else Double.NEGATIVE_INFINITY
        for (m in maps) {
            val v = metric(mp(mp(m)["metrics"]), k)
            acc = if (sum) acc + v else Math.max(acc, v)
        }
        return acc
    }

    /** The unanimity rule: the joint grant is the intersection of the principals' conservative grants. */
    @JvmStatic
    fun combineIntentMaps(maps: List<Any?>, orgs: Map<String, Any?>?): Map<String, Any?> = aggregateIntentMaps(maps, linkedMapOf<String, Any?>("kind" to "unanimity"), orgs)

    /** The rule an aggregated map records. */
    @JvmStatic
    fun ruleOf(aggMap: Any?): Map<String, Any?> {
        val ao = mp(aggMap)["aggregation"]
        require(truthy(ao)) { "ruleOf: not an aggregated map" }
        val a = mp(ao)
        val r = lm()
        val kind = a["rule"]
        if ("unanimity" == kind) { r["kind"] = "unanimity"; r["vetoers"] = a["vetoers"] }
        else if ("quorum" == kind) { r["kind"] = "quorum"; r["k"] = a["k"]; r["vetoers"] = a["vetoers"] }
        else { r["kind"] = "weighted"; r["weights"] = a["weights"]; r["threshold"] = a["threshold"]; r["vetoers"] = a["vetoers"] }
        return r
    }

    private fun result(ok: Boolean, problems: List<String>): Map<String, Any?> = linkedMapOf("ok" to ok, "problems" to ArrayList<Any?>(problems))

    private fun problemText(r: Map<String, Any?>): String = IntentOmega.arr(r["problems"]).joinToString("; ") { it as String }

    /** Verify an aggregated map against its inputs: replay-verify each input, recompute the aggregate and compare digests. */
    @JvmStatic
    fun verifyAggregate(agg: Any?, inputs: List<Any?>, orgs: Map<String, Any?>?): Map<String, Any?> {
        val problems = ArrayList<String>()
        try {
            for (i in inputs.indices) {
                val r = IntentMapKit.verifyIntentMap(inputs[i])
                if (r["ok"] != true) problems.add("input $i: ${problemText(r)}")
            }
            if (problems.isNotEmpty()) return result(false, problems)
            val again = aggregateIntentMaps(inputs, ruleOf(agg), orgs)
            if (IntentMapKit.intentMapDigest(again) != IntentMapKit.intentMapDigest(agg)) problems.add("aggregate does not match its recomputation")
        } catch (e: RuntimeException) {
            problems.add("recompute failed: " + ownMessage(e))
        }
        return result(problems.isEmpty(), problems)
    }

    /** Lift a replay-verified single-principal map onto a refinement of its outcome space (unseen verbs are denied: null mass 1). */
    @JvmStatic
    fun liftIntentMap(mapO: Any?, target: Omega): Map<String, Any?> {
        val m = mp(mapO)
        require(!(truthy(m["aggregation"]) || IntentOmega.arr(m["principals"]).size > 1)) { "liftIntentMap: lift single-principal maps, then aggregate" }
        val src = IntentMapKit.omegaFromJSON(m["omega"])
        val o = IntentMapKit.mapLearnerOptions(m)
        val known = LinkedHashSet<String>()
        for (v in src.verbs) known.add(v.verb)
        val nullMass = LinkedHashMap<String, Double>()
        for (vs in target.verbs) {
            val own = o.nullMassByVerb?.get(vs.verb)
            nullMass[vs.verb] = if (known.contains(vs.verb)) (own ?: 0.2) else 1.0
        }
        val o2 = IntentMapKit.MapLearnerOptions()
        o2.eta = o.eta; o2.tau = o.tau; o2.defaultNullMass = o.defaultNullMass; o2.etaPos = o.etaPos; o2.etaNeg = o.etaNeg; o2.strategy = o.strategy
        o2.nullMassByVerb = nullMass
        o2.anchor = o.anchor; o2.anchors = o.anchors; o2.hypothesisClass = o.hypothesisClass; o2.agnosticSlack = o.agnosticSlack
        o2.monotonePaths = o.monotonePaths; o2.monotoneOffMass = o.monotoneOffMass; o2.priorMixBeta = o.priorMixBeta; o2.priorMixCells = o.priorMixCells
        val l = IntentMapKit.createLearner(target, o2)
        for (obo in IntentOmega.arr(m["observations"])) {
            val ob = mp(obo)
            val verb = ob["verb"] as String
            val svs = src.verbs.firstOrNull { it.verb == verb }
            val tvs = target.verbs.firstOrNull { it.verb == verb }
            require(svs != null && tvs != null) { "liftIntentMap: verb $verb missing from Omega" }
            val own = LinkedHashMap<String, Any?>()
            for ((k, v) in mp(ob["values"])) own[k] = if (IntentOmega.isNumber(v)) IntentOmega.dbl(v) else v
            val values = LinkedHashMap(own)
            for (d in tvs.dims) if (!values.containsKey(d.path)) values[d.path] = IntentOmega.repValue(d, 0)
            val cell = IntentOmega.cellOf(svs, Outcome(verb, own))
            requireNotNull(cell) { "liftIntentMap: an observation of $verb lies outside the map's own Omega" }
            val region = if (ob["region"] != null) IntentRegion.Region.fromJson(ob["region"]) else IntentRegion.regionOfCell(svs, cell)
            l.observe(Outcome(verb, values), IntentOmega.dbl(ob["y"]).toInt(), ob["source"] as String, region)
        }
        val ir = m["intent_ref"]
        return IntentMapKit.emitIntentMap(l, if (ir == null) null else ir as String)
    }

    /** The aggregate, the lifted maps and the common refinement of a cross-organisation aggregation. */
    class CrossOrg internal constructor(@JvmField val aggregate: Map<String, Any?>, @JvmField val lifted: List<Any?>, @JvmField val omega: Omega)

    /** Replay-verify every map, lift them all onto the common refinement of their spaces, then aggregate. */
    @JvmStatic
    fun crossOrgAggregate(maps: List<Any?>, rule: Map<String, Any?>, orgs: Map<String, Any?>?): CrossOrg {
        for (i in maps.indices) {
            val r = IntentMapKit.verifyIntentMap(maps[i])
            require(r["ok"] == true) { "crossOrgAggregate: map $i does not verify: ${problemText(r)}" }
        }
        val omegas = maps.map { IntentMapKit.omegaFromJSON(mp(it)["omega"]) }
        val omega = IntentMulti.commonRefinement(omegas)
        val lifted = maps.map { liftIntentMap(it, omega) }
        return CrossOrg(aggregateIntentMaps(lifted, rule, orgs), lifted, omega)
    }

    /** Verify a cross-org aggregate by recomputing it from the original maps. */
    @JvmStatic
    fun verifyCrossOrgAggregate(agg: Any?, maps: List<Any?>, orgs: Map<String, Any?>?): Map<String, Any?> {
        try {
            val again = crossOrgAggregate(maps, ruleOf(agg), orgs).aggregate
            return if (IntentMapKit.intentMapDigest(again) == IntentMapKit.intentMapDigest(agg)) result(true, listOf()) else result(false, listOf("aggregate does not match its recomputation"))
        } catch (e: RuntimeException) {
            return result(false, listOf(ownMessage(e)))
        }
    }

    /** The outcome space as canonical-order JSON text (for callers that compare maps). */
    @JvmStatic
    fun omegaKey(o: Omega): String = stringify(IntentMapKit.omegaToJSON(o))
}
