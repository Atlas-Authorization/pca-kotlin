package net.atlasauth.pca.analyzer

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference oracle for the policy analyzer (one test per exported fn). */
@Suppress("UNCHECKED_CAST")
class AnalyzerDiffTest {
    private val module = "ref-analyzer"

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun opt(a: List<Any?>, i: Int): Map<String, Any?>? = a.getOrNull(i) as? Map<String, Any?>
    private fun obj(vararg kv: Pair<String, Any?>): MutableMap<String, Any?> = linkedMapOf(*kv)
    private fun num(o: Any?): Double = (o as Json.Num).raw.toDouble()

    private val keys = HashMap<String, Keys.EdKey>()

    /** The key of a label: seed = sha256("atlas-pca-conformance/" + label). */
    @Synchronized private fun key(label: String): Keys.EdKey = keys.getOrPut(label) { Keys.edFromSeed(OracleCases.seed(label)) }

    /** "$key:LABEL" stands for the public key of LABEL. */
    private fun keyed(v: Any?): String? = if (v is String && v.startsWith("\$key:")) key(v.substring(5)).id() else v as String?

    /** The reference's {"$num": "Infinity"} spelling of a non-finite number, and the inverse. */
    private fun out(v: Any?): Any? = when (v) {
        is Json.Num, is Double -> {
            val d = if (v is Double) v else (v as Json.Num).raw.toDouble()
            if (d.isNaN() || d.isInfinite()) obj("\$num" to (if (d.isNaN()) "NaN" else if (d > 0) "Infinity" else "-Infinity")) else v
        }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { r -> for ((k, x) in v) r[k as String] = out(x) }
        is List<*> -> v.map { out(it) }
        else -> v
    }

    private fun revive(v: Any?): Any? = when {
        v is Map<*, *> && v.size == 1 && v["\$num"] is String -> Json.Num(v["\$num"] as String)
        v is Map<*, *> -> LinkedHashMap<String, Any?>().also { r -> for ((k, x) in v) r[k as String] = revive(x) }
        v is List<*> -> v.map { revive(it) }
        else -> v
    }

    private fun each(fn: String, f: (List<Any?>) -> Any?) = OracleCases.each(module, fn) { a -> out(f(a)) }

    private fun iv(o: Any?): Field.NumInterval {
        if (o == null) return Field.FULL_INTERVAL
        val x = m(o)
        return Field.NumInterval(num(x["lo"]), x["loInclusive"] == true, num(x["hi"]), x["hiInclusive"] == true)
    }

    // ---- pure pieces ----

    @Test fun analyzeCaveats() = each("analyzeCaveats") { a -> CaveatAnalysis.analyzeCaveats(a[0]).toJson() }
    @Test fun numericConjunctionSatisfiable() = each("numericConjunctionSatisfiable") { a -> Field.numericConjunctionSatisfiable(l(a[0])) }
    @Test fun predicateNumericSatisfiable() = each("predicateNumericSatisfiable") { a -> Analyzer.predicateNumericSatisfiable(a[0]) }
    @Test fun tightenInterval() = each("tightenInterval") { a -> Field.tightenInterval(iv(a[0]), a.getOrNull(1), a.getOrNull(2)).toJson() }
    @Test fun intervalEmpty() = each("intervalEmpty") { a -> Field.intervalEmpty(iv(a[0])) }
    @Test fun fieldProbes() = each("fieldProbes") { a -> Field.fieldProbes(l(a[0])) }
    @Test fun vetoesFromConstitution() = each("vetoesFromConstitution") { a -> Constitution.vetoesFromConstitution(a[0]) }
    @Test fun toModel() = each("toModel") { a -> Enumerate.toModel(a[0]).toJson() }

    private fun probesOf(inO: Any?): Enumerate.Probes {
        val inp = m(inO)
        val pi = Enumerate.ProbeInputs()
        for (s in l(inp["predicateSets"])) pi.predicateSets.add(l(s))
        if (inp["extraVerbs"] != null) pi.extraVerbs.addAll(l(inp["extraVerbs"]))
        if (inp["extraResources"] != null) pi.extraResources.addAll(l(inp["extraResources"]))
        if (inp["extraFieldConditions"] != null) for (c in l(inp["extraFieldConditions"])) pi.extraFieldConditions.add(arrayOf(m(c)["path"], m(c)["cond"]))
        pi.varyReversibility = inp["varyReversibility"] == true
        return Enumerate.collectProbes(pi)
    }

    @Test fun collectProbes() = each("collectProbes") { a ->
        val p = probesOf(a[0])
        val fields = p.fields.map { f -> obj("path" to f.path, "values" to f.values.map { v -> if (v === Enumerate.ABSENT) obj("\$absent" to true) else v }) }
        obj("verbs" to ArrayList(p.verbs), "resources" to ArrayList(p.resources), "revClasses" to ArrayList(p.revClasses), "fields" to fields)
    }

    @Test fun representatives() = each("representatives") { a ->
        val p = probesOf(a[0])
        check(Enumerate.productSize(p) <= 400) { "grid too large for the corpus" }
        Enumerate.representatives(p).map { r ->
            val rep = obj("verb" to r.verb, "resource" to r.resource)
            if (r.revClass != null) rep["revClass"] = r.revClass
            rep["assignments"] = LinkedHashMap(r.assignments)
            rep["action"] = Enumerate.repToAction(r)
            rep
        }
    }

    // ---- concrete decisions ----

    @Test fun decideAction() = each("decideAction") { a -> Enumerate.decideAction(Enumerate.toModel(a[0]), a[1]) }
    @Test fun admitsConcrete() = each("admitsConcrete") { a -> Analyzer.admitsConcrete(a[0], a[1] as Map<String, Any?>?) }
    @Test fun witnessOf() = each("witnessOf") { a -> Coverage.witnessOf(Enumerate.toModel(a[0]), m(a[1])) }

    @Test fun vetoApplies() = each("vetoApplies") { a ->
        val x = LinkedHashMap(m(a[1]))
        if (!x.containsKey("params")) x["params"] = obj()
        val subject = m(a[1])["subject"] ?: obj()
        val env = m(a[1])["env"] ?: obj()
        Enumerate.vetoApplies(a[0], obj("action" to x, "subject" to subject, "env" to env))
    }

    // ---- reachable, vacuity, relations, intent ----

    @Test fun reachable() = each("reachable") { a -> Analyzer.reachable(a[0], opt(a, 1), opt(a, 2)) }
    @Test fun alwaysDenies() = each("alwaysDenies") { a -> Analyzer.alwaysDenies(a[0], a.getOrNull(1) as String?, opt(a, 2)) }
    @Test fun alwaysAllows() = each("alwaysAllows") { a -> Analyzer.alwaysAllows(a[0], a.getOrNull(1) as String?, opt(a, 2)) }
    @Test fun subsumes() = each("subsumes") { a -> Analyzer.subsumes(a[0], a[1], opt(a, 2)) }
    @Test fun disjoint() = each("disjoint") { a -> Analyzer.disjoint(a[0], a[1], opt(a, 2)) }
    @Test fun equivalent() = each("equivalent") { a -> Analyzer.equivalent(a[0], a[1], opt(a, 2)) }
    @Test fun intentConformance() = each("intentConformance") { a -> Analyzer.intentConformance(a[0], opt(a, 1), opt(a, 2)) }

    // ---- exposure ----

    @Test fun thresholdsOf() = each("thresholdsOf") { a -> Exposure.thresholdsOf(Enumerate.toModel(a[0]), a[1] as String) }
    @Test fun maxExposure() = each("maxExposure") { a -> Exposure.maxExposure(a[0], opt(a, 1)) }
    @Test fun escalationSurface() = each("escalationSurface") { a -> Exposure.escalationSurface(a[0], opt(a, 1)) }
    @Test fun delegationEnvelope() = each("delegationEnvelope") { a -> Exposure.delegationEnvelope(l(a[0]), opt(a, 1)) }
    @Test fun diffPolicies() = each("diffPolicies") { a -> Exposure.diffPolicies(a[0], a[1], opt(a, 2)) }
    @Test fun diffGate() = each("diffGate") { a -> Exposure.diffGate(m(revive(a[0])), opt(a, 1)) }

    @Test fun findWithBackend() = each("findWithBackend") { a ->
        val spec = m(a[1])
        val backend = object : Exposure.WitnessBackend {
            override fun name(): String = spec["name"] as String
            override fun find(query: Map<String, Any?>): Map<String, Any?> = m(spec["result"])
        }
        Exposure.findWithBackend(backend, m(a[0]))
    }

    @Test fun dagExposure() = each("dagExposure") { a -> DagExposure.dagExposure(m(a[0])) }

    // ---- residual, discovery, filters ----

    @Test fun residual() = each("residual") { a -> Residual.residual(a[0], opt(a, 1), opt(a, 2)) }
    @Test fun residualPolicy() = each("residualPolicy") { a -> Residual.residualPolicy(m(a[0])) }
    @Test fun evaluateResidual() = each("evaluateResidual") { a -> Residual.evaluateResidual(m(a[0]), m(a[1])) }
    @Test fun whatMayIDo() = each("whatMayIDo") { a -> Residual.whatMayIDo(a[0], l(a[1]), opt(a, 2), opt(a, 3)) }
    @Test fun toFilter() = each("toFilter") { a -> Filter.toFilter(Residual.residual(a[0], opt(a, 1), opt(a, 2)), opt(a, 3)) }
    @Test fun toUcast() = each("toUcast") { a -> Filter.toUcast(m(a[0])) }
    @Test fun evalFilter() = each("evalFilter") { a -> Filter.evalFilter(m(a[0]), m(a[1])) }
    @Test fun evalUcast() = each("evalUcast") { a -> Filter.evalUcast(m(a[0]), m(a[1])) }

    // ---- narrowing, coverage, flip, validation, tests ----

    @Test fun suggestNarrowing() = each("suggestNarrowing") { a -> Narrowing.suggestNarrowing(a[0], l(a[1]), opt(a, 2)) }
    @Test fun signAccessRequest() = each("signAccessRequest") { a -> Narrowing.signAccessRequest(m(a[0]), key(a[1] as String), key(a[1] as String).id()) }
    @Test fun verifyAccessRequest() = each("verifyAccessRequest") { a -> Narrowing.verifyAccessRequest(a[0], keyed(a.getOrNull(1))) }
    @Test fun coverage() = each("coverage") { a -> Coverage.coverage(a[0], l(a[1]), opt(a, 2)) }
    @Test fun coverageGate() = each("coverageGate") { a -> Coverage.coverageGate(m(a[0]), opt(a, 1)) }
    @Test fun minimalFlip() = each("minimalFlip") { a -> Flip.minimalFlip(a[0], opt(a, 1), opt(a, 2)) }
    @Test fun verbShapes() = each("verbShapes") { a -> Validate.verbShapes(a[0]) }
    @Test fun verbShapesFromActionDefs() = each("verbShapesFromActionDefs") { a -> Validate.verbShapesFromActionDefs(l(a[0])) }
    @Test fun validatePolicyAgainstSchema() = each("validatePolicyAgainstSchema") { a -> Validate.validatePolicyAgainstSchema(a[0], a[1], opt(a, 2)) }
    @Test fun policyTestsDoc() = each("policyTestsDoc") { a -> TestRunner.policyTestsDoc(a[0], l(a[1])) }
    @Test fun runPolicyTests() = each("runPolicyTests") { a -> TestRunner.runPolicyTests(a[0], m(a[1]), opt(a, 2)?.get("requireDigest") == true) }
    @Test fun generateBoundaryTests() = each("generateBoundaryTests") { a -> TestRunner.generateBoundaryTests(a[0], opt(a, 1)) }
    @Test fun decideAll() = each("decideAll") { a -> TestRunner.decideAll(a[0], m(a[1])) }
    @Test fun signPolicyTests() = each("signPolicyTests") { a -> TestRunner.signPolicyTests(m(a[0]), key(a[1] as String), key(a[1] as String).id()) }
    @Test fun verifyPolicyTests() = each("verifyPolicyTests") { a -> TestRunner.verifyPolicyTests(a[0], keyed(a.getOrNull(1))) }
}
