package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of bond sizing, the semantic judge threshold, action routing, IC-Att conformance and JIT consent. */
@Suppress("UNCHECKED_CAST")
class IntentRoutingDiffTest {
    private val m = "ref-intent-routing"

    private fun mp(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    private fun inf(x: Double): Any = if (!x.isNaN() && !x.isInfinite()) x else "inf"

    private fun make(omega: Any?, mapOpts: Any?, obs: Any?): IntentLearner {
        val l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts))
        for (xo in ls(obs)) {
            val x = mp(xo)
            l.observe(IntentOmega.outcomeFromJson(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, null)
        }
        return l
    }

    private fun metrics(r: IntentLearner.LearnerMetrics): Map<String, Any?> = linkedMapOf(
        "residualRisk" to r.residualRisk, "burden" to r.burden, "uncertainty" to r.uncertainty, "entropyBits" to r.entropyBits,
        "log2VersionSpace" to r.log2VersionSpace, "disagreementMass" to r.disagreementMass, "meanHarm" to r.meanHarm,
        "questions" to r.questions.toDouble(), "conflicts" to r.conflicts.toDouble(),
    )

    @Test fun bondAmount() = OracleCases.each(m, "bondAmount") { a -> IntentBond.bondAmount(IntentBond.BondPolicy.fromJson(a[0]), IntentOmega.dbl(a[1])) }

    @Test fun quantizeScore() = OracleCases.each(m, "quantizeScore") { a -> IntentSemantic.quantizeScore(IntentOmega.dbl(a[0])) }

    @Test fun verifyJudgeVerdict() = OracleCases.each(m, "verifyJudgeVerdict") { a ->
        val e = mp(a[1])
        val pins = if (a[2] == null || mp(a[2])["pqPins"] == null) null else mp(mp(a[2])["pqPins"])
        IntentSemantic.verifyJudgeVerdict(a[0], e["actionDigest"] as String?, e["goalCommitment"] as String?, pins)
    }

    @Test fun conformalThreshold() = OracleCases.each(m, "conformalThreshold") { a -> inf(IntentSemantic.conformalThreshold(a[0])) }

    @Test fun empiricalFalseAllowRate() = OracleCases.each(m, "empiricalFalseAllowRate") { a -> IntentSemantic.empiricalFalseAllowRate(a[0], IntentOmega.dbl(a[1])) }

    @Test fun verifySemanticThreshold() = OracleCases.each(m, "verifySemanticThreshold") { a ->
        val r = IntentSemantic.verifySemanticThreshold(a[0], mp(a[1]), null as IntentSemantic.SemanticAttestation?)
        if (r["cutoff"] != null) r["cutoff"] = inf(r["cutoff"] as Double)
        r
    }

    private fun route(a: List<Any?>, veto: Boolean): Any? {
        val l = make(a[0], a[1], a[2])
        val ro = IntentRouting.RouteOptions.fromJson(a[4])
        if (veto) for (x in ls(a[3])) l.observe(IntentOmega.outcomeFromJson(x), 0, "runtime", null)
        return ls(a[3]).map { IntentRouting.routeAction(l, IntentOmega.outcomeFromJson(it), ro) }
    }

    @Test fun routeScenario() = OracleCases.each(m, "routeScenario") { a -> route(a, false) }

    @Test fun routeVetoScenario() = OracleCases.each(m, "routeVetoScenario") { a -> route(a, true) }

    private fun add(x: MutableMap<String, Any?>, key: String, d: Double) { x[key] = Json.Num((IntentOmega.dbl(x[key]) + d).toLong().toString()) }

    private val muts: List<(MutableMap<String, Any?>) -> Unit> = listOf(
        { _ -> },
        { x -> x["ok"] = !(x["ok"] as Boolean) },
        { x -> add(x, "aggregate_score_ppm", 1.0) },
        { x -> val d = ls(x["verdict_digests"]) as MutableList<Any?>; if (d.isNotEmpty()) d.removeAt(d.size - 1) },
        { x -> add(x, "k", 1.0) },
        { x -> x["reason"] = "x" },
    )

    @Test fun conformanceScenario() = OracleCases.each(m, "conformanceScenario") { a ->
        val l = make(a[0], a[1], a[2])
        val input = IntentRouting.judgeInputOf(l, IntentOmega.outcomeFromJson(a[3]), mp(a[4]))
        val verdicts = ls(a[5])
        val copts = mp(a[6])
        val att = IntentRouting.intentConformanceAttestation(input, verdicts, copts, null)
        val tampered = ArrayList<Any?>()
        for (f in muts) {
            val copy = mp(IntentJs.normalize(att))
            f(copy)
            tampered.add(IntentRouting.verifyICAtt(copy, input, verdicts, copts, null))
        }
        tampered.add(IntentRouting.verifyICAtt(att, input, ArrayList(verdicts.subList(Math.min(1, verdicts.size), verdicts.size)), copts, null))
        linkedMapOf(
            "input" to input,
            "att" to att,
            "digest" to IntentRuntime.icAttDigest(att),
            "verify" to IntentRouting.verifyICAtt(att, input, verdicts, copts, null),
            "tampered" to tampered,
            "check" to IntentRouting.checkIntentConformance({ verdicts }, input, copts, null),
        )
    }

    @Test fun jitScenario() = OracleCases.each(m, "jitScenario") { a ->
        val l = make(a[0], a[1], a[2])
        val oc = IntentOmega.outcomeFromJson(a[3])
        val c = mp(a[5])
        val req = IntentRouting.jitConsentRequest(l, oc, c["intentRef"] as String?, c["mapDigest"] as String?)
        linkedMapOf(
            "req" to req,
            "digest" to IntentRuntime.jitConsentDigest(req),
            "result" to IntentRouting.recordJitDecision(l, req, a[4] as String?),
            "metrics" to metrics(l.metrics()),
            "route" to IntentRouting.routeAction(l, oc, IntentRouting.RouteOptions()),
        )
    }
}
