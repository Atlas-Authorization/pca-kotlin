package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of multi-principal and cross-organisation aggregation of Intent Maps. */
@Suppress("UNCHECKED_CAST")
class IntentMultiAggDiffTest {
    private val m = "ref-intent-multi-agg"

    private fun mp(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    private fun buildMap(omega: Any?, mapOpts: Any?, observations: Any?, ref: Any?): Map<String, Any?> {
        val l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts))
        for (xo in ls(observations)) {
            val x = mp(xo)
            l.observe(IntentOmega.outcomeFromJson(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, null)
        }
        return IntentMapKit.emitIntentMap(l, ref as String?)
    }

    private fun maps(omega: Any?, principals: Any?, mapOpts: Any?): List<Any?> = ls(principals).map { p -> buildMap(omega, mapOpts, mp(p)["observations"], mp(p)["ref"]) }

    private fun add(m: MutableMap<String, Any?>, key: String, d: Double) { m[key] = Json.Num((IntentOmega.dbl(m[key]) + d).toLong().toString()) }

    private val muts: List<(MutableMap<String, Any?>) -> Unit> = listOf(
        { _ -> },
        { x -> add(mp(x["metrics"]), "residual_risk_ppm", 7.0) },
        { x -> val c = mp(ls(x["cells"])[0]); c["in_grant"] = !(c["in_grant"] as Boolean) },
        { x -> x["aggregation"] = null },
        { x -> val a = mp(x["aggregation"]); a["rule"] = "quorum"; a["k"] = Json.Num("1") },
        { x -> mp(x["aggregation"])["vetoers"] = ArrayList<Any?>() },
    )

    // the reference takes its third argument as an options object and reads opts.orgs; the corpus passes the org map itself, so only an
    // {orgs: {...}} member counts
    private fun orgsOf(o: Any?): Map<String, Any?> = if (o is Map<*, *> && o["orgs"] is Map<*, *>) mp(o["orgs"]) else LinkedHashMap()

    @Test fun aggregateScenario() = OracleCases.each(m, "aggregateScenario") { a ->
        val ms = maps(a[0], a[1], a[4])
        val rule = mp(a[2])
        val orgs = orgsOf(a[3])
        val agg = IntentMultiAgg.aggregateIntentMaps(ms, rule, orgs)
        val tampered = ArrayList<Any?>()
        for (f in muts) {
            val copy = mp(IntentJs.normalize(agg))
            f(copy)
            tampered.add(IntentMultiAgg.verifyAggregate(copy, ms, orgs))
        }
        linkedMapOf(
            "aggregate" to agg,
            "digest" to IntentMapKit.intentMapDigest(agg),
            "rule" to IntentMultiAgg.ruleOf(agg),
            "verify" to IntentMultiAgg.verifyAggregate(agg, ms, orgs),
            "tampered" to tampered,
            "wrongInputs" to IntentMultiAgg.verifyAggregate(agg, ArrayList(ms.subList(0, Math.max(0, ms.size - 1))), orgs),
            "combined" to (if ("unanimity" == rule["kind"] && !rule.containsKey("vetoers")) IntentMultiAgg.combineIntentMaps(ms, orgs) else null),
        )
    }

    @Test fun aggregateTwoOmegas() = OracleCases.each(m, "aggregateTwoOmegas") { a ->
        val ps = ls(a[2])
        val ms = listOf(
            buildMap(a[0], null, mp(ps[0])["observations"], mp(ps[0])["ref"]),
            buildMap(a[1], null, ArrayList<Any?>(), mp(ps[1])["ref"]),
        )
        IntentMultiAgg.aggregateIntentMaps(ms, mp(a[3]), null)
    }

    @Test fun aggregateOfAggregate() = OracleCases.each(m, "aggregateOfAggregate") { a ->
        val ms = maps(a[0], a[1], null)
        val agg = IntentMultiAgg.aggregateIntentMaps(ms, mp(a[2]), null)
        IntentMultiAgg.aggregateIntentMaps(listOf(agg, ms[0]), mp(a[2]), null)
    }

    @Test fun liftOfAggregate() = OracleCases.each(m, "liftOfAggregate") { a ->
        val ms = maps(a[0], a[1], null)
        val agg = IntentMultiAgg.aggregateIntentMaps(ms.subList(0, 1), mp(a[2]), null)
        IntentMultiAgg.liftIntentMap(agg, IntentOmega.omegaFromJson(a[0]))
    }

    @Test fun crossScenario() = OracleCases.each(m, "crossScenario") { a ->
        val ms = ls(a[0]).map { s ->
            val sp = mp(s)
            buildMap(sp["omega"], sp["mapOpts"], sp["observations"], sp["ref"])
        }
        val rule = mp(a[1])
        val orgs = orgsOf(a[2])
        val r = IntentMultiAgg.crossOrgAggregate(ms, rule, orgs)
        val tampered = ArrayList<Any?>()
        for (f in muts) {
            val copy = mp(IntentJs.normalize(r.aggregate))
            f(copy)
            tampered.add(IntentMultiAgg.verifyCrossOrgAggregate(copy, ms, orgs))
        }
        linkedMapOf(
            "aggregate" to r.aggregate,
            "lifted" to r.lifted,
            "omega" to IntentOmega.omegaToJson(r.omega),
            "digest" to IntentMapKit.intentMapDigest(r.aggregate),
            "verify" to IntentMultiAgg.verifyCrossOrgAggregate(r.aggregate, ms, orgs),
            "tampered" to tampered,
            "wrong" to IntentMultiAgg.verifyCrossOrgAggregate(r.aggregate, ArrayList(ms.subList(Math.min(1, ms.size), ms.size)), orgs),
        )
    }

    @Test fun liftScenario() = OracleCases.each(m, "liftScenario") { a ->
        IntentMultiAgg.liftIntentMap(buildMap(a[0], a[1], a[2], a[3]), IntentOmega.omegaFromJson(a[4]))
    }

    @Test fun omegaKey() = OracleCases.each(m, "omegaKey") { a -> IntentMultiAgg.omegaKey(IntentOmega.omegaFromJson(a[0])) }
}
