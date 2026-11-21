package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertThrows
import org.junit.Test

/** Replays the reference vectors of the Intent Map: emit, verify under tampering, digests, options, the committed form and divergence. */
@Suppress("UNCHECKED_CAST")
class IntentMapKitDiffTest {
    private val m = "ref-intent-map"

    private fun mp(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>

    private fun ls(o: Any?): MutableList<Any?> = o as MutableList<Any?>

    private fun add(m: MutableMap<String, Any?>, key: String, d: Double) { m[key] = Json.Num((IntentOmega.dbl(m[key]) + d).toLong().toString()) }

    private fun secret(seed: Int): ByteArray = ByteArray(32) { ((seed + 7 * it) and 255).toByte() }

    private val muts: List<(MutableMap<String, Any?>) -> Unit> = listOf(
        { _ -> },
        { x -> add(mp(x["metrics"]), "residual_risk_ppm", 5.0) },
        { x -> add(mp(ls(x["cells"])[0]), "p_ppm", 3.0) },
        { x -> val c = mp(ls(x["cells"])[0]); c["in_grant"] = !(c["in_grant"] as Boolean) },
        { x -> x["grant_digest"] = "AAAA" },
        { x -> val o = ls(x["observations"]); if (o.isNotEmpty()) o.removeAt(o.size - 1) },
        { x -> x["kind"] = "x" },
        { x -> x["principals"] = arrayListOf<Any?>("a", "b") },
        { x -> x["aggregation"] = linkedMapOf<String, Any?>("rule" to "unanimity") },
        { x -> mp(x["metrics"]).remove("log2_vs_mbits") },
        { x -> add(mp(x["learner"]), "eta_ppm", 100000.0) },
        { x -> add(mp(x["metrics"]), "questions", 1.0) },
        { x -> val c = ls(x["cells"]); c.removeAt(c.size - 1) },
        { x -> mp(ls(mp(x["omega"])["verbs"])[0])["w"] = Json.Num("5") },
        { x -> mp(x["metrics"])["log2_vs_mbits"] = null },
        { x -> add(mp(ls(x["cells"])[0]), "p_ppm", 2.0) },
        { x -> add(mp(ls(x["cells"])[0]), "p_ppm", 1.0) },
    )

    private fun outcome(x: Map<String, Any?>) = IntentOmega.outcomeFromJson(x)

    private fun learnerOf(omega: IntentOmega.Omega, opts: Any?, obs: Any?): IntentLearner {
        val l = IntentMapKit.createLearner(omega, MapLearnerOptions.fromJson(opts))
        for (xo in ls(obs)) {
            val x = mp(xo)
            l.observe(outcome(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, null)
        }
        return l
    }

    private fun scenario(a: List<Any?>): Any? {
        val omega = IntentOmega.omegaFromJson(a[0])
        val l = learnerOf(omega, a[1], a[2])
        val ref = a[3] as String?
        val seed = IntentOmega.dbl(a[4]).toInt()
        val map = IntentMapKit.emitIntentMap(l, ref)
        val tampered = ArrayList<Any?>()
        for (f in muts) {
            val copy = mp(IntentJs.normalize(map))
            f(copy)
            tampered.add(IntentMapKit.verifyIntentMap(copy))
        }
        tampered.add(IntentMapKit.verifyIntentMap(null))
        tampered.add(IntentMapKit.verifyIntentMap(linkedMapOf<String, Any?>("v" to Json.Num("2"))))
        val out = LinkedHashMap<String, Any?>()
        out["map"] = map
        out["digest"] = IntentMapKit.intentMapDigest(map)
        out["grantDigest"] = IntentMapKit.grantDigest(map["grant"])
        out["verify"] = IntentMapKit.verifyIntentMap(map)
        out["tampered"] = tampered
        out["options"] = IntentMapKit.mapLearnerOptions(map).toJson()
        out["omegaRoundtrip"] = IntentMapKit.omegaToJSON(IntentMapKit.omegaFromJSON(map["omega"]))
        val commit = LinkedHashMap<String, Any?>()
        try {
            val cm = IntentMapKit.commitIntentMap(map, secret(seed))
            commit["map_commit"] = cm.mapCommit
            commit["size"] = cm.size.toLong()
            commit["leaves"] = cm.leavesJson()
            val ds = ArrayList<Any?>()
            for (vs in omega.verbs) {
                val t = IntentOmega.verbCellCount(vs)
                for (f in doubleArrayOf(0.0, Math.floor(t / 2), t - 1)) {
                    val oc = IntentOmega.cellRep(vs, IntentOmega.decodeCell(vs, f))
                    val params = LinkedHashMap<String, Any?>()
                    var resource: Any? = null
                    for ((k, v) in oc.values) {
                        if (k == "action.resource") resource = v else params[k.substring("action.params.".length)] = v
                    }
                    ds.add(cm.disclose(vs.verb, resource, params))
                }
            }
            commit["disclosures"] = ds
        } catch (e: RuntimeException) {
            commit.clear()
            commit["error"] = true
        }
        out["commit"] = commit
        return out
    }

    @Test fun mapScenarios() = OracleCases.each(m, "mapScenario") { a -> scenario(a) }

    @Test fun commitIntentMap() = OracleCases.each(m, "commitIntentMap") { a ->
        val cm = IntentMapKit.commitIntentMap(a[0], secret(3))
        linkedMapOf("map_commit" to cm.mapCommit, "size" to cm.size.toLong(), "leaves" to cm.leavesJson())
    }

    @Test fun commitRejectsShortSecret() {
        assertThrows(IllegalArgumentException::class.java) { IntentMapCommit.commitMap(ArrayList(), LinkedHashMap(), LinkedHashMap(), "x", ByteArray(31)) }
    }

    @Test fun grantDigest() = OracleCases.each(m, "grantDigest") { a -> IntentMapKit.grantDigest(a[0]) }

    @Test fun intentMapDigest() = OracleCases.each(m, "intentMapDigest") { a -> IntentMapKit.intentMapDigest(a[0]) }

    @Test fun omegaToJSON() = OracleCases.each(m, "omegaToJSON") { a -> IntentMapKit.omegaToJSON(IntentOmega.omegaFromJson(a[0])) }

    @Test fun omegaFromJSON() = OracleCases.each(m, "omegaFromJSON") { a -> IntentOmega.omegaToJson(IntentMapKit.omegaFromJSON(a[0])) }

    @Test fun divergence() = OracleCases.each(m, "divergence") { a ->
        val l = learnerOf(IntentOmega.omegaFromJson(a[0]), a[1], a[2])
        val out = ArrayList<Any?>()
        for (d in ls(a[3])) {
            val dm = mp(d)
            out.add(IntentMapKit.applyDivergence(l, outcome(mp(dm["outcome"])), IntentOmega.dbl(dm["y"]).toInt()))
        }
        out
    }
}
