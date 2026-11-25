package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The objective risk functional against the reference corpus (ref-objective-risk, 4052 cases): the canonical action, the inverse registry and
 * reversibility, the resource graph and blast radius, native and BYO embedders, goal commitments and distance, calibration, harm currency,
 * objectiveRisk and its dispute-game oracle. Every function, every case; a reference throw is a refusal.
 */
@Suppress("UNCHECKED_CAST")
class ObjectiveRiskRefDiffTest {
    private val mod = "ref-objective-risk"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun list(o: Any?): List<Any?> = o as List<Any?>

    private fun a(x: List<Any?>, i: Int): Any? = OracleCases.decNum(x[i])

    private fun nd(o: Any?): Double? = IntentJs.num(o)

    /** A non-finite number in a result is spelled `{"$num": text}` in the corpus. */
    private fun enc(v: Any?): Any? = when (v) {
        is Double -> if (v.isNaN() || v.isInfinite()) linkedMapOf<String, Any?>("\$num" to AttestUtil.jsNumString(v)) else v
        is Json.Num -> if (v.raw == "NaN" || v.raw == "Infinity" || v.raw == "-Infinity") linkedMapOf<String, Any?>("\$num" to v.raw) else v
        is List<*> -> v.map { enc(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = enc(x) }
        else -> v
    }

    private fun registry(s: Any?): ObjectiveRisk.InMemoryInverseRegistry {
        val m = map(s)!!
        val r = ObjectiveRisk.InMemoryInverseRegistry(((m["trusted"] as List<Any?>?) ?: emptyList()).map { it as String })
        for (e in ((m["entries"] as List<Any?>?) ?: emptyList())) { val l = list(e); r.register(l[0] as String, map(l[1])!!) }
        return r
    }

    private fun graph(s: Any?): ObjectiveRisk.ResourceGraph {
        val m = map(s)!!
        val g = ObjectiveRisk.ResourceGraph()
        for (nn in ((m["nodes"] as List<Any?>?) ?: emptyList())) g.addNode(map(nn)!!)
        for (e in ((m["edges"] as List<Any?>?) ?: emptyList())) g.addEdge(map(e)!!)
        return g
    }

    private fun inferOf(i: Map<String, Any?>, dims: Int?): (String) -> Any? = { j ->
        if (i["throws"] == true) throw RuntimeException("infer boom")
        if (i["notArray"] == true) "x"
        else if (i["byLen"] == true) List((dims ?: nd(i["dims"])?.toInt() ?: 4)) { k -> StoreJs.num((j.length + k).toLong()) }
        else i["vector"]
    }

    private fun byo(d: Map<String, Any?>, claimed: Any?, infer: Map<String, Any?>): ObjectiveRisk.Embedder {
        val dims = if (infer["byLen"] == true) nd(d["dims"])?.toInt() else null
        return ObjectiveRisk.byoEmbedder(d, inferOf(infer, dims), claimed as String?)
    }

    private fun embedder(s: Any?): ObjectiveRisk.Embedder {
        val m = map(s)!!
        return when (m["scheme"]) {
            "native" -> ObjectiveRisk.nativeHashEmbedder(map(m["config"])!!)
            "fixed" -> object : ObjectiveRisk.Embedder {
                override val modelId: String = m["modelId"] as String
                override val config: Any? = m["config"]
                override val dims: Double = nd(m["dims"])!!
                override fun embed(action: Map<String, Any?>): Any? = m["vector"]
            }
            else -> byo(map(m["descriptor"])!!, m["claimedModelId"], map(m["infer"])!!)
        }
    }

    private fun ctx(cc: Any?): ObjectiveRisk.ObjectiveRiskContext {
        val c = map(cc)!!
        return ObjectiveRisk.ObjectiveRiskContext(
            registry(c["registry"]), (c["authorizedKinds"] as List<Any?>).map { it as String }.toSet(), graph(c["graph"]), map(c["scope"]),
            embedder(c["embedder"]), map(c["goal"])!!, map(c["commitments"])!!, c["denominations"] as List<Any?>, map(c["weights"])!!,
            nd(c["taint"]) ?: Double.NaN, nd(c["age"]) ?: Double.NaN, if (c.containsKey("attestedUncertainty")) nd(c["attestedUncertainty"]) else null,
            c["calibration"] as List<Any?>?,
        )
    }

    private fun eps(o: Any?): Double? = if (o == null) null else nd(o) ?: Double.NaN

    @Test fun everyFunction() {
        OracleCases.each(mod, "constants") { _ ->
            linkedMapOf(
                "METRIC" to ObjectiveRisk.METRIC, "DEFAULT_EPSILON" to Json.Num("0.000244140625"), "NATIVE_SCHEME" to ObjectiveRisk.NATIVE_SCHEME,
                "DEFAULT_MAX_PARAM_LEAVES" to ObjectiveRisk.DEFAULT_MAX_PARAM_LEAVES, "DEFAULT_NATIVE_CONFIG" to ObjectiveRisk.DEFAULT_NATIVE_CONFIG,
            )
        }
        OracleCases.each(mod, "canonicalAction") { x -> ObjectiveRisk.canonicalAction(a(x, 0)) }
        OracleCases.each(mod, "canonicalActionJson") { x -> ObjectiveRisk.canonicalActionJson(a(x, 0)) }
        OracleCases.each(mod, "canonicalActionDigest") { x -> ObjectiveRisk.canonicalActionDigest(a(x, 0)) }
        OracleCases.each(mod, "registryOps") { x ->
            val r = ObjectiveRisk.InMemoryInverseRegistry(list(x[0]).map { it as String })
            list(x[1]).map { o ->
                val op = list(o)
                when (op[0] as String) {
                    "register" -> { r.register(op[1] as String, map(op[2])!!); null }
                    "lookup" -> r.lookup(op[1] as String)
                    "trustedVerifiers" -> r.trustedVerifiers()
                    else -> r.digest()
                }
            }
        }
        OracleCases.each(mod, "registryDigest") { x -> registry(x[0]).digest() }
        OracleCases.each(mod, "reversibility") { x -> ObjectiveRisk.reversibility(map(x[0])!!, registry(x[1]), list(x[2]).map { it as String }.toSet()) }
        OracleCases.each(mod, "graphBuild") { x -> val g = graph(a(x, 0)); linkedMapOf("size" to g.size, "digest" to g.digest()) }
        OracleCases.each(mod, "graphReachable") { x -> graph(a(x, 0)).reachable(x[1] as String, map(a(x, 2))) }
        OracleCases.each(mod, "graphNode") { x -> enc(graph(a(x, 0)).node(x[1] as String)) }
        OracleCases.each(mod, "blastRadius") { x -> enc(ObjectiveRisk.blastRadius(map(x[0])!!, graph(a(x, 1)), map(a(x, 2)))) }
        OracleCases.each(mod, "nativeEmbed") { x ->
            val e = ObjectiveRisk.nativeHashEmbedder(map(x[0])!!)
            linkedMapOf("modelId" to e.modelId, "dims" to e.dims, "config" to e.config, "vector" to e.embed(map(x[1])!!))
        }
        OracleCases.each(mod, "byoModelId") { x -> ObjectiveRisk.byoModelId(map(a(x, 0))!!) }
        OracleCases.each(mod, "byoEmbed") { x ->
            val e = byo(map(x[0])!!, x[1], map(x[2])!!)
            linkedMapOf("modelId" to e.modelId, "dims" to e.dims, "vector" to e.embed(map(x[3])!!))
        }
        OracleCases.each(mod, "validateVector") { x -> ObjectiveRisk.validateVector(a(x, 0), nd(x[1])!!).map { StoreJs.num(it) } }
        OracleCases.each(mod, "conformanceCheck") { x -> ObjectiveRisk.conformanceCheck(embedder(x[0]), list(x[1])) }
        OracleCases.each(mod, "commitGoal") { x -> val e = eps(x[2]); if (e == null) ObjectiveRisk.commitGoal(embedder(x[0]), a(x, 1)) else ObjectiveRisk.commitGoal(embedder(x[0]), a(x, 1), e) }
        OracleCases.each(mod, "verifyGoalCommitment") { x -> ObjectiveRisk.verifyGoalCommitment(a(x, 0), embedder(x[1])) }
        OracleCases.each(mod, "vectorDistance") { x ->
            val e = eps(a(x, 2))
            val d = if (e == null) ObjectiveRisk.vectorDistance(list(a(x, 0)), list(a(x, 1))) else ObjectiveRisk.vectorDistance(list(a(x, 0)), list(a(x, 1)), e)
            enc(StoreJs.num(d))
        }
        OracleCases.each(mod, "committedDistanceChecked") { x -> ObjectiveRisk.committedDistanceChecked(map(a(x, 0))!!, a(x, 1), embedder(x[2])) }
        OracleCases.each(mod, "committedDistance") { x -> StoreJs.num(ObjectiveRisk.committedDistance(a(x, 0), a(x, 1), embedder(x[2]))) }
        OracleCases.each(mod, "calibrate") { x -> StoreJs.num(ObjectiveRisk.calibrate(nd(a(x, 0)) ?: Double.NaN, list(a(x, 1)))) }
        OracleCases.each(mod, "conformalThreshold") { x -> ObjectiveRisk.conformalThreshold(list(a(x, 0)), nd(a(x, 1)) ?: Double.NaN)?.let { enc(StoreJs.num(it)) } }
        OracleCases.each(mod, "calibrationDigest") { x -> ObjectiveRisk.calibrationDigest(list(a(x, 0))) }
        OracleCases.each(mod, "harmReport") { x -> enc(ObjectiveRisk.harmReport(map(a(x, 0))!!, list(a(x, 1)))) }
        OracleCases.each(mod, "objectiveRisk") { x -> enc(ObjectiveRisk.objectiveRisk(a(x, 0), ctx(a(x, 1)))) }
        OracleCases.each(mod, "objectiveRiskOracle") { x -> enc(ObjectiveRisk.objectiveRiskOracle(ctx(a(x, 0)), x[1], a(x, 2))) }
        val fns = setOf(
            "constants", "canonicalAction", "canonicalActionJson", "canonicalActionDigest", "registryDigest", "registryOps", "reversibility", "graphBuild", "graphNode",
            "graphReachable", "blastRadius", "nativeEmbed", "byoModelId", "byoEmbed", "validateVector", "commitGoal", "verifyGoalCommitment", "vectorDistance",
            "committedDistanceChecked", "committedDistance", "conformanceCheck", "calibrationDigest", "calibrate", "conformalThreshold", "harmReport", "objectiveRisk",
            "objectiveRiskOracle",
        )
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(4052, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
