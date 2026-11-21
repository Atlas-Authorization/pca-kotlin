package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of layered consent, quorum rules and grant metrics. */
@Suppress("UNCHECKED_CAST")
class IntentLayersDiffTest {
    private val m = "ref-intent-layers"

    private fun map(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    private fun strs(o: Any?): List<String> = IntentOmega.arr(o).map { it as String }

    private fun bools(o: Any?): BooleanArray = IntentOmega.arr(o).let { l -> BooleanArray(l.size) { l[it] as Boolean } }

    private fun dbls(o: Any?): DoubleArray = IntentOmega.arr(o).let { l -> DoubleArray(l.size) { IntentOmega.dbl(l[it]) } }

    @Test fun normalizeRule() = OracleCases.each(m, "normalizeRule") { a -> IntentMulti.normalizeRule(map(a[0]), strs(a[1])).toJson() }

    @Test fun effectiveVetoers() = OracleCases.each(m, "effectiveVetoers") { a -> IntentMulti.effectiveVetoers(map(a[0]), strs(a[1])) }

    @Test fun ruleAdmits() = OracleCases.each(m, "ruleAdmits") { a -> IntentMulti.ruleAdmits(IntentMulti.NormalRule.fromJson(a[0]), bools(a[1])) }

    @Test fun jointAcceptance() = OracleCases.each(m, "jointAcceptance") { a -> IntentMulti.jointAcceptance(IntentMulti.NormalRule.fromJson(a[0]), dbls(a[1])) }

    @Test fun commonRefinement() = OracleCases.each(m, "commonRefinement") { a ->
        IntentOmega.omegaToJson(IntentMulti.commonRefinement(IntentOmega.arr(a[0]).map { IntentOmega.omegaFromJson(it) }))
    }

    @Test fun ceilingOf() = OracleCases.each(m, "ceilingOf") { a ->
        IntentLayers.ceilingOf(IntentLayers.ceilingAdmitters(map(a[0])), IntentOmega.verbSpaceFromJson(a[1]), IntentOmega.outcomeFromJson(a[2]))
    }

    @Test fun assertAskable() = OracleCases.each(m, "assertAskable") { a ->
        IntentLayers.assertAskable(map(a[0]), map(a[1]))
        null
    }

    @Test fun layerCells() = OracleCases.each(m, "layerCells") { a -> IntentLayers.layerCells(IntentOmega.omegaFromJson(a[0]), IntentPolicy.admitter(a[1])) }

    @Test fun ownerRisk() = OracleCases.each(m, "ownerRisk") { a ->
        IntentLayers.ownerRisk(IntentOmega.omegaFromJson(a[0]), a[1] as List<Map<String, Any?>>, IntentMetrics.acceptabilityOf(a[2]), IntentOmega.DEFAULT_HARM)
    }

    @Test fun cellKeyOf() = OracleCases.each(m, "cellKeyOf") { a -> IntentLayers.cellKeyOf(IntentOmega.omegaFromJson(a[0]), map(a[1])) }

    @Test fun signLayerApproval() = OracleCases.each(m, "signLayerApproval") { a -> IntentLayers.signLayerApproval(map(a[0]), Keys.unb64u(a[1] as String)) }

    @Test fun verifyQuorumApprovals() = OracleCases.each(m, "verifyQuorumApprovals") { a -> IntentLayers.verifyQuorumApprovals(a[0], a[1], map(a[2]), a[3]) }

    @Test fun measureGrantExact() = OracleCases.each(m, "measureGrantExact") { a ->
        IntentMetrics.measureGrantExact(IntentOmega.omegaFromJson(a[0]), a[1], IntentMetrics.acceptabilityOf(a[2])).toJson()
    }

    @Test fun measureGrant() = OracleCases.each(m, "measureGrant") { a ->
        val opts = map(a[3])
        val samples = if (opts.containsKey("samples")) IntentOmega.dbl(opts["samples"]) else 20000.0
        val seed = if (opts.containsKey("seed")) IntentOmega.dbl(opts["seed"]) else 1.0
        val hMax = if (opts.containsKey("hMax")) IntentOmega.dbl(opts["hMax"]) else null
        IntentMetrics.measureGrant(IntentOmega.omegaFromJson(a[0]), a[1], IntentMetrics.acceptabilityOf(a[2]), samples, seed, IntentOmega.DEFAULT_HARM, hMax).toJson()
    }
}
