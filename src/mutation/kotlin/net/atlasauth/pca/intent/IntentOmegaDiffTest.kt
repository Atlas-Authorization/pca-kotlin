package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the outcome space, its derivation, policy plumbing and regions. */
class IntentOmegaDiffTest {
    private val m = "ref-intent-omega"

    private fun d(o: Any?): Double = IntentOmega.dbl(o)
    private fun i(o: Any?): Int = d(o).toInt()
    private fun dim(o: Any?): Dim = IntentOmega.dimFromJson(o)
    private fun vs(o: Any?): VerbSpace = IntentOmega.verbSpaceFromJson(o)
    private fun out(o: Any?): Outcome = IntentOmega.outcomeFromJson(o)
    private fun idx(o: Any?): IntArray = (o as List<*>).let { l -> IntArray(l.size) { i(l[it]) } }
    private fun value(o: Any?): Any? = if (IntentOmega.isNumber(o)) d(o) else o
    private fun stats(s: IntentOmega.Stats): Map<String, Any?> = linkedMapOf("mass" to s.mass, "harm" to s.harm)
    private fun inner(o: Any?): Boolean = "inner" == o

    @Test fun deriveOmega() = OracleCases.each(m, "deriveOmega") { a -> IntentOmega.omegaToJson(IntentDerive.deriveOmega(IntentOmega.obj(a[0]))) }

    @Test fun harmMax() = OracleCases.each(m, "harmMax") { a -> IntentOmega.harmMax(IntentOmega.omegaFromJson(a[0])) }

    @Test fun verbSpace() = OracleCases.each(m, "verbSpace") { a -> IntentOmega.verbSpace(IntentOmega.omegaFromJson(a[0]), a[1] as String?)?.let { IntentOmega.verbSpaceToJson(it) } }

    @Test fun verbCellCount() = OracleCases.each(m, "verbCellCount") { a -> IntentOmega.verbCellCount(vs(a[0])) }

    @Test fun decodeCell() = OracleCases.each(m, "decodeCell") { a -> IntentOmega.decodeCell(vs(a[0]), d(a[1])).toList() }

    @Test fun encodeCell() = OracleCases.each(m, "encodeCell") { a -> IntentOmega.encodeCell(vs(a[0]), idx(a[1])) }

    @Test fun cellRep() = OracleCases.each(m, "cellRep") { a -> IntentOmega.outcomeToJson(IntentOmega.cellRep(vs(a[0]), idx(a[1]))) }

    @Test fun cellStats() = OracleCases.each(m, "cellStats") { a -> stats(IntentOmega.cellStats(vs(a[0]), idx(a[1]))) }

    @Test fun cellOf() = OracleCases.each(m, "cellOf") { a -> IntentOmega.cellOf(vs(a[0]), out(a[1]))?.toList() }

    @Test fun harmOf() = OracleCases.each(m, "harmOf") { a -> IntentOmega.harmOf(vs(a[0]), out(a[1])) }

    @Test fun cellCount() = OracleCases.each(m, "cellCount") { a -> IntentOmega.cellCount(dim(a[0])) }

    @Test fun numCells() = OracleCases.each(m, "numCells") { a -> IntentOmega.numCells(dim(a[0]) as NumDim).map { linkedMapOf<String, Any?>("lo" to it.lo, "hi" to it.hi) } }

    @Test fun numRep() = OracleCases.each(m, "numRep") { a -> IntentOmega.numRep(dim(a[0]) as NumDim, i(a[1])) }

    @Test fun repValue() = OracleCases.each(m, "repValue") { a -> IntentOmega.repValue(dim(a[0]), i(a[1])) }

    @Test fun catRep() = OracleCases.each(m, "catRep") { a -> IntentOmega.catRep(dim(a[0]) as IntentOmega.CatDim, i(a[1])) }

    @Test fun catCellOf() = OracleCases.each(m, "catCellOf") { a -> IntentOmega.catCellOf(dim(a[0]) as IntentOmega.CatDim, a[1] as String) }

    @Test fun cellOfValue() = OracleCases.each(m, "cellOfValue") { a -> IntentOmega.cellOfValue(dim(a[0]), value(a[1])) }

    @Test fun dimCellStats() = OracleCases.each(m, "dimCellStats") { a -> stats(IntentOmega.dimCellStats(dim(a[0]), i(a[1]))) }

    @Test fun intervalWeight() = OracleCases.each(m, "intervalWeight") { a -> IntentOmega.intervalWeight(dim(a[0]) as NumDim, d(a[1]), d(a[2])) }

    @Test fun rngSeq() = OracleCases.each(m, "rngSeq") { a ->
        val r = IntentOmega.rng(d(a[0]))
        (0 until i(a[1])).map { r() }
    }

    @Test fun sampleOutcomes() = OracleCases.each(m, "sampleOutcomes") { a ->
        val om = IntentOmega.omegaFromJson(a[0])
        val r = IntentOmega.rng(d(a[1]))
        (0 until i(a[2])).map { IntentOmega.outcomeToJson(IntentOmega.sampleOutcome(om, r).o) }
    }

    @Test fun normalizePolicy() = OracleCases.each(m, "normalizePolicy") { a -> IntentPolicy.normalizePolicy(a[0]) }

    @Test fun slotsToPolicy() = OracleCases.each(m, "slotsToPolicy") { a -> IntentDerive.slotsToPolicy(a[0]) }

    @Test fun outcomeToAction() = OracleCases.each(m, "outcomeToAction") { a -> IntentPolicy.outcomeToAction(vs(a[0]), out(a[1])) }

    @Test fun admits() = OracleCases.each(m, "admits") { a -> IntentPolicy.admitter(a[0]).admits(vs(a[1]), out(a[2])) }

    @Test fun regionOfCell() = OracleCases.each(m, "regionOfCell") { a -> IntentRegion.regionOfCell(vs(a[0]), idx(a[1])).toJson() }

    @Test fun regionCells() = OracleCases.each(m, "regionCells") { a -> IntentRegion.regionCells(vs(a[0]), IntentRegion.Region.fromJson(a[1]), inner(a[2])) }

    @Test fun dimCellsIn() = OracleCases.each(m, "dimCellsIn") { a -> IntentRegion.dimCellsIn(dim(a[0]), if (a[1] == null) null else IntentRegion.RegionDim.fromJson(a[1]), inner(a[2])) }

    @Test fun restrictRegion() = OracleCases.each(m, "restrictRegion") { a -> IntentRegion.restrictRegion(IntentRegion.Region("v", LinkedHashMap()), dim(a[0]), IntentOmega.obj(a[1])).toJson() }

    @Test fun valueInRegionDim() = OracleCases.each(m, "valueInRegionDim") { a -> IntentRegion.valueInRegionDim(a[0] as String, IntentRegion.RegionDim.fromJson(a[1]), value(a[2])) }
}
