package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentWitnesses.Witness
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of plain-language rendering, the claim diff and the boundary witnesses. */
@Suppress("UNCHECKED_CAST")
class IntentRenderDiffTest {
    private val m = "ref-intent-render"

    private fun idx(o: Any?): IntArray = (o as List<*>).let { l -> IntArray(l.size) { IntentOmega.dbl(l[it]).toInt() } }

    @Test fun renderCondition() = OracleCases.each(m, "renderCondition") { a -> IntentRender.renderCondition(a[0]) }

    @Test fun labelOf() = OracleCases.each(m, "labelOf") { a -> IntentRender.labelOf(a[0] as String) }

    @Test fun renderCaveat() = OracleCases.each(m, "renderCaveat") { a -> IntentRender.renderCaveat(a[0]) }

    @Test fun renderGrant() = OracleCases.each(m, "renderGrant") { a -> IntentRender.renderGrant(a[0]) }

    @Test fun renderQuestion() = OracleCases.each(m, "renderQuestion") { a -> IntentRender.renderQuestion(IntentOmega.verbSpaceFromJson(a[0]), idx(a[1])) }

    @Test fun renderAction() = OracleCases.each(m, "renderAction") { a ->
        val vals = LinkedHashMap<String, Any?>()
        for ((k, v) in IntentOmega.obj(a[1])) vals[k] = if (IntentOmega.isNumber(v)) IntentOmega.dbl(v) else v
        IntentRender.renderAction(IntentOmega.verbSpaceFromJson(a[0]), vals)
    }

    @Test fun claimsOf() = OracleCases.each(m, "claimsOf") { a -> IntentRender.claimsOf(a[0], IntentOmega.omegaFromJson(a[1])).map { it.toJson() } }

    private fun diffs(ds: List<IntentRender.ClaimDiff>): List<Any?> = ds.map { it.toJson() }

    @Test fun backTranslationDiff() = OracleCases.each(m, "backTranslationDiff") { a -> diffs(IntentRender.backTranslationDiff(a[0], a[1], IntentOmega.omegaFromJson(a[2]))) }

    @Test fun claimDiff() = OracleCases.each(m, "claimDiff") { a ->
        val om = IntentOmega.omegaFromJson(a[2])
        if (a.size > 3) {
            val names = a[3] as List<*>
            diffs(IntentRender.claimDiff(a[0], a[1], om, names[0] as String, names[1] as String))
        } else diffs(IntentRender.claimDiff(a[0], a[1], om))
    }

    @Test fun boundaryWitnesses() = OracleCases.each(m, "boundaryWitnesses") { a -> IntentWitnesses.boundaryWitnesses(a[0], IntentOmega.omegaFromJson(a[1])).map { it.toJson() } }

    private fun witnessFromJson(o: Any?): Witness {
        val w = o as Map<String, Any?>
        return Witness(w["kind"] as String, w["side"] as String, w["verb"] as String, idx(w["cell"]), IntentOmega.outcomeFromJson(w["outcome"]),
            w["grantAllows"] as Boolean, w["facet"] as String, w["question"] as String)
    }

    @Test fun checkWitnesses() = OracleCases.each(m, "checkWitnesses") { a ->
        val ws = (a[0] as List<*>).map { witnessFromJson(it) }
        val mode = a[1] as String
        val c = IntentWitnesses.checkWitnesses(ws) { w ->
            when (mode) {
                "agree" -> w.grantAllows
                "flip" -> !w.grantAllows
                "flip-boundary" -> if (w.kind == "boundary") !w.grantAllows else w.grantAllows
                else -> w.side == "inside" && w.kind != "unconstrained"
            }
        }
        linkedMapOf<String, Any?>("questions" to c.questions, "mismatches" to c.mismatches.map { it.toJson() })
    }
}
