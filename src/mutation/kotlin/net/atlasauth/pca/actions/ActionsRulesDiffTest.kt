package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the business rules of an action: validation, compile, evaluate, lint, diff and the rules review. */
@Suppress("UNCHECKED_CAST")
class ActionsRulesDiffTest {
    private val M = "ref-actions-rules"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun num(o: Any?): Double? = if (o is Json.Num) o.raw.toDouble() else null
    private fun mapOrThrow(o: Any?): Map<String, Any?> { if (o !is Map<*, *>) throw IllegalArgumentException("not an object"); return m(o) }

    @Test fun businessRulesError() = OracleCases.each(M, "businessRulesError") { a -> ActionBusinessRules.businessRulesError(m(a[0]), a[1]) }

    @Test fun compile() = OracleCases.each(M, "compileBusinessRules") { a -> ActionBusinessRules.compileBusinessRules(m(a[0]), mapOrThrow(a[1])) }

    @Test fun explain() = OracleCases.each(M, "explainBusinessRules") { a -> ActionBusinessRules.explainBusinessRules(m(a[0]), mapOrThrow(a[1])) }

    @Test fun lint() = OracleCases.each(M, "lintBusinessRules") { a -> ActionBusinessRules.lintBusinessRules(m(a[0]), a[1]) }

    @Test fun examples() = OracleCases.each(M, "runRuleExamples") { a -> ActionBusinessRules.runRuleExamples(m(a[0]), mapOrThrow(a[1])) }

    @Test fun moneyOf() = OracleCases.each(M, "moneyOf") { a -> ActionBusinessRules.moneyOf(m(a[0])) }

    @Test fun digest() = OracleCases.each(M, "businessRulesDigest") { a -> ActionBusinessRules.businessRulesDigest(a[0] as String, m(a[1])) }

    @Test fun diff() = OracleCases.each(M, "diffBusinessRules") { a ->
        ActionBusinessRules.diffBusinessRules(m(a[0]), if (a[1] == null) null else mapOrThrow(a[1]), if (a[2] == null) null else mapOrThrow(a[2]))
    }

    @Test fun evaluate() = OracleCases.each(M, "evaluateBusinessRules") { a -> ActionBusinessRules.evaluateBusinessRules(m(a[0]), m(a[1])) }

    @Test fun clockAt() = OracleCases.each(M, "clockAt") { a -> ActionBusinessRules.clockAt(num(a[0]) ?: Double.NaN, a[1] as String?) }

    @Test fun formatMoney() = OracleCases.each(M, "formatMoney") { a -> ActionBusinessRules.formatMoney(num(a[0])!!.toLong(), a[1] as String, num(a[2])!!.toInt()) }

    @Test fun minorUnits() = OracleCases.each(M, "minorUnits") { a -> ActionBusinessRules.minorUnits(a[0], num(a[1])!!.toInt(), "x") }

    @Test fun reviewMessage() = OracleCases.each(M, "rulesReviewMessage") { a -> ActionBusinessRules.rulesReviewMessage(m(a[0])) }

    @Test fun signReview() = OracleCases.each(M, "signRulesReview") { a -> ActionBusinessRules.signRulesReview(m(a[0]), Keys.unb64u(m(a[1])["\$bytes"] as String)) }

    @Test fun reviewError() = OracleCases.each(M, "rulesReviewError") { a -> ActionBusinessRules.rulesReviewError(a[0], m(a[1]), m(a[2]), a[3]) }
}
