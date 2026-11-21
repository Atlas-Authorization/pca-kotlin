package net.atlasauth.pca.actions

import net.atlasauth.pca.policyci.ActionLintRules
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the lint rules, the findings output (text and SARIF) and the undo shape checks the linter uses. */
@Suppress("UNCHECKED_CAST")
class ActionsLintDiffTest {
    private val M = "ref-actions-lint"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun fixed(c: Boolean): (Map<String, Any?>) -> Boolean = { _ -> c }

    @Test fun lintDefs() = OracleCases.each(M, "lintDefs") { a ->
        val opts = if (a.size > 1 && a[1] != null) m(a[1]) else null
        val att = opts?.get("att")
        ActionLint.lintDefs(l(a[0]), opts, if (att == null) null else fixed(att as Boolean))
    }
    @Test fun lintRulesDigest() = OracleCases.each(M, "lintRulesDigest") { _ -> ActionLint.lintRulesDigest() }
    @Test fun lintRules() = OracleCases.each(M, "LINT_RULES") { _ -> ActionLintRules.LINT_RULES.map { it.toList() } }
    @Test fun lintFails() = OracleCases.each(M, "lintFails") { a -> ActionLint.lintFails(l(a[0]), a[1] as Boolean) }
    @Test fun lintText() = OracleCases.each(M, "lintText") { a -> ActionLint.lintText(l(a[0])) }
    @Test fun toSarif() = OracleCases.each(M, "toSarif") { a -> ActionLint.toSarif(l(a[0]), if (a.size > 1) m(a[1]) else null) }
    @Test fun reversibilityFor() = OracleCases.each(M, "reversibilityFor") { a -> ActionUndo.reversibilityFor(m(a[0]), m(a[1])) }
    @Test fun mayBeReversible() = OracleCases.each(M, "mayBeReversible") { a -> ActionUndo.mayBeReversible(m(a[0])) }
    @Test fun compensationShape() = OracleCases.each(M, "compensationShape") { a -> ActionUndo.compensationShape(m(a[0]), m(a[1])) }
}
