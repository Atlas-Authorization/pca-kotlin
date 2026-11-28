package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over what a def yields: params, effect class, schema, operation binding, risk, predicates, ontology, card. */
@Suppress("UNCHECKED_CAST")
class ActionsDeriveDiffTest {
    private val M = "ref-actions-derive"
    private val CORE = Actions.CORE_REGISTRY

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun fixed(c: Boolean): (Map<String, Any?>) -> Boolean = { _ -> c }
    private fun eff(d: Any?, c: Boolean): Map<String, Any?> = ActionEffective.effective(m(d), CORE, fixed(c))
    private fun reg(defs: Any?): Map<String, Map<String, Any?>> = if (defs == null) CORE else Actions.extendRegistry(CORE, l(defs))

    @Test fun flattenParams() = OracleCases.each(M, "flattenParams") { a -> ActionDerive.flattenParams(m(a[0])) }
    @Test fun paramByRole() = OracleCases.each(M, "paramByRole") { a -> ActionDerive.paramByRole(m(a[0]), a[1] as String) }
    @Test fun effectClass() = OracleCases.each(M, "effectClass") { a -> ActionDerive.effectClass(m(a[0])) }
    @Test fun resourceMatcher() = OracleCases.each(M, "resourceMatcher") { a -> ActionDerive.resourceMatcher(m(a[0])) }
    @Test fun toSchemaVerb() = OracleCases.each(M, "toSchemaVerb") { a -> ActionDerive.toSchemaVerb(m(a[0]), CORE, fixed(a[1] as Boolean)) }
    @Test fun cardOf() = OracleCases.each(M, "cardOf") { a -> ActionDerive.cardOf(m(a[0]), eff(a[0], a[1] as Boolean), CORE) }
    @Test fun escalationOf() = OracleCases.each(M, "escalationOf") { a -> ActionDerive.escalationOf(eff(a[0], a[1] as Boolean)) }
    @Test fun mcpAnnotationsOf() = OracleCases.each(M, "mcpAnnotationsOf") { a -> ActionDerive.mcpAnnotationsOf(m(a[0]), eff(a[0], a[1] as Boolean)) }
    @Test fun explainDef() = OracleCases.each(M, "explainDef") { a -> ActionExplain.explainDef(m(a[0]), CORE, fixed(a[1] as Boolean)) }
    @Test fun operationOf() = OracleCases.each(M, "operationOf") { a -> ActionDerive.operationOf(m(a[0]), m(a[1])) }
    @Test fun riskOf() = OracleCases.each(M, "riskOf") { a ->
        ActionDerive.riskOf(m(a[0]), eff(a[0], a[1] as Boolean), if (a[2] == null) null else m(a[2]), if (a[3] == null) null else m(a[3]))
    }
    @Test fun predicatesOf() = OracleCases.each(M, "predicatesOf") { a -> ActionDerive.predicatesOf(m(a[0]), if (a.size > 1) m(a[1]) else null) }
    @Test fun reversibilityScore() = OracleCases.each(M, "REVERSIBILITY_SCORE") { _ -> ActionDerive.REVERSIBILITY_SCORE }
    @Test fun toSchemaDoc() = OracleCases.each(M, "toSchemaDoc") { a -> ActionDerive.toSchemaDoc(l(a[0]), reg(a[3]), m(a[1]), fixed(a[2] as Boolean)) }
    @Test fun toOntology() = OracleCases.each(M, "toOntology") { a -> ActionDerive.toOntology(l(a[0]), CORE, fixed(a[1] as Boolean)) }
}
