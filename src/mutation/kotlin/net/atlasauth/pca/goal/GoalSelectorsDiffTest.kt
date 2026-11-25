package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the selector layer: catalog, class verbs, roles, expansion, typing, card, carrier, catalog tape. */
@Suppress("UNCHECKED_CAST")
class GoalSelectorsDiffTest {
    private val M = "ref-goal-selectors"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null

    private fun l(o: Any?): List<Any?> = o as List<Any?>

    /** A shipped domain stands for its IR ontology. */
    private fun ont(o: Any?): Map<String, Any?> =
        if (o is String) GoalOntology.toIrOntology(GoalOntologies.ontology(o)!!, null, null) else m(o)!!

    /** A shipped domain stands for its selector catalog. */
    private fun cat(o: Any?): Map<String, Any?> = if (o is String) GoalOntologies.selCatalog(o)!! else m(o)!!

    @Test fun selCatalogDigest() = OracleCases.each(M, "selCatalogDigest") { a -> GoalSelectors.selCatalogDigest(cat(a[0])) }

    @Test fun selGoalDigest() = OracleCases.each(M, "selGoalDigest") { a -> GoalSelectors.selGoalDigest(m(a[0])!!) }

    @Test fun encodeSelCatalog() = OracleCases.each(M, "encodeSelCatalog") { a -> GoalSelectors.encodeSelCatalog(cat(a[0])) }

    @Test fun catalogOfDomain() = OracleCases.each(M, "catalogOfDomain") { a -> GoalSelectors.selCatalogOfDomain(a[0] as String) }

    @Test fun classVerbs() = OracleCases.each(M, "classVerbs") { a -> GoalSelectors.classVerbs(cat(a[0]), l(a[1]), l(a[2])) }

    @Test fun allowClassVerbs() = OracleCases.each(M, "allowClassVerbs") { a -> GoalSelectors.allowClassVerbs(cat(a[0]), l(a[1]), l(a[2])) }

    @Test fun floatClassVerbs() = OracleCases.each(M, "floatClassVerbs") { a -> GoalSelectors.floatClassVerbs(cat(a[0]), l(a[1]), l(a[2])) }

    @Test fun resolveRole() = OracleCases.each(M, "resolveRole") { a -> GoalSelectors.resolveRole(ont(a[0]), cat(a[1]), a[2] as String, a[3] as String) }

    @Test fun selReasons() = OracleCases.each(M, "selReasons") { a -> GoalSelectors.selReasons(m(a[0])!!, ont(a[1]), cat(a[2])) }

    @Test fun expandSelGoal() = OracleCases.each(M, "expandSelGoal") { a -> GoalSelectors.expandSelGoal(m(a[0])!!, ont(a[1]), cat(a[2])) }

    @Test fun selCarrier() = OracleCases.each(M, "selCarrier") { a -> GoalSelectors.selCarrier(m(a[0])!!) }

    @Test fun renderSelCard() = OracleCases.each(M, "renderSelCard") { a -> GoalSelectors.renderSelCard(m(a[0])!!, ont(a[1]), cat(a[2]), null) }

    @Test fun withRoleParams() = OracleCases.each(M, "withRoleParams") { a -> GoalSelectors.withRoleParams(m(a[0])!!, cat(a[1])) }

    @Test fun traitClosure() = OracleCases.each(M, "traitClosure") { a -> GoalSelectors.traitClosure(l(a[0]), null) }

    // only inputs the selector layer refuses: the proved compiler is not carried natively, so it must never be reached
    @Test fun compileSelGoal() = OracleCases.each(M, "compileSelGoal") { a ->
        GoalSelectors.compileSelGoal(m(a[0])!!, ont(a[1]), cat(a[2])) { _, _ -> throw IllegalStateException("compiler reached") }
    }

    @Test fun catalogOfDefs() = OracleCases.each(M, "catalogOfDefs") { a -> GoalSelectors.selCatalogOfDefs(l(a[0]), null, null) }
}
