package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the approval rendering, the facade rows and the provenance facts of action defs. */
@Suppress("UNCHECKED_CAST")
class ActionsRenderFacadeDiffTest {
    private val M = "ref-actions-render-facade"
    private val CORE = Actions.CORE_REGISTRY

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun renderApproval() = OracleCases.each(M, "renderApproval") { a -> ActionApprovals.renderApproval(m(a[0]), a[1], a[2] as Boolean) }

    @Test fun renderDigestForAction() = OracleCases.each(M, "renderDigestForAction") { a -> ActionApprovals.renderDigestForAction(m(a[0]), m(a[1]), m(a[2]), a[3] as Boolean) }

    @Test fun approverRenderCheck() = OracleCases.each(M, "approverRenderCheck") { a -> ActionApprovals.approverRenderCheck(m(a[0]), m(a[1]), a[2] as String?, a[3] as Boolean) }

    @Test fun singleTapAllowed() = OracleCases.each(M, "singleTapAllowed") { a -> ActionApprovals.singleTapAllowed(m(a[0])) }

    @Test fun renderersFromDefs() = OracleCases.each(M, "renderersFromDefs") { a ->
        ActionApprovals.renderFromDefs(l(a[0]), a[1] as String, if (a[2] == null) null else m(a[2]), a[3] as Boolean)
    }

    @Test fun specOfDef() = OracleCases.each(M, "specOfDef") { a -> val c = a[2] as Boolean; ActionFacade.specOfDef(m(a[0]), CORE, a[1] as Boolean) { _ -> c } }

    @Test fun facadeSpecs() = OracleCases.each(M, "facadeSpecs") { a -> val c = a[2] as Boolean; ActionFacade.facadeSpecs(l(a[0]), CORE, a[1] as Boolean) { _ -> c } }

    @Test fun provenanceInfoOf() = OracleCases.each(M, "provenanceInfoOf") { a -> val c = a[1] as Boolean; ActionProvenance.provenanceInfoOf(m(a[0]), CORE) { _ -> c } }

    @Test fun provenanceActions() = OracleCases.each(M, "provenanceActions") { a ->
        val c = a[1] as Boolean
        val f = ActionProvenance.provenanceActions(l(a[0]), CORE) { _ -> c }
        val out = ArrayList<Any?>()
        for (v in l(a[2])) out.add(f(v as String))
        out
    }
}
