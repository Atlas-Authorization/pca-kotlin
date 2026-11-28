package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the built-in action data, the domain vocabularies, and the starter templates. */
@Suppress("UNCHECKED_CAST")
class ActionsDataDiffTest {
    private val M = "ref-actions-data"

    @Test fun builtinDefs() = OracleCases.each(M, "builtinDefs") { ActionBuiltin.builtinDefs() }

    @Test fun domainDefs() = OracleCases.each(M, "domainDefs") { ActionBuiltin.domainDefs() }

    @Test fun corePackDefs() = OracleCases.each(M, "corePackDefs") { ActionBuiltin.corePackDefs() }

    @Test fun legacy() {
        OracleCases.each(M, "legacyCatalog") { ActionBuiltin.legacyCatalog() }
        OracleCases.each(M, "legacyOntologyEffect") { ActionBuiltin.legacyOntologyEffect() }
        OracleCases.each(M, "resolutions") { ActionBuiltin.resolutions() }
        OracleCases.each(M, "domainBindings") { ActionBuiltin.domainVerbBindings() }
    }

    @Test fun coreDigests() = OracleCases.each(M, "coreDigests") {
        val out = ArrayList<Any?>()
        for (d in ActionBuiltin.corePackDefs()) {
            val m = d as Map<String, Any?>
            out.add(listOf(m["verb"], Actions.defDigest(m)))
        }
        out
    }

    @Test fun domain() {
        OracleCases.each(M, "domainVerbs") { a -> ActionBuiltin.domainVerbs(a[0] as String, null) }
        OracleCases.each(M, "domainRoles") { a -> ActionBuiltin.domainRoles(a[0] as String) }
    }

    @Test fun release() {
        OracleCases.each(M, "releasedBuiltinDefs") { ActionBuiltin.releasedBuiltinDefs(null) == ActionBuiltin.builtinDefs() }
        OracleCases.each(M, "builtinConfirmed") { ActionBuiltin.builtinReviewOpts(null) != null }
    }

    @Test fun templates() {
        OracleCases.each(M, "starterTemplates") { ActionTemplates.starterTemplates() }
        OracleCases.each(M, "starterTemplate") { a -> ActionTemplates.starterTemplate(a[0] as String?) }
        OracleCases.each(M, "templateYaml") { a -> ActionTemplates.yaml(a[0] as String?, a[1]) }
        OracleCases.each(M, "templateTraits") { a -> ActionTemplates.traits(a[0] as String?, a[1]) }
    }
}
