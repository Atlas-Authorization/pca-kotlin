package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the build step: artifacts, generated types, tool map, pack signing and verification. */
@Suppress("UNCHECKED_CAST")
class ActionsBuildDiffTest {
    private val M = "ref-actions-build"
    private val CORE = Actions.CORE_REGISTRY

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun seed(o: Any?): ByteArray = Keys.unb64u(m(o)["\$bytes"] as String)

    @Test fun build() = OracleCases.each(M, "buildArtifacts") { a -> ActionBuild.buildArtifacts(l(a[0]), m(a[1]), CORE, null) }
    @Test fun types() = OracleCases.each(M, "generateTypes") { a -> ActionBuild.generateTypes(l(a[0])) }
    @Test fun toolAction() = OracleCases.each(M, "toolAction") { a -> ActionBuild.toolActionMapOf(l(a[0]))(a[1] as String, m(a[2])) }
    @Test fun consistency() = OracleCases.each(M, "packConsistencyError") { a -> ActionBuild.packConsistencyError(a[0], CORE) }
    @Test fun sign() = OracleCases.each(M, "signPack") { a -> ActionBuild.signPack(m(a[0]), a[1] as String, seed(a[2]), CORE) }
    @Test fun keyOf() = OracleCases.each(M, "packKeyOf") { a -> ActionBuild.packKeyOf(a[0] as String, seed(a[1])) }
    @Test fun verify() = OracleCases.each(M, "verifyPack") { a -> ActionBuild.verifyPack(a[0], a[1], CORE) }
}
