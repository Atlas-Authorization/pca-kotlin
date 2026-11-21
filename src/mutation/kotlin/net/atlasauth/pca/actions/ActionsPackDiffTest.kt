package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over pack building, sharding and upgrade verification, and the transparency statement payload. */
@Suppress("UNCHECKED_CAST")
class ActionsPackDiffTest {
    private val M = "ref-actions-pack"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun buildPack() = OracleCases.each(M, "buildPack") { a ->
        ActionPacks.buildPack(m(a[0]), Keys.ed25519(Keys.edFromSeed(Keys.unb64u(m(a[1])["\$bytes"] as String))), null, { _ -> false }, null)
    }

    @Test fun shardDefs() = OracleCases.each(M, "shardDefs") { a -> ActionPacks.shardDefs(l(a[0]), a[1]) }

    @Test fun verifyUpgrade() = OracleCases.each(M, "verifyUpgrade") { a ->
        ActionPacks.verifyUpgrade(m(a[0]), m(a[1]), a[2], if (a[3] == null) null else m(a[3]), if (a[4] == null) null else m(a[4])) { _ -> false }
    }

    @Test fun statementPayload() = OracleCases.each(M, "packStatementPayload") { a -> ActionTransparency.packStatementPayload(m(a[0])) }
}
