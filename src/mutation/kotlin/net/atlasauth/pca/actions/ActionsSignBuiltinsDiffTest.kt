package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the release signing of the built-in defs (the reviewer key is a seed label). */
@Suppress("UNCHECKED_CAST")
class ActionsSignBuiltinsDiffTest {
    @Test fun signBuiltins() = OracleCases.each("ref-actions-signbuiltins-py", "signBuiltins") { a ->
        val c = a[0] as Map<String, Any?>
        val label = (c["secret"] as Map<String, Any?>)["\$seed"] as String
        val all = ActionBuiltin.builtinDefs()
        val from = (c["from"] as net.atlasauth.pca.verifier.Json.Num).raw.toInt()
        val to = (c["to"] as net.atlasauth.pca.verifier.Json.Num).raw.toInt()
        val signed = ActionBuiltin.signBuiltins(null, c["kid"] as String, OracleCases.seed(label), c["ts"], all.subList(from, to))
        signed.map { d ->
            val m = d as Map<String, Any?>
            val r = m["review"] as Map<String, Any?>
            listOf(m["verb"], r["state"], r["attestation"])
        }
    }
}
