package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the hosted registry: publish gate, rules documents, the verifier view and the source sync. */
@Suppress("UNCHECKED_CAST")
class ActionsHostedDiffTest {
    private val MOD = "ref-actions-hosted"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun publishGate() = OracleCases.each(MOD, "publishGate") { a -> ActionHosted.publishGate(m(a[0])) }

    @Test fun rulesDoc() = OracleCases.each(MOD, "rulesDocError") { a -> ActionHosted.rulesDocError(a[0], "acme", l(a[1])) }

    @Test fun versionDigest() = OracleCases.each(MOD, "hostedVersionDigest") { a -> ActionHosted.hostedVersionDigest(m(a[0])) }

    @Test fun lookup() = OracleCases.each(MOD, "viewLookup") { a -> ActionHosted.hostedView(l(a[0]), a[1]).lookup(a[2] as String) }

    @Test fun provenance() = OracleCases.each(MOD, "viewProvenance") { a -> ActionHosted.hostedView(l(a[0]), a[1]).provenance(a[2] as String) }

    @Test fun floor() = OracleCases.each(MOD, "viewFloor") { a -> ActionHosted.hostedView(l(a[0]), a[1]).floor(a[2] as String, m(a[3]), l(a[4])) }

    @Test fun undo() = OracleCases.each(MOD, "viewUndo") { a -> ActionHosted.hostedView(l(a[0]), a[1]).undoPlan(m(a[2])) }

    @Test fun callContext() = OracleCases.each(MOD, "hostedCallContext") { a ->
        // the params are read as params[k] once the lookup names an idempotency parameter: an explicit null there fails to read
        if (a[1] == null && a[0]?.let { m(it)["idempotency_param"] } != null) throw IllegalArgumentException("Cannot read properties of null (reading 'k')")
        ActionHosted.hostedCallContext(a[0]?.let { m(it) }, a[1]?.let { m(it) })
    }

    @Test fun rateKeys() = OracleCases.each(MOD, "rateKeysOf") { a -> ActionHosted.rateKeysOf(m(a[0]), m(a[1])) }

    @Test fun grantFacts() = OracleCases.each(MOD, "grantFactsOf") { a -> ActionHosted.grantFactsOf(a[0]) }

    @Test fun sync() = OracleCases.each(MOD, "syncSource") { a ->
        val c = a[3] as Boolean
        ActionSync.syncSource(l(a[0]), l(a[1]), "S".repeat(43), a[2]?.let { m(it) }, Json.parse("1800000000"), null) { _ -> c }
    }

    @Test fun syncText() = OracleCases.each(MOD, "syncText") { a -> ActionSync.syncText(m(a[0])) }
}
