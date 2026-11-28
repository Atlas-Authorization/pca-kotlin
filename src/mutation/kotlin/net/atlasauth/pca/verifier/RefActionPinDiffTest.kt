package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The signing half of the action pin module against the reference (ref-action-pin, 111 cases): the constants, registry document signing under
 * Ed25519, ML-DSA-65 and the hybrid suite (signature bytes compare), evolution records, the registry key entry, the principal's re-approval, and
 * the verify side over documents the oracle signs. A signing key is a seed label; a secret is the 32-byte Ed25519 seed.
 */
@Suppress("UNCHECKED_CAST")
class RefActionPinDiffTest {
    private val mod = "ref-action-pin"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun registry(secret: Any?, suite: Any?): Keys.SuiteKey {
        val s = suite as Map<String, Any?>?
        val alg = if (s != null && s.containsKey("alg")) s["alg"] as String else "ed25519"
        val pq = s?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(secret)), pq)
    }

    private fun verdict(r: String?): Map<String, Any?> = if (r == null) linkedMapOf("ok" to true) else linkedMapOf("ok" to false, "reason" to r)

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "ACTION_PIN_ON_NEW" to ActionsRegistry.ACTION_PIN_ON_NEW, "EVOLUTION_CLASSES" to ActionsRegistry.EVOLUTION_CLASSES,
            "EVOLUTION_RECORD_KIND" to ActionsRegistry.EVOLUTION_RECORD_KIND, "REAPPROVAL_KIND" to ActionsRegistry.REAPPROVAL_KIND,
            "EVOLUTION_DOMAIN" to ActionsRegistry.EVOLUTION_DOMAIN, "EVOLUTION_DIFF_DOMAIN" to ActionsRegistry.EVOLUTION_DIFF_DOMAIN,
            "REAPPROVAL_DOMAIN" to ActionsRegistry.REAPPROVAL_DOMAIN, "MAX_EVOLUTION_STEPS" to ActionsRegistry.MAX_EVOLUTION_STEPS,
            "MAX_ESC_TIER" to ActionsRegistry.MAX_ESC_TIER,
        )
        "signRegistryDoc" -> ActionsRegistry.signRegistryDoc(a[0] as String, OracleCases.decNum(a[1]), a[2] as String, registry(a[3], a.getOrNull(4)))
        "signEvolutionRecord" -> ActionsRegistry.signEvolutionRecord(map(a[0]), a[1] as String, registry(a[2], a.getOrNull(3)))
        "registryKeyOf" -> ActionsRegistry.registryKeyOf(a[0] as String, registry(a[1], a.getOrNull(2)))
        "signReapproval" -> {
            val x = map(a[0])
            ActionsRegistry.signReapproval(x["grantId"] as String, map(x["record"]), Keys.edFromSeed(seed(x["principalSecret"])))
        }
        "verifyRegistrySig" -> verdict(ActionsRegistry.verifyRegistrySig(a[0] as String, a[1], map(a[2]), a[3]))
        "verifyEvolutionRecord" -> verdict(ActionsRegistry.verifyEvolutionRecord(a[0], a[1]))
        "reapprovalValid" -> ActionsRegistry.reapprovalValid(a[0], a[1], a[2], a[3], a[4])
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        val fns = setOf("constants", "signRegistryDoc", "signEvolutionRecord", "registryKeyOf", "signReapproval", "verifyRegistrySig", "verifyEvolutionRecord", "reapprovalValid")
        var n = 0
        for (fn in fns) {
            OracleCases.each(mod, fn) { a -> call(fn, a) }
            n += OracleCases.of(mod, fn).size
        }
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(111, n)
    }
}
