package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The objective-risk binding to a grant: nothing committed, a malformed commitment, the instance config that must reproduce the digests, and the heuristic-fallback opt-in. */
@Suppress("UNCHECKED_CAST")
class ObjectiveBindingTest {
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 3 }))
    private val holder = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 4 }))
    private val embedder = ObjectiveRisk.nativeHashEmbedder()
    private val action = linkedMapOf<String, Any?>("verb" to "read", "resource" to "doc:1", "params" to linkedMapOf<String, Any?>())

    private fun grant(objective: Any?, has: Boolean = true): Map<String, Any?> {
        val env = Issue.obj("predicates" to listOf(Issue.obj("verb" to "read", "resource" to "doc:1")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy())
        if (has) env["objective_risk"] = objective
        return Issue.mintGrant(principal, holder.id()!!, null, env, "read the doc").grant
    }

    private fun instance(): Map<String, Any?> = Issue.obj(
        "registry" to Issue.obj("trusted_verifiers" to ArrayList<Any?>(), "entries" to ArrayList<Any?>()),
        "graph" to Issue.obj("nodes" to listOf(Issue.obj("id" to "doc:1"), Issue.obj("id" to "doc:2")), "edges" to ArrayList<Any?>()),
    )

    private fun commitment(registryDigest: String? = null, onMismatch: String? = null): Map<String, Any?> {
        val inst = instance()
        val reg = ObjectiveRisk.InMemoryInverseRegistry()
        val g = ObjectiveRisk.ResourceGraph()
        for (n in (inst["graph"] as Map<String, Any?>)["nodes"] as List<Any?>) g.addNode(n as Map<String, Any?>)
        val c = Issue.obj(
            "v" to IntentJs.ofLong(1), "embedder" to Issue.obj("scheme" to "native", "model_id" to embedder.modelId, "config" to ObjectiveRisk.DEFAULT_NATIVE_CONFIG),
            "goal" to ObjectiveRisk.commitGoal(embedder, action), "registry_digest" to (registryDigest ?: reg.digest()), "graph_digest" to g.digest(),
            "authorized_kinds" to ArrayList<Any?>(),
        )
        if (onMismatch != null) c["on_mismatch"] = onMismatch
        return c
    }

    @Test fun nothingCommittedIsTheHeuristic() {
        val g = grant(null, has = false)
        assertTrue(ObjectiveBinding.readObjectiveCommitment(g).isEmpty())
        assertEquals("none", ObjectiveBinding.resolveObjectiveRisk(g, action, instance())["mode"])
    }

    @Test fun aMalformedCommitmentIsRefused() {
        val r = ObjectiveBinding.resolveObjectiveRisk(grant(Issue.obj("v" to IntentJs.ofLong(2))), action, instance())
        assertEquals("mismatch", r["mode"])
        assertEquals("deny", r["onMismatch"])
        assertEquals(listOf<Any?>("objective_risk: unsupported shape/version"), r["reasons"])
    }

    @Test fun aCommitmentNeedsTheInstanceConfigThatReproducesIt() {
        val g = grant(commitment())
        val none = ObjectiveBinding.resolveObjectiveRisk(g, action, null)
        assertEquals("mismatch", none["mode"])
        val ok = ObjectiveBinding.resolveObjectiveRisk(g, action, instance())
        assertEquals("objective", ok["mode"])
        val inputs = ok["inputs"] as Map<String, Any?>
        assertEquals(setOf("reversibility", "blastRadius", "semanticDistance"), inputs.keys)
        assertTrue((ok["evidenceDigest"] as String).isNotEmpty())
    }

    @Test fun aDigestMismatchDeniesAndOnlyTheInstanceMayAllowTheHeuristic() {
        val g = grant(commitment(registryDigest = "AAAA", onMismatch = "heuristic"))
        val denied = ObjectiveBinding.resolveObjectiveRisk(g, action, instance())
        assertEquals("mismatch", denied["mode"])
        assertEquals("deny", denied["onMismatch"])
        assertEquals(listOf<Any?>("registry digest does not match the committed digest"), denied["reasons"])
        val inst = LinkedHashMap(instance())
        inst["allow_heuristic_fallback"] = true
        assertEquals("heuristic", ObjectiveBinding.resolveObjectiveRisk(g, action, inst)["onMismatch"])
    }
}
