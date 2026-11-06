package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rules 20 (units) and 21 (tighten-only) END TO END through [Authorize.authorize]: the shared
 * `model-rules-vectors.json` (signed grants, decided by the TypeScript reference). A grant's tighten[] rules, unit tags and
 * polarity are signed policy: ignoring them would let a model move a decision up, so every case must decide the same as the
 * reference, reason text included, over the FULL per-check set.
 */
@Suppress("UNCHECKED_CAST")
class ModelRulesTest {
    private val modelReason = Regex("^(units|tighten|schema|intent_session): .*", RegexOption.DOT_MATCHES_ALL)

    private fun run(d: Map<String, Any?>, c: Map<String, Any?>): Authorize.Result {
        val grant = c["grant"] as Map<String, Any?>
        val v2 = if (c.containsKey("intent_v2")) c["intent_v2"] else null
        val cx = c["context"] as? Map<String, Any?>
        val ctxFn: ((Map<String, Any?>) -> Map<String, Any?>?)? =
            if (cx == null) null else fun(_: Map<String, Any?>): Map<String, Any?>? = linkedMapOf("env" to cx["env"])
        val v2Fn: ((Map<String, Any?>) -> IntentV2.Context?)? =
            if (!c.containsKey("intent_v2")) null else fun(_: Map<String, Any?>): IntentV2.Context? = IntentV2.Context.fromJson(v2)
        return Authorize.authorize(
            c["pcactn"],
            Authorize.Input(
                operation = Authorize.Operation.fromJson(c["operation"]), audience = d["audience"] as String,
                resolveGrant = { grant }, stateStore = Authorize.MemoryStateStore(), isRevoked = { _, _ -> false },
                now = Json.asLong(d["now"]), plan = Authorize.SINGLE_STEP,
                context = ctxFn, intentV2 = v2Fn,
                provenanceOptions = ProvHarness.options, provenance = ProvHarness.bundle(Authorize.Operation.fromJson(c["operation"])),
            ),
        )
    }

    @Test
    fun everyCaseDecidesLikeTheReference() {
        val d = ParityVectors.load("model-rules-vectors.json")
        assertEquals("pca-model-rules-vectors/1", d["format"])
        val cases = d["cases"] as List<Map<String, Any?>>
        assertTrue(cases.size >= 32)
        val decisions = HashSet<String>()
        for (c in cases) {
            val name = c["name"].toString()
            val e = c["expect"] as Map<String, Any?>
            decisions.add(e["decision"] as String)
            val r = run(d, c)
            assertEquals("$name allow ${r.reasons}", e["allow"], r.allow)
            assertEquals("$name decision ${r.reasons}", e["decision"], r.decision)
            assertEquals("$name status", Json.asLong(e["status"]).toInt(), r.status)
            assertEquals("$name failed ${r.reasons}", (e["failed"] as List<*>).map { it as String }, r.checks.filterValues { it == "fail" }.keys.sorted())
            val got = r.reasons.filter { modelReason.matches(it) }
            assertEquals("$name reasons", (e["reasons"] as List<*>).map { it as String }, got)
            for (k in listOf("units", "tighten")) assertEquals("$name check $k", e[k] as String?, r.checks[k]?.takeIf { it != "" })
            val wantDeg = LinkedHashMap<String, String>()
            (e["degraded"] as? Map<String, Any?>)?.forEach { (k, v) -> wantDeg[k] = v as String }
            assertEquals("$name degraded", wantDeg, r.degraded)
        }
        for (dec in listOf("allow", "escalate", "deny")) assertTrue("no $dec case", decisions.contains(dec))
    }
}
