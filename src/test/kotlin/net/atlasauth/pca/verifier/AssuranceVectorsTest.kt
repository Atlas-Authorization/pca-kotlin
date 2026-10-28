package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Assurance labels and the high-assurance gate (T8 / B7): replays `assurance-vectors.json` (`signature_level`, `report`, `requirement`,
 * `multi_root`; reports and reasons exactly, key order is irrelevant) and checks the `requireAssurance` wiring of `authorize`. A missing
 * vector file fails.
 */
@Suppress("UNCHECKED_CAST")
class AssuranceVectorsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("assurance-vectors.json") }
    private fun rows(k: String) = doc[k] as List<Map<String, Any?>>
    private fun canon(v: Any?) = Json.canonicalize(v)

    /** A verifier hook carrying the declared label, or an unlabelled one. */
    private fun hook(label: Any?): Any {
        val h = Any()
        if (label == "unlabelled") return h
        val l = label as Map<String, Any?>
        return Assurance.setLabel(h, l["level"] as String, l["vendor"] as String?, l["awaiting_audit"] as Boolean?, l["ceremony"] as String?)
    }

    private fun build(v: Map<String, Any?>): Map<String, Map<String, Any?>> {
        val hooks = LinkedHashMap<String, Any?>()
        for ((k, x) in (v["hooks"] as? Map<String, Any?>).orEmpty()) hooks[k] = hook(x)
        return Assurance.report(
            v["pcactn"] as Map<String, Any?>?, v["checks"] as Map<String, String>, v["degraded"] as Map<String, String>?, hooks,
            if (v.containsKey("attestation_hook")) hook(v["attestation_hook"]) else null, v["threshold_t"], v["allow_unbound_pq"] == true,
        )
    }

    @Test
    fun corpusIsComplete() {
        assertEquals(listOf(14, 37, 47, 10), listOf("signature_level", "report", "requirement", "multi_root").map { rows(it).size })
    }

    @Test
    fun signatureLevels() {
        for (v in rows("signature_level")) assertEquals("${v["alg"]}", v["level"], Assurance.signatureLevel(v["alg"]))
    }

    @Test
    fun reports() {
        for (v in rows("report")) assertEquals(v["name"].toString(), canon(v["report"]), canon(build(v)))
    }

    @Test
    fun requirements() {
        for (v in rows("requirement"))
            assertEquals(v["name"].toString(), v["unmet"], Assurance.unmetAssurance(v["report"] as Map<String, Map<String, Any?>>, v["require"] as Map<String, Any?>))
    }

    @Test
    fun multiRoot() {
        for (v in rows("multi_root")) {
            val roots = (v["roots"] as List<Map<String, Any?>>).map { Assurance.Root(hook(linkedMapOf("level" to it["level"])), it["required"] == true) }
            assertEquals(v["name"].toString(), v["level"], Assurance.multiRootLevel(roots, IntentJs.num(v["threshold"])!!))
        }
    }

    @Test
    fun aLabelNeverComesFromThePresentedEvidence() {
        // the report reads the hook's label only; a PCActn claiming "hardware" changes nothing
        val r = Assurance.report(
            ParityVectors.obj("""{"attestation":{"level":"hardware"}}"""), linkedMapOf("attestation" to "pass"), null,
            linkedMapOf<String, Any?>("attestation" to Any()),
        )
        assertEquals(canon(linkedMapOf("attestation" to linkedMapOf("outcome" to "pass", "level" to "unknown"))), canon(r))
    }

    @Test
    fun unknownRequirementKeysAndValuesFailClosed() {
        val ok = ParityVectors.obj("""{"attestation":{"outcome":"pass","level":"hardware"},"zk_compliance":{"outcome":"pass","level":"groth16"}}""")
            as Map<String, Map<String, Any?>>
        val bad = listOf(
            mapOf("attestation" to "unknown"), mapOf("attestation" to "tpm"), mapOf("zk" to "magic"), mapOf("threshold" to "multisig"),
            mapOf("signature" to "any"), mapOf("surprise" to true),
        )
        for (req in bad) {
            val why = Assurance.unmetAssurance(ok, req)
            assertTrue("$req -> $why", why != null && why.startsWith("assurance: unknown ") && why.endsWith("(fail closed)"))
        }
    }

    // ---- authorize(): the assurance step ----

    private val c = case("envelope-max-spend-within")

    private fun run(store: Authorize.StateStore, require: Map<String, Any?>?): Authorize.Result = Authorize.authorize(
        pcactn(c),
        Authorize.Input(
            operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) }, stateStore = store,
            isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP, requireAssurance = require,
        ),
    )

    @Test
    fun everyResultCarriesTheReport() {
        val r = run(Authorize.MemoryStateStore(), null)
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals(canon(linkedMapOf("outcome" to "pass", "suites" to listOf("ed25519"), "level" to "ed25519")), canon(r.assurance["leaf_signature"]))
        assertEquals("ed25519", r.assurance["chain"]?.get("level"))
        assertEquals(canon(linkedMapOf("outcome" to "pass")), canon(r.assurance["replay"]))
        assertFalse(r.checks.containsKey("assurance"))
    }

    @Test
    fun anUnmetPolicyDeniesBeforeTheCounterIsConsumed() {
        val store = Authorize.MemoryStateStore()
        val denied = run(store, mapOf("signature" to "pq"))
        assertFalse(denied.allow)
        assertEquals("fail", denied.checks["assurance"])
        assertEquals("assurance: post-quantum signatures required but leaf_signature is ed25519", denied.reason)
        assertEquals("fail", denied.assurance["assurance"]?.get("outcome"))
        // no replay state was written: the same proof is admitted without the policy
        val ok = run(store, null)
        assertTrue(ok.reasons.toString(), ok.allow)
    }

    @Test
    fun aMetEmptyPolicyPassesTheCheck() {
        val r = run(Authorize.MemoryStateStore(), emptyMap())
        assertTrue(r.reasons.toString(), r.allow)
        assertEquals("pass", r.checks["assurance"])
    }

    @Test
    fun aBadRequirementIsRefusedFailClosed() {
        val r = run(Authorize.MemoryStateStore(), mapOf("nonsense" to 1))
        assertFalse(r.allow)
        assertEquals("assurance: unknown assurance requirement(s): nonsense (fail closed)", r.reason)
    }

    @Test
    fun degradedAndBondEvidenceIsNeverAPass() {
        val deg = Assurance.report(null, linkedMapOf("tighten" to "pass"), mapOf("tighten" to "model_polarity legacy"))
        assertEquals(true, deg["tighten"]?.get("degraded"))
        assertEquals(
            "assurance: tighten rests on a degraded compatibility mode (model_polarity legacy); a high-assurance policy never accepts it",
            Assurance.unmetAssurance(deg, emptyMap()),
        )
        val bond = Assurance.report(ParityVectors.obj("""{"bond_ref":"x"}"""), linkedMapOf("replay" to "pass"))
        assertEquals("unsupported", bond["bond"]?.get("outcome"))
        assertNotNull(Assurance.unmetAssurance(bond, emptyMap()))
        assertNull(Assurance.unmetAssurance(Assurance.report(null, linkedMapOf("replay" to "pass")), emptyMap()))
    }
}
